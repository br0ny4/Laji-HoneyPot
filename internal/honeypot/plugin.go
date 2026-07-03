package honeypot

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/bait"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	dnsSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/dns"
	ftpSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/ftp"
	httpSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/http"
	ldapSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/ldap"
	mysqlSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/mysql"
	rdpSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/rdp"
	redisSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/redis"
	smbSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/smb"
	sshSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/ssh"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/tcpstack"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

// Engine 蜜罐引擎插件
type Engine struct {
	plugin.Base
	logger           *log.Logger
	bus              *bus.Bus
	store            *store.Store
	stack            *tcpstack.Stack
	udpListener      net.PacketConn
	activeSvcs       int
	runningSvcs      []string                                      // 成功启动的服务名列表
	failedSvcs       []string                                      // 启动失败的服务及原因
	portOffset       int                                           // 端口偏移量（HP_PORT_OFFSET 环境变量）
	trapRegistry     *traps.Registry                               // 陷阱模块注册中心（场景化选配）
	httpSrv          *httpSvc.Server                               // HTTP 蜜罐实例
	countermeasureFn func(path, userAgent, remoteIP string) string // 面包屑触发的反制 JS 注入回调
	scanMu           sync.Mutex
	scanTracker      map[string]*scanState // IP -> 扫描状态
}

type scanState struct {
	ports map[int]bool
	first time.Time
	last  time.Time
	svc   string
}

const (
	portScanThreshold = 5  // 不同端口数阈值
	portScanWindow    = 60 // 扫描窗口(秒)
)

// NewEngine 创建蜜罐引擎
func NewEngine(logger *log.Logger, bus *bus.Bus, st *store.Store) *Engine {
	return &Engine{
		logger:      logger,
		bus:         bus,
		store:       st,
		stack:       tcpstack.New(logger),
		scanTracker: make(map[string]*scanState),
	}
}

func (e *Engine) Name() string    { return "honeypot-engine" }
func (e *Engine) Version() string { return "0.4.0" }

// ServiceStatus 返回蜜罐服务的运行状态
func (e *Engine) ServiceStatus() map[string]interface{} {
	return map[string]interface{}{
		"total":            e.activeSvcs,
		"running":          e.runningSvcs,
		"failed":           e.failedSvcs,
		"scenario":         e.trapRegistry.Scenario,
		"enabled_services": e.trapRegistry.EnabledServices(),
	}
}

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("honeypot engine initializing")

	// 初始化陷阱模块注册中心（场景化选配）
	scenario := traps.ParseScenario(cfg.Get("trap_scenario"))
	customSvcs := parseStringSlice(cfg, "custom_services")
	e.trapRegistry = traps.New(scenario, customSvcs)
	e.logger.Infow("trap registry initialized",
		"scenario", e.trapRegistry.Scenario,
		"enabled_services", e.trapRegistry.EnabledServices(),
	)

	// 解析 HP_PORT_OFFSET 环境变量，支持手动整体偏移所有端口
	if offsetStr := os.Getenv("HP_PORT_OFFSET"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			e.portOffset = o
			e.logger.Infow("HP_PORT_OFFSET applied, all ports will be shifted",
				"offset", e.portOffset)
		} else {
			e.logger.Warnw("invalid HP_PORT_OFFSET, ignoring", "value", offsetStr)
		}
	}

	// HTTP 蜜罐（仅在场景启用时创建）
	var httpSrv *httpSvc.Server
	if e.trapRegistry.IsHTTPEnabled() {
		httpSrv = httpSvc.New(e.logger, e.store)
		e.httpSrv = httpSrv

		// 加载自定义 HTTP 响应模板（YAML 配置驱动，无需改代码即可添加蜜罐页面）
		if tmpls := parseCustomTemplates(cfg); len(tmpls) > 0 {
			httpSrv.SetCustomTemplates(tmpls)
			e.logger.Infow("custom http templates loaded", "count", len(tmpls))
		}
	}

	// 数据库蜜罐（按场景选配）
	mysqlSrv := mysqlSvc.New(e.logger)
	mysqlSrv.SetBus(e.bus)
	redisSrv := redisSvc.New(e.logger)
	redisSrv.SetBus(e.bus)

	// 远程访问蜜罐（按场景选配）
	sshSrv := sshSvc.New(e.logger)
	sshSrv.SetBus(e.bus)
	ftpSrv := ftpSvc.New(e.logger)
	ftpSrv.SetBus(e.bus)
	rdpSrv := rdpSvc.New(e.logger)

	// 基础设施蜜罐（按场景选配）
	ldapSrv := ldapSvc.New(e.logger)
	smbSrv := smbSvc.New(e.logger)

	// TCP 服务（通过陷阱注册中心过滤：仅启动场景选配的服务）
	tcpPorts := []struct {
		port    int
		name    string
		handler func(net.Conn)
	}{
		{port: cfg.GetInt("http_port"), name: "HTTP",
			handler: e.wrapHandler("HTTP", func(c net.Conn) {
				if httpSrv != nil {
					httpSrv.Handle(c, e.onBreadcrumb)
				}
			})},
		{port: cfg.GetInt("mysql_port"), name: "MySQL",
			handler: e.wrapHandler("MySQL", func(c net.Conn) { mysqlSrv.Handle(c) })},
		{port: cfg.GetInt("redis_port"), name: "Redis",
			handler: e.wrapHandler("Redis", func(c net.Conn) { redisSrv.Handle(c) })},
		{port: cfg.GetInt("ssh_port"), name: "SSH",
			handler: e.wrapHandler("SSH", func(c net.Conn) { sshSrv.Handle(c) })},
		{port: cfg.GetInt("ftp_port"), name: "FTP",
			handler: e.wrapHandler("FTP", func(c net.Conn) { ftpSrv.Handle(c) })},
		{port: cfg.GetInt("ldap_port"), name: "LDAP",
			handler: e.wrapHandler("LDAP", func(c net.Conn) { ldapSrv.Handle(c) })},
		{port: cfg.GetInt("smb_port"), name: "SMB",
			handler: e.wrapHandler("SMB", func(c net.Conn) { smbSrv.Handle(c) })},
		{port: cfg.GetInt("rdp_port"), name: "RDP",
			handler: e.wrapHandler("RDP", func(c net.Conn) { rdpSrv.Handle(c) })},
	}

	for _, s := range tcpPorts {
		// 通过陷阱注册中心判断该服务是否在当前场景下启用
		if !e.trapRegistry.IsServiceEnabled(strings.ToLower(s.name)) {
			e.logger.Infow("service disabled by trap scenario", "name", s.name, "scenario", e.trapRegistry.Scenario)
			continue
		}
		if s.port <= 0 {
			continue
		}

		// 应用 HP_PORT_OFFSET 偏移
		actualPort := s.port + e.portOffset

		// 预检测端口是否可用（端口冲突检测）
		if !IsPortAvailable(fmt.Sprintf(":%d", actualPort)) {
			e.logger.Errorw("port conflict detected",
				"service", s.name, "port", actualPort,
				"msg", fmt.Sprintf("Port %d (%s) is already in use", actualPort, s.name))

			// 自动递增回退：尝试寻找下一个可用端口
			fallbackPort := FindAvailablePort(actualPort+1, 100)
			if fallbackPort > 0 {
				e.logger.Infow("port escalated due to conflict",
					"service", s.name,
					"from", actualPort,
					"to", fallbackPort,
					"msg", fmt.Sprintf("%s port escalated from %d to %d due to conflict", s.name, actualPort, fallbackPort))
				actualPort = fallbackPort
			} else {
				e.logger.Errorw("no available port found after escalation",
					"service", s.name, "original_port", actualPort)
				e.failedSvcs = append(e.failedSvcs,
					fmt.Sprintf("%s(:%d): port occupied, no fallback available", s.name, actualPort))
				continue
			}
		}

		if err := e.stack.Listen(actualPort, s.handler); err != nil {
			e.logger.Errorw("failed to start tcp service", "name", s.name, "port", actualPort, "error", err)
			e.failedSvcs = append(e.failedSvcs, fmt.Sprintf("%s(:%d): %v", s.name, actualPort, err))
			continue
		}
		e.activeSvcs++
		e.runningSvcs = append(e.runningSvcs, s.name)
	}

	// DNS 使用 UDP（按场景选配）
	if e.trapRegistry.IsServiceEnabled("dns") {
		if dnsPort := cfg.GetInt("dns_port"); dnsPort > 0 {
			dnsSrv := dnsSvc.New(e.logger)
			actualPort := dnsPort + e.portOffset
			addr := fmt.Sprintf(":%d", actualPort)
			dnsFailed := false

			// 预检测 DNS UDP 端口是否可用
			if !IsPortAvailable(addr) {
				e.logger.Errorw("port conflict detected",
					"service", "DNS", "port", actualPort,
					"msg", fmt.Sprintf("Port %d (DNS/UDP) is already in use", actualPort))
				fallbackPort := FindAvailablePort(actualPort+1, 100)
				if fallbackPort > 0 {
					e.logger.Infow("port escalated due to conflict",
						"service", "DNS",
						"from", actualPort,
						"to", fallbackPort,
						"msg", fmt.Sprintf("DNS port escalated from %d to %d due to conflict", actualPort, fallbackPort))
					actualPort = fallbackPort
					addr = fmt.Sprintf(":%d", actualPort)
				} else {
					e.logger.Errorw("no available port found after escalation",
						"service", "DNS", "original_port", actualPort)
					e.failedSvcs = append(e.failedSvcs,
						fmt.Sprintf("DNS(:%d/udp): port occupied, no fallback available", actualPort))
					dnsFailed = true
				}
			}

			if !dnsFailed {
				pc, err := net.ListenPacket("udp", addr)
				if err != nil {
					e.logger.Errorw("failed to start dns udp", "port", actualPort, "error", err)
					e.failedSvcs = append(e.failedSvcs, fmt.Sprintf("DNS(:%d/udp): %v", actualPort, err))
				} else {
					e.udpListener = pc
					e.activeSvcs++
					go e.udpLoop(pc, func(c net.Conn) { dnsSrv.Handle(c) }, actualPort)
					e.logger.Infow("dns honeypot listening", "port", actualPort, "proto", "udp")
				}
			}
		}
	}

	e.logger.Infow("honeypot engine initialized",
		"active_services", e.activeSvcs,
		"scenario", e.trapRegistry.Scenario,
	)
	return nil
}

// detectPortScan 基于连接频率的端口扫描检测
func (e *Engine) detectPortScan(remoteIP string, port int, service string) {
	e.scanMu.Lock()
	defer e.scanMu.Unlock()

	now := time.Now()
	state, exists := e.scanTracker[remoteIP]

	if !exists {
		e.scanTracker[remoteIP] = &scanState{
			ports: map[int]bool{port: true},
			first: now,
			last:  now,
			svc:   service,
		}
		return
	}

	// 清理过期状态（扫描窗口外的重置）
	if now.Sub(state.first) > time.Duration(portScanWindow)*time.Second {
		state.ports = map[int]bool{port: true}
		state.first = now
		state.last = now
		state.svc = service
		return
	}

	state.ports[port] = true
	state.last = now

	// 达到阈值 → 触发扫描告警
	if len(state.ports) >= portScanThreshold {
		portsList := make([]int, 0, len(state.ports))
		for p := range state.ports {
			portsList = append(portsList, p)
		}
		sort.Ints(portsList)
		portsStr := intsToStr(portsList)

		e.logger.Warnw("PORT SCAN DETECTED",
			"remote", remoteIP,
			"ports", portsStr,
			"count", len(state.ports),
			"duration", int(now.Sub(state.first).Seconds()),
		)

		// 持久化
		e.store.RecordPortScan(remoteIP, portsStr, len(state.ports),
			int(now.Sub(state.first).Seconds()), state.svc)

		// 发布扫描事件
		evtData, _ := json.Marshal(map[string]interface{}{
			"remote_ip":   remoteIP,
			"ports":       portsStr,
			"ports_count": len(state.ports),
			"duration":    int(now.Sub(state.first).Seconds()),
			"service":     state.svc,
		})
		e.bus.Publish("honeypot.portscan", evtData)

		// 重置状态，避免重复告警
		delete(e.scanTracker, remoteIP)
	}
}

func intsToStr(arr []int) string {
	parts := make([]string, len(arr))
	for i, v := range arr {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func (e *Engine) udpLoop(pc net.PacketConn, handler func(net.Conn), port int) {
	// 速率限制：最多 100 并发 UDP 处理
	sem := make(chan struct{}, 100)

	for {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			e.logger.Debugw("udp read closed", "port", port, "error", err)
			return
		}

		host, _, _ := net.SplitHostPort(addr.String())
		e.store.RecordConnection(host, port, "DNS", "")
		evtData, _ := json.Marshal(map[string]interface{}{"remote_ip": host, "port": port, "service": "DNS"})
		e.bus.Publish("honeypot.connection", evtData)

		fakeConn := &udpConn{pc: pc, addr: addr, buf: buf[:n], n: n}

		sem <- struct{}{} // 获取令牌
		go func() {
			defer func() {
				if r := recover(); r != nil {
					e.logger.Errorw("DNS handler panic recovered", "port", port, "panic", r)
				}
				<-sem // 释放令牌
			}()
			handler(fakeConn)
		}()
	}
}

// udpConn 将 net.PacketConn 伪装为 net.Conn 供 handler 统一调用
type udpConn struct {
	pc   net.PacketConn
	addr net.Addr
	buf  []byte
	n    int
}

func (c *udpConn) Read(b []byte) (int, error)         { n := copy(b, c.buf[:c.n]); return n, nil }
func (c *udpConn) Write(b []byte) (int, error)        { return c.pc.WriteTo(b, c.addr) }
func (c *udpConn) Close() error                       { return nil }
func (c *udpConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *udpConn) RemoteAddr() net.Addr               { return c.addr }
func (c *udpConn) SetDeadline(t time.Time) error      { return nil }
func (c *udpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *udpConn) SetWriteDeadline(t time.Time) error { return nil }

// bufferedConn 缓冲连接 — 预读数据后仍可完整交付给下游 handler
type bufferedConn struct {
	net.Conn
	buf    []byte // 预读的数据
	cursor int    // 当前读取位置
}

func newBufferedConn(conn net.Conn, buf []byte) *bufferedConn {
	return &bufferedConn{Conn: conn, buf: buf}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.cursor < len(b.buf) {
		n := copy(p, b.buf[b.cursor:])
		b.cursor += n
		if b.cursor >= len(b.buf) {
			b.buf = nil // 释放已读取的缓冲区
		}
		return n, nil
	}
	return b.Conn.Read(p)
}

func (e *Engine) wrapHandler(service string, handler func(net.Conn)) func(net.Conn) {
	return func(conn net.Conn) {
		defer func() {
			if r := recover(); r != nil {
				e.logger.Errorw("handler panic recovered",
					"service", service,
					"remote", conn.RemoteAddr().String(),
					"panic", r,
				)
			}
		}()

		remote := conn.RemoteAddr().String()
		host, portStr, _ := net.SplitHostPort(remote)
		portNum := 0
		if p, err := net.LookupPort("tcp", portStr); err == nil {
			portNum = p
		}

		// 被动 TLS ClientHello 检测（缓冲读取，不丢数据）
		peeked, tlsData := e.detectTLSClientHello(conn, host, portNum, service)
		wrappedConn := newBufferedConn(conn, peeked)

		e.store.RecordConnection(host, portNum, service, "")

		// 端口扫描检测：基于连接频率分析
		e.detectPortScan(host, portNum, service)

		evtData, err := json.Marshal(map[string]interface{}{
			"remote_ip": host, "port": portNum, "service": service,
		})
		if err != nil {
			e.logger.Warnw("json marshal failed in wrapHandler", "error", err)
		} else {
			e.bus.Publish("honeypot.connection", evtData)
		}

		handler(wrappedConn)

		// TLS 指纹数据采集（在 handler 执行后发布，确保协议数据已由服务侧发布）
		e.collectProtocolFingerprint(service, host, tlsData)
	}
}

// detectTLSClientHello 被动检测 TLS ClientHello，返回预读数据(用于缓冲连接)和TLS指纹JSON
func (e *Engine) detectTLSClientHello(conn net.Conn, host string, port int, service string) ([]byte, string) {
	// 仅对常见 TLS 端口检测
	tlsPorts := map[int]bool{443: true, 8081: true, 33890: true, 4450: true, 2121: true, 3890: true}
	if !tlsPorts[port] {
		return nil, ""
	}

	rawConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, ""
	}

	// 读取首字节
	buf := make([]byte, 1)
	rawConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := rawConn.Read(buf)
	rawConn.SetReadDeadline(time.Time{})

	if err != nil || n == 0 {
		return buf[:n], ""
	}

	// TLS ClientHello 首字节为 0x16 (Handshake)
	if buf[0] != 0x16 {
		return buf[:n], ""
	}

	// 读取更多字节解析 ClientHello (最多256字节)
	hello := make([]byte, 256)
	copy(hello, buf)
	rawConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err = rawConn.Read(hello[1:])
	rawConn.SetReadDeadline(time.Time{})
	hello = hello[:1+n]

	// 提取 TLS 版本
	var tlsVersion uint16
	if len(hello) >= 3 {
		tlsVersion = uint16(hello[1])<<8 | uint16(hello[2])
	}

	// 提取 SNI 和 Cipher Suites
	sni, cipherSuites := parseTLSClientHello(hello)

	fp := map[string]interface{}{
		"tls_version":   fmt.Sprintf("0x%04x", tlsVersion),
		"sni":           sni,
		"cipher_suites": cipherSuites,
		"detected":      true,
	}
	data, _ := json.Marshal(fp)
	e.logger.Infow("tls client hello detected",
		"remote", host, "port", port, "service", service,
		"tls_version", fmt.Sprintf("0x%04x", tlsVersion), "sni", sni)

	return hello, string(data)
}

// parseTLSClientHello 解析 TLS ClientHello 提取 SNI 和 Cipher Suites
func parseTLSClientHello(hello []byte) (string, []uint16) {
	var sni string
	var cipherSuites []uint16

	if len(hello) < 45 {
		return sni, cipherSuites
	}

	// 跳过 TLS record header(5) + handshake header(4) + client version(2) + random(32) + session_id_len(1)
	pos := 44
	sidLen := int(hello[pos])
	pos += 1 + sidLen

	// cipher suites
	if pos+1 < len(hello) {
		csLen := int(hello[pos])<<8 | int(hello[pos+1])
		pos += 2
		for i := 0; i < csLen/2 && pos+1 < len(hello) && i < 8; i++ {
			cs := uint16(hello[pos])<<8 | uint16(hello[pos+1])
			cipherSuites = append(cipherSuites, cs)
			pos += 2
		}
		// 跳过未读取完的 cipher suites
		pos = 44 + 1 + sidLen + 2 + csLen
	}

	// compression methods
	if pos < len(hello) {
		compLen := int(hello[pos])
		pos += 1 + compLen
	}

	// Extensions
	if pos+1 < len(hello) {
		extLen := int(hello[pos])<<8 | int(hello[pos+1])
		pos += 2
		extEnd := pos + extLen
		for pos+3 < extEnd && pos+3 < len(hello) {
			extType := uint16(hello[pos])<<8 | uint16(hello[pos+1])
			extSize := int(hello[pos+2])<<8 | int(hello[pos+3])
			pos += 4
			if extType == 0 && pos+4 < len(hello) {
				// SNI: server_name_list_len(2) + name_type(1) + name_len(2) + name
				nameLen := int(hello[pos+3])<<8 | int(hello[pos+4])
				if pos+5+nameLen <= len(hello) {
					sni = string(hello[pos+5 : pos+5+nameLen])
				}
			}
			pos += extSize
		}
	}

	return sni, cipherSuites
}

// collectProtocolFingerprint 采集 TLS 指纹基线数据并通过事件总线发布
func (e *Engine) collectProtocolFingerprint(service, host, tlsData string) {
	if tlsData == "" {
		return
	}
	evtData, _ := json.Marshal(map[string]interface{}{
		"remote_ip": host,
		"service":   service,
		"tls_data":  tlsData,
		"timestamp": time.Now().Unix(),
	})
	if evtData != nil {
		e.bus.Publish("honeypot.fingerprint", evtData)
	}
}

func (e *Engine) onBreadcrumb(remoteIP, path, userAgent string) {
	e.logger.Warnw("BREADCRUMB TRIGGERED", "remote", remoteIP, "path", path, "ua", userAgent)
	// 异步记录攻击事件，避免阻塞 TCP 响应
	go e.store.RecordAttack(remoteIP, path, userAgent, "breadcrumb_trigger")
	// 标记该IP上次反制措施为有效（攻击者再次触发面包屑说明反制奏效）
	go e.store.MarkCountermeasureEffective(remoteIP)
	evtData, err := json.Marshal(map[string]interface{}{
		"remote_ip": remoteIP, "path": path, "user_agent": userAgent,
	})
	if err != nil {
		e.logger.Warnw("json marshal failed in onBreadcrumb", "error", err)
		return
	}
	// 异步发布 breadcrumb 事件，避免阻塞 TCP 响应
	e.bus.Publish("honeypot.breadcrumb", evtData)
	e.bus.Publish("honeypot.attack", evtData)
}

// SetCountermeasureProvider 注册反制 Payload 注入回调
// 当面包屑触发时，HTTP 蜜罐会调用此回调获取额外 JS 注入到响应中
func (e *Engine) SetCountermeasureProvider(fn func(path, userAgent, remoteIP string) string) {
	e.countermeasureFn = fn
	if e.httpSrv != nil {
		e.httpSrv.SetCountermeasureCallback(fn)
	}
}

// SetDecoyPageProvider 注册诱饵页面回调（如冰蝎 JSP、Cobalt Strike 反制页面）
func (e *Engine) SetDecoyPageProvider(fn httpSvc.DecoyPageCallback) {
	if e.httpSrv != nil {
		e.httpSrv.SetDecoyPageCallback(fn)
	}
}

// SetBaitSystem 注入蜜标生成器和追踪器到 HTTP 蜜罐服务
func (e *Engine) SetBaitSystem(gen *bait.Generator, tracker *bait.Tracker) {
	if e.httpSrv != nil {
		e.httpSrv.SetBaitSystem(gen, tracker)
	}
}

// Close 停止所有监听器并释放所有端口。
// 应在收到 SIGINT/SIGTERM 时调用以确保端口被正确释放。
func (e *Engine) Close() error {
	e.logger.Info("releasing all honeypot ports...")
	e.stack.CloseAll()
	if e.udpListener != nil {
		e.udpListener.Close()
	}
	e.logger.Info("all ports released")
	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("honeypot engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("honeypot engine stopping")
	return e.Close()
}

// GetTrapRegistry 暴露陷阱注册中心（供溯源引擎查询场景信息）
func (e *Engine) GetTrapRegistry() *traps.Registry {
	return e.trapRegistry
}

// parseCustomTemplates 从配置中解析自定义 HTTP 响应模板
func parseCustomTemplates(cfg config.Section) []httpSvc.CustomTemplate {
	raw, ok := cfg["custom_templates"]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	templates := make([]httpSvc.CustomTemplate, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		t := httpSvc.CustomTemplate{}
		if v, ok := m["path"].(string); ok {
			t.Path = v
		}
		if v, ok := m["status"].(int); ok {
			t.Status = v
		}
		if v, ok := m["content_type"].(string); ok {
			t.ContentType = v
		}
		if v, ok := m["body"].(string); ok {
			t.Body = v
		}
		if v, ok := m["is_breadcrumb"].(bool); ok {
			t.IsBreadcrumb = v
		}
		if t.Path != "" {
			if t.Status == 0 {
				t.Status = 200
			}
			if t.ContentType == "" {
				t.ContentType = "text/html"
			}
			templates = append(templates, t)
		}
	}
	return templates
}

// parseStringSlice 从配置 Section 中解析字符串数组（如 custom_services）
func parseStringSlice(cfg config.Section, key string) []string {
	raw, ok := cfg[key]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
