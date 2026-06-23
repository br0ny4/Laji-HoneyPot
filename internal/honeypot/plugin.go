package honeypot

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

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
	httpSrv          *httpSvc.Server                               // HTTP 蜜罐实例
	countermeasureFn func(path, userAgent, remoteIP string) string // 面包屑触发的反制 JS 注入回调
}

// NewEngine 创建蜜罐引擎
func NewEngine(logger *log.Logger, bus *bus.Bus, st *store.Store) *Engine {
	return &Engine{
		logger: logger,
		bus:    bus,
		store:  st,
		stack:  tcpstack.New(logger),
	}
}

func (e *Engine) Name() string    { return "honeypot-engine" }
func (e *Engine) Version() string { return "0.4.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("honeypot engine initializing")

	httpSrv := httpSvc.New(e.logger, e.store)
	e.httpSrv = httpSrv
	mysqlSrv := mysqlSvc.New(e.logger)
	redisSrv := redisSvc.New(e.logger)
	sshSrv := sshSvc.New(e.logger)
	ftpSrv := ftpSvc.New(e.logger)
	ldapSrv := ldapSvc.New(e.logger)
	smbSrv := smbSvc.New(e.logger)
	rdpSrv := rdpSvc.New(e.logger)

	// TCP 服务
	tcpPorts := []struct {
		port    int
		name    string
		handler func(net.Conn)
	}{
		{port: cfg.GetInt("http_port"), name: "HTTP",
			handler: e.wrapHandler("HTTP", func(c net.Conn) { httpSrv.Handle(c, e.onBreadcrumb) })},
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
		if s.port <= 0 {
			continue
		}
		if err := e.stack.Listen(s.port, s.handler); err != nil {
			e.logger.Warnw("failed to start tcp service", "name", s.name, "port", s.port, "error", err)
			continue
		}
		e.activeSvcs++
	}

	// DNS 使用 UDP
	if dnsPort := cfg.GetInt("dns_port"); dnsPort > 0 {
		dnsSrv := dnsSvc.New(e.logger)
		addr := fmt.Sprintf(":%d", dnsPort)
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			e.logger.Warnw("failed to start dns udp", "port", dnsPort, "error", err)
		} else {
			e.udpListener = pc
			e.activeSvcs++
			go e.udpLoop(pc, func(c net.Conn) { dnsSrv.Handle(c) }, dnsPort)
			e.logger.Infow("dns honeypot listening", "port", dnsPort, "proto", "udp")
		}
	}

	e.logger.Infow("honeypot engine initialized", "active_services", e.activeSvcs)
	return nil
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

		evtData, err := json.Marshal(map[string]interface{}{
			"remote_ip": host, "port": portNum, "service": service,
		})
		if err != nil {
			e.logger.Warnw("json marshal failed in wrapHandler", "error", err)
		} else {
			e.bus.Publish("honeypot.connection", evtData)
		}

		// 协议指纹数据采集
		e.collectProtocolFingerprint(service, conn, host, tlsData)

		handler(wrappedConn)
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

// collectProtocolFingerprint 采集协议指纹数据并通过事件总线发布
func (e *Engine) collectProtocolFingerprint(service string, conn net.Conn, host string, tlsData string) {
	// 通过事件总线发布指纹事件，溯源引擎负责消费和持久化
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
	e.store.RecordAttack(remoteIP, path, userAgent, "breadcrumb_trigger")
	// 标记该IP上次反制措施为有效（攻击者再次触发面包屑说明反制奏效）
	e.store.MarkCountermeasureEffective(remoteIP)
	evtData, err := json.Marshal(map[string]interface{}{
		"remote_ip": remoteIP, "path": path, "user_agent": userAgent,
	})
	if err != nil {
		e.logger.Warnw("json marshal failed in onBreadcrumb", "error", err)
		return
	}
	// 同步发布 breadcrumb 事件（溯源引擎需即时响应）
	e.bus.PublishSync("honeypot.breadcrumb", evtData)
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

func (e *Engine) Start() error {
	e.logger.Info("honeypot engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("honeypot engine stopping")
	e.stack.CloseAll()
	if e.udpListener != nil {
		e.udpListener.Close()
	}
	return nil
}
