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
		host, port, _ := net.SplitHostPort(remote)
		portNum := 0
		if p, err := net.LookupPort("tcp", port); err == nil {
			portNum = p
		}

		e.store.RecordConnection(host, portNum, service, "")

		evtData, err := json.Marshal(map[string]interface{}{
			"remote_ip": host, "port": portNum, "service": service,
		})
		if err != nil {
			e.logger.Warnw("json marshal failed in wrapHandler", "error", err)
		} else {
			e.bus.Publish("honeypot.connection", evtData)
		}

		handler(conn)
	}
}

func (e *Engine) onBreadcrumb(remoteIP, path, userAgent string) {
	e.logger.Warnw("BREADCRUMB TRIGGERED", "remote", remoteIP, "path", path, "ua", userAgent)
	e.store.RecordAttack(remoteIP, path, userAgent, "breadcrumb_trigger")
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
