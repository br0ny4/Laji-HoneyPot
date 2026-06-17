package honeypot

import (
	"encoding/json"
	"net"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	httpSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/http"
	mysqlSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/mysql"
	redisSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/redis"
	sshSvc "github.com/Laji-HoneyPot/honeypot/internal/honeypot/services/ssh"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/tcpstack"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

// Engine 蜜罐引擎插件
type Engine struct {
	plugin.Base
	logger *log.Logger
	bus    *bus.Bus
	store  *store.Store
	stack  *tcpstack.Stack
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
func (e *Engine) Version() string { return "0.1.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("honeypot engine initializing")

	httpSrv := httpSvc.New(e.logger)
	mysqlSrv := mysqlSvc.New(e.logger)
	redisSrv := redisSvc.New(e.logger)
	sshSrv := sshSvc.New(e.logger)

	ports := []struct {
		port    int
		name    string
		handler func(net.Conn)
	}{
		{
			port: cfg.GetInt("http_port"),
			name: "HTTP",
			handler: e.wrapHandler("HTTP", func(c net.Conn) {
				httpSrv.Handle(c, e.onBreadcrumb)
			}),
		},
		{
			port: cfg.GetInt("mysql_port"),
			name: "MySQL",
			handler: e.wrapHandler("MySQL", func(c net.Conn) {
				mysqlSrv.Handle(c)
			}),
		},
		{
			port: cfg.GetInt("redis_port"),
			name: "Redis",
			handler: e.wrapHandler("Redis", func(c net.Conn) {
				redisSrv.Handle(c)
			}),
		},
		{
			port: cfg.GetInt("ssh_port"),
			name: "SSH",
			handler: e.wrapHandler("SSH", func(c net.Conn) {
				sshSrv.Handle(c)
			}),
		},
	}

	for _, s := range ports {
		if s.port <= 0 {
			continue
		}
		if err := e.stack.Listen(s.port, s.handler); err != nil {
			e.logger.Warnw("failed to start service", "name", s.name, "port", s.port, "error", err)
		}
	}

	return nil
}

// wrapHandler 包裹 handler，自动记录连接日志、发布事件
func (e *Engine) wrapHandler(service string, handler func(net.Conn)) func(net.Conn) {
	return func(conn net.Conn) {
		remote := conn.RemoteAddr().String()
		host, port, _ := net.SplitHostPort(remote)
		portNum := 0
		if p, err := net.LookupPort("tcp", port); err == nil {
			portNum = p
		}

		// 记录连接到数据库
		e.store.RecordConnection(host, portNum, service, "")

		// 发布连接事件到事件总线
		evtData, _ := json.Marshal(map[string]interface{}{
			"remote_ip": host,
			"port":      portNum,
			"service":   service,
		})
		e.bus.Publish("honeypot.connection", evtData)

		// 执行实际 handler
		handler(conn)
	}
}

// onBreadcrumb HTTP 面包屑触发回调
func (e *Engine) onBreadcrumb(remoteIP, path, userAgent string) {
	e.logger.Warnw("BREADCRUMB TRIGGERED",
		"remote", remoteIP,
		"path", path,
		"ua", userAgent,
	)

	// 记录攻击事件到数据库
	e.store.RecordAttack(remoteIP, path, "unknown", userAgent)

	// 发布事件到总线
	evtData, _ := json.Marshal(map[string]interface{}{
		"remote_ip":  remoteIP,
		"path":       path,
		"user_agent": userAgent,
	})
	e.bus.Publish("honeypot.attack", evtData)
}

func (e *Engine) Start() error {
	e.logger.Info("honeypot engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("honeypot engine stopping")
	e.stack.CloseAll()
	return nil
}
