package honeypot

import (
	"net"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
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
	stack  *tcpstack.Stack
}

// NewEngine 创建蜜罐引擎
func NewEngine(logger *log.Logger, bus *bus.Bus) *Engine {
	return &Engine{
		logger: logger,
		bus:    bus,
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
		{port: cfg.GetInt("http_port"), name: "HTTP", handler: func(c net.Conn) { httpSrv.Handle(c) }},
		{port: cfg.GetInt("mysql_port"), name: "MySQL", handler: func(c net.Conn) { mysqlSrv.Handle(c) }},
		{port: cfg.GetInt("redis_port"), name: "Redis", handler: func(c net.Conn) { redisSrv.Handle(c) }},
		{port: cfg.GetInt("ssh_port"), name: "SSH", handler: func(c net.Conn) { sshSrv.Handle(c) }},
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

func (e *Engine) Start() error {
	e.logger.Info("honeypot engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("honeypot engine stopping")
	e.stack.CloseAll()
	return nil
}
