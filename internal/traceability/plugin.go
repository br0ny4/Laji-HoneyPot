package traceability

import (
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/fingerprint"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/payload"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

// Engine 溯源反制引擎插件
type Engine struct {
	plugin.Base
	logger     *log.Logger
	bus        *bus.Bus
	vulnDB     *vulndb.DB
	collector  *fingerprint.Collector
	payloadGen *payload.Generator
}

// NewEngine 创建溯源反制引擎
func NewEngine(logger *log.Logger, bus *bus.Bus) *Engine {
	e := &Engine{
		logger:     logger,
		bus:        bus,
		vulnDB:     vulndb.NewDB(logger),
		collector:  fingerprint.NewCollector(logger),
		payloadGen: payload.NewGenerator(logger, "http://localhost:8080"),
	}

	// 订阅蜜罐引擎的连接事件
	bus.Subscribe("honeypot.connection", e.onConnection)
	bus.Subscribe("honeypot.attack", e.onAttack)
	bus.Subscribe("honeypot.breadcrumb", e.onBreadcrumbTrigger)

	return e
}

func (e *Engine) Name() string    { return "traceability-engine" }
func (e *Engine) Version() string { return "0.1.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("traceability engine initialized")
	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("traceability engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("traceability engine stopped")
	return nil
}

func (e *Engine) onConnection(evt bus.Event) {
	e.collector.RecordConnection(string(evt.Payload))
}

func (e *Engine) onAttack(evt bus.Event) {
	e.logger.Infow("attack detected", "payload", string(evt.Payload))
}

func (e *Engine) onBreadcrumbTrigger(evt bus.Event) {
	e.logger.Warnw("BREADCRUMB TRIGGERED — attacker confirmed", "details", string(evt.Payload))
}

// GetVulnDB 暴露漏洞库
func (e *Engine) GetVulnDB() *vulndb.DB { return e.vulnDB }

// GetCollector 暴露指纹采集器
func (e *Engine) GetCollector() *fingerprint.Collector { return e.collector }

// GetPayloadGen 暴露 Payload 生成器
func (e *Engine) GetPayloadGen() *payload.Generator { return e.payloadGen }
