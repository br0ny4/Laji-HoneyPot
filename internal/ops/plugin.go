package ops

import (
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/github"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/research"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

// Engine 运维引擎插件
type Engine struct {
	plugin.Base
	logger     *log.Logger
	bus        *bus.Bus
	syncer     *github.Syncer
	comparator *research.Comparator
}

// NewEngine 创建运维引擎
func NewEngine(logger *log.Logger, bus *bus.Bus) *Engine {
	return &Engine{
		logger:     logger,
		bus:        bus,
		comparator: research.NewComparator(logger),
	}
}

func (e *Engine) Name() string    { return "ops-engine" }
func (e *Engine) Version() string { return "0.4.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("ops engine initializing")

	token := cfg.Get("github_token")
	owner := cfg.Get("github_owner")
	repo := cfg.Get("github_repo")
	if token != "" && owner != "" && repo != "" {
		e.syncer = github.NewSyncer(e.logger, token, owner, repo)
		e.logger.Info("github syncer initialized")
	}

	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("ops engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("ops engine stopped")
	return nil
}

func (e *Engine) GetComparator() *research.Comparator { return e.comparator }
func (e *Engine) GetSyncer() *github.Syncer           { return e.syncer }
