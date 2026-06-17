package registry

import (
	"fmt"
	"sync"

	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

// Registry 插件注册中心，负责所有插件的生命周期管理
type Registry struct {
	mu      sync.Mutex
	plugins map[string]plugin.Plugin
	logger  *log.Logger
	cfg     *config.Config
}

// New 创建注册中心
func New(logger *log.Logger, cfg *config.Config) *Registry {
	return &Registry{
		plugins: make(map[string]plugin.Plugin),
		logger:  logger,
		cfg:     cfg,
	}
}

// Register 注册插件
func (r *Registry) Register(p plugin.Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}
	r.plugins[name] = p
	r.logger.Infow("plugin registered", "name", name, "version", p.Version())
	return nil
}

// InitAll 初始化所有已注册插件
func (r *Registry) InitAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, p := range r.plugins {
		section, ok := r.cfg.Plugins[name]
		if !ok {
			section = config.Section{}
		}
		if err := p.Init(section); err != nil {
			return fmt.Errorf("init plugin %s: %w", name, err)
		}
		r.logger.Infow("plugin initialized", "name", name)
	}
	return nil
}

// StartAll 启动所有已注册插件
func (r *Registry) StartAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, p := range r.plugins {
		if err := p.Start(); err != nil {
			return fmt.Errorf("start plugin %s: %w", name, err)
		}
		r.logger.Infow("plugin started", "name", name)
	}
	return nil
}

// StopAll 停止所有插件
func (r *Registry) StopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, p := range r.plugins {
		if err := p.Stop(); err != nil {
			r.logger.Errorw("stop plugin failed", "name", name, "error", err)
		} else {
			r.logger.Infow("plugin stopped", "name", name)
		}
	}
}

// Get 按名称获取插件
func (r *Registry) Get(name string) (plugin.Plugin, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plugins[name]
	return p, ok
}

// List 列出所有插件名称
func (r *Registry) List() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}
