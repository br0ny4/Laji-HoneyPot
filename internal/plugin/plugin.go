package plugin

import "github.com/Laji-HoneyPot/honeypot/internal/core/config"

// Plugin 是所有蜜罐插件的统一接口契约。
// 任何功能模块（蜜罐引擎、溯源引擎、反制引擎、运维引擎）都必须实现此接口。
type Plugin interface {
	// Name 返回插件唯一标识，如 "honeypot-http", "traceability-vulndb"
	Name() string
	// Version 返回语义化版本号
	Version() string
	// Init 初始化插件，接收配置切片
	Init(cfg config.Section) error
	// Start 启动插件，不应阻塞
	Start() error
	// Stop 优雅停止插件
	Stop() error
}

// Base 提供默认空实现，插件可嵌入以减少样板代码
type Base struct{}

func (Base) Init(cfg config.Section) error { return nil }
func (Base) Start() error                  { return nil }
func (Base) Stop() error                   { return nil }
