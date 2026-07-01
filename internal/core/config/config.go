package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// AlertChannelConfig 告警通道配置
type AlertChannelConfig struct {
	Type        string   `yaml:"type"`
	URL         string   `yaml:"url"`
	Enabled     bool     `yaml:"enabled"`
	EventFilter []string `yaml:"event_filter,omitempty"`
}

// ClusterConfig 集群配置
type ClusterConfig struct {
	Enabled     bool   `yaml:"enabled"`      // 是否启用集群模式
	Role        string `yaml:"role"`         // 角色: manager | node
	ListenAddr  string `yaml:"listen_addr"`  // 管理端监听地址
	ManagerAddr string `yaml:"manager_addr"` // 节点端：管理端地址
	CertFile    string `yaml:"cert_file"`    // TLS 证书路径
	KeyFile     string `yaml:"key_file"`     // TLS 私钥路径
	CAFile      string `yaml:"ca_file"`      // CA 证书路径
}

// Config 顶层配置结构
type Config struct {
	LogLevel      string               `yaml:"log_level"`
	Plugins       map[string]Section   `yaml:"plugins"`
	APIAddr       string               `yaml:"api_addr"`
	DataDir       string               `yaml:"data_dir"`
	APIKey        string               `yaml:"api_key"`
	Cluster       ClusterConfig        `yaml:"cluster"`
	AlertChannels []AlertChannelConfig `yaml:"alerts,omitempty"`
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
			applyEnvOverrides(cfg)
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
	if v := os.Getenv("HP_API_KEY"); v != "" {
		cfg.APIKey = v
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

// GetBool 从 Section 中安全获取 bool 值
func (s Section) GetBool(key string) bool {
	v, ok := s[key]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true" || val == "1"
	case int:
		return val != 0
	case float64:
		return val != 0
	default:
		return false
	}
}
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
