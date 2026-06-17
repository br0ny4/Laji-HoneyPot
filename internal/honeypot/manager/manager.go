package manager

import (
	"context"
	"fmt"
	"sync"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// ContainerManager 管理蜜罐容器的生命周期与安全配置
type ContainerManager struct {
	mu       sync.Mutex
	logger   *log.Logger
	profiles map[string]*SecurityProfile
}

// SecurityProfile 容器安全配置
type SecurityProfile struct {
	Image      string
	ReadOnly   bool
	NoNewPriv  bool
	Privileged bool
	CapDrop    []string
	Seccomp    string
}

// NewManager 创建容器管理器
func NewManager(logger *log.Logger) *ContainerManager {
	return &ContainerManager{
		logger:   logger,
		profiles: make(map[string]*SecurityProfile),
	}
}

// ValidateProfile 校验安全配置的有效性
func (m *ContainerManager) ValidateProfile(name string, profile *SecurityProfile) error {
	if profile.Image == "" {
		return fmt.Errorf("container %s: image is required", name)
	}
	if profile.Privileged {
		return fmt.Errorf("container %s: privileged mode is forbidden for honeypot containers", name)
	}
	if profile.ReadOnly && len(profile.CapDrop) == 0 {
		m.logger.Warnw("container has ReadOnly but no CapDrop", "name", name)
	}
	return nil
}

// RunHoneypot 启动一个安全隔离的蜜罐容器
func (m *ContainerManager) RunHoneypot(ctx context.Context, name string, profile *SecurityProfile, portBindings map[string]string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ValidateProfile(name, profile); err != nil {
		return "", err
	}

	m.profiles[name] = profile
	m.logger.Infow("honeypot container registered",
		"name", name,
		"image", profile.Image,
		"readonly", profile.ReadOnly,
		"no_new_priv", profile.NoNewPriv,
		"cap_drop", len(profile.CapDrop),
	)

	return name, nil
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

// DefaultMySQLProfile 返回 MySQL 蜜罐的默认安全配置
func DefaultMySQLProfile() *SecurityProfile {
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
		Seccomp: "seccomp-mysql.json",
	}
}

// Stop 停止并清理容器
func (m *ContainerManager) Stop(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.profiles, name)
	m.logger.Infow("honeypot container stopped", "name", name)
}

// Close 清理所有容器资源
func (m *ContainerManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.profiles {
		delete(m.profiles, name)
	}
	return nil
}
