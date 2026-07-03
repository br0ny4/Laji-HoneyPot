package honeypot

import (
	"fmt"
	"net"
)

// ServiceConfig 描述一个蜜罐服务的端口配置
type ServiceConfig struct {
	Name string // 服务名称，如 "HTTP", "MySQL"
	Port int    // 计划监听的端口号
}

// PortConflict 描述端口冲突的详细信息
type PortConflict struct {
	Port       int    // 冲突的端口号
	Service    string // 服务名称
	OccupiedBy string // 占用进程的描述信息（跨平台兼容，可能为空）
}

// PortCheckResult 批量端口检查的结果
type PortCheckResult struct {
	Available []string       // 端口可用的服务名列表
	Conflicted []PortConflict // 端口冲突的服务列表
}

// PortChecker 端口可用性检查器
type PortChecker struct{}

// IsPortAvailable 通过尝试短暂 TCP 监听来检查指定地址的端口是否可用。
// addr 格式应为 ":port" 或 "host:port"。
// 返回 true 表示端口空闲可用，false 表示端口已被占用。
func IsPortAvailable(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// FindAvailablePort 从 startPort 开始逐个尝试，寻找第一个可用的 TCP 端口。
// 最多尝试 maxAttempts 次，每次端口号递增 1。
// 返回找到的可用端口号；如果全部被占用则返回 -1。
func FindAvailablePort(startPort int, maxAttempts int) int {
	for i := 0; i < maxAttempts; i++ {
		port := startPort + i
		addr := fmt.Sprintf(":%d", port)
		if IsPortAvailable(addr) {
			return port
		}
	}
	return -1
}

// CheckServicePorts 批量检查所有蜜罐服务计划使用的端口是否可用。
// 返回哪些服务端口可用、哪些存在冲突。
func CheckServicePorts(services []ServiceConfig) (*PortCheckResult, error) {
	result := &PortCheckResult{
		Available:  make([]string, 0, len(services)),
		Conflicted: make([]PortConflict, 0),
	}

	for _, svc := range services {
		addr := fmt.Sprintf(":%d", svc.Port)
		if IsPortAvailable(addr) {
			result.Available = append(result.Available, svc.Name)
		} else {
			result.Conflicted = append(result.Conflicted, PortConflict{
				Port:    svc.Port,
				Service: svc.Name,
			})
		}
	}

	return result, nil
}
