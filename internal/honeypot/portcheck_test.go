package honeypot

import (
	"fmt"
	"net"
	"strconv"
	"testing"
)

func TestIsPortAvailable_FreePort(t *testing.T) {
	// 找一个随机可用端口来验证
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if !IsPortAvailable(addr) {
		t.Errorf("expected port %s to be available after close", addr)
	}
}

func TestIsPortAvailable_OccupiedPort(t *testing.T) {
	// 占用一个端口，验证 IsPortAvailable 返回 false
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	if IsPortAvailable(addr) {
		t.Errorf("expected port %s to be occupied", addr)
	}
}

func TestFindAvailablePort_FindsFreePort(t *testing.T) {
	// 从一个很大的端口开始找，大概率是空闲的
	port := FindAvailablePort(50000, 10)
	if port <= 0 {
		t.Error("expected to find a free port")
	}

	// 验证找到的端口确实可用
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Errorf("found port %d but it's not available: %v", port, err)
	} else {
		ln.Close()
	}
}

func TestFindAvailablePort_AllOccupied(t *testing.T) {
	// 占用一个端口（绑定所有接口），验证从该端口开始找不到可用端口
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	result := FindAvailablePort(port, 1)
	if result != -1 {
		t.Errorf("expected no available port starting from %d (only 1 attempt), got %d", port, result)
	}
}

func TestCheckServicePorts_AllAvailable(t *testing.T) {
	// 使用高位端口，大概率空闲
	services := []ServiceConfig{
		{Name: "HTTP", Port: 51080},
		{Name: "MySQL", Port: 51306},
	}

	result, err := CheckServicePorts(services)
	if err != nil {
		t.Fatalf("CheckServicePorts failed: %v", err)
	}

	if len(result.Available) != 2 {
		t.Errorf("expected 2 available services, got %d: %v", len(result.Available), result.Available)
	}
	if len(result.Conflicted) != 0 {
		t.Errorf("expected 0 conflicted, got %d", len(result.Conflicted))
	}
}

func TestCheckServicePorts_WithConflict(t *testing.T) {
	// 占用一个端口（绑定所有接口），验证冲突检测
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to listen on random port: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	occupiedPort, _ := strconv.Atoi(portStr)

	services := []ServiceConfig{
		{Name: "HTTP", Port: 52080},
		{Name: "MySQL", Port: occupiedPort}, // 这个被占用
	}

	result, err := CheckServicePorts(services)
	if err != nil {
		t.Fatalf("CheckServicePorts failed: %v", err)
	}

	if len(result.Available) != 1 || result.Available[0] != "HTTP" {
		t.Errorf("expected HTTP available, got: %v", result.Available)
	}
	if len(result.Conflicted) != 1 || result.Conflicted[0].Service != "MySQL" {
		t.Errorf("expected MySQL conflicted, got: %v", result.Conflicted)
	}
	if result.Conflicted[0].Port != occupiedPort {
		t.Errorf("expected conflicted port %d, got %d", occupiedPort, result.Conflicted[0].Port)
	}
}

func TestCheckServicePorts_EmptyList(t *testing.T) {
	result, err := CheckServicePorts(nil)
	if err != nil {
		t.Fatalf("CheckServicePorts failed: %v", err)
	}
	if len(result.Available) != 0 || len(result.Conflicted) != 0 {
		t.Errorf("expected empty results, got available=%d conflicted=%d",
			len(result.Available), len(result.Conflicted))
	}
}
