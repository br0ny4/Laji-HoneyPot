package ftp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestFTPBannerAndLogin(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	// 在随机端口启动 TCP 监听
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	// 客户端连接
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 读取 220 banner
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}
	if !strings.Contains(line, "vsFTPd") {
		t.Errorf("banner should contain 'vsFTPd', got: %s", line)
	}

	// 发送 USER
	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		t.Fatalf("failed to write USER: %v", err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read USER response: %v", err)
	}
	if !strings.Contains(line, "331") {
		t.Errorf("expected 331, got: %s", line)
	}

	// 发送 PASS
	_, err = conn.Write([]byte("PASS guest\r\n"))
	if err != nil {
		t.Fatalf("failed to write PASS: %v", err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read PASS response: %v", err)
	}
	if !strings.Contains(line, "530") {
		t.Errorf("expected 530, got: %s", line)
	}
}

func TestFTPSYSTCommand(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 读取 banner
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	// 发送 SYST
	_, err = conn.Write([]byte("SYST\r\n"))
	if err != nil {
		t.Fatalf("failed to write SYST: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read SYST response: %v", err)
	}
	if !strings.Contains(line, "UNIX Type") {
		t.Errorf("SYST response should contain 'UNIX Type', got: %s", line)
	}
}

func TestFTPFEATCommand(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 读取 banner
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	// 发送 FEAT
	_, err = conn.Write([]byte("FEAT\r\n"))
	if err != nil {
		t.Fatalf("failed to write FEAT: %v", err)
	}

	// 读取多行 FEAT 响应
	var response string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read FEAT response: %v", err)
		}
		response += line
		if strings.HasPrefix(line, "211 ") {
			break
		}
	}

	if !strings.Contains(response, "EPRT") {
		t.Errorf("FEAT response should contain 'EPRT', got: %s", response)
	}
	if !strings.Contains(response, "PASV") {
		t.Errorf("FEAT response should contain 'PASV', got: %s", response)
	}
}

func TestFTPUnknownCommand(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 读取 banner
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	// 发送未知命令
	_, err = conn.Write([]byte("FOOBAR\r\n"))
	if err != nil {
		t.Fatalf("failed to write unknown command: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read unknown command response: %v", err)
	}
	if !strings.Contains(line, "500") || !strings.Contains(line, "Unknown command") {
		t.Errorf("expected '500 Unknown command.', got: %s", line)
	}
}
