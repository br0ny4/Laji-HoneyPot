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
	mu        sync.Mutex
	logger    *log.Logger
	handlers  map[int]ConnHandler
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
