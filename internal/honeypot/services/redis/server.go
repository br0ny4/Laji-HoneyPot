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

		cmd := s.readRESP(reader, line)
		s.logger.Infow("redis command", "remote", remote, "command", cmd)

		resp := s.handleCommand(cmd)
		conn.Write([]byte(resp))
	}
}

func (s *Server) readRESP(reader *bufio.Reader, firstLine string) []string {
	parts := []string{}
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

	cmd := ""
	for _, p := range parts {
		up := strings.ToUpper(p)
		if up == "PING" || up == "INFO" || up == "AUTH" || up == "SET" ||
			up == "GET" || up == "CONFIG" || up == "KEYS" || up == "COMMAND" ||
			up == "SLAVEOF" || up == "REPLCONF" || up == "CLIENT" ||
			up == "FLUSHALL" || up == "FLUSHDB" || up == "DEBUG" || up == "EVAL" {
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
		return s.fakeConfig()
	case "KEYS":
		return s.fakeKeys()
	case "COMMAND":
		return "*0\r\n"
	case "FLUSHALL", "FLUSHDB":
		return "-ERR operation not permitted\r\n"
	case "DEBUG":
		return "-ERR unknown subcommand\r\n"
	case "EVAL":
		return "-ERR Redis is configured in read-only mode\r\n"
	default:
		return "-ERR unknown command '" + cmd + "'\r\n"
	}
}

func (s *Server) fakeInfo() string {
	body := "# Server\r\nredis_version:6.2.13\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\n# Clients\r\nconnected_clients:1\r\n# Memory\r\nused_memory_human:1.2G\r\n"
	return fmt.Sprintf("$%d\r\n%s", len(body), body)
}

func (s *Server) fakeConfig() string {
	return "*4\r\n" +
		"$4\r\ndir\r\n$8\r\n/var/redis\r\n" +
		"$7\r\ndbfile\r\n$12\r\ndump.rdb\r\n"
}

func (s *Server) fakeKeys() string {
	return "*3\r\n$8\r\nuser:100\r\n$8\r\nuser:200\r\n$6\r\nconfig\r\n"
}
