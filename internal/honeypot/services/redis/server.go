package redis

import (
	"bufio"
	"fmt"
	"io"
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
		if _, err := conn.Write([]byte(resp)); err != nil {
			s.logger.Debugw("redis write error", "remote", remote, "error", err)
			return
		}
	}
}

// readRESP 正确解析 RESP 协议数组，返回命令参数列表。
// firstLine 格式: *N\r\n，N 为元素个数，上限 128。
func (s *Server) readRESP(reader *bufio.Reader, firstLine string) []string {
	var count int
	if _, err := fmt.Sscanf(firstLine, "*%d", &count); err != nil || count <= 0 || count > 128 {
		return nil
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "$") {
			var length int
			if _, err := fmt.Sscanf(line, "$%d", &length); err != nil || length < 0 || length > 512*1024*1024 {
				break
			}
			data := make([]byte, length+2) // +2 for trailing \r\n
			if _, err := io.ReadFull(reader, data); err != nil {
				break
			}
			args = append(args, string(data[:length]))
		} else {
			args = append(args, line)
		}
	}
	return args
}

func (s *Server) handleCommand(args []string) string {
	if len(args) == 0 {
		return "-ERR unknown command\r\n"
	}

	cmd := strings.ToUpper(args[0])

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
	case "SET", "GET", "SLAVEOF", "REPLCONF", "CLIENT":
		return "-ERR operation not permitted\r\n"
	default:
		return fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd)
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
