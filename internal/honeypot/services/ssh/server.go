package ssh

import (
	"bufio"
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

	banner := "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu2.1\r\n"
	conn.Write([]byte(banner))

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	clientBanner, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	clientBanner = strings.TrimSpace(clientBanner)
	s.logger.Infow("ssh client banner", "remote", remote, "banner", clientBanner)

	s.parseClientBanner(clientBanner, remote)

	// 发送协议错误（捕获版本信息后断开）
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

func (s *Server) String() string { return "SSH-Honeypot/OpenSSH-9.3" }
