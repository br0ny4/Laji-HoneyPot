package ssh

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/bait"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server SSH 蜜罐服务（模拟 OpenSSH 9.3）
type Server struct {
	logger      *log.Logger
	bus         *bus.Bus
	baitLinkage *bait.LinkageEngine
}

// New 创建 SSH 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// SetBus 注入事件总线（由蜜罐引擎调用）
func (s *Server) SetBus(b *bus.Bus) { s.bus = b }

// SetBaitLinkage 注入蜜饵联动引擎（用于凭据验证与攻击链追溯）
// 当 SSH 认证实现完善后，Handle 方法中应调用 s.baitLinkage.CheckCredential()
// 以验证攻击者使用的用户名/密码是否来自蜜饵
func (s *Server) SetBaitLinkage(linkage *bait.LinkageEngine) {
	s.baitLinkage = linkage
}

// Handle 处理 SSH 连接
// 模拟真实 OpenSSH 的多步交互行为：
// 1. 发送服务端 banner  →  2. 读取客户端 banner  →  3. 发送协议错误
// 真实 OpenSSH 在协议不匹配时不会立即关闭连接，而是发送错误后等待客户端 ACK 或关闭，
// 这个多步行为让扫描器更难通过单包响应特征识别蜜罐。
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("ssh connection", "remote", remote)

	banner := "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu2.1\r\n"
	if _, err := conn.Write([]byte(banner)); err != nil {
		return
	}

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
	if _, err := conn.Write([]byte("Protocol mismatch.\r\n")); err != nil {
		s.logger.Debugw("ssh write error", "remote", remote, "error", err)
	}

	// 模拟真实 OpenSSH 多步行为：发送协议错误后不立即断开，
	// 再读取一个客户端包并发送断开消息，使连接关闭看起来像正常的 SSH 协商失败
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	extra := make([]byte, 1024)
	n, _ := conn.Read(extra)
	if n > 0 {
		s.logger.Debugw("ssh post-mismatch data",
			"remote", remote,
			"bytes", n,
		)
	}
	// 发送 SSH 断开消息（SSH_MSG_DISCONNECT: 0x01，原因：协议错误 0x02）
	conn.Write([]byte("SSH-2.0-OpenSSH_9.3p1\r\n"))
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

		// 发布协议指纹事件
		if s.bus != nil {
			host, _, _ := net.SplitHostPort(remote)
			evt, _ := json.Marshal(map[string]interface{}{
				"remote_ip":          host,
				"service":            "SSH",
				"ssh_client_version": version,
				"ssh_impl":           impl,
			})
			if evt != nil {
				s.bus.Publish("honeypot.fingerprint", evt)
			}
		}
	}
}

func (s *Server) String() string { return "SSH-Honeypot/OpenSSH-9.3" }
