package ssh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/bait"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/domain"
	"github.com/Laji-HoneyPot/honeypot/internal/evidence"
	"github.com/Laji-HoneyPot/honeypot/internal/intent"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// Server SSH 蜜罐服务 (v0.21: 高交互 Shell 模式)
type Server struct {
	logger          *log.Logger
	bus             *bus.Bus
	baitLinkage     *bait.LinkageEngine
	topology        *domain.VirtualTopology
	evidenceColl    *evidence.Collector
	config          *ssh.ServerConfig
	shellEnabled    bool
	localIP         string // 本地虚拟 IP
}

// New 创建 SSH 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger, localIP: "192.168.56.20"} // 默认 jumpbox IP
}

// SetBus 注入事件总线
func (s *Server) SetBus(b *bus.Bus) { s.bus = b }

// SetBaitLinkage 注入蜜饵联动引擎
func (s *Server) SetBaitLinkage(linkage *bait.LinkageEngine) {
	s.baitLinkage = linkage
}

// SetTopology 注入虚拟拓扑 (v0.21)
func (s *Server) SetTopology(t *domain.VirtualTopology) {
	s.topology = t
}

// SetEvidenceCollector 注入证据收集器 (v0.21)
func (s *Server) SetEvidenceCollector(coll *evidence.Collector) {
	s.evidenceColl = coll
}

// EnableShell 启用高交互 Shell 模式
func (s *Server) EnableShell(localIP string) {
	s.shellEnabled = true
	if localIP != "" {
		s.localIP = localIP
	}
	s.initSSHConfig()
}

func (s *Server) initSSHConfig() {
	s.config = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return s.handleAuth(c, pass)
		},
		ServerVersion: "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu2.1",
	}
	// 生成临时主机密钥（生产环境应从配置文件加载）
	key, err := sshHostKey()
	if err != nil {
		s.logger.Warnw("failed to generate SSH host key", "error", err)
		return
	}
	s.config.AddHostKey(key)
}

func (s *Server) handleAuth(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	remote := c.RemoteAddr().String()
	username := c.User()
	password := string(pass)

	s.logger.Infow("ssh auth attempt",
		"remote", remote,
		"user", username,
		"client_version", string(c.ClientVersion()),
	)

	// 蜜饵凭据验证 — 检查是否使用了蜜饵中的凭据
	if s.baitLinkage != nil && s.baitLinkage.CheckCredential(bait.LinkSSH, username, password) != nil {
		s.logger.Warnw("BAIT CREDENTIAL USED via SSH",
			"remote", remote,
			"user", username,
		)
		// 发布 bait-triggered 事件
		if s.bus != nil {
			host, _, _ := net.SplitHostPort(remote)
			evt, _ := json.Marshal(map[string]interface{}{
				"remote_ip":  host,
				"service":    "SSH",
				"event_type": "bait_credential_used",
				"username":   username,
			})
			if evt != nil {
				s.bus.Publish("honeypot.breadcrumb", evt)
			}
		}
	}

	// 始终接受任意凭据（蜜罐不应拒绝连接）
	return &ssh.Permissions{
		Extensions: map[string]string{
			"username": username,
			"remote":   remote,
		},
	}, nil
}

// Handle 处理 SSH 连接（TCP handler 入口）
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	if !s.shellEnabled || s.config == nil {
		s.handleBannerMode(conn)
		return
	}

	s.handleShellMode(conn)
}

// handleBannerMode 旧版 Banner 模式（保留向后兼容）
func (s *Server) handleBannerMode(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	s.logger.Infow("ssh connection (banner mode)", "remote", remote)

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

	if _, err := conn.Write([]byte("Protocol mismatch.\r\n")); err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	extra := make([]byte, 1024)
	n, _ := conn.Read(extra)
	if n > 0 {
		s.logger.Debugw("ssh post-mismatch data", "remote", remote, "bytes", n)
	}
	conn.Write([]byte("SSH-2.0-OpenSSH_9.3p1\r\n"))
}

// handleShellMode 高交互 Shell 模式
func (s *Server) handleShellMode(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	s.logger.Infow("ssh connection (shell mode)", "remote", remote)

	// 使用 golang.org/x/crypto/ssh 进行完整的 SSH 握手
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		s.logger.Debugw("ssh handshake failed", "remote", remote, "error", err)
		s.parseClientBanner(string(err.Error()), remote)
		return
	}
	defer sshConn.Close()

	s.logger.Infow("ssh authenticated",
		"remote", remote,
		"user", sshConn.User(),
		"client_version", string(sshConn.ClientVersion()),
	)

	// 发布连接事件
	host, _, _ := net.SplitHostPort(remote)
	if s.bus != nil {
		evt, _ := json.Marshal(map[string]interface{}{
			"remote_ip": host,
			"username":  sshConn.User(),
			"service":   "SSH",
		})
		if evt != nil {
			s.bus.Publish("honeypot.connection", evt)
		}
	}

	// 处理全局请求（忽略 keepalive 等）
	go ssh.DiscardRequests(reqs)

	// 处理通道请求
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		// 启动 shell 会话
		go s.handleSession(channel, requests, sshConn.User(), host)
	}
}

// handleSession 处理 SSH session 通道
func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, username, remoteIP string) {
	defer channel.Close()

	// 创建 Shell 模拟器
	var shell *ShellSimulator
	if s.topology != nil {
		shell = NewShellSimulator(s.topology, s.localIP)
	} else {
		shell = &ShellSimulator{
			localIP:    s.localIP,
			hostname:   "web-prod-01",
			osInfo:     "Ubuntu 22.04 LTS",
			promptUser: username,
			promptHost: "web-prod-01",
		}
	}

	// 发送登录横幅
	fmt.Fprintf(channel, "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n")
	fmt.Fprintf(channel, " * Documentation:  https://help.ubuntu.com\n")
	fmt.Fprintf(channel, " * Management:     https://landscape.canonical.com\n\n")
	fmt.Fprintf(channel, "Last login: %s from 10.0.0.100\n\n", time.Now().Format("Mon Jan 2 15:04:05 2006"))

	// 创建会话上下文
	session := &domain.SessionContext{
		SessionID:     fmt.Sprintf("%s:%s", remoteIP, username),
		RemoteIP:      remoteIP,
		Username:      username,
		SubnetLocalIP: s.localIP,
		Evidence:      domain.NewEvidenceSet(),
		ConnectedAt:   time.Now().Unix(),
		LastActive:    time.Now().Unix(),
	}

	// 处理 ssh 请求（PTY、shell、exec 等）
	go s.handleSSHRequests(requests, channel, shell, session)
}

func (s *Server) handleSSHRequests(requests <-chan *ssh.Request, channel ssh.Channel, shell *ShellSimulator, session *domain.SessionContext) {
	var shellLaunched bool

	for req := range requests {
		switch req.Type {
		case "shell":
			if !shellLaunched {
				shellLaunched = true
				req.Reply(true, nil)
				s.runInteractiveShell(channel, shell, session)
			} else {
				req.Reply(false, nil)
			}
		case "exec":
			req.Reply(true, nil)
			s.runExecCommand(channel, req, shell, session)
		case "pty-req":
			req.Reply(true, nil)
		case "window-change":
			// 忽略窗口大小变更
		default:
			req.Reply(false, nil)
		}
	}
}

// runInteractiveShell 运行交互式 Shell
func (s *Server) runInteractiveShell(channel ssh.Channel, shell *ShellSimulator, session *domain.SessionContext) {
	reader := bufio.NewReader(channel)
	// 发送初始提示符
	channel.Write([]byte(shell.Prompt()))

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				s.logger.Debugw("ssh shell read error", "error", err)
			}
			return
		}

		cmdLine := strings.TrimSpace(line)
		if cmdLine == "" {
			channel.Write([]byte(shell.Prompt()))
			continue
		}

		session.LastActive = time.Now().Unix()

		// 意图分析
		i := intent.Analyze(cmdLine)
		if i.Category != intent.Unknown && i.Category != intent.ShellCommand {
			s.logger.Infow("ssh intent detected",
				"remote", session.RemoteIP,
				"user", session.Username,
				"command", cmdLine,
				"intent", i.Category,
				"confidence", i.Confidence,
			)
		}

		// 证据收集
		if s.evidenceColl != nil {
			hits := s.evidenceColl.Check(session.RemoteIP, cmdLine)
			for _, hit := range hits {
				session.Evidence.Add(string(hit.Token))
				s.logger.Infow("ssh evidence collected",
					"remote", session.RemoteIP,
					"token", hit.Token,
					"command", cmdLine,
				)
			}
		}

		// 执行命令
		output := shell.Handle(cmdLine, session)
		channel.Write([]byte(output))

		// 退出命令
		if strings.ToLower(cmdLine) == "exit" || strings.ToLower(cmdLine) == "logout" {
			return
		}

		channel.Write([]byte(shell.Prompt()))
	}
}

// runExecCommand 处理 exec 请求（非交互式命令，如 ssh user@host 'command'）
func (s *Server) runExecCommand(channel ssh.Channel, req *ssh.Request, shell *ShellSimulator, session *domain.SessionContext) {
	var payload struct{ Command string }
	ssh.Unmarshal(req.Payload, &payload)

	cmdLine := strings.TrimSpace(payload.Command)

	// 意图分析
	intentResult := intent.Analyze(cmdLine)
	if intentResult.Category != intent.Unknown && intentResult.Category != intent.ShellCommand {
		s.logger.Infow("ssh exec intent detected",
			"remote", session.RemoteIP,
			"command", cmdLine,
			"intent", intentResult.Category,
			"confidence", intentResult.Confidence,
		)
	}

	// 证据收集
	if s.evidenceColl != nil {
		s.evidenceColl.Check(session.RemoteIP, cmdLine)
	}

	output := shell.Handle(cmdLine, session)
	channel.Write([]byte(output))
	channel.Close()
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

func (s *Server) String() string {
	if s.shellEnabled {
		return "SSH-Honeypot-HighInteraction/OpenSSH-9.3"
	}
	return "SSH-Honeypot/OpenSSH-9.3"
}

// sshHostKey 生成临时 SSH 主机密钥（RSA 2048-bit）
// 生产环境应从持久化配置文件加载，避免每次重启密钥变化
func sshHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("sshHostKey: generate RSA key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("sshHostKey: marshal private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}
	return ssh.ParsePrivateKey(pem.EncodeToMemory(block))
}
