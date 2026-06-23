package ftp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server FTP 蜜罐服务（模拟 vsftpd 3.0.3）
type Server struct {
	logger *log.Logger
	bus    *bus.Bus
}

// New 创建 FTP 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// SetBus 注入事件总线（由蜜罐引擎调用）
func (s *Server) SetBus(b *bus.Bus) { s.bus = b }

// Handle 处理 FTP 连接
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("ftp connection", "remote", remote)

	// vsftpd 220 banner
	s.reply(conn, "220 (vsFTPd 3.0.3)")

	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)

	var ftpUser string // 跟踪当前用户名用于指纹采集

	for {
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		n, err := reader.Read(buf)
		if err != nil || n == 0 {
			return
		}

		cmd := strings.TrimSpace(strings.ToUpper(string(buf[:n])))
		s.logger.Infow("ftp command", "remote", remote, "command", cmd)

		switch {
		case strings.HasPrefix(cmd, "USER"):
			parts := strings.Fields(string(buf[:n]))
			if len(parts) > 1 {
				ftpUser = parts[1]
			}
			s.publishFingerprint(remote, ftpUser, "")
			s.reply(conn, "331 Please specify the password.")
		case strings.HasPrefix(cmd, "PASS"):
			// 收集登录凭据（诱饵）
			parts := strings.Fields(cmd)
			pass := ""
			if len(parts) > 1 {
				pass = parts[1]
			}
			s.logger.Infow("ftp login attempt", "remote", remote, "password", pass)
			s.publishFingerprint(remote, ftpUser, pass)
			s.reply(conn, "530 Login incorrect.")
		case strings.HasPrefix(cmd, "QUIT"):
			s.reply(conn, "221 Goodbye.")
			return
		case strings.HasPrefix(cmd, "SYST"):
			s.reply(conn, "215 UNIX Type: L8")
		case strings.HasPrefix(cmd, "FEAT"):
			s.reply(conn, "211-Features:\n EPRT\n EPSV\n MDTM\n PASV\n REST STREAM\n SIZE\n TVFS\n UTF8\n211 End")
		case strings.HasPrefix(cmd, "PWD"):
			s.reply(conn, "257 \"/var/www/html\" is the current directory")
		case strings.HasPrefix(cmd, "TYPE"):
			s.reply(conn, "200 Switching to Binary mode.")
		case strings.HasPrefix(cmd, "PASV"):
			s.reply(conn, "227 Entering Passive Mode (127,0,0,1,195,80).")
		case strings.HasPrefix(cmd, "LIST") || strings.HasPrefix(cmd, "MLSD"):
			s.reply(conn, "150 Here comes the directory listing.")
			// 伪造文件列表
			if _, err := conn.Write([]byte(
				"-rw-r--r--    1 ftp      ftp          4096 Jan 01 2024 index.html\r\n" +
					"-rw-r--r--    1 ftp      ftp          2048 Jan 01 2024 config.php\r\n" +
					"drwxr-xr-x    2 ftp      ftp          4096 Jan 01 2024 uploads\r\n" +
					"-rw-r--r--    1 ftp      ftp        102400 Jan 01 2024 backup.sql\r\n",
			)); err != nil {
				return
			}
			s.reply(conn, "226 Directory send OK.")
		case strings.HasPrefix(cmd, "CWD"):
			s.reply(conn, "250 Directory successfully changed.")
		case strings.HasPrefix(cmd, "HELP"):
			s.reply(conn, "214-The following commands are recognized.\n USER PASS QUIT SYST FEAT PWD TYPE PASV LIST CWD HELP\n214 Help OK.")
		default:
			// 未知命令 — 收集攻击者行为
			s.reply(conn, "500 Unknown command.")
		}
	}
}

func (s *Server) reply(conn net.Conn, msg string) {
	if _, err := fmt.Fprintf(conn, "%s\r\n", msg); err != nil {
		s.logger.Debugw("ftp write error", "error", err)
	}
}

// publishFingerprint 发布 FTP 协议指纹事件
func (s *Server) publishFingerprint(remote, username, password string) {
	if s.bus == nil {
		return
	}
	host, _, _ := net.SplitHostPort(remote)
	data := map[string]interface{}{
		"remote_ip":    host,
		"service":      "FTP",
		"ftp_username": username,
		"ftp_password": password,
	}
	evt, _ := json.Marshal(data)
	if evt != nil {
		s.bus.Publish("honeypot.fingerprint", evt)
	}
}
