package mysql

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server MySQL 蜜罐服务
type Server struct {
	logger *log.Logger
	connID atomic.Uint32
}

// New 创建 MySQL 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 MySQL 连接
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	id := s.connID.Add(1)
	remote := conn.RemoteAddr().String()

	s.logger.Infow("mysql connection", "remote", remote, "conn_id", id)

	greeting := DefaultGreeting(id)
	if err := s.sendGreeting(conn, greeting); err != nil {
		s.logger.Debugw("mysql greeting failed", "remote", remote, "error", err)
		return
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		s.logger.Debugw("mysql read handshake failed", "remote", remote, "error", err)
		return
	}

	username := s.extractUsername(resp[:n])
	s.logger.Infow("mysql login attempt",
		"remote", remote,
		"username", username,
		"conn_id", id,
	)

	s.sendErr(conn, 1045, "Access denied for user '"+username+"'@'"+remote+"' (using password: YES)")
}

func (s *Server) sendGreeting(conn net.Conn, g *GreetingPacket) error {
	buf := make([]byte, 0, 128)

	buf = append(buf, g.ProtocolVersion)
	buf = append(buf, []byte(g.ServerVersion)...)
	buf = append(buf, 0x00)

	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, g.ConnectionID)
	buf = append(buf, id...)

	buf = append(buf, g.AuthPluginData[:8]...)
	buf = append(buf, 0x00)

	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, g.CapabilityFlags)
	buf = append(buf, flags[:2]...)
	buf = append(buf, g.Charset)

	status := make([]byte, 2)
	binary.LittleEndian.PutUint16(status, g.StatusFlags)
	buf = append(buf, status...)
	buf = append(buf, flags[2:]...)

	buf = append(buf, byte(21))
	buf = append(buf, make([]byte, 10)...)
	buf = append(buf, g.AuthPluginData[8:]...)

	buf = append(buf, []byte(g.AuthPluginName)...)
	buf = append(buf, 0x00)

	pkt := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(buf)))
	pkt[3] = 0
	copy(pkt[4:], buf)

	_, err := conn.Write(pkt)
	return err
}

func (s *Server) extractUsername(data []byte) string {
	if len(data) < 36 {
		return "unknown"
	}
	offset := 36
	end := offset
	for end < len(data) && data[end] != 0x00 {
		end++
	}
	if end > offset {
		return string(data[offset:end])
	}
	return "unknown"
}

func (s *Server) sendErr(conn net.Conn, code uint16, message string) {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0xFF)
	codeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBytes, code)
	buf = append(buf, codeBytes...)
	buf = append(buf, '#')
	buf = append(buf, []byte("28000")...)
	buf = append(buf, []byte(message)...)

	pkt := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(buf)))
	pkt[3] = 2
	copy(pkt[4:], buf)

	conn.Write(pkt)
}

var _ fmt.Stringer = (*Server)(nil)

func (s *Server) String() string { return "MySQL-Honeypot/8.0.35" }
