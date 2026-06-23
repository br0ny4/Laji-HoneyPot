package mysql

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server MySQL 蜜罐服务
type Server struct {
	logger *log.Logger
	bus    *bus.Bus
	connID atomic.Uint32
}

// New 创建 MySQL 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// SetBus 注入事件总线（由蜜罐引擎调用）
func (s *Server) SetBus(b *bus.Bus) { s.bus = b }

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

	// 发布协议指纹事件
	s.publishFingerprint(remote, username, "")

	s.sendErr(conn, 1045, "Access denied for user '"+username+"'@'"+remote+"' (using password: YES)")

	// 查询响应循环 — 攻击者常通过发送特定查询指纹识别蜜罐
	// 真实 MySQL 在接受未认证查询时仍会返回错误，而非无响应
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		hdr := make([]byte, 4)
		n, err := conn.Read(hdr)
		if err != nil || n < 4 {
			return
		}
		length := int(binary.LittleEndian.Uint32(hdr[:4])) & 0xFFFFFF
		seq := int(hdr[3])

		if length < 1 || length > 16*1024*1024 {
			return
		}

		payload := make([]byte, length)
		if _, err := netReadFull(conn, payload); err != nil {
			return
		}

		cmd := payload[0]
		query := strings.TrimSpace(strings.ToUpper(string(payload[1:])))

		if cmd == 0x03 { // COM_QUERY
			s.logger.Infow("mysql query",
				"remote", remote,
				"query", string(payload[1:]),
				"conn_id", id,
			)
			s.publishFingerprint(remote, username, string(payload[1:]))
			if s.handleFingerprintQuery(conn, seq, query) {
				continue
			}
			s.sendErr(conn, 1045, "Access denied for user '"+username+"'@'"+hostPart(remote)+"' (using password: YES)")
		} else if cmd == 0x01 { // COM_QUIT
			return
		}
		// 其他命令静默忽略
	}
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

	if _, err := conn.Write(pkt); err != nil {
		s.logger.Debugw("mysql write error", "error", err)
	}
}

func netReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func hostPart(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// handleFingerprintQuery 检测常见指纹查询并返回伪造数据
func (s *Server) handleFingerprintQuery(conn net.Conn, seq int, query string) bool {
	switch {
	case strings.HasPrefix(query, "SHOW DATABASES"):
		s.sendFakeShowDatabases(conn, seq+1)
		return true
	case strings.HasPrefix(query, "SELECT VERSION()"),
		strings.HasPrefix(query, "SELECT @@VERSION"):
		s.sendFakeSelectVersion(conn, seq+1)
		return true
	case strings.HasPrefix(query, "SELECT @@VERSION_COMMENT"):
		s.sendFakeSelectVar(conn, seq+1, "@@version_comment", "MySQL Community Server - GPL")
		return true
	case strings.HasPrefix(query, "SELECT @@HOSTNAME"):
		s.sendFakeSelectVar(conn, seq+1, "@@hostname", "db-prod-01")
		return true
	}
	return false
}

// sendFakeShowDatabases 返回伪造的数据库列表
func (s *Server) sendFakeShowDatabases(conn net.Conn, seq int) {
	databases := []string{"information_schema", "mysql", "performance_schema", "sys", "wordpress", "app_production", "internal_admin"}
	col := buildColumnDef(seq, "def", "Database")
	seq++
	col = append(col, buildEOF(seq)...)
	seq++

	var rows []byte
	for _, db := range databases {
		rows = append(rows, buildTextRow(seq, db)...)
		seq++
	}
	rows = append(rows, buildEOF(seq)...)

	resp := append(col, rows...)
	conn.Write(resp)
}

// sendFakeSelectVersion 返回伪造的 MySQL 版本
func (s *Server) sendFakeSelectVersion(conn net.Conn, seq int) {
	col := buildColumnDef(seq, "def", "VERSION()")
	seq++
	col = append(col, buildEOF(seq)...)
	seq++

	row := buildTextRow(seq, "8.0.35")
	seq++
	row = append(row, buildEOF(seq)...)

	resp := append(col, row...)
	conn.Write(resp)
}

// sendFakeSelectVar 返回伪造的系统变量值
func (s *Server) sendFakeSelectVar(conn net.Conn, seq int, name, value string) {
	col := buildColumnDef(seq, "def", name)
	seq++
	col = append(col, buildEOF(seq)...)
	seq++

	row := buildTextRow(seq, value)
	seq++
	row = append(row, buildEOF(seq)...)

	resp := append(col, row...)
	conn.Write(resp)
}

// buildColumnDef 构建列定义包
func buildColumnDef(seq int, catalog, name string) []byte {
	payload := []byte{
		0x03, 0x64, 0x65, 0x66, // "def" catalog
	}
	// catalog
	payload = append(payload, byte(len(catalog)))
	payload = append(payload, []byte(catalog)...)
	// schema (empty)
	payload = append(payload, 0x00)
	// table (empty)
	payload = append(payload, 0x00)
	// org_table (empty)
	payload = append(payload, 0x00)
	// name
	payload = append(payload, byte(len(name)))
	payload = append(payload, []byte(name)...)
	// org_name (empty)
	payload = append(payload, 0x00)
	// filler
	payload = append(payload, 0x0c)                   // length of fixed fields
	payload = append(payload, 0x3f, 0x00)             // charset
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // column length placeholder
	payload = append(payload, 0xfd)                   // type: VAR_STRING
	payload = append(payload, 0x00, 0x00)             // flags
	payload = append(payload, 0x00)                   // decimals

	return packPacket(payload, seq)
}

// buildTextRow 构建文本行
func buildTextRow(seq int, val string) []byte {
	payload := []byte{byte(len(val))}
	payload = append(payload, []byte(val)...)
	return packPacket(payload, seq)
}

// buildEOF 构建 EOF 包
func buildEOF(seq int) []byte {
	payload := []byte{0xfe, 0x00, 0x00, 0x02, 0x00}
	return packPacket(payload, seq)
}

// packPacket 打包 MySQL 协议包（3 字节长度 + 序列号 + payload）
func packPacket(payload []byte, seq int) []byte {
	pkt := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(payload)))
	pkt[3] = byte(seq)
	copy(pkt[4:], payload)
	return pkt
}

// publishFingerprint 发布 MySQL 协议指纹事件
func (s *Server) publishFingerprint(remote, username, query string) {
	if s.bus == nil {
		return
	}
	host, _, _ := net.SplitHostPort(remote)
	data := map[string]interface{}{
		"remote_ip":      host,
		"service":        "MySQL",
		"mysql_username": username,
	}
	if query != "" {
		data["mysql_query"] = query
	}
	evt, _ := json.Marshal(data)
	if evt != nil {
		s.bus.Publish("honeypot.fingerprint", evt)
	}
}

var _ fmt.Stringer = (*Server)(nil)

func (s *Server) String() string { return "MySQL-Honeypot/8.0.35" }
