package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server DNS 蜜罐服务（模拟 BIND 9.18，仅 UDP）
type Server struct {
	logger *log.Logger
}

// New 创建 DNS 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 DNS UDP 查询
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	buf := make([]byte, 512)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return
	}

	// DNS 头部: 2字节 Transaction ID + 2字节 Flags + 2字节 QDCOUNT + ...
	txID := binary.BigEndian.Uint16(buf[0:2])

	// 解析域名（从 offset 12 开始读取 QNAME）
	domain := s.parseDomain(buf[12:n])
	s.logger.Infow("dns query", "remote", remote, "domain", domain, "tx_id", txID)

	// 构造 DNS 响应：授权服务器拒绝（REFUSED），诱捕攻击者
	resp := s.buildResponse(txID, domain)
	if _, err := conn.Write(resp); err != nil {
		s.logger.Debugw("dns write error", "remote", remote, "error", err)
	}
}

func (s *Server) parseDomain(data []byte) string {
	var parts []string
	offset := 0
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}
		if length > 63 || offset+1+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}
	return strings.Join(parts, ".")
}

// buildResponse 构造 DNS 响应包
func (s *Server) buildResponse(txID uint16, domain string) []byte {
	resp := make([]byte, 0, 512)

	// Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txID) // Transaction ID（回显）
	// Flags: QR=1(响应) OPCODE=0 RCODE=5(REFUSED) — 模拟权威服务器拒绝
	binary.BigEndian.PutUint16(header[2:4], 0x8185)
	binary.BigEndian.PutUint16(header[4:6], 0)   // QDCOUNT=0
	binary.BigEndian.PutUint16(header[6:8], 0)   // ANCOUNT=0
	binary.BigEndian.PutUint16(header[8:10], 0)  // NSCOUNT=0
	binary.BigEndian.PutUint16(header[10:12], 0) // ARCOUNT=0
	resp = append(resp, header...)

	// Question section — 回显原始查询以便客户端解析
	if domain != "" {
		for _, label := range strings.Split(domain, ".") {
			resp = append(resp, byte(len(label)))
			resp = append(resp, []byte(label)...)
		}
		resp = append(resp, 0x00)       // 终止符
		resp = append(resp, 0x00, 0x01) // QTYPE=A
		resp = append(resp, 0x00, 0x01) // QCLASS=IN
		// 更新 QDCOUNT=1
		binary.BigEndian.PutUint16(resp[4:6], 1)
	}

	return resp
}
