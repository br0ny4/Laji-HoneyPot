package ldap

import (
	"encoding/asn1"
	"fmt"
	"net"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server LDAP 蜜罐服务（模拟 OpenLDAP 2.6）
type Server struct {
	logger *log.Logger
}

// New 创建 LDAP 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 LDAP 连接（ASN.1 BER 编码）
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("ldap connection", "remote", remote)

	buf := make([]byte, 8192)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// 解析 LDAP Message（简化版）
	// LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { bindRequest ... } }
	msgID := s.extractMessageID(buf[:n])
	s.logger.Infow("ldap bind request", "remote", remote, "msg_id", msgID)

	// 构造 bindResponse: resultCode=49 (invalidCredentials)
	resp := s.buildBindResponse(msgID, 49, "", "Invalid credentials")
	if _, err := conn.Write(resp); err != nil {
		s.logger.Debugw("ldap write error", "remote", remote, "error", err)
	}

	s.logger.Infow("ldap auth rejected", "remote", remote, "result", "invalidCredentials")
}

// extractMessageID 从 BER 编码提取 MessageID
func (s *Server) extractMessageID(data []byte) int {
	if len(data) < 4 || data[0] != 0x30 {
		return 0
	}
	// 跳过 SEQUENCE 标签和长度，读取 INTEGER 标签
	offset := 2
	if data[1]&0x80 != 0 {
		lenBytes := int(data[1] & 0x7f)
		offset += lenBytes
	}
	if offset+2 >= len(data) || data[offset] != 0x02 {
		return 0
	}
	intLen := int(data[offset+1])
	if offset+2+intLen > len(data) {
		return 0
	}
	return s.berIntToInt(data[offset+2 : offset+2+intLen])
}

func (s *Server) berIntToInt(data []byte) int {
	result := 0
	for _, b := range data {
		result = (result << 8) | int(b)
	}
	return result
}

// buildBindResponse 构造 LDAP BindResponse
func (s *Server) buildBindResponse(msgID, resultCode int, matchedDN, diagMsg string) []byte {
	// BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode, matchedDN, errorMessage }
	bindResp := s.encodeInt(resultCode)
	matchedDNEnc := s.encodeOctetString(matchedDN)
	diagEnc := s.encodeOctetString(diagMsg)

	// SEQUENCE 内容
	seqContent := append(bindResp, matchedDNEnc...)
	seqContent = append(seqContent, diagEnc...)

	// [APPLICATION 1] 包装
	appTag := s.encodeTag(0x61, seqContent) // 0x61 = APPLICATION 1, constructed

	// LDAPMessage SEQUENCE: messageID + protocolOp
	msgIDEnc := s.encodeInt(msgID)
	msgContent := append(msgIDEnc, appTag...)
	fullMsg := s.encodeTag(0x30, msgContent)

	return fullMsg
}

func (s *Server) encodeInt(val int) []byte {
	raw, _ := asn1.Marshal(val)
	return raw
}

func (s *Server) encodeOctetString(val string) []byte {
	if val == "" {
		return []byte{0x04, 0x00} // OCTET STRING, length 0
	}
	raw, _ := asn1.Marshal(val)
	return raw
}

func (s *Server) encodeTag(tag byte, content []byte) []byte {
	result := []byte{tag}
	length := len(content)
	if length < 128 {
		result = append(result, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length&0xFF))
	}
	result = append(result, content...)
	return result
}

func (s *Server) String() string { return fmt.Sprintf("LDAP-Honeypot/OpenLDAP-2.6") }
