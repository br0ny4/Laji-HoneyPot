package smb

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server SMB 蜜罐服务（模拟 Windows SMB 3.1.1）
type Server struct {
	logger *log.Logger
}

// New 创建 SMB 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 SMB 连接（NetBIOS Session Service + SMB 协议协商）
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("smb connection", "remote", remote)

	buf := make([]byte, 8192)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		s.logger.Debugw("smb read error", "remote", remote, "error", err)
		return
	}

	// 解析 NetBIOS Session Message
	// [0] 消息类型 (0x00 = Session Message)
	// [1-3] 长度 (24-bit big-endian)
	// [4-7] SMB 魔术字 "\xffSMB"
	if buf[0] != 0x00 {
		return
	}

	length := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if length+4 > n {
		s.logger.Debugw("smb truncated", "remote", remote, "expected", length, "got", n-4)
	}

	smbData := buf[4:]
	s.logger.Infow("smb negotiate", "remote", remote, "msg_len", length)

	// 检测 SMB 协议版本
	if len(smbData) >= 4 {
		s.logger.Infow("smb protocol", "remote", remote, "magic", fmt.Sprintf("%02x", smbData[:4]))
	}

	// 构造 SMB Negotiate Response（简化，模拟 Windows Server 2019）
	resp := s.buildNegotiateResponse()
	s.reply(conn, resp)

	s.logger.Infow("smb negotiate complete", "remote", remote)
}

// reply 发送 NetBIOS Session Message 包装的响应
func (s *Server) reply(conn net.Conn, smbPayload []byte) {
	// NetBIOS Session Message 头部
	nbHeader := make([]byte, 4)
	nbHeader[0] = 0x00 // Session Message
	payloadLen := len(smbPayload)
	binary.BigEndian.PutUint32(nbHeader[0:], uint32(payloadLen))
	nbHeader[0] = 0x00 // 确保类型字节正确

	// 合并响应
	fullResp := make([]byte, 4+payloadLen)
	fullResp[0] = 0x00
	fullResp[1] = byte((payloadLen >> 16) & 0xFF)
	fullResp[2] = byte((payloadLen >> 8) & 0xFF)
	fullResp[3] = byte(payloadLen & 0xFF)
	copy(fullResp[4:], smbPayload)

	if _, err := conn.Write(fullResp); err != nil {
		s.logger.Debugw("smb write error", "error", err)
	}
}

// buildNegotiateResponse 构造 SMB2 Negotiate Response
// 模拟 Windows Server 2019 (NT 10.0), 但不启用 SMB3 加密
func (s *Server) buildNegotiateResponse() []byte {
	// SMB2 Header (64 bytes) + Negotiate Response (variable)
	resp := make([]byte, 0, 128)

	// SMB2 Header
	protoID := []byte{0xFE, 'S', 'M', 'B'} // SMB2 协议标识
	resp = append(resp, protoID...)

	// StructureSize (2 bytes) = 64
	resp = append(resp, 0x40, 0x00)

	// CreditCharge (2 bytes) = 0
	resp = append(resp, 0x00, 0x00)

	// Status (4 bytes) = STATUS_SUCCESS (0x00000000)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// Command (2 bytes) = SMB2_NEGOTIATE (0x0000)
	resp = append(resp, 0x00, 0x00)

	// CreditRequest/Response (2 bytes) = 1
	resp = append(resp, 0x01, 0x00)

	// Flags (4 bytes) = SMB2_FLAGS_SERVER_TO_REDIR (0x00000001)
	resp = append(resp, 0x01, 0x00, 0x00, 0x00)

	// NextCommand (4 bytes) = 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// MessageId (8 bytes) = 0 (server response to client's message 0)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Reserved (4 bytes) = 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// TreeId (4 bytes) = 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// SessionId (8 bytes) = 0
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Signature (16 bytes) = 0
	sig := make([]byte, 16)
	resp = append(resp, sig...)

	// --- Negotiate Response (starts at SMB2 Header offset 64) ---
	// StructureSize: 36
	resp = append(resp, 0x24, 0x00)

	// SecurityMode: SMB2_NEGOTIATE_SIGNING_ENABLED (0x01)
	resp = append(resp, 0x01, 0x00)

	// DialectRevision: SMB 3.1.1 (0x0311)
	resp = append(resp, 0x11, 0x03)

	// Reserved (2 bytes)
	resp = append(resp, 0x00, 0x00)

	// ServerGuid (16 bytes) - fake
	guid := make([]byte, 16)
	copy(guid, []byte("Laji-HoneyPotSRV"))
	resp = append(resp, guid...)

	// Capabilities: SMB2_GLOBAL_CAP_DFS (0x01)
	resp = append(resp, 0x01, 0x00, 0x00, 0x00)

	// MaxTransactSize: 1MB
	resp = append(resp, 0x00, 0x00, 0x10, 0x00)

	// MaxReadSize: 1MB
	resp = append(resp, 0x00, 0x00, 0x10, 0x00)

	// MaxWriteSize: 1MB
	resp = append(resp, 0x00, 0x00, 0x10, 0x00)

	// SystemTime (8 bytes) - epoch 1601-01-01, filetime
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// ServerStartTime (8 bytes) - epoch 1601-01-01, filetime
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// SecurityBufferOffset (2 bytes) + SecurityBufferLength (2 bytes) - 均为 0，不包含安全 Blob
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	// Reserved2 (4 bytes)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)

	return resp
}

func (s *Server) String() string { return fmt.Sprintf("SMB-Honeypot/Windows-Server-2019") }
