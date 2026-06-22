package rdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server RDP 蜜罐服务（模拟 Windows RDP 10.0）
type Server struct {
	logger *log.Logger
}

// New 创建 RDP 蜜罐
func New(logger *log.Logger) *Server {
	return &Server{logger: logger}
}

// Handle 处理 RDP 连接（TPKT + X.224 + RDP Negotiation）
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Infow("rdp connection", "remote", remote)

	buf := make([]byte, 8192)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		s.logger.Debugw("rdp read error", "remote", remote, "error", err)
		return
	}

	s.logger.Infow("rdp request", "remote", remote, "bytes", n)

	// 解析 TPKT 头部: [version(1)][reserved(1)][length(2 bytes big-endian)]
	if buf[0] != 0x03 {
		// 非 TPKT 协议
		return
	}

	// 构造 RDP Connection Confirm (CC) 响应
	// 但不返回有效的 TLS 证书 — 仅做协议指纹收集
	resp := s.buildConnectionConfirm()
	s.reply(conn, resp)

	s.logger.Infow("rdp handshake complete", "remote", remote)
}

// reply 发送 TPKT 包装的响应
func (s *Server) reply(conn net.Conn, payload []byte) {
	if _, err := conn.Write(payload); err != nil {
		s.logger.Debugw("rdp write error", "error", err)
	}
}

// buildConnectionConfirm 构造 RDP Connection Confirm PDU
// RDP Negotiation Response (TYPE_RDP_NEG_RSP = 0x02)
func (s *Server) buildConnectionConfirm() []byte {
	// TPKT Header (4 bytes): version=3, reserved=0, length
	// X.224 Connection Confirm (7 bytes): length(1), code=0xD0(CC), dst-ref(2),
	//   src-ref(2), class=0
	// RDP Negotiation Response: type(1)=0x02, flags(1), length(2), selectedProto(4)

	negRespLen := 8
	x224Len := 7
	tpktBodyLen := x224Len + negRespLen
	tpktTotalLen := 4 + tpktBodyLen

	resp := make([]byte, tpktTotalLen)

	// TPKT Header
	resp[0] = 0x03 // version 3
	resp[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(resp[2:4], uint16(tpktTotalLen))

	// X.224 Connection Confirm (CC)
	offset := 4
	resp[offset] = byte(tpktBodyLen - 1) // X.224 length (excluding length byte)
	offset++
	resp[offset] = 0xD0 // CC (Connection Confirm)
	offset++
	// dst-ref = 0x00, src-ref = 0x00
	resp[offset] = 0x00
	resp[offset+1] = 0x00
	resp[offset+2] = 0x00
	resp[offset+3] = 0x00
	offset += 4
	// class = 0
	resp[offset] = 0x00
	offset++

	// RDP Negotiation Response (TYPE_RDP_NEG_RSP)
	resp[offset] = 0x02 // TYPE_RDP_NEG_RSP
	offset++
	resp[offset] = 0x00 // flags
	offset++
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(negRespLen))
	offset += 2
	// selectedProtocols: PROTOCOL_HYBRID | PROTOCOL_SSL (0x00000002)
	binary.LittleEndian.PutUint32(resp[offset:offset+4], 0x00000002)

	return resp
}

func (s *Server) String() string { return fmt.Sprintf("RDP-Honeypot/Windows-10") }
