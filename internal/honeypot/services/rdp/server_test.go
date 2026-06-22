package rdp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestRDPConnectionConfirm(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:13391")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	srv := New(log.New("debug"))

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn)
	}()

	time.Sleep(30 * time.Millisecond)

	// 发送 TPKT + X.224 Connection Request（最小化）
	client, err := net.Dial("tcp", "127.0.0.1:13391")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// TPKT: version=3, reserved=0, length=19
	// X.224 CR: length=6, code=0xE0(CR), dst-ref=0, src-ref=0, class=0
	// RDP Negotiation Request: type=1, flags=0, length=8, proto=0x00000003
	req := make([]byte, 19)
	req[0] = 0x03 // TPKT version
	req[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(req[2:4], 19)
	req[4] = 6    // X.224 length
	req[5] = 0xE0 // CR (Connection Request)
	req[6] = 0x00 // dst-ref
	req[7] = 0x00
	req[8] = 0x00 // src-ref
	req[9] = 0x00
	req[10] = 0x00 // class
	req[11] = 0x01 // TYPE_RDP_NEG_REQ
	req[12] = 0x00 // flags
	req[13] = 0x08 // length (neg req)
	req[14] = 0x00 // length low
	req[15] = 0x03 // PROTOCOL_SSL | PROTOCOL_HYBRID
	req[16] = 0x00
	req[17] = 0x00
	req[18] = 0x00

	client.Write(req)

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 4096)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if n < 19 {
		t.Fatalf("response too short: %d bytes", n)
	}

	// 验证 TPKT 头部
	if resp[0] != 0x03 {
		t.Errorf("expected TPKT version 3, got %d", resp[0])
	}

	// 验证 X.224 Connection Confirm: 0xD0
	if len(resp) >= 6 {
		if resp[5] != 0xD0 {
			t.Errorf("expected CC (0xD0), got 0x%02x", resp[5])
		}
	}

	// 验证 RDP Negotiation Response type: 0x02
	negRespOffset := 4 + 7 // TPKT(4) + X.224(7)
	if len(resp) > negRespOffset {
		if resp[negRespOffset] != 0x02 {
			t.Errorf("expected RDP_NEG_RSP (0x02), got 0x%02x", resp[negRespOffset])
		}
	}
}

func TestRDPInvalidTPKT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:13392")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	srv := New(log.New("debug"))

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn)
	}()

	time.Sleep(30 * time.Millisecond)

	// 发送非 TPKT 数据
	client, err := net.Dial("tcp", "127.0.0.1:13392")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	client.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00})
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	if n > 0 {
		t.Error("expected no response for invalid TPKT")
	}
}

func TestRDPConnectionError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:13393")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	srv := New(log.New("debug"))

	go func() {
		conn, _ := ln.Accept()
		conn.Close() // 立即关闭，模拟连接错误
		srv.Handle(conn)
	}()

	time.Sleep(30 * time.Millisecond)

	// 连接已被关闭，应优雅处理
	client, err := net.Dial("tcp", "127.0.0.1:13393")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// 尝试发送数据到已关闭的连接
	time.Sleep(50 * time.Millisecond)
	_, err = client.Write([]byte{0x03, 0x00, 0x00, 0x1a})
	if err != nil {
		// 预期行为：连接可能已关闭
		return
	}
}

func TestRDPString(t *testing.T) {
	srv := New(log.New("debug"))
	s := srv.String()
	if s != "RDP-Honeypot/Windows-10" {
		t.Errorf("unexpected string: %s", s)
	}
}
