package smb

import (
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestSMBNegotiateResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19451")
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

	// 发送 NetBIOS Session Message + SMB2 NEGOTIATE 请求
	client, err := net.Dial("tcp", "127.0.0.1:19451")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// 构造最小 NetBIOS Session Message + SMB2 魔术字
	nbReq := make([]byte, 0)
	// NetBIOS Session Message: type=0, length=0
	nbReq = append(nbReq, 0x00, 0x00, 0x00, 0x00)
	client.Write(nbReq)

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 4096)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if n < 68 {
		t.Fatalf("response too short: %d bytes", n)
	}

	// 验证 NetBIOS 头部: type=0
	if resp[0] != 0x00 {
		t.Errorf("expected NetBIOS type 0, got %d", resp[0])
	}

	// 验证 SMB2 协议标识: 0xFE, 'S', 'M', 'B'
	smbData := resp[4:]
	if len(smbData) < 4 {
		t.Fatal("smb data too short")
	}
	if smbData[0] != 0xFE || smbData[1] != 'S' || smbData[2] != 'M' || smbData[3] != 'B' {
		t.Errorf("invalid SMB2 magic: %v", smbData[:4])
	}

	// 验证 Negotiate Response StructureSize: 36
	// SMB2 header = 64 bytes, so offset 64 in smbData
	if len(smbData) >= 66 {
		structSize := int(smbData[64]) | int(smbData[65])<<8
		if structSize != 36 {
			t.Errorf("expected structure size 36, got %d", structSize)
		}
	}

	// 验证 DialectRevision: SMB 3.1.1 (0x0311)
	if len(smbData) >= 72 {
		dialect := int(smbData[68]) | int(smbData[69])<<8
		if dialect != 0x0311 {
			t.Errorf("expected SMB 3.1.1 (0x0311), got 0x%04x", dialect)
		}
	}
}

func TestSMBInvalidRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19452")
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

	// 发送无效请求（非 NetBIOS 消息类型）
	client, err := net.Dial("tcp", "127.0.0.1:19452")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// 非 0x00 首字节应被忽略
	client.Write([]byte{0xFF, 0x00, 0x00, 0x00})
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	if n > 0 {
		t.Error("expected no response for invalid NetBIOS type")
	}
}

func TestSMBTruncatedRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19453")
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

	// 发送截断的请求（仅 2 字节）
	client, err := net.Dial("tcp", "127.0.0.1:19453")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	client.Write([]byte{0x00, 0x00})
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	if n > 0 {
		t.Error("expected no response for truncated NetBIOS request")
	}
}

func TestSMBString(t *testing.T) {
	srv := New(log.New("debug"))
	s := srv.String()
	if s != "SMB-Honeypot/Windows-Server-2019" {
		t.Errorf("unexpected string: %s", s)
	}
}
