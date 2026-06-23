package mysql

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func dialAndHandleMySQL(t *testing.T) (*Server, net.Conn, func()) {
	t.Helper()

	logger := log.New("info")
	srv := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}

	cleanup := func() {
		conn.Close()
		ln.Close()
	}
	return srv, conn, cleanup
}

// readMySQLPacket 读取一个完整的 MySQL 协议包，返回 payload 和序列号
func readMySQLPacket(t *testing.T, conn net.Conn) ([]byte, int) {
	t.Helper()
	hdr := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(hdr)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if n < 4 {
		t.Fatalf("short header: %d bytes", n)
	}
	length := int(binary.LittleEndian.Uint32(hdr[:4])) & 0xFFFFFF
	seq := int(hdr[3])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := conn.Read(payload); err != nil {
			t.Fatalf("read payload (len=%d): %v", length, err)
		}
	}
	return payload, seq
}

// buildHandshakeResponse 构建简化的 MySQL 握手响应包
func buildHandshakeResponse(username string) []byte {
	// 基本握手响应：capability(4) + max_packet(4) + charset(1) + reserved(23) + username + null
	cap := uint32(ClientProtocol41 | ClientSecureConn | ClientPluginAuth | ClientLongPassword)
	buf := make([]byte, 0, 64)
	cb := make([]byte, 4)
	binary.LittleEndian.PutUint32(cb, cap)
	buf = append(buf, cb...)          // capability flags
	buf = append(buf, 0, 0, 0, 0x10) // max packet size (16M)
	buf = append(buf, CharsetUTF8)    // charset
	buf = append(buf, make([]byte, 23)...) // reserved
	buf = append(buf, []byte(username)...)
	buf = append(buf, 0x00)

	// pack as MySQL packet (seq=1)
	pkt := make([]byte, 4+len(buf))
	binary.LittleEndian.PutUint32(pkt[:4], uint32(len(buf)))
	pkt[3] = 1
	copy(pkt[4:], buf)
	return pkt
}

// buildQuery 构建 COM_QUERY 包
func buildQuery(seq int, query string) []byte {
	payload := []byte{0x03} // COM_QUERY
	payload = append(payload, []byte(query)...)
	return packPacket(payload, seq)
}

// buildQuit 构建 COM_QUIT 包
func buildQuit(seq int) []byte {
	return packPacket([]byte{0x01}, seq)
}

func TestMySQLGreeting(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	payload, seq := readMySQLPacket(t, conn)

	if seq != 0 {
		t.Errorf("greeting seq: expected 0, got %d", seq)
	}
	if len(payload) < 5 {
		t.Fatalf("greeting too short: %d bytes", len(payload))
	}
	if payload[0] != 10 {
		t.Errorf("protocol version: expected 10, got %d", payload[0])
	}

	// server version null-terminated string
	end := 1
	for end < len(payload) && payload[end] != 0x00 {
		end++
	}
	version := string(payload[1:end])
	if !strings.Contains(version, "8.0.35") {
		t.Errorf("server version: expected 8.0.35, got %q", version)
	}
}

func TestMySQLLoginAccessDenied(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	// 读取问候包
	readMySQLPacket(t, conn)

	// 发送握手响应
	hs := buildHandshakeResponse("root")
	if _, err := conn.Write(hs); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	// 应返回 ERR 包 (access denied)
	payload, seq := readMySQLPacket(t, conn)

	if len(payload) < 1 || payload[0] != 0xFF {
		t.Errorf("expected ERR packet (0xFF), got 0x%02X", payload[0])
	}
	if seq != 2 {
		t.Errorf("err seq: expected 2, got %d", seq)
	}

	errMsg := string(payload[3:]) // skip err marker + code(2)
	if !strings.Contains(errMsg, "Access denied") {
		t.Errorf("expected Access denied, got %q", errMsg)
	}
	if !strings.Contains(errMsg, "root") {
		t.Errorf("expected username in error, got %q", errMsg)
	}
}

func TestMySQLShowDatabases(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	// 问候 + 握手
	readMySQLPacket(t, conn)
	conn.Write(buildHandshakeResponse("admin"))
	readMySQLPacket(t, conn) // access denied

	// 发送 SHOW DATABASES
	conn.Write(buildQuery(3, "SHOW DATABASES"))

	// 读取列定义
	payload, _ := readMySQLPacket(t, conn)
	if !bytesContains(payload, []byte("def")) {
		t.Errorf("expected column def, got %q", string(payload))
	}

	// 读取 EOF
	readMySQLPacket(t, conn)

	// 读取所有行 — 应该有 7 个数据库
	var dbNames []string
	for i := 0; i < 20; i++ { // max reads
		payload, _ = readMySQLPacket(t, conn)
		// EOF detecion: 0xFE header
		if len(payload) > 0 && payload[0] == 0xFE && len(payload) < 9 {
			break
		}
		// text row: len(1) + text
		if len(payload) > 1 {
			l := int(payload[0])
			if l > 0 && l < len(payload) {
				dbNames = append(dbNames, string(payload[1:1+l]))
			}
		}
	}

	if len(dbNames) == 0 {
		t.Error("expected database names in response")
	}
	if len(dbNames) != 7 {
		t.Errorf("expected 7 databases, got %d: %v", len(dbNames), dbNames)
	}

	hasWordpress := false
	for _, db := range dbNames {
		if db == "wordpress" {
			hasWordpress = true
			break
		}
	}
	if !hasWordpress {
		t.Error("expected wordpress database in SHOW DATABASES")
	}
}

func TestMySQLSelectVersion(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	readMySQLPacket(t, conn)
	conn.Write(buildHandshakeResponse("scanner"))
	readMySQLPacket(t, conn)

	conn.Write(buildQuery(3, "SELECT VERSION()"))

	// col def
	readMySQLPacket(t, conn)
	// eof
	readMySQLPacket(t, conn)
	// text row
	payload, _ := readMySQLPacket(t, conn)
	if len(payload) > 1 {
		l := int(payload[0])
		version := string(payload[1 : 1+l])
		if version != "8.0.35" {
			t.Errorf("SELECT VERSION(): expected 8.0.35, got %q", version)
		}
	} else {
		t.Error("expected version text row")
	}
}

func TestMySQLSelectHostname(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	readMySQLPacket(t, conn)
	conn.Write(buildHandshakeResponse("probe"))
	readMySQLPacket(t, conn)

	conn.Write(buildQuery(3, "SELECT @@HOSTNAME"))

	readMySQLPacket(t, conn) // col def
	readMySQLPacket(t, conn) // eof
	payload, _ := readMySQLPacket(t, conn)
	if len(payload) > 1 {
		l := int(payload[0])
		hostname := string(payload[1 : 1+l])
		if hostname != "db-prod-01" {
			t.Errorf("SELECT @@HOSTNAME: expected db-prod-01, got %q", hostname)
		}
	}
}

func TestMySQLUnknownQueryReturnsError(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	readMySQLPacket(t, conn)
	conn.Write(buildHandshakeResponse("test"))
	readMySQLPacket(t, conn) // access denied

	conn.Write(buildQuery(3, "SELECT * FROM secret.users"))

	payload, _ := readMySQLPacket(t, conn)
	if len(payload) < 1 || payload[0] != 0xFF {
		t.Errorf("expected ERR packet for unknown query, got 0x%02X", payload[0])
	}
}

func TestMySQLQuit(t *testing.T) {
	_, conn, cleanup := dialAndHandleMySQL(t)
	defer cleanup()

	readMySQLPacket(t, conn)
	conn.Write(buildHandshakeResponse("user"))
	readMySQLPacket(t, conn) // access denied

	conn.Write(buildQuit(3))

	// COM_QUIT 应使服务端关闭连接，尝试读取应得到 EOF
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err == nil {
		t.Error("expected connection close after COM_QUIT")
	}
}

func TestMySQLExtractUsername(t *testing.T) {
	logger := log.New("info")
	srv := New(logger)

	// 构造握手响应：cap(4) + max_pkt(4) + charset(1) + reserved(23) + "scanner\0"
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], ClientProtocol41|ClientSecureConn)
	buf[8] = CharsetUTF8
	buf = append(buf, []byte("scanner")...)
	buf = append(buf, 0x00)

	username := srv.extractUsername(buf)
	if username != "scanner" {
		t.Errorf("expected scanner, got %q", username)
	}
}

func TestMySQLGreetingProtocolVersion(t *testing.T) {
	g := DefaultGreeting(42)
	if g.ProtocolVersion != 10 {
		t.Errorf("protocol version: expected 10, got %d", g.ProtocolVersion)
	}
	if g.ServerVersion != "8.0.35" {
		t.Errorf("server version: expected 8.0.35, got %q", g.ServerVersion)
	}
	if g.ConnectionID != 42 {
		t.Errorf("connection ID: expected 42, got %d", g.ConnectionID)
	}
	if g.Charset != CharsetUTF8 {
		t.Errorf("charset: expected %d, got %d", CharsetUTF8, g.Charset)
	}
	if len(g.AuthPluginData) != 21 {
		t.Errorf("auth plugin data length: expected 21, got %d", len(g.AuthPluginData))
	}
}

func TestMySQLPackPacket(t *testing.T) {
	pkt := packPacket([]byte{0x03, 0x68, 0x65, 0x6C, 0x6C, 0x6F}, 5) // COM_QUERY "hello"
	length := int(binary.LittleEndian.Uint32(pkt[:4])) & 0xFFFFFF
	if length != 6 {
		t.Errorf("pack packet length: expected 6, got %d", length)
	}
	if pkt[3] != 5 {
		t.Errorf("pack packet seq: expected 5, got %d", pkt[3])
	}
	if string(pkt[4:]) != "\x03hello" {
		t.Errorf("pack packet payload: expected COM_QUERY+hello, got %q", string(pkt[4:]))
	}
}

func bytesContains(data, sub []byte) bool {
	return len(data) >= len(sub) && stringSearch(data, sub)
}

func stringSearch(data, sub []byte) bool {
	for i := 0; i <= len(data)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if data[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
