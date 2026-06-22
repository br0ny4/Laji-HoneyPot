package dns

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// udpConnWrapper 将 PacketConn + 已收到的数据包包装为 net.Conn，
// 模拟生产环境中 plugin.go 的 udpConn。
type udpConnWrapper struct {
	pc   net.PacketConn
	addr net.Addr
	buf  []byte
	n    int
}

func (c *udpConnWrapper) Read(b []byte) (int, error)  { return copy(b, c.buf[:c.n]), nil }
func (c *udpConnWrapper) Write(b []byte) (int, error) { return c.pc.WriteTo(b, c.addr) }
func (c *udpConnWrapper) Close() error                { return nil }
func (c *udpConnWrapper) LocalAddr() net.Addr         { return c.pc.LocalAddr() }
func (c *udpConnWrapper) RemoteAddr() net.Addr        { return c.addr }
func (c *udpConnWrapper) SetDeadline(t time.Time) error      { return nil }
func (c *udpConnWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (c *udpConnWrapper) SetWriteDeadline(t time.Time) error { return nil }

// buildDNSQuery 构造一个最小 DNS 查询包（A 记录）
func buildDNSQuery(txID uint16, domain string) []byte {
	buf := make([]byte, 12)

	// Header: Transaction ID
	binary.BigEndian.PutUint16(buf[0:2], txID)
	// Flags: standard query (RD=1)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	// QDCOUNT = 1
	binary.BigEndian.PutUint16(buf[4:6], 1)
	// ANCOUNT, NSCOUNT, ARCOUNT = 0 (already zero)

	// Question: QNAME (domain labels)
	labels := []byte(domain)
	start := 0
	for i := 0; i <= len(labels); i++ {
		if i == len(labels) || labels[i] == '.' {
			labelLen := i - start
			buf = append(buf, byte(labelLen))
			buf = append(buf, labels[start:i]...)
			start = i + 1
		}
	}
	// Terminator
	buf = append(buf, 0x00)
	// QTYPE = A (1)
	buf = append(buf, 0x00, 0x01)
	// QCLASS = IN (1)
	buf = append(buf, 0x00, 0x01)

	return buf
}

func TestDNSQueryResponse(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	// 在随机端口启动 UDP 监听
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()

	localAddr := pc.LocalAddr().String()

	// 客户端发送 DNS 查询
	clientConn, err := net.Dial("udp", localAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	txID := uint16(0x1234)
	query := buildDNSQuery(txID, "test.example.com")

	clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = clientConn.Write(query)
	if err != nil {
		t.Fatalf("failed to write query: %v", err)
	}

	// 服务端读取数据包并调用 Handle
	buf := make([]byte, 512)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read from packet conn: %v", err)
	}

	fakeConn := &udpConnWrapper{pc: pc, addr: addr, buf: make([]byte, n), n: n}
	copy(fakeConn.buf, buf[:n])

	// 在 goroutine 中处理，以便客户端可以并行读取响应
	go srv.Handle(fakeConn)

	// 读取响应
	resp := make([]byte, 512)
	n, err = clientConn.Read(resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if n < 12 {
		t.Fatalf("response too short: %d bytes", n)
	}

	// 验证 Transaction ID 匹配
	respTxID := binary.BigEndian.Uint16(resp[0:2])
	if respTxID != txID {
		t.Errorf("expected txID %04x, got %04x", txID, respTxID)
	}

	// 验证 DNS REFUSED flag (0x8185)
	respFlags := binary.BigEndian.Uint16(resp[2:4])
	if respFlags != 0x8185 {
		t.Errorf("expected flags 0x8185 (DNS REFUSED), got 0x%04x", respFlags)
	}
}

func TestDNSParseDomain(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	// 测试 "www.google.com"
	// DNS 标签编码: 3 'w' 'w' 'w' 6 'g' 'o' 'o' 'g' 'l' 'e' 3 'c' 'o' 'm' 0
	wwwGoogleCom := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	result := srv.parseDomain(wwwGoogleCom)
	if result != "www.google.com" {
		t.Errorf("expected 'www.google.com', got '%s'", result)
	}

	// 测试 "localhost" (单标签)
	localhost := []byte{
		9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0,
	}
	result = srv.parseDomain(localhost)
	if result != "localhost" {
		t.Errorf("expected 'localhost', got '%s'", result)
	}
}

func TestDNSInvalidQuery(t *testing.T) {
	logger := log.New("debug")
	srv := New(logger)

	// 使用 Pipe 模拟连接，发送短于 12 字节的数据
	serverConn, clientConn := net.Pipe()

	go func() {
		srv.Handle(serverConn)
	}()

	// 发送不足 12 字节的无效查询
	invalidQuery := []byte{0x00, 0x01, 0x02, 0x03}
	clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := clientConn.Write(invalidQuery)
	if err != nil {
		t.Fatalf("failed to write invalid query: %v", err)
	}

	// Handle 应该静默返回（不 crash），确认没有 panic
	// 等待 goroutine 处理完毕
	clientConn.Close()
	time.Sleep(100 * time.Millisecond)
	// 如果到达这里说明没有 panic
}
