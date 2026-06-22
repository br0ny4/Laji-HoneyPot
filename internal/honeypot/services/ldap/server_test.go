package ldap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestLDAPBindResponse(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		server.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Minimal BindRequest: SEQUENCE { messageID=1, bindRequest { version=3, name="", simple="" } }
	bindReq := []byte{
		0x30, 0x0c, // SEQUENCE, length 12
		0x02, 0x01, 0x01, // INTEGER, length 1, value 1 (messageID)
		0x60, 0x07, // APPLICATION 0, length 7 (bindRequest)
		0x02, 0x01, 0x03, // INTEGER, length 1, value 3 (version)
		0x04, 0x00, // OCTET STRING, length 0 (empty name)
		0x80, 0x00, // CONTEXT-SPECIFIC 0, length 0 (simple auth, empty password)
	}

	_, err = conn.Write(bindReq)
	if err != nil {
		t.Fatalf("failed to send bind request: %v", err)
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	resp = resp[:n]

	// Response should start with 0x30 (SEQUENCE tag)
	if resp[0] != 0x30 {
		t.Errorf("expected response to start with 0x30 (SEQUENCE), got 0x%02x", resp[0])
	}

	// Response should contain 0x61 (APPLICATION 1 tag for BindResponse)
	foundAppTag := false
	for _, b := range resp {
		if b == 0x61 {
			foundAppTag = true
			break
		}
	}
	if !foundAppTag {
		t.Error("expected response to contain 0x61 (APPLICATION 1) tag for BindResponse")
	}

	// Verify resultCode 49 (invalidCredentials): INTEGER 49 → 0x02 0x01 0x31
	resultCodeMarker := []byte{0x02, 0x01, 0x31}
	if !bytes.Contains(resp, resultCodeMarker) {
		t.Errorf("expected response to contain resultCode 49 (invalidCredentials), response: %x", resp)
	}
}

func TestLDAPExtractMessageID(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	// Valid BER with messageID=1
	validData := []byte{
		0x30, 0x0c, // SEQUENCE, length 12
		0x02, 0x01, 0x01, // INTEGER, length 1, value 1
		0x60, 0x07, // APPLICATION 0
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}

	msgID := server.extractMessageID(validData)
	if msgID != 1 {
		t.Errorf("expected messageID 1, got %d", msgID)
	}

	// Data too short (less than 4 bytes)
	shortData := []byte{0x30, 0x0c}
	msgID = server.extractMessageID(shortData)
	if msgID != 0 {
		t.Errorf("expected messageID 0 for short data, got %d", msgID)
	}

	// Wrong tag (first byte not 0x30)
	wrongTagData := []byte{0x31, 0x0c, 0x02, 0x01, 0x01}
	msgID = server.extractMessageID(wrongTagData)
	if msgID != 0 {
		t.Errorf("expected messageID 0 for wrong tag, got %d", msgID)
	}

	// Wrong inner tag (not INTEGER 0x02 for messageID)
	wrongInnerTag := []byte{
		0x30, 0x0c,
		0x04, 0x01, 0x01, // OCTET STRING instead of INTEGER
		0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
	}
	msgID = server.extractMessageID(wrongInnerTag)
	if msgID != 0 {
		t.Errorf("expected messageID 0 for wrong inner tag, got %d", msgID)
	}
}

func TestLDAPInvalidPacket(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		server.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Send garbage data (less than 2 bytes)
	_, err = conn.Write([]byte{0xff})
	if err != nil {
		t.Fatalf("failed to send garbage data: %v", err)
	}

	// Give the server time to process
	time.Sleep(100 * time.Millisecond)

	// If we reach here without panic, the test passes
}
