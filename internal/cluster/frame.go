package cluster

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// framer 消息帧处理器
// 协议格式: [4 字节 BigEndian 长度] + [JSON body]
// 最大消息大小: 1MB
type framer struct {
	conn net.Conn
	mu   sync.Mutex // 保护写操作
}

const maxMessageSize = 1 << 20 // 1MB

func newFramer(conn net.Conn) *framer {
	return &framer{conn: conn}
}

// readMessage 从连接读取一条消息
func (f *framer) readMessage() (*Message, error) {
	// 读取 4 字节长度前缀
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(f.conn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// 读取 JSON body
	body := make([]byte, length)
	if _, err := io.ReadFull(f.conn, body); err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("message unmarshal: %w", err)
	}

	return &msg, nil
}

// writeMessage 向连接写入一条消息
// msgType: 消息类型, nodeID: 发送方 ID, payload: 消息载荷
func (f *framer) writeMessage(msgType, nodeID string, payload interface{}) error {
	msg := Message{
		Type:      msgType,
		NodeID:    nodeID,
		Timestamp: time.Now().UnixMilli(),
		Payload:   payload,
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("message marshal: %w", err)
	}

	if len(body) > maxMessageSize {
		return fmt.Errorf("message body too large: %d bytes", len(body))
	}

	// 4 字节长度前缀 + body
	f.mu.Lock()
	defer f.mu.Unlock()

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(body)))

	if _, err := f.conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := f.conn.Write(body); err != nil {
		return err
	}

	return nil
}

// randomHex 生成 n 个字符的随机十六进制字符串
func randomHex(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// unmarshalPayload 从 Message 中解析 Payload 到目标结构体
func unmarshalPayload(msg *Message, target interface{}) error {
	payloadBytes, err := json.Marshal(msg.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(payloadBytes, target)
}
