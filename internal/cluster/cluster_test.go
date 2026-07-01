package cluster

import (
	"net"
	"sync"
	"testing"
	"time"
)

// ---------- framer 测试 ----------

// TestFramerReadWrite 验证消息帧的编码/解码往返
func TestFramerReadWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverFr := newFramer(server)
	clientFr := newFramer(client)

	// 写入测试消息
	testPayload := RegisterRequest{
		Node: NodeInfo{
			NodeID:   "test-node-001",
			Hostname: "test-host",
			Version:  "0.10.0",
			Services: []string{"HTTP", "SSH"},
		},
	}

	errCh := make(chan error, 1)
	var receivedMsg *Message

	go func() {
		msg, err := clientFr.readMessage()
		if err != nil {
			errCh <- err
			return
		}
		receivedMsg = msg
		errCh <- nil
	}()

	if err := serverFr.writeMessage(MsgTypeRegister, "test-node-001", testPayload); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}

	if receivedMsg == nil {
		t.Fatal("expected non-nil message")
	}
	if receivedMsg.Type != MsgTypeRegister {
		t.Errorf("expected type %q, got %q", MsgTypeRegister, receivedMsg.Type)
	}
	if receivedMsg.NodeID != "test-node-001" {
		t.Errorf("expected nodeID test-node-001, got %s", receivedMsg.NodeID)
	}
}

// TestFramerReadWrite_Heartbeat 验证心跳消息帧
func TestFramerReadWrite_Heartbeat(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverFr := newFramer(server)
	clientFr := newFramer(client)

	hb := Heartbeat{
		Stats: HeartbeatStats{
			Connections:  42,
			Attacks:      7,
			Fingerprints: 3,
			MemoryMB:     15.5,
			Goroutines:   12,
			UptimeSec:    3600,
		},
	}

	errCh := make(chan error, 1)
	var msg *Message
	go func() {
		var err error
		msg, err = clientFr.readMessage()
		errCh <- err
	}()

	if err := serverFr.writeMessage(MsgTypeHeartbeat, "node-abc", hb); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}

	var decoded Heartbeat
	if err := unmarshalPayload(msg, &decoded); err != nil {
		t.Fatalf("unmarshalPayload failed: %v", err)
	}
	if decoded.Stats.Connections != 42 {
		t.Errorf("expected 42 connections, got %d", decoded.Stats.Connections)
	}
	if decoded.Stats.MemoryMB != 15.5 {
		t.Errorf("expected 15.5 MB, got %f", decoded.Stats.MemoryMB)
	}
}

// ---------- nodeRegistry 测试 ----------

// TestNodeRegistry_Register 验证节点注册
func TestNodeRegistry_Register(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	info := &NodeInfo{
		NodeID:   "node-1",
		Hostname: "host-1",
		Version:  "0.10.0",
		Services: []string{"HTTP", "SSH"},
	}
	reg.register(info, "192.168.1.1:12345")

	// 验证状态
	states := reg.allStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 node, got %d", len(states))
	}
	if !states[0].Online {
		t.Error("expected node to be online")
	}
	if states[0].NodeID != "node-1" {
		t.Errorf("expected node-1, got %s", states[0].NodeID)
	}

	// 验证信息
	retrieved := reg.getInfo("node-1")
	if retrieved == nil {
		t.Fatal("expected non-nil info")
	}
	if retrieved.Hostname != "host-1" {
		t.Errorf("expected host-1, got %s", retrieved.Hostname)
	}
}

// TestNodeRegistry_Heartbeat 验证心跳更新
func TestNodeRegistry_Heartbeat(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	reg.register(&NodeInfo{NodeID: "node-2"}, "")

	// 发送心跳
	reg.heartbeat("node-2", &HeartbeatStats{
		Connections:  100,
		Attacks:      10,
		Fingerprints: 5,
	})

	states := reg.allStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 node, got %d", len(states))
	}
	if states[0].Connections != 100 {
		t.Errorf("expected 100 connections, got %d", states[0].Connections)
	}
	if states[0].Attacks != 10 {
		t.Errorf("expected 10 attacks, got %d", states[0].Attacks)
	}
	if states[0].Fingerprints != 5 {
		t.Errorf("expected 5 fingerprints, got %d", states[0].Fingerprints)
	}
}

// TestNodeRegistry_MarkOffline 验证离线标记
func TestNodeRegistry_MarkOffline(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	reg.register(&NodeInfo{NodeID: "node-3"}, "")
	reg.markOffline("node-3")

	states := reg.allStates()
	if states[0].Online {
		t.Error("expected node to be offline")
	}
}

// TestNodeRegistry_AllStates_Timeout 验证超时自动离线
func TestNodeRegistry_AllStates_Timeout(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	reg.register(&NodeInfo{NodeID: "node-4"}, "")
	// 手动将 LastSeen 设置为 2 分钟前
	reg.mu.Lock()
	reg.nodes["node-4"].LastSeen = time.Now().Add(-2 * time.Minute)
	reg.mu.Unlock()

	states := reg.allStates()
	if states[0].Online {
		t.Error("expected node to be marked offline after 60s timeout")
	}
}

// TestNodeRegistry_MultipleNodes 验证多节点注册
func TestNodeRegistry_MultipleNodes(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	for i := 0; i < 5; i++ {
		reg.register(&NodeInfo{NodeID: fmtNodeID(i)}, "")
	}

	states := reg.allStates()
	if len(states) != 5 {
		t.Errorf("expected 5 nodes, got %d", len(states))
	}
}

// TestNodeRegistry_ConcurrentAccess 验证并发安全
func TestNodeRegistry_ConcurrentAccess(t *testing.T) {
	reg := &nodeRegistry{
		nodes: make(map[string]*NodeState),
		info:  make(map[string]*NodeInfo),
	}

	reg.register(&NodeInfo{NodeID: "concurrent-node"}, "")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.heartbeat("concurrent-node", &HeartbeatStats{Connections: 1})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.allStates()
		}()
	}
	wg.Wait()

	states := reg.allStates()
	if len(states) != 1 {
		t.Errorf("expected 1 node, got %d", len(states))
	}
}

// ---------- Manager 基础测试 ----------

// TestNewManager 验证 Manager 创建
func TestNewManager(t *testing.T) {
	// 使用 nil logger 和 nil tls config 测试创建（实际使用需要有效 TLS 配置）
	mgr := NewManager(nil, nil)
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if mgr.registry == nil {
		t.Error("expected non-nil registry")
	}
	if mgr.EventCh == nil {
		t.Error("expected non-nil EventCh")
	}

	// 验证空节点列表
	nodes := mgr.GetNodes()
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

// TestManager_Close 验证 Manager 关闭
func TestManager_Close(t *testing.T) {
	mgr := NewManager(nil, nil)
	mgr.Close()

	// EventCh 应该被关闭
	_, ok := <-mgr.EventCh
	if ok {
		t.Error("expected EventCh to be closed")
	}
}

// ---------- Agent 基础测试 ----------

// TestNewAgent 验证 Agent 创建
func TestNewAgent(t *testing.T) {
	cfg := AgentConfig{
		ManagerAddr: "127.0.0.1:8443",
		NodeID:      "test-agent-01",
		Services:    []string{"HTTP", "MySQL"},
	}

	agent := NewAgent(nil, cfg)
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
	if agent.NodeID() != "test-agent-01" {
		t.Errorf("expected test-agent-01, got %s", agent.NodeID())
	}
	if agent.managerAddr != "127.0.0.1:8443" {
		t.Errorf("expected 127.0.0.1:8443, got %s", agent.managerAddr)
	}
}

// TestNewAgent_AutoNodeID 验证自动生成 NodeID
func TestNewAgent_AutoNodeID(t *testing.T) {
	cfg := AgentConfig{
		ManagerAddr: "127.0.0.1:8443",
		// NodeID 留空
	}
	agent := NewAgent(nil, cfg)
	if agent.NodeID() == "" {
		t.Error("expected auto-generated node ID")
	}
	// 格式: hostname-xxxxxxxx
	if len(agent.NodeID()) < 9 {
		t.Errorf("node ID too short: %s", agent.NodeID())
	}
}

// TestAgent_PushEvent 验证事件缓冲
func TestAgent_PushEvent(t *testing.T) {
	cfg := AgentConfig{
		ManagerAddr: "127.0.0.1:8443",
		NodeID:      "test-agent",
	}
	agent := NewAgent(nil, cfg)

	// Push 事件到缓冲
	agent.PushEvent("connection", map[string]string{"ip": "10.0.0.1"}, "10.0.0.1")
	agent.PushEvent("attack", map[string]string{"path": "/admin"}, "10.0.0.2")

	if len(agent.eventBuf) != 2 {
		t.Errorf("expected 2 buffered events, got %d", len(agent.eventBuf))
	}
	if agent.eventBuf[0].Topic != "connection" {
		t.Errorf("expected connection, got %s", agent.eventBuf[0].Topic)
	}
	if agent.eventBuf[1].Topic != "attack" {
		t.Errorf("expected attack, got %s", agent.eventBuf[1].Topic)
	}
}

// TestAgent_Close 验证 Agent 关闭
func TestAgent_Close(t *testing.T) {
	cfg := AgentConfig{
		ManagerAddr: "127.0.0.1:8443",
	}
	agent := NewAgent(nil, cfg)
	agent.Close()
	// Close 应该不会 panic（即使没有活动连接）
}

// ---------- 工具函数测试 ----------

// TestRandomHex 验证随机字符串生成
func TestRandomHex(t *testing.T) {
	s1 := randomHex(8)
	s2 := randomHex(8)

	if len(s1) != 8 {
		t.Errorf("expected 8 chars, got %d", len(s1))
	}
	if s1 == s2 {
		t.Log("random collision unlikely but possible (1 in 2^32)")
	}
}

// TestUnmarshalPayload 验证 Payload 反序列化
func TestUnmarshalPayload(t *testing.T) {
	msg := &Message{
		Type:   MsgTypeRegister,
		NodeID: "test",
		Payload: map[string]interface{}{
			"node": map[string]interface{}{
				"node_id":  "abc-123",
				"hostname": "test-host",
				"version":  "0.10.0",
			},
		},
	}

	var req RegisterRequest
	if err := unmarshalPayload(msg, &req); err != nil {
		t.Fatalf("unmarshalPayload failed: %v", err)
	}
	if req.Node.NodeID != "abc-123" {
		t.Errorf("expected abc-123, got %s", req.Node.NodeID)
	}
	if req.Node.Hostname != "test-host" {
		t.Errorf("expected test-host, got %s", req.Node.Hostname)
	}
}

// ---------- 协议常量测试 ----------

// TestConstants 验证协议常量
func TestConstants(t *testing.T) {
	if MsgTypeRegister != "register" {
		t.Errorf("expected register, got %s", MsgTypeRegister)
	}
	if MsgTypeHeartbeat != "heartbeat" {
		t.Errorf("expected heartbeat, got %s", MsgTypeHeartbeat)
	}
	if MsgTypeEventPush != "event_push" {
		t.Errorf("expected event_push, got %s", MsgTypeEventPush)
	}
	if DefaultHeartbeatSec != 30 {
		t.Errorf("expected 30, got %d", DefaultHeartbeatSec)
	}
	if DefaultClusterPort != 8443 {
		t.Errorf("expected 8443, got %d", DefaultClusterPort)
	}
}

// ---------- 辅助函数 ----------

func fmtNodeID(i int) string {
	return "node-" + string(rune('0'+i))
}
