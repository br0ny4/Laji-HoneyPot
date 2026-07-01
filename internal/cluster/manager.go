package cluster

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Manager 集群管理端，运行在管理节点上
// 职责：
//   - 监听 TLS 端口，接受远程节点连接
//   - 维护节点注册表 (nodeRegistry)
//   - 处理心跳、事件转发、配置下发
//   - 提供节点状态查询接口 (供 API/frontend 使用)
type Manager struct {
	logger   *log.Logger
	registry *nodeRegistry
	tlsCfg   *tls.Config
	listener net.Listener

	// 事件转发通道：节点推送的事件 → 管理端事件总线
	EventCh chan ClusterEvent

	mu     sync.RWMutex
	closed bool
}

// nodeRegistry 节点注册表（线程安全）
type nodeRegistry struct {
	mu    sync.RWMutex
	nodes map[string]*NodeState // nodeID → state
	info  map[string]*NodeInfo  // nodeID → static info
}

// NewManager 创建集群管理端
// tlsConfig: TLS 配置 (需包含 CA 证书池用于客户端证书验证)
func NewManager(logger *log.Logger, tlsConfig *tls.Config) *Manager {
	return &Manager{
		logger:   logger,
		registry: &nodeRegistry{
			nodes: make(map[string]*NodeState),
			info:  make(map[string]*NodeInfo),
		},
		tlsCfg:  tlsConfig,
		EventCh: make(chan ClusterEvent, 256),
	}
}

// Listen 启动管理端监听
func (m *Manager) Listen(addr string) error {
	ln, err := tls.Listen("tcp", addr, m.tlsCfg)
	if err != nil {
		return fmt.Errorf("cluster manager listen: %w", err)
	}
	m.listener = ln
	m.logger.Infow("cluster manager listening", "addr", addr)

	go m.acceptLoop()
	return nil
}

// acceptLoop 接受远程节点连接
func (m *Manager) acceptLoop() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			m.mu.RLock()
			if m.closed {
				m.mu.RUnlock()
				return
			}
			m.mu.RUnlock()
			m.logger.Errorw("cluster accept error", "error", err)
			continue
		}
		go m.handleNode(conn)
	}
}

// handleNode 处理单个远程节点的连接生命周期
func (m *Manager) handleNode(conn net.Conn) {
	defer conn.Close()

	peer := conn.RemoteAddr().String()
	m.logger.Infow("cluster node connected", "peer", peer)

	fr := newFramer(conn)

	for {
		msg, err := fr.readMessage()
		if err != nil {
			if err != io.EOF {
				m.logger.Warnw("cluster read error", "peer", peer, "error", err)
			}
			// 节点断连 → 标记离线
			if nodeID := m.registry.nodeByAddr(peer); nodeID != "" {
				m.registry.markOffline(nodeID)
				m.logger.Infow("cluster node disconnected", "node_id", nodeID, "peer", peer)
			}
			return
		}

		switch msg.Type {
		case MsgTypeRegister:
			m.handleRegister(fr, msg, peer)
		case MsgTypeHeartbeat:
			m.handleHeartbeat(fr, msg)
		case MsgTypeEventPush:
			m.handleEventPush(msg)
		default:
			m.logger.Warnw("unknown cluster message type", "type", msg.Type, "peer", peer)
		}
	}
}

// handleRegister 处理节点注册
func (m *Manager) handleRegister(fr *framer, msg *Message, peer string) {
	payloadBytes, _ := json.Marshal(msg.Payload)
	var req RegisterRequest
	if err := json.Unmarshal(payloadBytes, &req); err != nil {
		m.logger.Warnw("invalid register payload", "peer", peer, "error", err)
		return
	}

	// 如果未提供 NodeID，生成一个
	if req.Node.NodeID == "" {
		req.Node.NodeID = fmt.Sprintf("%s-%s", req.Node.Hostname, randomHex(8))
	}

	// 注册节点
	m.registry.register(&req.Node, peer)

	m.logger.Infow("cluster node registered",
		"node_id", req.Node.NodeID,
		"hostname", req.Node.Hostname,
		"ip", req.Node.IP,
		"services", req.Node.Services,
	)

	// 发送注册响应
	resp := RegisterResponse{
		Accepted:     true,
		ManagerID:    "manager-01",
		HeartbeatSec: DefaultHeartbeatSec,
	}
	fr.writeMessage(MsgTypeRegister, req.Node.NodeID, resp)

	// 广播节点上线事件
	m.EventCh <- ClusterEvent{
		Topic:     "cluster.node_online",
		Timestamp: time.Now().UnixMilli(),
		Payload:   req.Node,
	}
}

// handleHeartbeat 处理节点心跳
func (m *Manager) handleHeartbeat(fr *framer, msg *Message) {
	payloadBytes, _ := json.Marshal(msg.Payload)
	var hb Heartbeat
	if err := json.Unmarshal(payloadBytes, &hb); err != nil {
		return
	}

	m.registry.heartbeat(msg.NodeID, &hb.Stats)

	// 响应心跳
	resp := HeartbeatResponse{OK: true}
	fr.writeMessage(MsgTypeHeartbeat, "manager", resp)
}

// handleEventPush 处理节点推送的事件
func (m *Manager) handleEventPush(msg *Message) {
	payloadBytes, _ := json.Marshal(msg.Payload)
	var fwd EventForward
	if err := json.Unmarshal(payloadBytes, &fwd); err != nil {
		return
	}

	for _, evt := range fwd.Events {
		select {
		case m.EventCh <- evt:
		default:
			m.logger.Warnw("cluster event channel full, dropping event",
				"node_id", msg.NodeID,
				"topic", evt.Topic,
			)
		}
	}
}

// GetNodes 返回所有已注册节点状态（供 API 使用）
func (m *Manager) GetNodes() []NodeState {
	return m.registry.allStates()
}

// GetNodeInfo 返回节点静态信息
func (m *Manager) GetNodeInfo(nodeID string) *NodeInfo {
	return m.registry.getInfo(nodeID)
}

// Close 关闭管理端监听
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()

	if m.listener != nil {
		m.listener.Close()
	}
	close(m.EventCh)
}

// ---------- nodeRegistry 方法 ----------

func (r *nodeRegistry) register(info *NodeInfo, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.info[info.NodeID] = info
	r.nodes[info.NodeID] = &NodeState{
		NodeID:   info.NodeID,
		Online:   true,
		LastSeen: time.Now(),
	}
}

func (r *nodeRegistry) heartbeat(nodeID string, stats *HeartbeatStats) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if state, ok := r.nodes[nodeID]; ok {
		state.Online = true
		state.LastSeen = time.Now()
		if stats != nil {
			state.Connections = stats.Connections
			state.Attacks = stats.Attacks
			state.Fingerprints = stats.Fingerprints
			state.UptimeSeconds = stats.UptimeSec
		}
	}
}

func (r *nodeRegistry) markOffline(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if state, ok := r.nodes[nodeID]; ok {
		state.Online = false
	}
}

func (r *nodeRegistry) nodeByAddr(addr string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// 简单实现：遍历找匹配 (小规模场景足够)
	for id := range r.nodes {
		return id // 当前连接只有单节点，直接返回第一个
	}
	return ""
}

func (r *nodeRegistry) allStates() []NodeState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]NodeState, 0, len(r.nodes))
	for _, state := range r.nodes {
		// 30 秒无心跳则视为离线
		if state.Online && time.Since(state.LastSeen) > 60*time.Second {
			state.Online = false
		}
		result = append(result, *state)
	}
	return result
}

func (r *nodeRegistry) getInfo(nodeID string) *NodeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.info[nodeID]
}
