package cluster

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Agent 集群节点代理，运行在远程蜜罐节点上
// 职责：
//   - 连接管理端，发送注册请求
//   - 周期性发送心跳 (携带运行时统计)
//   - 转发本地事件到管理端
//   - 断线重连
type Agent struct {
	logger    *log.Logger
	managerAddr string
	tlsCfg    *tls.Config
	nodeInfo  NodeInfo

	conn     net.Conn
	fr       *framer

	// 事件缓冲队列：本地事件 → 批量转发到管理端
	eventBuf []ClusterEvent
	bufMu    sync.Mutex

	hbSec      int          // 心跳间隔 (秒)
	stopCh     chan struct{}
	reconnectCh chan struct{}

	mu     sync.Mutex
	closed bool
}

// AgentConfig Agent 配置
type AgentConfig struct {
	ManagerAddr string      // 管理端地址 (host:port)
	TLSConfig   *tls.Config // TLS 配置
	NodeID      string      // 节点 ID (空则自动生成)
	Services    []string    // 启用的蜜罐服务
}

// NewAgent 创建集群节点代理
func NewAgent(logger *log.Logger, cfg AgentConfig) *Agent {
	nodeID := cfg.NodeID
	if nodeID == "" {
		hostname, _ := os.Hostname()
		nodeID = fmt.Sprintf("%s-%s", hostname, randomHex(8))
	}

	return &Agent{
		logger:      logger,
		managerAddr: cfg.ManagerAddr,
		tlsCfg:      cfg.TLSConfig,
		nodeInfo: NodeInfo{
			NodeID:    nodeID,
			Hostname:  hostnameOr("unknown"),
			Version:   "0.10.0",
			Services:  cfg.Services,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			StartTime: time.Now().Unix(),
		},
		eventBuf:    make([]ClusterEvent, 0, 64),
		hbSec:       DefaultHeartbeatSec,
		stopCh:      make(chan struct{}),
		reconnectCh: make(chan struct{}, 1),
	}
}

// Connect 连接管理端并开始工作循环
func (a *Agent) Connect() error {
	if err := a.dial(); err != nil {
		return fmt.Errorf("agent connect: %w", err)
	}

	go a.heartbeatLoop()
	go a.eventFlushLoop()

	return nil
}

// dial 建立到管理端的 TLS 连接并完成注册握手
func (a *Agent) dial() error {
	conn, err := tls.Dial("tcp", a.managerAddr, a.tlsCfg)
	if err != nil {
		return err
	}

	a.conn = conn
	a.fr = newFramer(conn)

	// 发送注册请求
	req := RegisterRequest{Node: a.nodeInfo}
	if err := a.fr.writeMessage(MsgTypeRegister, a.nodeInfo.NodeID, req); err != nil {
		conn.Close()
		return fmt.Errorf("register: %w", err)
	}

	// 读取注册响应
	msg, err := a.fr.readMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("register response: %w", err)
	}

	var resp RegisterResponse
	if err := unmarshalPayload(msg, &resp); err != nil {
		conn.Close()
		return fmt.Errorf("register response parse: %w", err)
	}

	if !resp.Accepted {
		conn.Close()
		return fmt.Errorf("registration rejected")
	}

	if resp.HeartbeatSec > 0 {
		a.hbSec = resp.HeartbeatSec
	}

	a.logger.Infow("cluster agent registered",
		"node_id", a.nodeInfo.NodeID,
		"manager", a.managerAddr,
		"heartbeat_sec", a.hbSec,
	)

	return nil
}

// heartbeatLoop 周期性发送心跳
func (a *Agent) heartbeatLoop() {
	ticker := time.NewTicker(time.Duration(a.hbSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.sendHeartbeat()
		case <-a.reconnectCh:
			// 重连后重置 ticker
			ticker.Reset(time.Duration(a.hbSec) * time.Second)
		}
	}
}

// sendHeartbeat 发送心跳
func (a *Agent) sendHeartbeat() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.fr == nil {
		return
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	hb := Heartbeat{
		Stats: HeartbeatStats{
			Goroutines: runtime.NumGoroutine(),
			MemoryMB:   float64(mem.Alloc) / 1024 / 1024,
			UptimeSec:  int64(time.Since(time.Unix(a.nodeInfo.StartTime, 0)).Seconds()),
		},
	}

	if err := a.fr.writeMessage(MsgTypeHeartbeat, a.nodeInfo.NodeID, hb); err != nil {
		a.logger.Warnw("heartbeat send failed", "error", err)
		a.triggerReconnect()
	}
}

// eventFlushLoop 周期性刷新事件缓冲到管理端
func (a *Agent) eventFlushLoop() {
	ticker := time.NewTicker(5 * time.Second) // 每 5 秒批量推送事件
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.flushEvents()
		}
	}
}

// flushEvents 将缓冲的事件批量发送到管理端
func (a *Agent) flushEvents() {
	a.bufMu.Lock()
	if len(a.eventBuf) == 0 {
		a.bufMu.Unlock()
		return
	}
	events := a.eventBuf
	a.eventBuf = make([]ClusterEvent, 0, 64)
	a.bufMu.Unlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.fr == nil {
		// 未连接时重新缓冲
		a.bufMu.Lock()
		a.eventBuf = append(events, a.eventBuf...)
		a.bufMu.Unlock()
		return
	}

	fwd := EventForward{Events: events}
	if err := a.fr.writeMessage(MsgTypeEventPush, a.nodeInfo.NodeID, fwd); err != nil {
		a.logger.Warnw("event push failed", "error", err, "count", len(events))
		a.triggerReconnect()
	}
}

// PushEvent 将本地事件加入转发队列
func (a *Agent) PushEvent(topic string, payload interface{}, remoteIP string) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()

	// 限制缓冲区大小，防止内存溢出
	if len(a.eventBuf) >= 1024 {
		a.eventBuf = a.eventBuf[512:] // 丢弃旧的一半
	}

	a.eventBuf = append(a.eventBuf, ClusterEvent{
		Topic:     topic,
		Payload:   payload,
		Timestamp: time.Now().UnixMilli(),
		RemoteIP:  remoteIP,
	})
}

// triggerReconnect 触发重连
func (a *Agent) triggerReconnect() {
	select {
	case a.reconnectCh <- struct{}{}:
	default:
	}
}

// NodeID 返回节点 ID
func (a *Agent) NodeID() string {
	return a.nodeInfo.NodeID
}

// Close 关闭代理
func (a *Agent) Close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()

	close(a.stopCh)

	if a.conn != nil {
		a.conn.Close()
	}
}

// ---------- 工具函数 ----------

func hostnameOr(fallback string) string {
	h, err := os.Hostname()
	if err != nil {
		return fallback
	}
	return h
}
