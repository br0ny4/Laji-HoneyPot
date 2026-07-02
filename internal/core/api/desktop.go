package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/countermeasure"
	"github.com/gorilla/websocket"
)

// DesktopFrame 桌面远控帧消息
type DesktopFrame struct {
	Action    string `json:"action"`               // frame, ping, close, config
	TargetIP  string `json:"target_ip,omitempty"`  // 目标主机 IP
	ImageData string `json:"image_data,omitempty"` // base64 编码的 JPEG/PNG 帧
	Width     int    `json:"width,omitempty"`      // 帧宽度
	Height    int    `json:"height,omitempty"`     // 帧高度
	Format    string `json:"format,omitempty"`     // jpeg / png
	Quality   int    `json:"quality,omitempty"`    // 图像质量 1-100
	FrameRate int    `json:"frame_rate,omitempty"` // 帧率 fps
	FrameSeq  int64  `json:"frame_seq,omitempty"`  // 帧序号
	SizeBytes int64  `json:"size_bytes,omitempty"` // 帧大小
	Error     string `json:"error,omitempty"`      // 错误信息
	TS        int64  `json:"ts,omitempty"`         // 时间戳
}

// DesktopSession 桌面远控会话
type DesktopSession struct {
	ID         string
	TargetIP   string
	ViewerConn *websocket.Conn // 管理端查看者
	AgentConn  *websocket.Conn // Agent 端帧源（可选，由 Agent 推送）
	CreatedAt  time.Time
	LastFrame  time.Time
	FrameCount int64
	TotalBytes int64
	FrameRate  int
	Quality    int
	mu         sync.Mutex
	done       chan struct{}
}

// DesktopHub 桌面远控会话管理
type DesktopHub struct {
	mu       sync.RWMutex
	sessions map[string]*DesktopSession // key = target IP (活跃的每个目标只能有一个远控会话)
	logger   *log.Logger
	auditFn  func(opType countermeasure.OpType, targetIP, actor, action, result string)
}

// NewDesktopHub 创建桌面远控管理器
func NewDesktopHub(logger *log.Logger) *DesktopHub {
	return &DesktopHub{
		sessions: make(map[string]*DesktopSession),
		logger:   logger,
	}
}

// SetAuditRecorder 设置审计回调
func (h *DesktopHub) SetAuditRecorder(fn func(opType countermeasure.OpType, targetIP, actor, action, result string)) {
	h.auditFn = fn
}

// recordAudit 记录审计
func (h *DesktopHub) recordAudit(targetIP, action, result string) {
	if h.auditFn != nil {
		h.auditFn(countermeasure.OpScreenCapture, targetIP, "desktop_hub", action, result)
	}
}

// HandleDesktopViewer 管理端查看者连接
// GET /api/countermeasure/desktop?target={ip}&quality={1-100}&fps={1-30}
func (h *DesktopHub) HandleDesktopViewer(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")
	if targetIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target IP required"})
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Errorw("desktop ws upgrade failed", "error", err)
		return
	}

	quality := 70
	if q := r.URL.Query().Get("quality"); q != "" {
		fmt.Sscanf(q, "%d", &quality)
		if quality < 10 {
			quality = 10
		}
		if quality > 100 {
			quality = 100
		}
	}

	fps := 5
	if f := r.URL.Query().Get("fps"); f != "" {
		fmt.Sscanf(f, "%d", &fps)
		if fps < 1 {
			fps = 1
		}
		if fps > 30 {
			fps = 30
		}
	}

	sessionID := fmt.Sprintf("desk_%s_%d", targetIP, time.Now().UnixNano())

	sess := &DesktopSession{
		ID:         sessionID,
		TargetIP:   targetIP,
		ViewerConn: conn,
		CreatedAt:  time.Now(),
		LastFrame:  time.Now(),
		FrameRate:  fps,
		Quality:    quality,
		done:       make(chan struct{}),
	}

	// 注册会话（每个目标只能有一个远控会话，新连接替换旧连接）
	h.mu.Lock()
	if old, ok := h.sessions[targetIP]; ok {
		h.logger.Infow("desktop session replaced", "target", targetIP, "old", old.ID, "new", sessionID)
		old.ViewerConn.Close()
		close(old.done)
	}
	h.sessions[targetIP] = sess
	h.mu.Unlock()

	h.logger.Infow("desktop viewer connected", "session", sessionID, "target", targetIP, "quality", quality, "fps", fps)

	h.recordAudit(targetIP, "viewer_connect",
		fmt.Sprintf("session=%s quality=%d fps=%d", sessionID, quality, fps))

	// 发送配置确认
	h.sendFrame(conn, DesktopFrame{
		Action:    "config",
		TargetIP:  targetIP,
		Quality:   quality,
		FrameRate: fps,
		TS:        time.Now().Unix(),
	})

	// 启动查看者循环
	h.viewerLoop(sess)

	// 清理
	h.mu.Lock()
	if h.sessions[targetIP] == sess {
		delete(h.sessions, targetIP)
	}
	h.mu.Unlock()

	h.recordAudit(targetIP, "viewer_disconnect",
		fmt.Sprintf("session=%s frames=%d bytes=%d", sessionID, sess.FrameCount, sess.TotalBytes))
	h.logger.Infow("desktop viewer disconnected", "session", sessionID, "frames", sess.FrameCount, "bytes", sess.TotalBytes)
}

// HandleDesktopAgent Agent 端帧推送连接
// Agent 通过此 WebSocket 实时推送截屏帧给管理端
// GET /api/countermeasure/desktop/agent?target={ip}
func (h *DesktopHub) HandleDesktopAgent(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")
	if targetIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target IP required"})
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Errorw("desktop agent ws upgrade failed", "error", err)
		return
	}

	h.logger.Infow("desktop agent connected", "target", targetIP)

	// 查找对应的查看者会话
	h.mu.RLock()
	sess, ok := h.sessions[targetIP]
	h.mu.RUnlock()

	if !ok {
		// 没有查看者，仍接收帧但丢弃（缓存最新一帧）
		h.logger.Infow("desktop agent: no viewer, caching frames", "target", targetIP)
		h.receiveFrames(targetIP, conn, nil)
		conn.Close()
		return
	}

	sess.mu.Lock()
	sess.AgentConn = conn
	sess.mu.Unlock()

	h.receiveFrames(targetIP, conn, sess)

	sess.mu.Lock()
	sess.AgentConn = nil
	sess.mu.Unlock()

	h.logger.Infow("desktop agent disconnected", "target", targetIP)
}

// viewerLoop 查看者消息循环（接收配置变更、心跳等）
func (h *DesktopHub) viewerLoop(sess *DesktopSession) {
	defer sess.ViewerConn.Close()

	// 空闲超时 goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sess.mu.Lock()
				idle := time.Since(sess.LastFrame)
				sess.mu.Unlock()
				if idle > 5*time.Minute {
					h.logger.Infow("desktop viewer idle timeout", "session", sess.ID)
					sess.ViewerConn.Close()
					return
				}
				sess.mu.Lock()
				sess.ViewerConn.WriteMessage(websocket.PingMessage, nil)
				sess.mu.Unlock()
			case <-sess.done:
				return
			}
		}
	}()

	for {
		_, msgBytes, err := sess.ViewerConn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Warnw("desktop viewer ws error", "session", sess.ID, "error", err)
			}
			close(sess.done)
			return
		}

		var msg DesktopFrame
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}

		switch msg.Action {
		case "config":
			sess.mu.Lock()
			if msg.Quality > 0 {
				sess.Quality = msg.Quality
			}
			if msg.FrameRate > 0 {
				sess.FrameRate = msg.FrameRate
			}
			sess.mu.Unlock()

			h.sendFrame(sess.ViewerConn, DesktopFrame{
				Action:    "config_ack",
				Quality:   sess.Quality,
				FrameRate: sess.FrameRate,
				TS:        time.Now().Unix(),
			})

			// 转发配置到 Agent
			sess.mu.Lock()
			if sess.AgentConn != nil {
				h.sendFrame(sess.AgentConn, DesktopFrame{
					Action:    "config",
					Quality:   sess.Quality,
					FrameRate: sess.FrameRate,
					TS:        time.Now().Unix(),
				})
			}
			sess.mu.Unlock()

		case "ping":
			h.sendFrame(sess.ViewerConn, DesktopFrame{
				Action: "pong",
				TS:     time.Now().Unix(),
			})

		case "close":
			h.sendFrame(sess.ViewerConn, DesktopFrame{
				Action: "closed",
				TS:     time.Now().Unix(),
			})
			close(sess.done)
			return
		}
	}
}

// receiveFrames 接收 Agent 推送的帧并转发给查看者
func (h *DesktopHub) receiveFrames(targetIP string, agentConn *websocket.Conn, sess *DesktopSession) {
	defer agentConn.Close()

	for {
		_, msgBytes, err := agentConn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Warnw("desktop agent ws error", "target", targetIP, "error", err)
			}
			return
		}

		var frame DesktopFrame
		if err := json.Unmarshal(msgBytes, &frame); err != nil {
			h.logger.Warnw("desktop frame parse error", "target", targetIP, "error", err)
			continue
		}

		if frame.Action != "frame" {
			continue
		}

		// 更新统计
		if sess != nil {
			sess.mu.Lock()
			sess.FrameCount++
			sess.LastFrame = time.Now()
			sess.TotalBytes += frame.SizeBytes
			sess.mu.Unlock()

			// 转发帧给查看者
			frame.TS = time.Now().Unix()
			h.sendFrame(sess.ViewerConn, frame)
		}
	}
}

// sendFrame 发送帧消息
func (h *DesktopHub) sendFrame(conn *websocket.Conn, frame DesktopFrame) {
	data, err := json.Marshal(frame)
	if err != nil {
		h.logger.Warnw("desktop frame marshal failed", "error", err)
		return
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		h.logger.Warnw("desktop frame send failed", "error", err)
	}
}

// ActiveSessions 返回活跃远控会话数
func (h *DesktopHub) ActiveSessions() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.sessions)
}

// CloseAll 关闭所有远控会话
func (h *DesktopHub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for target, sess := range h.sessions {
		sess.ViewerConn.Close()
		if sess.AgentConn != nil {
			sess.AgentConn.Close()
		}
		delete(h.sessions, target)
	}
}
