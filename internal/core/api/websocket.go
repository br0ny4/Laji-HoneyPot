package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
)

// WSHub WebSocket 连接管理中心
type WSHub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
	logger  *log.Logger
	store   *store.Store
}

// NewWSHub 创建 WebSocket Hub
func NewWSHub(logger *log.Logger, st *store.Store) *WSHub {
	return &WSHub{
		clients: make(map[chan []byte]struct{}),
		logger:  logger,
		store:   st,
	}
}

// Subscribe 注册新客户端，返回消息通道
func (h *WSHub) Subscribe() chan []byte {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	h.logger.Debugw("ws client connected", "total", len(h.clients))
	return ch
}

// Unsubscribe 移除客户端
func (h *WSHub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	close(ch)
	h.mu.Unlock()
}

// Broadcast 广播消息给所有客户端
func (h *WSHub) Broadcast(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
			// 客户端消费太慢，跳过
		}
	}
}

// BroadcastStats 推送实时统计
func (h *WSHub) BroadcastStats() {
	stats, err := h.store.GetStats()
	if err != nil {
		return
	}
	data, err := json.Marshal(map[string]interface{}{
		"type":      "stats",
		"data":      stats,
		"timestamp": time.Now().Unix(),
	})
	if err != nil {
		h.logger.Warnw("broadcast stats marshal failed", "error", err)
		return
	}
	h.Broadcast(data)
}

// ServeWS HTTP handler — 升级为 WebSocket（简化实现：SSE 替代）
func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	// 使用 Server-Sent Events 简化实时推送（免 WebSocket 库依赖）
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	// 立即发送初始数据
	h.BroadcastStats()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			// 心跳保持连接
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
