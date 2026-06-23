package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

// Server HTTP API 服务器
type Server struct {
	logger *log.Logger
	store  *store.Store
	vulnDB *vulndb.DB
	wsHub  *WSHub
	mux    *http.ServeMux
}

// NewServer 创建 API 服务器
func NewServer(logger *log.Logger, st *store.Store, vdb *vulndb.DB, hub *WSHub) *Server {
	s := &Server{
		logger: logger,
		store:  st,
		vulnDB: vdb,
		wsHub:  hub,
		mux:    http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// 仪表盘
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/stats/detailed", s.handleDetailedStats)
	// 连接列表
	s.mux.HandleFunc("/api/connections", s.handleConnections)
	// 攻击事件
	s.mux.HandleFunc("/api/attacks", s.handleAttacks)
	// 攻击者汇总
	s.mux.HandleFunc("/api/attackers", s.handleAttackers)
	// 拓扑图数据
	s.mux.HandleFunc("/api/topology", s.handleTopology)
	// 指纹数据
	s.mux.HandleFunc("/api/fingerprints", s.handleFingerprints)
	// 漏洞数据库
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	// 健康检查
	s.mux.HandleFunc("/healthz", s.handleHealth)
	// 实时推送(SSE)
	s.mux.HandleFunc("/api/events", s.wsHub.ServeWS)
	// 浏览器指纹采集
	s.mux.HandleFunc("/api/collect", s.handleCollect)
}

// Handler 返回带 CORS + 速率限制的 http.Handler
func (s *Server) Handler() http.Handler {
	return corsMiddleware(rateLimitMiddleware(s.mux))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		s.logger.Errorw("stats query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	conns, err := s.store.GetConnections(limit)
	if err != nil {
		s.logger.Errorw("connections query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":       len(conns),
		"connections": conns,
	})
}

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	attacks, err := s.store.GetAttacks(limit)
	if err != nil {
		s.logger.Errorw("attacks query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":   len(attacks),
		"attacks": attacks,
	})
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	vulns := s.vulnDB.All()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": len(vulns),
		"vulns": vulns,
	})
}

func (s *Server) handleDetailedStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetDetailedStats()
	if err != nil {
		s.logger.Errorw("detailed stats query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleAttackers(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	attackers, err := s.store.GetAttackers(limit)
	if err != nil {
		s.logger.Errorw("attackers query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":     len(attackers),
		"attackers": attackers,
	})
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	td, err := s.store.GetTopologyData()
	if err != nil {
		s.logger.Errorw("topology query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, td)
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	fps, err := s.store.GetFingerprints(limit)
	if err != nil {
		s.logger.Errorw("fingerprints query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":        len(fps),
		"fingerprints": fps,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.4.0"})
}

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = fwd
	}
	userAgent := r.Header.Get("User-Agent")

	// 读取或生成追踪 Cookie
	cookie, err := r.Cookie("_hp_track")
	trackingID := ""
	if err == nil && cookie != nil {
		trackingID = cookie.Value
	}
	if trackingID == "" {
		trackingID = newUUID()
	}

	// 解析指纹数据
	rawData := ""
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			rawData = string(body)
		}
	} else {
		rawData = r.URL.Query().Get("d")
	}

	if rawData == "" {
		rawData = "{}"
	}

	// 存储指纹数据
	if _, err := s.store.RecordFingerprint(trackingID, remoteIP, userAgent, rawData); err != nil {
		s.logger.Errorw("fingerprint store failed", "error", err)
	}

	// 设置持久化追踪 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "_hp_track",
		Value:    trackingID,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// 响应 1x1 透明像素 GIF（用于 img 标签回调）
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b"))
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultVal
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// rateLimiter 基于 IP 的简易令牌桶速率限制，默认 100 req/s
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{visitors: make(map[string]*visitor)}
	go rl.cleanup(5 * time.Minute)
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{tokens: 100, lastSeen: time.Now()}
		return true
	}

	elapsed := time.Since(v.lastSeen).Seconds()
	v.tokens += elapsed * 100 // 100 tokens per second
	if v.tokens > 100 {
		v.tokens = 100 // 桶容量
	}
	v.lastSeen = time.Now()

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

func (rl *rateLimiter) cleanup(interval time.Duration) {
	for {
		time.Sleep(interval)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > interval {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

var rl = newRateLimiter()

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/collect 端点豁免速率限制 — JS Payload 的 img beacon 回传不可丢失
		if strings.HasPrefix(r.URL.Path, "/api/collect") {
			next.ServeHTTP(w, r)
			return
		}
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = fwd
		}
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
