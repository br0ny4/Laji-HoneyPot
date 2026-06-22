package api

import (
	"encoding/json"
	"net/http"
	"strconv"
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
	// 连接列表
	s.mux.HandleFunc("/api/connections", s.handleConnections)
	// 攻击事件
	s.mux.HandleFunc("/api/attacks", s.handleAttacks)
	// 漏洞数据库
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	// 健康检查
	s.mux.HandleFunc("/healthz", s.handleHealth)
	// 实时推送(SSE)
	s.mux.HandleFunc("/api/events", s.wsHub.ServeWS)
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.4.0"})
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
		rl.visitors[ip] = &visitor{tokens: 9, lastSeen: time.Now()}
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
