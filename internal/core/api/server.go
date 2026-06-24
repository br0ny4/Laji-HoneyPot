package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
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
	logger          *log.Logger
	store           *store.Store
	vulnDB          *vulndb.DB
	wsHub           *WSHub
	mux             *http.ServeMux
	apiKey          string // 管理后台认证密钥，空则不启用
	startTime       time.Time
	frontendHandler http.Handler // 可选：嵌入式前端 SPA handler
}

// NewServer 创建 API 服务器
func NewServer(logger *log.Logger, st *store.Store, vdb *vulndb.DB, hub *WSHub, apiKey string) *Server {
	s := &Server{
		logger:    logger,
		store:     st,
		vulnDB:    vdb,
		wsHub:     hub,
		mux:       http.NewServeMux(),
		apiKey:    apiKey,
		startTime: time.Now(),
	}
	s.registerRoutes()
	return s
}

// SetFrontendHandler 设置前端静态文件 handler（由 go:embed 提供）
func (s *Server) SetFrontendHandler(h http.Handler) {
	s.frontendHandler = h
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
	// 系统状态
	s.mux.HandleFunc("/api/system", s.handleSystem)
	// 反制事件
	s.mux.HandleFunc("/api/countermeasures", s.handleCountermeasures)
	s.mux.HandleFunc("/api/countermeasures/stats", s.handleCountermeasureStats)
	// 端口扫描
	s.mux.HandleFunc("/api/portscans", s.handlePortScans)
	// 运行时监控
	s.mux.HandleFunc("/api/metrics", s.handleMetrics)
	// 漏洞数据库
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	// 健康检查
	s.mux.HandleFunc("/healthz", s.handleHealth)
	// 实时推送(SSE)
	s.mux.HandleFunc("/api/events", s.wsHub.ServeWS)
	// 浏览器指纹采集
	s.mux.HandleFunc("/api/collect", s.handleCollect)

	// 前端 SPA 静态文件服务（由 go:embed 嵌入 web/dist/）
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if s.frontendHandler != nil {
			s.frontendHandler.ServeHTTP(w, r)
		} else {
			http.Error(w, "前端未构建。请运行: cd web && npm run build", http.StatusNotFound)
		}
	})
}

// Handler 返回带安全中间件链的 http.Handler
// 链式顺序: 请求日志 → CORS白名单 → API Key认证 → 速率限制
func (s *Server) Handler() http.Handler {
	return requestLogMiddleware(s.logger, corsMiddleware(s.apiKeyMiddleware(rateLimitMiddleware(s.mux))))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// 仅允许本地开发和生产 localhost 来源
		allowedOrigins := map[string]bool{
			"http://localhost:3000": true,
			"http://127.0.0.1:3000": true,
			"http://localhost:8080": true,
			"http://127.0.0.1:8080": true,
		}
		if allowedOrigins[origin] || origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if origin == "" {
				// 同源请求（如直接访问 API），允许
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Expose-Headers", "X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiKeyMiddleware API Key 认证中间件
// 仅当配置了 api_key 时才启用。以下端点豁免认证：
//   - /healthz        （健康检查，无需认证）
//   - /api/collect     （浏览器指纹采集，由攻击者浏览器触发，不可拦截）
//   - /api/events       （SSE 实时推送，前端 EventSource 不支持自定义 Header）
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 未配置 API Key → 跳过认证
		if s.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path

		// 豁免端点：健康检查、指纹采集、SSE 推送
		if path == "/healthz" || strings.HasPrefix(path, "/api/collect") || path == "/api/events" {
			next.ServeHTTP(w, r)
			return
		}

		// 校验 X-API-Key 请求头
		key := r.Header.Get("X-API-Key")
		// 也支持 ?api_key=xxx 查询参数（SSE 场景下前端无法设置 Header）
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key != s.apiKey {
			s.logger.Warnw("api auth failed",
				"remote", r.RemoteAddr,
				"path", path,
				"provided_key", maskKey(key),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized","message":"valid X-API-Key required"}`)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// maskKey 脱敏显示 Key（仅用于日志）
func maskKey(key string) string {
	if len(key) <= 4 {
		return "***"
	}
	return key[:4] + strings.Repeat("*", len(key)-4)
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

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.GetDetailedStats()
	info := map[string]interface{}{
		"version":    "0.9.0",
		"go_version": "go1.22+",
		"database":   "SQLite (WAL模式)",
		"services":   "HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP",
	}
	if stats != nil {
		info["active_services"] = stats.ActiveServices
		info["total_conns"] = stats.TotalConns
		info["fingerprint_cnt"] = stats.FingerprintCnt
		info["attackers_today"] = stats.Attackers
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleCountermeasures(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	cms, err := s.store.GetCountermeasures(limit)
	if err != nil {
		s.logger.Errorw("countermeasures query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":           len(cms),
		"countermeasures": cms,
	})
}

func (s *Server) handleCountermeasureStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetCountermeasureStats()
	if err != nil {
		s.logger.Errorw("countermeasure stats query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handlePortScans(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	scans, err := s.store.GetPortScans(limit)
	if err != nil {
		s.logger.Errorw("port scan query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": len(scans),
		"scans": scans,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	var goroutines = runtime.NumGoroutine()

	metrics := map[string]interface{}{
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"goroutines":     goroutines,
		"memory": map[string]interface{}{
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(mem.TotalAlloc) / 1024 / 1024,
			"sys_mb":         float64(mem.Sys) / 1024 / 1024,
			"num_gc":         mem.NumGC,
			"heap_objects":   mem.HeapObjects,
			"heap_inuse_mb":  float64(mem.HeapInuse) / 1024 / 1024,
			"stack_inuse_kb": float64(mem.StackInuse) / 1024,
		},
		"go_version": runtime.Version(),
		"num_cpu":    runtime.NumCPU(),
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.9.0"})
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

// requestLogMiddleware 记录每个 HTTP 请求的方法、路径、状态码和耗时
func requestLogMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		logger.Infow("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// responseWriter 包装 http.ResponseWriter，捕获写入的状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
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
