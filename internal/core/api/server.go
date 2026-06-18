package api

import (
	"encoding/json"
	"net/http"
	"strconv"

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

// Handler 返回带 CORS 的 http.Handler
func (s *Server) Handler() http.Handler {
	return corsMiddleware(s.mux)
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	conns, err := s.store.GetConnections(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":  len(attacks),
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.3.0"})
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
	if err != nil {
		return defaultVal
	}
	return n
}
