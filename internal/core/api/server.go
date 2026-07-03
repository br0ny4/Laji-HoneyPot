package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/asset"
	"github.com/Laji-HoneyPot/honeypot/internal/cluster"
	"github.com/Laji-HoneyPot/honeypot/internal/core"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/profile"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/countermeasure"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

// Server HTTP API 服务器
type Server struct {
	logger          *log.Logger
	store           *store.Store
	vulnDB          *vulndb.DB
	wsHub           *WSHub
	shellHub        *ShellHub    // 远程 Shell WebSocket 会话管理
	transferHub     *TransferHub // 文件传输管理
	processHub      *ProcessHub  // 进程管理
	desktopHub      *DesktopHub  // 桌面远控会话管理
	mfaProvider     *MFAProvider // MFA 多因子认证
	auditChain      *AuditChain  // 不可篡改审计链
	authManager     *AuthManager // JWT 认证管理器
	profileEngine   *profile.Engine
	clusterMgr      *cluster.Manager     // 集群管理端 (可选)
	clusterGen      *cluster.Generator   // Agent 生成引擎 (可选)
	trapConfigData  []byte               // 陷阱配置 JSON 缓存（启动时写入，只读）
	traceEngine     *traceability.Engine // 溯源反制引擎（深度反制API）
	hpEngine        *honeypot.Engine     // 蜜罐引擎（服务状态查询）
	mux             *http.ServeMux
	frontendHandler http.Handler // 可选：嵌入式前端 SPA handler
	startTime       time.Time
	clusterEvents   []cluster.ClusterEvent // 集群事件缓冲区（最近 N 条）
	eventsMu        sync.RWMutex
}

// NewServer 创建 API 服务器
func NewServer(logger *log.Logger, st *store.Store, vdb *vulndb.DB, hub *WSHub, authMgr *AuthManager) *Server {
	s := &Server{
		logger:        logger,
		store:         st,
		vulnDB:        vdb,
		wsHub:         hub,
		shellHub:      NewShellHub(logger),
		transferHub:   NewTransferHub(""),
		processHub:    NewProcessHub(),
		desktopHub:    NewDesktopHub(logger),
		mfaProvider:   NewMFAProvider(),
		auditChain:    NewAuditChain(),
		authManager:   authMgr,
		profileEngine: profile.NewEngine(),
		mux:           http.NewServeMux(),
		startTime:     time.Now(),
	}
	s.registerRoutes()
	return s
}

// SetFrontendHandler 设置前端静态文件 handler（由 go:embed 提供）
func (s *Server) SetFrontendHandler(h http.Handler) {
	s.frontendHandler = h
}

// SetClusterManager 设置集群管理端（由 main 注入）
func (s *Server) SetClusterManager(mgr *cluster.Manager) {
	s.clusterMgr = mgr
	// 启动集群事件消费协程——将 EventCh 中的事件缓冲到内存供 API 查询
	go s.consumeClusterEvents()
}

// SetClusterGenerator 设置 Agent 生成引擎（由 main 注入）
func (s *Server) SetClusterGenerator(gen *cluster.Generator) {
	s.clusterGen = gen
}

// consumeClusterEvents 消费集群 EventCh 中的事件并缓冲到内存（最多保留 500 条）
func (s *Server) consumeClusterEvents() {
	const maxEvents = 500
	for evt := range s.clusterMgr.EventCh {
		s.eventsMu.Lock()
		s.clusterEvents = append(s.clusterEvents, evt)
		if len(s.clusterEvents) > maxEvents {
			// 环形丢弃旧事件
			s.clusterEvents = s.clusterEvents[len(s.clusterEvents)-maxEvents:]
		}
		s.eventsMu.Unlock()
	}
}

// SetTrapConfig 设置陷阱配置数据（由 main 在启动时注入，用于 /api/traps/config 接口）
func (s *Server) SetTrapConfig(data []byte) {
	s.trapConfigData = data
}

// SetTraceEngine 设置溯源反制引擎（由 main 注入，用于深度反制 API）
func (s *Server) SetTraceEngine(engine *traceability.Engine) {
	s.traceEngine = engine
	if engine != nil {
		auditFn := func(opType countermeasure.OpType, targetIP, actor, action, result string) {
			engine.GetAuditTrail().RecordComplete(opType, targetIP, actor, action, result)
			// 同步追加到不可篡改审计链
			s.auditChain.Append(string(opType), targetIP, actor, action, result)
		}
		s.shellHub.SetAuditRecorder(auditFn)
		s.transferHub.SetAuditRecorder(auditFn)
		s.processHub.SetAuditRecorder(auditFn)
		s.desktopHub.SetAuditRecorder(auditFn)
	}
}

// SetHoneypotEngine 设置蜜罐引擎（由 main 注入，用于服务状态 API）
func (s *Server) SetHoneypotEngine(engine *honeypot.Engine) {
	s.hpEngine = engine
}

func (s *Server) registerRoutes() {
	// 仪表盘
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/stats/detailed", s.handleDetailedStats)
	s.mux.HandleFunc("/api/stats/dashboard", s.handleDetailedStats) // 别名,前端仪表盘用
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
	// 蜜罐服务运行状态
	s.mux.HandleFunc("/api/services/status", s.handleServiceStatus)
	// 健康检查
	s.mux.HandleFunc("/healthz", s.handleHealth)

	// 认证 — JWT 登录/刷新/登出
	s.mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		s.authManager.HandleLogin(s.logger, w, r)
	})
	s.mux.HandleFunc("/api/auth/refresh", s.authManager.HandleRefresh)
	s.mux.HandleFunc("/api/auth/logout", s.authManager.HandleLogout)
	s.mux.HandleFunc("/api/auth/changepassword", s.authManager.HandleChangepassword)
	// 实时推送(SSE)
	s.mux.HandleFunc("/api/events", s.wsHub.ServeWS)
	// 浏览器指纹采集
	s.mux.HandleFunc("/api/collect", s.handleCollect)
	// 攻击者画像
	s.mux.HandleFunc("/api/profiles", s.handleProfiles)
	s.mux.HandleFunc("/api/profiles/stats", s.handleProfileStats)
	s.mux.HandleFunc("/api/profiles/tags", s.handleProfileTags)
	// 资产探测
	s.mux.HandleFunc("/api/assets/scan", s.handleAssetScan)
	// 集群节点
	s.mux.HandleFunc("/api/cluster/nodes", s.handleClusterNodes)
	// Agent 生成引擎
	s.mux.HandleFunc("/api/cluster/agent/generate", s.handleAgentGenerate)
	// 集群事件聚合
	s.mux.HandleFunc("/api/cluster/events", s.handleClusterEvents)
	// 陷阱配置
	s.mux.HandleFunc("/api/traps/config", s.handleTrapConfig)
	// 深度反制 — 植入体数据回传
	s.mux.HandleFunc("/api/countermeasure/exfil", s.handleCountermeasureExfil)
	// 深度反制 — 防守方得分总表
	s.mux.HandleFunc("/api/countermeasure/scoreboard", s.handleCountermeasureScoreboard)
	// 深度反制 — 得分事件注册
	s.mux.HandleFunc("/api/countermeasure/score", s.handleCountermeasureScore)
	// 深度反制 — 合规审计记录
	s.mux.HandleFunc("/api/countermeasure/audit", s.handleCountermeasureAudit)
	// 深度反制 — 攻击者团队拓扑
	s.mux.HandleFunc("/api/countermeasure/topology", s.handleCountermeasureTopology)
	// 深度反制 — 截屏记录列表/查询/下载
	s.mux.HandleFunc("/api/countermeasure/screencaps", s.handleScreenCapsList)
	s.mux.HandleFunc("/api/countermeasure/screencaps/", s.handleScreenCapDetail)
	// 深度反制 — 文件扫描记录
	s.mux.HandleFunc("/api/countermeasure/filescans", s.handleFileScansList)
	// 深度反制 — 远程 Shell WebSocket
	s.mux.HandleFunc("/api/countermeasure/shell", s.shellHub.HandleShell)
	// 深度反制 — 文件传输
	s.mux.HandleFunc("/api/countermeasure/transfer/upload", s.transferHub.HandleTransferUpload)
	s.mux.HandleFunc("/api/countermeasure/transfer/download", s.transferHub.HandleTransferDownload)
	s.mux.HandleFunc("/api/countermeasure/transfer/status", s.transferHub.HandleTransferStatus)
	s.mux.HandleFunc("/api/countermeasure/transfer/pause", s.transferHub.HandleTransferPause)
	s.mux.HandleFunc("/api/countermeasure/transfer/list", s.transferHub.HandleTransferList)
	// 深度反制 — 进程管理
	s.mux.HandleFunc("/api/countermeasure/processes", s.processHub.HandleProcessList)
	s.mux.HandleFunc("/api/countermeasure/processes/start", s.processHub.HandleProcessStart)
	s.mux.HandleFunc("/api/countermeasure/processes/stop", s.processHub.HandleProcessStop)
	s.mux.HandleFunc("/api/countermeasure/processes/delete", s.processHub.HandleProcessDelete)
	// 深度反制 — 桌面远控（WebSocket 帧流）
	s.mux.HandleFunc("/api/countermeasure/desktop", s.desktopHub.HandleDesktopViewer)
	s.mux.HandleFunc("/api/countermeasure/desktop/agent", s.desktopHub.HandleDesktopAgent)
	// 安全合规 — MFA 二次认证
	s.mux.HandleFunc("/api/mfa/challenge", s.handleMFAChallenge)
	s.mux.HandleFunc("/api/mfa/verify", s.handleMFAVerify)
	// 安全合规 — 不可篡改审计链
	s.mux.HandleFunc("/api/audit/chain", s.handleAuditChain)
	s.mux.HandleFunc("/api/audit/chain/verify", s.handleAuditChainVerify)

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
// 链式顺序: 请求日志 → CORS白名单 → JWT认证 → 速率限制
func (s *Server) Handler() http.Handler {
	var authMW func(http.Handler) http.Handler
	if s.authManager != nil {
		authMW = s.authManager.JWTAuthMiddleware
	} else {
		authMW = func(next http.Handler) http.Handler { return next }
	}
	return requestLogMiddleware(s.logger, corsMiddleware(authMW(rateLimitMiddleware(s.mux))))
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-MFA-Token, X-MFA-Code")
		w.Header().Set("Access-Control-Expose-Headers", "Authorization, X-MFA-Token")

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
	q := r.URL.Query()
	tool := q.Get("tool")
	exploitType := q.Get("exploit_type")
	cve := q.Get("cve")
	active := q.Get("active")

	var vulns []*vulndb.VulnEntry

	switch {
	case cve != "":
		if entry, ok := s.vulnDB.Get(cve); ok {
			vulns = []*vulndb.VulnEntry{entry}
		}
	case tool != "" && exploitType != "":
		vulns = s.vulnDB.FindByToolAndExploitType(tool, vulndb.ExploitType(exploitType))
	case tool != "":
		vulns = s.vulnDB.FindByTool(tool)
	case exploitType != "" && active == "true":
		all := s.vulnDB.FindByExploitType(vulndb.ExploitType(exploitType))
		for _, e := range all {
			if e.IsActive {
				vulns = append(vulns, e)
			}
		}
	case exploitType != "":
		vulns = s.vulnDB.FindByExploitType(vulndb.ExploitType(exploitType))
	case active == "true":
		vulns = s.vulnDB.FindActive()
	default:
		vulns = s.vulnDB.All()
	}

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

	// 合并集群 Agent 节点到拓扑
	if s.clusterMgr != nil {
		nodes := s.clusterMgr.GetNodes()
		for _, n := range nodes {
			if !n.Online {
				continue
			}
			info := s.clusterMgr.GetNodeInfo(n.NodeID)
			if info == nil {
				continue
			}
			// 添加 Agent 节点
			agentNodeID := "agent_" + n.NodeID
			agentLabel := info.Hostname
			if agentLabel == "" {
				agentLabel = info.IP
			}
			td.Nodes = append(td.Nodes, store.TopoNode{
				ID:     agentNodeID,
				Label:  agentLabel,
				Type:   "agent",
				IP:     info.IP,
				Status: "online",
				Data: map[string]interface{}{
					"node_id":  info.NodeID,
					"services": info.Services,
					"os":       info.OS,
					"version":  info.Version,
				},
			})
			// 为 Agent 的每个蜜罐服务创建与蜜罐节点的边
			for _, svc := range info.Services {
				td.Edges = append(td.Edges, store.TopoEdge{
					Source:   agentNodeID,
					Target:   "hp_" + strings.ToLower(svc),
					Label:    "exposes " + svc,
					EdgeType: "agent_service",
				})
			}
		}
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
		"version":    core.Version,
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

func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	if s.hpEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "honeypot engine not available"})
		return
	}
	status := s.hpEngine.ServiceStatus()
	writeJSON(w, http.StatusOK, status)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": core.Version})
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

	// 解析指纹 JSON，如果数据稀疏则从 HTTP 头提取回退数据（针对非浏览器工具）
	var fpData map[string]interface{}
	if err := json.Unmarshal([]byte(rawData), &fpData); err != nil {
		fpData = make(map[string]interface{})
	}
	if len(fpData) <= 2 {
		headerFP := extractHeaderFingerprint(r)
		for k, v := range headerFP {
			fpData[k] = v
		}
		if enhanced, err := json.Marshal(fpData); err == nil {
			rawData = string(enhanced)
		}
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

// extractHeaderFingerprint 从 HTTP 请求头提取回退指纹数据
// 用于非浏览器工具（curl、sqlmap、nmap 等）访问时，JS 未执行的情况
func extractHeaderFingerprint(r *http.Request) map[string]interface{} {
	result := make(map[string]interface{})

	ua := r.Header.Get("User-Agent")
	if ua != "" {
		result["tool_name"] = detectToolFromUA(ua)
	}

	if al := r.Header.Get("Accept-Language"); al != "" {
		parts := strings.Split(al, ",")
		langs := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if idx := strings.Index(p, ";"); idx > 0 {
				p = p[:idx]
			}
			if p != "" {
				langs = append(langs, p)
			}
		}
		result["languages"] = langs
	}

	if ref := r.Header.Get("Referer"); ref != "" {
		result["referrer"] = ref
	}

	return result
}

// detectToolFromUA 根据 User-Agent 识别攻击工具
// 逻辑与 fingerprint/collector.go 的 DetectTool 保持一致
func detectToolFromUA(ua string) string {
	if ua == "" {
		return "unknown"
	}
	// Burp Suite
	if strings.Contains(ua, "Burp Suite") || strings.Contains(ua, "Java/1.") {
		return "burpsuite"
	}
	// Cobalt Strike Beacon
	if strings.Contains(ua, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)") {
		return "cobaltstrike"
	}
	// SQLMap
	if strings.Contains(ua, "sqlmap") {
		return "sqlmap"
	}
	// 冰蝎
	if strings.Contains(ua, "Apache-HttpClient") || strings.Contains(ua, "okhttp") || strings.Contains(ua, "Java") {
		return "behinder"
	}
	// Nuclei
	if strings.Contains(ua, "Nuclei") || strings.Contains(ua, "nuclei") {
		return "nuclei"
	}
	// curl
	if strings.Contains(ua, "curl") {
		return "curl"
	}
	// Go HTTP client
	if strings.Contains(ua, "Go-http-client") {
		return "go-http"
	}
	// 浏览器类
	if strings.Contains(ua, "Chrome") {
		return "chrome"
	}
	if strings.Contains(ua, "Firefox") {
		return "firefox"
	}
	if strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome") {
		return "safari"
	}
	if strings.Contains(ua, "Edge") {
		return "edge"
	}
	return "unknown"
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
		// /api/countermeasure/exfil 端点豁免速率限制 — 植入体加密数据回传不可丢失
		if strings.HasPrefix(r.URL.Path, "/api/countermeasure/exfil") {
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

// ---------- 资产探测 API ----------

func (s *Server) handleAssetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// 解析可选的目标主机
	hosts := []string{"127.0.0.1"}
	if h := r.URL.Query().Get("host"); h != "" {
		hosts = strings.Split(h, ",")
	}

	scanner := asset.NewScanner(hosts)
	result := scanner.Scan(nil) // 扫描所有已知端口

	writeJSON(w, http.StatusOK, result)
}

// handleClusterNodes 返回集群节点列表
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if s.clusterMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"nodes":           []interface{}{},
			"total":           0,
			"cluster_enabled": false,
		})
		return
	}
	nodes := s.clusterMgr.GetNodes()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes":           nodes,
		"total":           len(nodes),
		"cluster_enabled": true,
	})
}

// handleClusterEvents 返回集群事件聚合列表
// GET /api/cluster/events?limit=50&topic=connection
func (s *Server) handleClusterEvents(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	topic := r.URL.Query().Get("topic")

	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	// 按 topic 过滤（可选）
	var filtered []cluster.ClusterEvent
	for _, evt := range s.clusterEvents {
		if topic != "" && evt.Topic != topic {
			continue
		}
		filtered = append(filtered, evt)
	}

	// 取最近 N 条
	start := len(filtered) - limit
	if start < 0 {
		start = 0
	}
	result := filtered[start:]

	if result == nil {
		result = []cluster.ClusterEvent{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":           len(filtered),
		"returned":        len(result),
		"limit":           limit,
		"cluster_enabled": s.clusterMgr != nil,
		"events":          result,
	})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/profiles")
	ip := r.URL.Query().Get("ip")

	// /api/profiles?ip=1.2.3.4 — 单个画像详情
	if ip != "" {
		p, err := s.store.AggregateProfileByIP(s.profileEngine, ip)
		if err != nil {
			s.logger.Errorw("profile query failed", "ip", ip, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		writeJSON(w, http.StatusOK, p)
		return
	}

	// /api/profiles — 列表（支持标签筛选 ?tag=skill）
	tagFilter := r.URL.Query().Get("tag")
	profiles, err := s.store.AggregateAllProfiles(s.profileEngine, tagFilter)
	if err != nil {
		s.logger.Errorw("profiles query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":    len(profiles),
		"profiles": profiles,
	})
	_ = path
}

func (s *Server) handleProfileStats(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.AggregateAllProfiles(s.profileEngine, "")
	if err != nil {
		s.logger.Errorw("profile stats failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	skillDist := map[string]int{"novice": 0, "script_kiddie": 0, "intermediate": 0, "advanced_actor": 0}
	behaviorDist := map[string]int{}
	motiveDist := map[string]int{}
	toolDist := map[string]int{}
	threatDist := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}

	for _, p := range profiles {
		threatDist[p.ThreatLevel]++
		for _, t := range p.Tags {
			switch t.Category {
			case "skill":
				skillDist[t.Name]++
			case "behavior":
				behaviorDist[t.Name]++
			case "motive":
				motiveDist[t.Name]++
			case "tool":
				toolDist[t.Name]++
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_profiles": len(profiles),
		"skill_dist":     skillDist,
		"behavior_dist":  behaviorDist,
		"motive_dist":    motiveDist,
		"tool_dist":      toolDist,
		"threat_dist":    threatDist,
	})
}

func (s *Server) handleProfileTags(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": profile.TagCategories,
	})
}

// handleTrapConfig 返回当前陷阱场景配置（GET /api/traps/config）
func (s *Server) handleTrapConfig(w http.ResponseWriter, r *http.Request) {
	if s.trapConfigData == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"error": "trap config not available",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.trapConfigData)
}

// handleAgentGenerate 生成 Agent 部署配置与命令（POST /api/cluster/agent/generate）
// 接收前端提交的场景选配，返回 config.yaml、CLI命令、部署脚本
func (s *Server) handleAgentGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "method not allowed, use POST",
		})
		return
	}

	if s.clusterGen == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "agent generator not available",
			"hint":  "management node must be running in manager role",
		})
		return
	}

	var req cluster.AgentDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	// 如果未提供 manager_addr，自动填写当前 Management Node 地址
	if req.ManagerAddr == "" && s.clusterMgr != nil {
		// 从集群配置推断管理端地址（由前端传入或使用默认值）
		// 此时由前端负责检测管理端地址，后端仅做兜底
	}

	artifact, err := s.clusterGen.Generate(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, artifact)
}

// ============================================================
// 安全合规 — MFA 二次认证 & 不可篡改审计链
// ============================================================

// handleMFAChallenge 请求 MFA 二次验证码
// POST /api/mfa/challenge
func (s *Server) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.User == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user required"})
		return
	}

	// 如果用户还没有 TOTP secret，先生成一个
	secret := s.mfaProvider.GetSecret(req.User)
	if secret == "" {
		secret = s.mfaProvider.GenerateSecret(req.User)
		s.logger.Infow("mfa secret generated", "user", req.User)
	}

	// 生成一次性挑战码
	challenge := s.mfaProvider.GenerateChallenge(req.User)
	// 同时计算当前 TOTP
	totp := generateTOTP(secret, time.Now().Unix())

	s.logger.Infow("mfa challenge issued", "user", req.User)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge":  challenge,
		"totp":       totp,   // 仅在开发/测试环境返回
		"secret":     secret, // 仅在开发/测试环境返回
		"expires_in": 120,
	})
}

// handleMFAVerify 验证 MFA 码并签发操作令牌
// POST /api/mfa/verify
func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		User string   `json:"user"`
		Code string   `json:"code"`
		Ops  []string `json:"ops"` // 请求的操作列表
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.User == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user and code required"})
		return
	}

	// 验证挑战码或 TOTP
	valid := s.mfaProvider.VerifyChallenge(req.User, req.Code) ||
		s.mfaProvider.ValidateCode(req.User, req.Code)

	if !valid {
		s.logger.Warnw("mfa verify failed", "user", req.User)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA code"})
		return
	}

	// 签发临时操作令牌
	if len(req.Ops) == 0 {
		req.Ops = []string{"shell", "transfer", "process", "desktop"}
	}
	token := s.mfaProvider.IssueToken(req.User, req.Ops)

	s.logger.Infow("mfa token issued", "user", req.User, "ops", req.Ops)

	// 记录到审计链
	s.auditChain.Append("mfa", req.User, "mfa", "token_issued", fmt.Sprintf("ops=%v", req.Ops))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"expires_in": 300,
		"ops":        req.Ops,
	})
}

// handleAuditChain 获取不可篡改审计链
// GET /api/audit/chain?limit={n}
func (s *Server) handleAuditChain(w http.ResponseWriter, r *http.Request) {
	entries := s.auditChain.Entries()
	limit := queryInt(r, "limit", 100)

	if limit > 0 && limit < len(entries) {
		entries = entries[len(entries)-limit:]
	}

	// 验证链完整性
	valid, tamperedIdx := s.auditChain.Verify()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":          len(entries),
		"head":           s.auditChain.Head(),
		"chain_valid":    valid,
		"tampered_index": tamperedIdx,
		"entries":        entries,
	})
}

// handleAuditChainVerify 验证审计链完整性
// GET /api/audit/chain/verify
func (s *Server) handleAuditChainVerify(w http.ResponseWriter, r *http.Request) {
	valid, tamperedIdx := s.auditChain.Verify()

	status := "intact"
	if !valid {
		status = fmt.Sprintf("tampered at index %d", tamperedIdx)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":          valid,
		"tampered_index": tamperedIdx,
		"status":         status,
		"head":           s.auditChain.Head(),
		"total_entries":  len(s.auditChain.Entries()),
	})
}

// ============================================================
// 深度反制 C2 API — 植入体数据回传、得分、审计、拓扑
// ============================================================

// handleCountermeasureExfil 接收植入体加密回传数据
// 支持两种模式：
//   - GET + Query Params: Image Beacon 分片回传（植入体JS使用）
//   - POST + JSON Body: 结构化数据回传（测试/管理API使用）
func (s *Server) handleCountermeasureExfil(w http.ResponseWriter, r *http.Request) {
	if s.traceEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trace engine not available"})
		return
	}

	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = fwd
	}

	var (
		data     string
		dataType string
	)

	// POST JSON 模式：从请求体解析结构化数据
	if r.Method == http.MethodPost {
		var body struct {
			Type     string      `json:"type"`
			TargetIP string      `json:"target_ip"`
			Data     interface{} `json:"data"`
			DataType string      `json:"data_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if body.TargetIP != "" {
			remoteIP = body.TargetIP
		}
		dataType = body.DataType
		if dataType == "" {
			dataType = body.Type
		}
		// 将 JSON body 序列化为 data 字符串用于日志/审计
		if jsonBytes, err := json.Marshal(body.Data); err == nil {
			data = string(jsonBytes)
		}
	} else {
		// GET Image Beacon 模式：从查询参数解析
		data = r.URL.Query().Get("d")
		offset := r.URL.Query().Get("s")
		total := r.URL.Query().Get("t")
		dataType = r.URL.Query().Get("tt")

		if data == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing data"})
			return
		}

		// 分片重组逻辑
		if offset != "" && total != "" {
			s.logger.Debugw("exfil chunk received", "ip", remoteIP, "offset", offset, "total", total, "type", dataType)
			writeJSON(w, http.StatusOK, map[string]string{"status": "chunk_received"})
			return
		}
	}

	s.logger.Infow("countermeasure exfil received",
		"ip", remoteIP, "type", dataType, "dataLen", len(data))

	// 根据数据类型注册得分
	scoreEngine := s.traceEngine.GetScoringEngine()
	audit := s.traceEngine.GetAuditTrail()

	var opType countermeasure.OpType
	switch dataType {
	case "screen_capture", "screen_cap":
		opType = countermeasure.OpScreenCapture
	case "file_scan":
		opType = countermeasure.OpFileScan
	case "net_probe":
		opType = countermeasure.OpNetProbe
	default:
		opType = countermeasure.OpFingerprint
	}

	score := scoreEngine.RegisterScore(remoteIP, opType, "exfil_"+dataType)
	audit.RecordComplete(opType, remoteIP, "implant", "exfil_endpoint",
		fmt.Sprintf("data_received: %d bytes, score: %d", len(data), score))

	// 持久化存储截屏和文件扫描数据
	s.persistExfilData(remoteIP, dataType, data, len(data))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "received",
		"score":  score,
	})
}

// persistExfilData 根据数据类型将回传数据持久化到 DB
func (s *Server) persistExfilData(remoteIP, dataType, data string, dataLen int) {
	switch dataType {
	case "screen_capture", "screen_cap":
		s.persistScreenCapture(remoteIP, data)
	case "file_scan":
		s.persistFileScan(remoteIP, data)
	default:
		s.logger.Debugw("exfil persist skipped (unsupported type)", "type", dataType)
	}
}

// persistScreenCapture 解析并存储截屏数据
func (s *Server) persistScreenCapture(remoteIP, data string) {
	// 截屏数据格式: base64 JPEG (data:image/jpeg;base64,xxx 或纯 base64)
	var (
		resolution = "unknown"
		imageData  string
		thumbnail  string
		format     = "jpeg"
	)

	// 解析 JSON 格式的截屏元数据 (来自 JS 植入体)
	type screencapMeta struct {
		Width  int    `json:"width"`
		Height int    `json:"height"`
		Image  string `json:"image"`
		Format string `json:"format"`
	}
	var meta screencapMeta
	if err := json.Unmarshal([]byte(data), &meta); err == nil && meta.Image != "" {
		if meta.Width > 0 && meta.Height > 0 {
			resolution = fmt.Sprintf("%dx%d", meta.Width, meta.Height)
		}
		imageData = meta.Image
		if meta.Format != "" {
			format = meta.Format
		}
	} else {
		// 纯 base64 字符串或 data: URI
		imageData = data
	}

	// 去掉 data: URI 前缀
	if idx := strings.Index(imageData, "base64,"); idx != -1 {
		imageData = imageData[idx+7:]
	}

	// 计算数据哈希
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(imageData)))
	sizeBytes := int64(len(imageData))

	// 生成缩略图 (取前 256 字符作为预览标识，实际缩略图由前端渲染)
	thumbLen := 256
	if len(imageData) < thumbLen {
		thumbLen = len(imageData)
	}
	thumbnail = imageData[:thumbLen]

	// 验证 base64 有效性
	if _, err := base64.StdEncoding.DecodeString(imageData); err != nil {
		s.logger.Warnw("invalid screencap base64", "ip", remoteIP, "error", err)
		return
	}

	// 生成会话 ID
	sessionID := fmt.Sprintf("sc_%s_%d", strings.ReplaceAll(remoteIP, ".", "_"), time.Now().Unix())

	id, err := s.store.SaveScreenCapture(remoteIP, resolution, format, dataHash, sessionID, thumbnail, sizeBytes, true)
	if err != nil {
		s.logger.Errorw("persist screencap failed", "ip", remoteIP, "error", err)
		return
	}
	s.logger.Infow("screencap persisted", "id", id, "ip", remoteIP, "resolution", resolution, "size", sizeBytes)

	// 记录审计
	if s.traceEngine != nil {
		s.traceEngine.GetAuditTrail().RecordComplete(
			countermeasure.OpScreenCapture, remoteIP, "persist", "db_store",
			fmt.Sprintf("screencap_id=%d resolution=%s size=%d", id, resolution, sizeBytes),
		)
	}
}

// persistFileScan 解析并存储文件扫描数据
func (s *Server) persistFileScan(remoteIP, data string) {
	var files []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &files); err != nil {
		// 可能不是数组，尝试单个文件
		var single map[string]interface{}
		if err2 := json.Unmarshal([]byte(data), &single); err2 != nil {
			s.logger.Warnw("invalid filescan data", "ip", remoteIP, "error", err)
			return
		}
		files = []map[string]interface{}{single}
	}

	for _, f := range files {
		filePath, _ := f["path"].(string)
		fileName, _ := f["name"].(string)
		if fileName == "" {
			fileName = filePath
		}
		fileSize := int64(0)
		if sz, ok := f["size"].(float64); ok {
			fileSize = int64(sz)
		}
		category, _ := f["category"].(string)
		sensitive := false
		if sens, ok := f["sensitive"].(bool); ok {
			sensitive = sens
		}
		contentPreview, _ := f["preview"].(string)
		if len(contentPreview) > 1024 {
			contentPreview = contentPreview[:1024]
		}

		id, err := s.store.SaveFileScan(remoteIP, filePath, fileName, category, contentPreview, fileSize, sensitive)
		if err != nil {
			s.logger.Errorw("persist filescan failed", "ip", remoteIP, "file", filePath, "error", err)
			continue
		}
		s.logger.Infow("filescan persisted", "id", id, "ip", remoteIP, "file", filePath, "sensitive", sensitive)
	}
}

// handleCountermeasureScoreboard 获取防守方得分总表
func (s *Server) handleCountermeasureScoreboard(w http.ResponseWriter, r *http.Request) {
	if s.traceEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trace engine not available"})
		return
	}
	sb := s.traceEngine.GetScoringEngine().GetScoreboard()
	writeJSON(w, http.StatusOK, sb)
}

// handleCountermeasureScore 手动注册得分事件
func (s *Server) handleCountermeasureScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.traceEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trace engine not available"})
		return
	}

	var req struct {
		TargetIP string                `json:"target_ip"`
		OpType   countermeasure.OpType `json:"op_type"`
		Evidence string                `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	score := s.traceEngine.GetScoringEngine().RegisterScore(req.TargetIP, req.OpType, req.Evidence)
	writeJSON(w, http.StatusOK, map[string]interface{}{"score": score})
}

// handleCountermeasureAudit 获取合规审计记录
func (s *Server) handleCountermeasureAudit(w http.ResponseWriter, r *http.Request) {
	if s.traceEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trace engine not available"})
		return
	}

	audit := s.traceEngine.GetAuditTrail()
	targetIP := r.URL.Query().Get("target")

	var entries []countermeasure.AuditEntry
	if targetIP != "" {
		entries = audit.GetEntriesByTarget(targetIP)
	} else {
		entries = audit.GetEntries()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":   len(entries),
		"entries": entries,
	})
}

// handleCountermeasureTopology 获取攻击者团队拓扑
func (s *Server) handleCountermeasureTopology(w http.ResponseWriter, r *http.Request) {
	if s.traceEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trace engine not available"})
		return
	}

	// 从连接记录中推断拓扑
	connections, _ := s.store.GetConnections(200)

	// 构建简单拓扑
	nodes := make([]countermeasure.HostAsset, 0)
	seenIPs := make(map[string]bool)
	for _, conn := range connections {
		if !seenIPs[conn.RemoteIP] {
			seenIPs[conn.RemoteIP] = true
			nodes = append(nodes, countermeasure.HostAsset{
				IP:     conn.RemoteIP,
				Status: "up",
				Role:   "unknown",
			})
		}
	}

	topo := countermeasure.GenerateNetProbeReport("honeypot", nodes)
	writeJSON(w, http.StatusOK, topo)
}

// handleScreenCapsList 截屏记录分页列表
// GET /api/countermeasure/screencaps?ip=&limit=&offset=
func (s *Server) handleScreenCapsList(w http.ResponseWriter, r *http.Request) {
	remoteIP := r.URL.Query().Get("ip")
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	records, total, err := s.store.ListScreenCaptures(remoteIP, limit, offset)
	if err != nil {
		s.logger.Errorw("screencaps list failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	if records == nil {
		records = []store.ScreenCaptureRecord{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"records": records,
	})
}

// handleScreenCapDetail 截屏详情/下载
// GET /api/countermeasure/screencaps/{id}  - 获取单条记录完整数据(含缩略图)
// GET /api/countermeasure/screencaps/{id}/download - 下载完整截屏 thumbnail
func (s *Server) handleScreenCapDetail(w http.ResponseWriter, r *http.Request) {
	// 解析路径: /api/countermeasure/screencaps/{id}[/download]
	path := strings.TrimPrefix(r.URL.Path, "/api/countermeasure/screencaps/")
	parts := strings.SplitN(path, "/", 2)

	idStr := parts[0]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	record, err := s.store.GetScreenCapture(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "screencap not found"})
		return
	}

	// 如果路径包含 /download，返回 base64 图片数据
	if len(parts) > 1 && parts[1] == "download" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(record.Thumbnail))
		return
	}

	writeJSON(w, http.StatusOK, record)
}

// handleFileScansList 文件扫描分页列表
// GET /api/countermeasure/filescans?ip=&category=&limit=&offset=
func (s *Server) handleFileScansList(w http.ResponseWriter, r *http.Request) {
	remoteIP := r.URL.Query().Get("ip")
	category := r.URL.Query().Get("category")
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	records, total, err := s.store.ListFileScans(remoteIP, category, limit, offset)
	if err != nil {
		s.logger.Errorw("filescans list failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	if records == nil {
		records = []store.FileScanRecord{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"records": records,
	})
}

// requestLogMiddleware 记录每个 HTTP 请求的方法、路径、状态码和耗时
