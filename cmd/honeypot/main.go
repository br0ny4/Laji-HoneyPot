package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Laji-HoneyPot/honeypot/internal/alerter"
	"github.com/Laji-HoneyPot/honeypot/internal/bait"
	"github.com/Laji-HoneyPot/honeypot/internal/cluster"
	"github.com/Laji-HoneyPot/honeypot/internal/core"
	"github.com/Laji-HoneyPot/honeypot/internal/core/api"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/profile"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	honeypotEngine "github.com/Laji-HoneyPot/honeypot/internal/honeypot"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
	opsEngine "github.com/Laji-HoneyPot/honeypot/internal/ops"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/daemon"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/upgrade"
	traceEngine "github.com/Laji-HoneyPot/honeypot/internal/traceability"
)

func main() {
	// Handle subcommands: honeypot agent daemon <install|uninstall|start|stop|restart|status>
	if len(os.Args) >= 3 && os.Args[1] == "agent" && os.Args[2] == "daemon" {
		handleAgentDaemon()
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.LogLevel)
	eventBus := bus.New()

	const version = core.Version
	logger.Info("Laji-HoneyPot starting", "version", version)

	st, err := store.New(cfg.DataDir)
	if err != nil {
		logger.Errorw("failed to init store", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("SQLite store initialized")

	reg := registry.New(logger, cfg)

	hpEngine := honeypotEngine.NewEngine(logger, eventBus, st)
	trEngine := traceEngine.NewEngine(logger, eventBus)
	opEngine := opsEngine.NewEngine(logger, eventBus)

	reg.Register(hpEngine)
	reg.Register(trEngine)
	reg.Register(opEngine)

	if err := reg.InitAll(); err != nil {
		logger.Errorw("failed to init plugins", "error", err)
		os.Exit(1)
	}

	if err := reg.StartAll(); err != nil {
		logger.Errorw("failed to start plugins", "error", err)
		os.Exit(1)
	}
	logger.Infow("plugins started", "count", len(reg.List()), "plugins", reg.List())

	// 蜜标/HoneyToken 诱饵系统：生成虚假凭证文件，注入到 HTTP 蜜罐响应中
	// 攻击者下载蜜标文件时，自动追踪记录访问事件
	baitGen := bait.NewGenerator()
	baitTokens := baitGen.GenerateAll()
	logger.Infow("bait tokens generated", "count", len(baitTokens))

	baitTracker := bait.NewTracker(10000)
	logger.Info("bait tracker initialized")

	// 蜜饵联动引擎：将蜜饵凭据与蜜罐服务建立关联，实现攻击链追溯
	baitLinkage := bait.NewLinkageEngine()
	svcHosts := hpEngine.GetServiceHosts()
	for _, t := range baitTokens {
		baitLinkage.RegisterFromToken(&t, svcHosts)
	}
	logger.Infow("bait linkages registered", "total", baitLinkage.Stats()["total"])

	// 注入蜜标系统到 HTTP 蜜罐（所有 HTTP 响应自动包含蜜标链接）
	hpEngine.SetBaitSystem(baitGen, baitTracker)

	// 面包屑触发 → 反制 Payload 注入链路：溯源引擎根据攻击上下文智能选择最优载荷
	hpEngine.SetCountermeasureProvider(func(path, userAgent, remoteIP string) string {
		return trEngine.SelectPayload(path, userAgent, remoteIP)
	})

	// 注入陷阱注册中心到溯源引擎：场景化过滤反制载荷（非 HTTP 场景不生成浏览器 payload）
	trEngine.SetTrapRegistry(hpEngine.GetTrapRegistry())

	// 诱饵页面回调：JSP/Java 端点返回冰蝎反制诱饵
	hpEngine.SetDecoyPageProvider(func(decoyType, path string) string {
		if decoyType == "behinder" {
			return trEngine.BehinderDecoyPage()
		}
		return ""
	})

	// API 服务器（含 SSE），支持优雅关闭
	wsHub := api.NewWSHub(logger, st)

	// 实时推送：连接/攻击/面包屑事件触发 SSE 广播
	eventBus.Subscribe("honeypot.connection", func(evt bus.Event) { wsHub.BroadcastStats() })
	eventBus.Subscribe("honeypot.attack", func(evt bus.Event) { wsHub.BroadcastStats() })
	eventBus.Subscribe("honeypot.breadcrumb", func(evt bus.Event) { wsHub.BroadcastStats() })
	eventBus.Subscribe("honeypot.portscan", func(evt bus.Event) { wsHub.BroadcastStats() })

	// 告警通道：面包屑/攻击事件 → 多通道推送
	if len(cfg.AlertChannels) > 0 {
		alertChannels := make([]alerter.ChannelConfig, 0, len(cfg.AlertChannels))
		for _, ac := range cfg.AlertChannels {
			alertChannels = append(alertChannels, alerter.ChannelConfig{
				Type:        alerter.ChannelType(ac.Type),
				URL:         ac.URL,
				Enabled:     ac.Enabled,
				EventFilter: ac.EventFilter,
			})
		}
		alertSvc := alerter.New(logger.SugaredLogger, alertChannels)
		eventBus.Subscribe("honeypot.breadcrumb", func(evt bus.Event) {
			if event := alerter.BuildAlertEvent(evt.Topic, evt.Payload); event != nil {
				alertSvc.Send(*event)
			}
		})
		eventBus.Subscribe("honeypot.attack", func(evt bus.Event) {
			if event := alerter.BuildAlertEvent(evt.Topic, evt.Payload); event != nil {
				alertSvc.Send(*event)
			}
		})
		eventBus.Subscribe("honeypot.portscan", func(evt bus.Event) {
			if event := alerter.BuildAlertEvent(evt.Topic, evt.Payload); event != nil {
				alertSvc.Send(*event)
			}
		})
		logger.Infow("alerter initialized", "channels", len(alertChannels))
	}

	// JWT 认证管理器
	authCfg := api.DefaultJWTConfig()
	var authMgr *api.AuthManager
	if cfg.JWTSecret != "" {
		authMgr = api.NewAuthManagerWithSecret(authCfg, cfg.JWTSecret, st)
		logger.Info("JWT signing key loaded from config")
	} else {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			logger.Fatalw("failed to generate JWT secret", "error", err)
		}
		hexSecret := hex.EncodeToString(secret)
		cfg.JWTSecret = hexSecret
		if err := config.Save(cfg); err != nil {
			logger.Warnw("failed to save JWT secret to config.yaml", "error", err)
		} else {
			logger.Info("JWT signing key generated and saved to config.yaml")
		}
		authMgr = api.NewAuthManagerWithSecret(authCfg, hexSecret, st)
	}

	// 管理员初始密码：首次启动自动生成强密码，后续启动永不显示
	adminPasswordHash := cfg.AdminPasswordHash
	if adminPasswordHash == "" {
		plainPassword, err := api.GenerateStrongPassword()
		if err != nil {
			logger.Fatalw("failed to generate admin password", "error", err)
		}
		pwHash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), authCfg.BcryptCost)
		if err != nil {
			logger.Fatalw("failed to hash admin password", "error", err)
		}
		adminPasswordHash = string(pwHash)

		// 持久化到配置文件（仅存 bcrypt 哈希，绝不存明文）
		cfg.AdminPasswordHash = adminPasswordHash
		if err := config.Save(cfg); err != nil {
			logger.Warnw("failed to save admin password hash to config.yaml", "error", err)
		}

		// 终端安全输出：仅在首次启动时打印
		fmt.Println("")
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║  🔐 Laji-HoneyPot 管理端初始密码                              ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  用户名: admin                                               ║\n")
		fmt.Printf("║  密  码: %-52s ║\n", plainPassword)
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Println("║  ⚠️  请立即登录并修改初始密码！                              ║")
		fmt.Println("║  ⚠️  此密码仅在本次启动时显示一次，请妥善保管！             ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println("")

		logger.Infow("audit: initial admin password generated and bcrypt-hashed",
			"user", "admin",
			"hash_algorithm", "bcrypt",
			"cost", authCfg.BcryptCost,
			"stored_in", "config.yaml (admin_password_hash)",
		)
	} else {
		logger.Info("admin password hash loaded from config (not displayed)")
	}

	if err := authMgr.EnsureDefaultAdmin(adminPasswordHash); err != nil {
		logger.Fatalw("ensure default admin failed", "error", err)
	}
	logger.Infow("auth manager initialized", "default_user", "admin")

	apiSrv := api.NewServer(logger, st, trEngine.GetVulnDB(), wsHub, authMgr)
	apiSrv.SetTraceEngine(trEngine)            // 注入溯源反制引擎（深度反制 API）
	apiSrv.SetHoneypotEngine(hpEngine)         // 注入蜜罐引擎（服务状态查询 API）
	apiSrv.SetBaitSystem(baitGen, baitTracker) // 注入蜜标系统（诱饵管理 API）
	apiSrv.SetBaitLinkage(baitLinkage)         // 注入蜜饵联动引擎

	// 注入攻击者画像构建器
	profileBuilder := profile.NewBuilder(st)
	apiSrv.SetProfileBuilder(profileBuilder)

	// 注入陷阱配置到 API 服务器（供前端 /api/traps/config 查询）
	if trapData := buildTrapConfigJSON(hpEngine.GetTrapRegistry()); trapData != nil {
		apiSrv.SetTrapConfig(trapData)
	}

	// 集群管理端 (仅在 role=manager 且 enabled=true 时启动)
	var clusterMgr *cluster.Manager
	clusterGen := cluster.NewGenerator(version)
	apiSrv.SetClusterGenerator(clusterGen) // Generator 始终可用（前端需 manager mode 才可部署）

	// v0.17.2: Agent 编译引擎 — 在管理端交叉编译独立可执行文件
	clusterCompiler := cluster.NewCompiler(".")
	apiSrv.SetClusterCompiler(clusterCompiler)
	logger.Info("agent compiler initialized")

	// v0.18.1: 升级管理器 — 生成升级包、管理升级任务
	upgradeMgr := upgrade.NewUpgradeManager(st, logger, cfg.DataDir)
	apiSrv.SetUpgradeManager(upgradeMgr)
	logger.Info("upgrade manager initialized")

	// v0.18.1: 守护进程管理器 — Agent 服务管理
	binPath, _ := os.Executable()
	configPath := "config.yaml"
	daemonMgr := daemon.NewDaemonManager(binPath, configPath, cfg.DataDir, logger)
	apiSrv.SetDaemonManager(daemonMgr)
	logger.Info("daemon manager initialized")

	if cfg.Cluster.Enabled && cfg.Cluster.Role == "manager" {
		tlsCfg, tlsErr := buildClusterTLS(cfg.Cluster, logger)
		if tlsErr != nil {
			logger.Errorw("cluster TLS config failed", "error", tlsErr)
		} else {
			clusterMgr = cluster.NewManager(logger, tlsCfg)
			if err := clusterMgr.Listen(cfg.Cluster.ListenAddr); err != nil {
				logger.Errorw("cluster manager listen failed", "error", err)
			} else {
				apiSrv.SetClusterManager(clusterMgr)
				logger.Infow("cluster manager started", "listen", cfg.Cluster.ListenAddr)
			}
		}
	}

	// 集群 Agent 模式 (role=node): 连接管理端注册
	if cfg.Cluster.Enabled && cfg.Cluster.Role == "node" {
		agentTLS := &tls.Config{
			InsecureSkipVerify: cfg.Cluster.TLSInsecure,
			MinVersion:         tls.VersionTLS13,
		}
		clusterAgent := cluster.NewAgent(logger, cluster.AgentConfig{
			ManagerAddr: cfg.Cluster.ManagerAddr,
			TLSConfig:   agentTLS,
			Services: []string{
				"http", "mysql", "redis", "ssh", "ftp", "ldap", "dns", "smb", "rdp",
			},
		})
		go func() {
			for {
				if err := clusterAgent.Connect(); err != nil {
					logger.Errorw("cluster agent connect failed", "error", err)
					time.Sleep(10 * time.Second)
					continue
				}
				break
			}
		}()
		logger.Infow("cluster agent connecting", "manager", cfg.Cluster.ManagerAddr)
	}

	// 前端 SPA 静态文件服务（从 web/dist/ 或 web/ 目录加载）
	if fh := getFrontendFS("."); fh != nil {
		apiSrv.SetFrontendHandler(http.FileServer(fh))
		logger.Info("frontend serving static files")
	} else {
		logger.Warn("frontend not found — run: cd web && npm run build")
	}

	httpSrv := &http.Server{
		Addr:    cfg.APIAddr,
		Handler: apiSrv.Handler(),
	}
	go func() {
		logger.Infow("API server listening", "addr", cfg.APIAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorw("API server error", "error", err)
		}
	}()

	logger.Infow("Laji-HoneyPot running", "plugins", reg.List(), "api", cfg.APIAddr)
	logger.Info("press Ctrl+C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down gracefully...")

	// 优雅关闭 API 服务器（最多等 5 秒）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Errorw("API shutdown error", "error", err)
	}

	// 先释放蜜罐端口，再停止其他插件
	if err := hpEngine.Close(); err != nil {
		logger.Errorw("honeypot port release error", "error", err)
	}
	reg.StopAll()
	logger.Info("All ports released")
	logger.Info("Laji-HoneyPot stopped")
}

// buildClusterTLS 构建集群 TLS 配置
// 优先使用配置文件中的证书路径；若未配置则自动生成自签名证书（仅适用于测试环境）
func buildClusterTLS(cfg config.ClusterConfig, logger *log.Logger) (*tls.Config, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}, nil
	}

	// 自动生成自签名证书（仅测试用）
	logger.Warn("cluster: generating self-signed TLS cert (TEST ONLY — use real certs in production)")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "honeypot-cluster"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // 测试环境不验证客户端证书
	}, nil
}
func buildTrapConfigJSON(reg *traps.Registry) []byte {
	if reg == nil {
		return nil
	}
	data, _ := json.Marshal(map[string]interface{}{
		"scenarios":        traps.GetScenarioInfo(),
		"current_scenario": reg.Scenario,
		"enabled_services": reg.EnabledServices(),
		"all_services":     traps.AllServices,
	})
	return data
}

// handleAgentDaemon handles the "agent daemon" subcommands.
// Usage: honeypot agent daemon <install|uninstall|start|stop|restart|status>
func handleAgentDaemon() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s agent daemon <install|uninstall|start|stop|restart|status>\n", os.Args[0])
		os.Exit(1)
	}

	action := os.Args[3]

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(cfg.LogLevel)

	// Determine binary path
	binPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	// Determine config path
	configPath := "config.yaml"
	for i := 4; i < len(os.Args); i++ {
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			i++
		}
	}

	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data"
	}

	mgr := daemon.NewDaemonManager(binPath, configPath, dataDir, logger)

	var actionErr error
	switch action {
	case "install":
		fmt.Printf("Installing Laji-HoneyPot Agent daemon...\n")
		actionErr = mgr.Install()
		if actionErr == nil {
			fmt.Printf("Daemon installed successfully.\n")
		}
	case "uninstall":
		fmt.Printf("Uninstalling Laji-HoneyPot Agent daemon...\n")
		actionErr = mgr.Uninstall()
		if actionErr == nil {
			fmt.Printf("Daemon uninstalled successfully.\n")
		}
	case "start":
		actionErr = mgr.Start()
		if actionErr == nil {
			fmt.Printf("Daemon started.\n")
		}
	case "stop":
		actionErr = mgr.Stop()
		if actionErr == nil {
			fmt.Printf("Daemon stopped.\n")
		}
	case "restart":
		actionErr = mgr.Restart()
		if actionErr == nil {
			fmt.Printf("Daemon restarted.\n")
		}
	case "status":
		status, err := mgr.Status()
		if err != nil {
			fmt.Printf("Status: %s (error: %v)\n", status, err)
		} else {
			fmt.Printf("Status: %s\n", status)
		}
		if mgr.IsInstalled() {
			fmt.Println("Service is installed.")
		} else {
			fmt.Println("Service is NOT installed.")
		}
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		fmt.Fprintf(os.Stderr, "Usage: %s agent daemon <install|uninstall|start|stop|restart|status>\n", os.Args[0])
		os.Exit(1)
	}

	if actionErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", actionErr)
		os.Exit(1)
	}
}
