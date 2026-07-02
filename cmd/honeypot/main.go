package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/Laji-HoneyPot/honeypot/internal/alerter"
	"github.com/Laji-HoneyPot/honeypot/internal/cluster"
	"github.com/Laji-HoneyPot/honeypot/internal/core"
	"github.com/Laji-HoneyPot/honeypot/internal/core/api"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	honeypotEngine "github.com/Laji-HoneyPot/honeypot/internal/honeypot"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
	opsEngine "github.com/Laji-HoneyPot/honeypot/internal/ops"
	traceEngine "github.com/Laji-HoneyPot/honeypot/internal/traceability"
)

func main() {
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

	// JWT 认证管理器（默认密码 admin/admin123，生产环境请务必修改）
	authCfg := api.DefaultJWTConfig()
	authMgr := api.NewAuthManager(authCfg, st)
	if err := authMgr.EnsureDefaultAdmin(); err != nil {
		logger.Fatalw("ensure default admin failed", "error", err)
	}
	logger.Infow("auth manager initialized", "default_user", "admin")

	apiSrv := api.NewServer(logger, st, trEngine.GetVulnDB(), wsHub, authMgr)
	apiSrv.SetTraceEngine(trEngine) // 注入溯源反制引擎（深度反制 API）

	// 注入陷阱配置到 API 服务器（供前端 /api/traps/config 查询）
	if trapData := buildTrapConfigJSON(hpEngine.GetTrapRegistry()); trapData != nil {
		apiSrv.SetTrapConfig(trapData)
	}

	// 集群管理端 (仅在 role=manager 且 enabled=true 时启动)
	var clusterMgr *cluster.Manager
	clusterGen := cluster.NewGenerator(version)
	apiSrv.SetClusterGenerator(clusterGen) // Generator 始终可用（前端需 manager mode 才可部署）

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

	logger.Info("shutting down...")

	// 优雅关闭 API 服务器（最多等 5 秒）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Errorw("API shutdown error", "error", err)
	}

	reg.StopAll()
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
