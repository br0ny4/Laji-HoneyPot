package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/alerter"
	"github.com/Laji-HoneyPot/honeypot/internal/core/api"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	honeypotEngine "github.com/Laji-HoneyPot/honeypot/internal/honeypot"
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

	logger.Info("Laji-HoneyPot starting", "version", "0.8.0")

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

	// 面包屑触发 → 反制 Payload 注入链路：溯源引擎根据攻击上下文智能选择最优载荷
	hpEngine.SetCountermeasureProvider(func(path, userAgent, remoteIP string) string {
		return trEngine.SelectPayload(path, userAgent, remoteIP)
	})

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

	apiSrv := api.NewServer(logger, st, trEngine.GetVulnDB(), wsHub, cfg.APIKey)
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
