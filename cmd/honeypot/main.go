package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	logger.Info("Laji-HoneyPot starting", "version", "0.1.0")

	// 初始化 SQLite 持久化
	st, err := store.New(cfg.DataDir)
	if err != nil {
		logger.Errorw("failed to init store", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("SQLite store initialized")

	reg := registry.New(logger, cfg)

	// 注册插件（传入 Store 支持持久化）
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

	// 启动 API 服务器
	apiSrv := api.NewServer(logger, st, trEngine.GetVulnDB())
	go func() {
		logger.Infow("API server listening", "addr", cfg.APIAddr)
		if err := http.ListenAndServe(cfg.APIAddr, apiSrv.Handler()); err != nil {
			logger.Errorw("API server stopped", "error", err)
		}
	}()

	logger.Infow("Laji-HoneyPot running", "plugins", reg.List(), "api", cfg.APIAddr)
	logger.Info("press Ctrl+C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	reg.StopAll()
	logger.Info("Laji-HoneyPot stopped")
}
