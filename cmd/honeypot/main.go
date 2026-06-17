package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/registry"
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

	reg := registry.New(logger, cfg)

	// 注册三大引擎插件
	reg.Register(honeypotEngine.NewEngine(logger, eventBus))
	reg.Register(traceEngine.NewEngine(logger, eventBus))
	reg.Register(opsEngine.NewEngine(logger, eventBus))

	if err := reg.InitAll(); err != nil {
		logger.Errorw("failed to init plugins", "error", err)
		os.Exit(1)
	}

	if err := reg.StartAll(); err != nil {
		logger.Errorw("failed to start plugins", "error", err)
		os.Exit(1)
	}

	logger.Infow("Laji-HoneyPot running", "plugins", reg.List())
	logger.Info("press Ctrl+C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	reg.StopAll()
	logger.Info("Laji-HoneyPot stopped")
}
