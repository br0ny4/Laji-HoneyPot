package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger 封装 zap 的结构化日志
type Logger struct {
	*zap.SugaredLogger
}

// New 根据日志等级创建 Logger
func New(level string) *Logger {
	var lvl zapcore.Level
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	default:
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := cfg.Build()
	if err != nil {
		panic("failed to build logger: " + err.Error())
	}

	return &Logger{logger.Sugar()}
}
