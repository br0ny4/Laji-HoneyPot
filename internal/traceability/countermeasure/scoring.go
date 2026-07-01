package countermeasure

import (
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// ScoringEngine 防守方得分评估引擎
// 将所有反制获取的攻击方情报接入得分体系
type ScoringEngine struct {
	mu         sync.RWMutex
	logger     *log.Logger
	scoreboard *Scoreboard
	auditTrail *AuditTrail
	cooldowns  map[string]map[OpType]time.Time // targetIP -> opType -> lastExec
}

// NewScoringEngine 创建得分引擎
func NewScoringEngine(logger *log.Logger, audit *AuditTrail) *ScoringEngine {
	return &ScoringEngine{
		logger:    logger,
		auditTrail: audit,
		scoreboard: &Scoreboard{
			ByCategory:    make(map[OpType]int),
			ByTarget:      make(map[string]int),
			CapabilityHit: make(map[OpType]int),
			LastUpdated:   time.Now(),
		},
		cooldowns: make(map[string]map[OpType]time.Time),
	}
}

// GetScoreboard 获取当前得分
func (e *ScoringEngine) GetScoreboard() *Scoreboard {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// 返回副本
	sb := *e.scoreboard
	sb.ByCategory = make(map[OpType]int)
	sb.ByTarget = make(map[string]int)
	sb.CapabilityHit = make(map[OpType]int)
	sb.Events = make([]ScoreEvent, len(e.scoreboard.Events))
	for k, v := range e.scoreboard.ByCategory {
		sb.ByCategory[k] = v
	}
	for k, v := range e.scoreboard.ByTarget {
		sb.ByTarget[k] = v
	}
	for k, v := range e.scoreboard.CapabilityHit {
		sb.CapabilityHit[k] = v
	}
	copy(sb.Events, e.scoreboard.Events)
	return &sb
}

// RegisterScore 注册得分事件
// 返回实际得分数（若冷却中返回0）
func (e *ScoringEngine) RegisterScore(targetIP string, opType OpType, evidence string) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	cap, ok := CapabilityRegistry[opType]
	if !ok || !cap.Compliant {
		e.logger.Warnw("score rejected: unknown or non-compliant", "op", opType, "target", targetIP)
		return 0
	}

	// 冷却检测（防止刷分）
	if e.isOnCooldown(targetIP, opType) {
		e.logger.Debugw("score cooldown active", "op", opType, "target", targetIP)
		return 0
	}

	score := cap.MaxScore
	now := time.Now()

	evt := ScoreEvent{
		Timestamp: now,
		Category:  opType,
		TargetIP:  targetIP,
		Score:     score,
		Evidence:  evidence,
		AuditID:   e.generateAuditRef(targetIP, opType),
	}

	e.scoreboard.Events = append(e.scoreboard.Events, evt)
	e.scoreboard.TotalScore += score
	e.scoreboard.ByCategory[opType] += score
	e.scoreboard.ByTarget[targetIP] += score
	e.scoreboard.CapabilityHit[opType]++
	e.scoreboard.LastUpdated = now

	// 设置冷却
	e.setCooldown(targetIP, opType, cap.Cooldown)

	e.logger.Infow("countermeasure score registered",
		"op", opType, "target", targetIP, "score", score,
		"total", e.scoreboard.TotalScore)

	return score
}

// BatchRegisterScore 批量注册得分（如网络探测发现多个资产）
func (e *ScoringEngine) BatchRegisterScore(targetIP string, opType OpType, count int, evidence string) int {
	total := 0
	for i := 0; i < count; i++ {
		s := e.RegisterScore(targetIP, opType, evidence)
		if s == 0 {
			break // 冷却
		}
		total += s
	}
	return total
}

func (e *ScoringEngine) isOnCooldown(targetIP string, opType OpType) bool {
	if ops, ok := e.cooldowns[targetIP]; ok {
		if last, ok := ops[opType]; ok {
			// last 是到期时间 (setCooldown 设定为 now + cooldownSec)
			// 如果当前时间早于到期时间，说明冷却中
			return time.Now().Before(last)
		}
	}
	return false
}

func (e *ScoringEngine) setCooldown(targetIP string, opType OpType, cooldownSec int) {
	if e.cooldowns[targetIP] == nil {
		e.cooldowns[targetIP] = make(map[OpType]time.Time)
	}
	e.cooldowns[targetIP][opType] = time.Now().Add(time.Duration(cooldownSec) * time.Second)
}

func (e *ScoringEngine) generateAuditRef(targetIP string, opType OpType) string {
	return e.auditTrail.LastID()
}

// EvaluateMaxScore 评估该类别可从该目标获得的最高分（理论满分）
func (e *ScoringEngine) EvaluateMaxScore(targetIP string, opType OpType) int {
	cap, ok := CapabilityRegistry[opType]
	if !ok {
		return 0
	}
	return cap.MaxScore
}
