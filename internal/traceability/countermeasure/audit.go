package countermeasure

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// AuditTrail 合规审计追踪系统
// 所有反制操作行为留痕可追溯，签名防篡改
type AuditTrail struct {
	mu      sync.RWMutex
	logger  *log.Logger
	entries []AuditEntry
	lastID  string
}

// NewAuditTrail 创建审计追踪
func NewAuditTrail(logger *log.Logger) *AuditTrail {
	return &AuditTrail{
		logger:  logger,
		entries: make([]AuditEntry, 0),
	}
}

// Record 记录一条审计日志
func (a *AuditTrail) Record(eventType OpType, targetIP, sourceIP, operator, action, detail string) *AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	id := a.generateID(now, eventType, targetIP)
	cap := CapabilityRegistry[eventType]

	entry := AuditEntry{
		ID:        id,
		Timestamp: now,
		EventType: eventType,
		TargetIP:  targetIP,
		SourceIP:  sourceIP,
		Operator:  operator,
		Action:    action,
		Detail:    detail,
		Compliant: cap.Compliant,
		Signature: a.sign(id, now, eventType, targetIP),
	}

	a.entries = append(a.entries, entry)
	a.lastID = id

	a.logger.Infow("audit recorded",
		"id", id, "type", eventType, "target", targetIP,
		"action", action, "compliant", cap.Compliant)

	// 合规检查告警
	if !cap.Compliant {
		a.logger.Warnw("COMPLIANCE VIOLATION: non-compliant operation attempted",
			"id", id, "type", eventType, "target", targetIP)
	}

	return &entry
}

// RecordInitiate 记录操作开始
func (a *AuditTrail) RecordInitiate(eventType OpType, targetIP, sourceIP, operator string) *AuditEntry {
	return a.Record(eventType, targetIP, sourceIP, operator, "initiate",
		fmt.Sprintf("反制操作[%s]启动，目标: %s", CapabilityRegistry[eventType].Name, targetIP))
}

// RecordComplete 记录操作完成
func (a *AuditTrail) RecordComplete(eventType OpType, targetIP, sourceIP, operator string, result string) *AuditEntry {
	return a.Record(eventType, targetIP, sourceIP, operator, "complete",
		fmt.Sprintf("反制操作[%s]完成，目标: %s，结果: %s", CapabilityRegistry[eventType].Name, targetIP, result))
}

// RecordError 记录操作异常
func (a *AuditTrail) RecordError(eventType OpType, targetIP, sourceIP, operator string, err error) *AuditEntry {
	return a.Record(eventType, targetIP, sourceIP, operator, "error",
		fmt.Sprintf("反制操作[%s]异常，目标: %s，错误: %v", CapabilityRegistry[eventType].Name, targetIP, err))
}

// RecordTerminate 记录操作终止
func (a *AuditTrail) RecordTerminate(eventType OpType, targetIP, sourceIP, operator, reason string) *AuditEntry {
	return a.Record(eventType, targetIP, sourceIP, operator, "terminate",
		fmt.Sprintf("反制操作[%s]终止，目标: %s，原因: %s", CapabilityRegistry[eventType].Name, targetIP, reason))
}

// GetEntries 获取所有审计记录
func (a *AuditTrail) GetEntries() []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]AuditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// GetEntriesByTarget 按目标获取审计记录
func (a *AuditTrail) GetEntriesByTarget(targetIP string) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var result []AuditEntry
	for _, e := range a.entries {
		if e.TargetIP == targetIP {
			result = append(result, e)
		}
	}
	return result
}

// VerifySignature 验证审计条目签名防篡改
func (a *AuditTrail) VerifySignature(entry AuditEntry) bool {
	expected := a.sign(entry.ID, entry.Timestamp, entry.EventType, entry.TargetIP)
	return expected == entry.Signature
}

// LastID 获取最后一条记录ID
func (a *AuditTrail) LastID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lastID
}

// generateID 生成审计条目唯一ID
func (a *AuditTrail) generateID(ts time.Time, eventType OpType, targetIP string) string {
	data := fmt.Sprintf("%s.%d.%s.%s", targetIP, ts.UnixNano(), eventType, ts.Format("20060102-150405"))
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("AUD-%x", h[:8])
}

// sign 对审计条目签名
func (a *AuditTrail) sign(id string, ts time.Time, eventType OpType, targetIP string) string {
	data := fmt.Sprintf("%s|%d|%s|%s|%s", id, ts.UnixNano(), eventType, targetIP, "laji-honeypot-audit-salt")
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}
