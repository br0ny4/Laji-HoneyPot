package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MFAProvider TOTP 多因子认证提供者
type MFAProvider struct {
	mu      sync.RWMutex
	secrets map[string]string       // user -> base32 secret
	tokens  map[string]tokenEntry   // temp tokens for sensitive ops
	codes   map[string]mfaCodeEntry // one-time MFA challenge codes
}

type tokenEntry struct {
	Token     string
	User      string
	CreatedAt time.Time
	Ops       []string // allowed operations
}

type mfaCodeEntry struct {
	Code      string
	User      string
	CreatedAt time.Time
	Used      bool
}

// NewMFAProvider 创建 MFA 提供者
func NewMFAProvider() *MFAProvider {
	return &MFAProvider{
		secrets: make(map[string]string),
		tokens:  make(map[string]tokenEntry),
		codes:   make(map[string]mfaCodeEntry),
	}
}

// GenerateSecret 为用户生成 TOTP 密钥
func (p *MFAProvider) GenerateSecret(user string) string {
	secret := make([]byte, 20)
	for i := range secret {
		secret[i] = byte(time.Now().UnixNano()>>uint(i*4)) ^ 0xAA
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	p.mu.Lock()
	p.secrets[user] = encoded
	p.mu.Unlock()

	return encoded
}

// GetSecret 获取用户 TOTP 密钥
func (p *MFAProvider) GetSecret(user string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.secrets[user]
}

// ValidateCode 验证 TOTP 码（支持前后 30 秒窗口）
func (p *MFAProvider) ValidateCode(user, code string) bool {
	p.mu.RLock()
	secret, ok := p.secrets[user]
	p.mu.RUnlock()
	if !ok {
		return false
	}

	now := time.Now().Unix()
	for offset := int64(-1); offset <= 1; offset++ {
		expected := generateTOTP(secret, now+offset*30)
		if code == expected {
			return true
		}
	}
	return false
}

// IssueToken 为用户签发敏感操作临时令牌（有效期 5 分钟）
func (p *MFAProvider) IssueToken(user string, ops []string) string {
	token := fmt.Sprintf("mfa_%s_%x", user, sha256.Sum256([]byte(fmt.Sprintf("%s%d", user, time.Now().UnixNano()))))
	token = token[:48]

	p.mu.Lock()
	p.tokens[token] = tokenEntry{
		Token:     token,
		User:      user,
		CreatedAt: time.Now(),
		Ops:       ops,
	}
	p.mu.Unlock()

	return token
}

// ValidateToken 验证临时令牌
func (p *MFAProvider) ValidateToken(token string) (user string, ok bool) {
	p.mu.RLock()
	entry, exists := p.tokens[token]
	p.mu.RUnlock()

	if !exists {
		return "", false
	}
	if time.Since(entry.CreatedAt) > 5*time.Minute {
		p.mu.Lock()
		delete(p.tokens, token)
		p.mu.Unlock()
		return "", false
	}
	return entry.User, true
}

// GenerateChallenge 生成一次性 MFA 验证码
func (p *MFAProvider) GenerateChallenge(user string) string {
	code := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)

	p.mu.Lock()
	p.codes[code] = mfaCodeEntry{
		Code:      code,
		User:      user,
		CreatedAt: time.Now(),
	}
	p.mu.Unlock()

	return code
}

// VerifyChallenge 验证并消耗一次性 MFA 验证码
func (p *MFAProvider) VerifyChallenge(user, code string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, ok := p.codes[code]
	if !ok {
		return false
	}
	if entry.Used {
		return false
	}
	if time.Since(entry.CreatedAt) > 2*time.Minute {
		delete(p.codes, code)
		return false
	}
	if entry.User != user {
		return false
	}

	entry.Used = true
	p.codes[code] = entry
	return true
}

// MFAMiddleware 敏感操作二次认证中间件
// 用法: 在路由前包装此中间件，要求请求携带 X-MFA-Token 或 X-MFA-Code
func (p *MFAProvider) MFAMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mfaToken := r.Header.Get("X-MFA-Token")
		mfaCode := r.Header.Get("X-MFA-Code")
		user := r.Header.Get("X-MFA-User")

		// 尝试通过 token 验证
		if mfaToken != "" {
			if _, ok := p.ValidateToken(mfaToken); ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 尝试通过 code 验证
		if mfaCode != "" && user != "" {
			if p.VerifyChallenge(user, mfaCode) {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "mfa_required",
			"message": "敏感操作需要二次身份验证。请先请求 MFA 验证码并携带 X-MFA-Code 或 X-MFA-Token",
		})
	})
}

// generateTOTP 生成 TOTP 码（RFC 6238）
func generateTOTP(secret string, timestamp int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "000000"
	}

	counter := uint64(math.Floor(float64(timestamp) / 30))
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	binary := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	otp := binary % 1000000

	return fmt.Sprintf("%06d", otp)
}

// AuditChain 不可篡改审计链（SHA256 链式哈希）
type AuditChain struct {
	mu      sync.Mutex
	entries []AuditChainEntry
	head    string // 当前链头哈希
}

// AuditChainEntry 审计链条目
type AuditChainEntry struct {
	Index     int64  `json:"index"`
	Timestamp string `json:"timestamp"`
	OpType    string `json:"op_type"`
	TargetIP  string `json:"target_ip"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	PrevHash  string `json:"prev_hash"`
	CurrHash  string `json:"curr_hash"`
}

// NewAuditChain 创建审计链
func NewAuditChain() *AuditChain {
	return &AuditChain{
		entries: make([]AuditChainEntry, 0),
		head:    "genesis",
	}
}

// Append 追加一条审计记录并计算链式哈希
func (c *AuditChain) Append(opType, targetIP, actor, action, result string) *AuditChainEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	index := int64(len(c.entries))
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	entry := AuditChainEntry{
		Index:     index,
		Timestamp: timestamp,
		OpType:    opType,
		TargetIP:  targetIP,
		Actor:     actor,
		Action:    action,
		Result:    result,
		PrevHash:  c.head,
	}

	// 计算当前条目哈希: SHA256(index|timestamp|opType|targetIP|actor|action|result|prevHash)
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		entry.Index, entry.Timestamp, entry.OpType, entry.TargetIP,
		entry.Actor, entry.Action, entry.Result, entry.PrevHash)
	hash := sha256.Sum256([]byte(payload))
	entry.CurrHash = hex.EncodeToString(hash[:])

	c.head = entry.CurrHash
	c.entries = append(c.entries, entry)

	return &entry
}

// Verify 验证整条审计链的完整性
func (c *AuditChain) Verify() (valid bool, tamperedIndex int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) == 0 {
		return true, -1
	}

	prevHash := "genesis"
	for _, entry := range c.entries {
		// 验证前驱哈希匹配
		if entry.PrevHash != prevHash {
			return false, entry.Index
		}

		// 重新计算当前哈希
		payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
			entry.Index, entry.Timestamp, entry.OpType, entry.TargetIP,
			entry.Actor, entry.Action, entry.Result, entry.PrevHash)
		hash := sha256.Sum256([]byte(payload))
		expected := hex.EncodeToString(hash[:])

		if entry.CurrHash != expected {
			return false, entry.Index
		}

		prevHash = entry.CurrHash
	}

	return true, -1
}

// Entries 返回所有审计条目
func (c *AuditChain) Entries() []AuditChainEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]AuditChainEntry, len(c.entries))
	copy(result, c.entries)
	return result
}

// Head 返回当前链头哈希
func (c *AuditChain) Head() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}
