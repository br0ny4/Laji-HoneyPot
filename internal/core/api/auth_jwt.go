package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// contextKey 用于在 context 中存储用户信息
type contextKey string

const claimsContextKey contextKey = "auth_claims"

// JWTConfig JWT 配置
type JWTConfig struct {
	Secret           []byte
	AccessTokenTTL   time.Duration // 访问令牌有效期，默认 15 分钟
	RefreshTokenTTL  time.Duration // 刷新令牌有效期，默认 24 小时
	BcryptCost       int           // bcrypt 哈希成本，默认 12
	MaxLoginAttempts int           // 最大登录失败次数，默认 5
	LockDuration     time.Duration // 锁定时间，默认 15 分钟
}

// DefaultJWTConfig 返回安全的默认配置
func DefaultJWTConfig() *JWTConfig {
	secret := make([]byte, 32)
	rand.Read(secret)
	return &JWTConfig{
		Secret:           secret,
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  24 * time.Hour,
		BcryptCost:       12,
		MaxLoginAttempts: 5,
		LockDuration:     15 * time.Minute,
	}
}

// TokenPair JWT 令牌对
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// AuthClaims JWT 声明
type AuthClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// LoginRateLimiter 登录频率限制器（按 IP + 用户名）
type LoginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

type loginAttempt struct {
	count       int
	firstTryAt  time.Time
	lockedUntil time.Time
}

// NewLoginRateLimiter 创建登录频率限制器
func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts: make(map[string]*loginAttempt),
	}
}

// RecordAttempt 记录一次登录尝试，返回是否允许继续尝试
func (l *LoginRateLimiter) RecordAttempt(key string, maxAttempts int, lockDuration time.Duration) (allowed bool, remaining int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, exists := l.attempts[key]

	if !exists {
		l.attempts[key] = &loginAttempt{count: 1, firstTryAt: now}
		return true, maxAttempts - 1
	}

	// 检查是否在锁定期
	if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
		return false, 0
	}

	// 超过窗口期（30 分钟），重置计数
	if now.Sub(entry.firstTryAt) > 30*time.Minute {
		entry.count = 0
		entry.firstTryAt = now
	}

	entry.count++

	// 达到最大尝试次数，锁定
	if entry.count >= maxAttempts {
		entry.lockedUntil = now.Add(lockDuration)
		return false, 0
	}

	return true, maxAttempts - entry.count
}

// ResetAttempt 重置登录尝试计数
func (l *LoginRateLimiter) ResetAttempt(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// AuthManager JWT 认证管理器
type AuthManager struct {
	config  *JWTConfig
	store   *store.Store
	limiter *LoginRateLimiter
	mu      sync.RWMutex
	// 刷新令牌黑名单（服务端主动失效时使用）
	refreshBlacklist map[string]time.Time
}

// NewAuthManager 创建认证管理器
func NewAuthManager(cfg *JWTConfig, st *store.Store) *AuthManager {
	if cfg == nil {
		cfg = DefaultJWTConfig()
	}
	if st == nil {
		panic("store is required for AuthManager")
	}
	return &AuthManager{
		config:           cfg,
		store:            st,
		limiter:          NewLoginRateLimiter(),
		refreshBlacklist: make(map[string]time.Time),
	}
}

// NewAuthManagerWithSecret 使用指定的 hex 编码密钥创建认证管理器
// secret 为 hex 编码的 256 位密钥；若为空则回退到随机生成
func NewAuthManagerWithSecret(cfg *JWTConfig, secret string, st *store.Store) *AuthManager {
	if cfg == nil {
		cfg = DefaultJWTConfig()
	}
	if secret != "" {
		key, err := hex.DecodeString(secret)
		if err == nil && len(key) == 32 {
			cfg.Secret = key
		}
	}
	return NewAuthManager(cfg, st)
}

// EnsureDefaultAdmin 确保存在默认管理员账号（首次启动自动创建）
func (a *AuthManager) EnsureDefaultAdmin() error {
	exists, err := a.store.UserExists("admin")
	if err != nil {
		return fmt.Errorf("check admin exists: %w", err)
	}
	if exists {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), a.config.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash default password: %w", err)
	}
	return a.store.CreateUser("admin", string(hash), "admin")
}

// GenerateTokens 生成 JWT 令牌对
func (a *AuthManager) GenerateTokens(userID int64, username, role string) (*TokenPair, error) {
	// Access Token
	accessToken, err := a.generateToken(userID, username, role, "access", a.config.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// Refresh Token
	refreshToken, err := a.generateToken(userID, username, role, "refresh", a.config.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(a.config.AccessTokenTTL.Seconds()),
	}, nil
}

// generateToken 内部令牌生成
func (a *AuthManager) generateToken(userID int64, username, role, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now()
	tokenID := make([]byte, 16)
	rand.Read(tokenID)

	claims := AuthClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        hex.EncodeToString(tokenID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "Laji-HoneyPot",
			Subject:   fmt.Sprintf("%s|%s", username, tokenType),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.config.Secret)
}

// ValidateToken 验证 JWT 令牌，返回 Claims
func (a *AuthManager) ValidateToken(tokenString string) (*AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.config.Secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*AuthClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// contextWithClaims 将 AuthClaims 注入 context
func contextWithClaims(ctx context.Context, claims *AuthClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext 从 context 提取 AuthClaims
func ClaimsFromContext(ctx context.Context) *AuthClaims {
	if claims, ok := ctx.Value(claimsContextKey).(*AuthClaims); ok {
		return claims
	}
	return nil
}

// RefreshTokens 使用刷新令牌换取新令牌对
func (a *AuthManager) RefreshTokens(refreshToken string) (*TokenPair, error) {
	a.mu.RLock()
	if _, blacklisted := a.refreshBlacklist[refreshToken]; blacklisted {
		a.mu.RUnlock()
		return nil, fmt.Errorf("refresh token has been revoked")
	}
	a.mu.RUnlock()

	claims, err := a.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if !strings.Contains(claims.Subject, "|refresh") {
		return nil, fmt.Errorf("not a refresh token")
	}

	return a.GenerateTokens(claims.UserID, claims.Username, claims.Role)
}

// RevokeRefreshToken 撤销刷新令牌
func (a *AuthManager) RevokeRefreshToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshBlacklist[token] = time.Now()
}

// Login 处理登录请求
func (a *AuthManager) Login(username, password, clientIP string) (*TokenPair, error) {
	// 频率限制
	limiterKey := fmt.Sprintf("%s:%s", clientIP, username)
	allowed, remaining := a.limiter.RecordAttempt(limiterKey, a.config.MaxLoginAttempts, a.config.LockDuration)
	if !allowed {
		return nil, fmt.Errorf("account temporarily locked, try again later")
	}

	// 查询用户
	user, err := a.store.GetUser(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials (%d attempts remaining)", remaining)
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials (%d attempts remaining)", remaining)
	}

	// 登录成功，重置限流
	a.limiter.ResetAttempt(limiterKey)

	// 更新最后登录时间
	a.store.UpdateLastLogin(user.ID)

	// 生成令牌
	return a.GenerateTokens(user.ID, user.Username, user.Role)
}

// Changepassword 修改密码
func (a *AuthManager) Changepassword(username, oldPassword, newPassword string) error {
	user, err := a.store.GetUser(username)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password incorrect")
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), a.config.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return a.store.UpdatePassword(username, string(hash))
}

// ValidatePassword 验证密码复杂度
// 要求：最少 8 个字符，至少 1 个大写字母、1 个小写字母、1 个数字、1 个特殊字符
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("密码需至少8个字符")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?"

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case strings.ContainsRune(specialChars, ch):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("密码需至少包含1个大写字母")
	}
	if !hasLower {
		return errors.New("密码需至少包含1个小写字母")
	}
	if !hasDigit {
		return errors.New("密码需至少包含1个数字")
	}
	if !hasSpecial {
		return errors.New("密码需至少包含1个特殊字符（!@#$%^&*()_+-=[]{}|;':\",./<>?）")
	}

	return nil
}

// JWTClaimsFromRequest 从 HTTP 请求提取并验证 JWT Claims
func (a *AuthManager) JWTClaimsFromRequest(r *http.Request) (*AuthClaims, error) {
	token := extractBearerToken(r)
	if token == "" {
		return nil, fmt.Errorf("missing authorization header")
	}
	return a.ValidateToken(token)
}

// JWTAuthMiddleware JWT 认证中间件 — 全局 API 鉴权
func (a *AuthManager) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 豁免端点
		if isExemptPath(path) {
			next.ServeHTTP(w, r)
			return
		}

		// 仅拦截 /api/ 路径
		if !strings.HasPrefix(path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// 验证 JWT
		claims, err := a.JWTClaimsFromRequest(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": "valid JWT Bearer token required. Please login at /api/auth/login",
			})
			return
		}

		// 将用户信息注入请求上下文
		ctx := r.Context()
		ctx = contextWithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isExemptPath 判断路径是否豁免 JWT 认证
func isExemptPath(path string) bool {
	exemptPaths := []string{
		"/healthz",
		"/api/auth/login",
		"/api/auth/refresh",
		"/api/collect",
		"/api/events",
		"/api/countermeasure/exfil",
		"/api/cluster/agent/package", // v0.17.1: 部署包下载无需认证
	}
	for _, ep := range exemptPaths {
		if path == ep || (strings.Contains(ep, "?") && ep == path) {
			return true
		}
		// 豁免带 query 参数的端点（如 /api/cluster/agent/package?os=linux）
		if strings.HasPrefix(path, ep+"?") {
			return true
		}
	}
	return false
}

// extractBearerToken 从 Authorization header 提取 Bearer token
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// ============================================================
// 认证 API 处理器
// ============================================================

// HandleLogin 登录接口
// POST /api/auth/login
func (a *AuthManager) HandleLogin(logger *log.Logger, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.Split(fwd, ",")[0]
	}

	tokens, err := a.Login(req.Username, req.Password, clientIP)
	if err != nil {
		if logger != nil {
			logger.Warnw("login failed", "user", req.Username, "ip", clientIP, "error", err.Error())
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	if logger != nil {
		logger.Infow("login success", "user", req.Username, "ip", clientIP)
	}

	writeJSON(w, http.StatusOK, tokens)
}

// HandleRefresh 令牌刷新接口
// POST /api/auth/refresh
func (a *AuthManager) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token required"})
		return
	}

	tokens, err := a.RefreshTokens(req.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}

// HandleLogout 登出接口
// POST /api/auth/logout
func (a *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token required"})
		return
	}

	a.RevokeRefreshToken(req.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// HandleChangepassword 修改密码接口
// POST /api/auth/changepassword
func (a *AuthManager) HandleChangepassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if err := a.Changepassword(claims.Username, req.OldPassword, req.NewPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}
