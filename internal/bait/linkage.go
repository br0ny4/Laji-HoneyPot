package bait

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LinkageType defines the type of linkage between bait and honeypot
type LinkageType string

const (
	LinkSSH   LinkageType = "ssh"   // SSH credential bait → SSH honeypot
	LinkMySQL LinkageType = "mysql" // DB credential bait → MySQL honeypot
	LinkRedis LinkageType = "redis" // Redis credential bait → Redis honeypot
	LinkFTP   LinkageType = "ftp"   // FTP credential bait → FTP honeypot
	LinkRDP   LinkageType = "rdp"   // RDP credential bait → RDP honeypot
	LinkHTTP  LinkageType = "http"  // URL/API bait → HTTP honeypot
	LinkLDAP  LinkageType = "ldap"  // LDAP credential bait → LDAP honeypot
	LinkSMB   LinkageType = "smb"   // SMB credential bait → SMB honeypot
)

// BaitLinkage associates a bait token's credential with a specific honeypot service
type BaitLinkage struct {
	ID            string      `json:"id"`                       // unique linkage ID
	TokenID       string      `json:"token_id"`                 // the bait token's ID
	BaitType      string      `json:"bait_type"`                // bait type (aws_key, db_creds, etc.)
	LinkageType   LinkageType `json:"linkage_type"`             // target honeypot type
	ServiceHost   string      `json:"service_host"`             // honeypot service host (e.g., "10.0.0.1:2222")
	CredentialKey string      `json:"credential_key"`           // the fake username/API key
	CredentialVal string      `json:"credential_val"`           // the fake password/token (hashed for security)
	SeedData      string      `json:"seed_data"`                // tracking seed for traceability
	CreatedAt     time.Time   `json:"created_at"`
	IsTriggered   bool        `json:"is_triggered"`             // has attacker used this credential?
	TriggeredAt   *time.Time  `json:"triggered_at,omitempty"`
	TriggerSource string      `json:"trigger_source,omitempty"` // source IP that triggered
}

// LinkageEngine manages bait-to-honeypot associations
type LinkageEngine struct {
	mu             sync.RWMutex
	linkages       map[string]*BaitLinkage // keyed by ID
	credHashIndex  map[string]*BaitLinkage // keyed by SHA256 hash of credential value
}

// NewLinkageEngine creates a new LinkageEngine
func NewLinkageEngine() *LinkageEngine {
	return &LinkageEngine{
		linkages:      make(map[string]*BaitLinkage),
		credHashIndex: make(map[string]*BaitLinkage),
	}
}

// randomID generates a random 8-character alphanumeric string
func randomID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// hashCredential returns the SHA256 hex hash of a credential value
func hashCredential(val string) string {
	h := sha256.Sum256([]byte(val))
	return hex.EncodeToString(h[:])
}

// Register registers a new bait linkage
func (e *LinkageEngine) Register(linkage *BaitLinkage) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if linkage.ID == "" {
		linkage.ID = fmt.Sprintf("link_%s_%s", linkage.LinkageType, randomID())
	}
	if linkage.CreatedAt.IsZero() {
		linkage.CreatedAt = time.Now()
	}

	e.linkages[linkage.ID] = linkage

	// Index by credential hash for fast lookup
	if linkage.CredentialVal != "" {
		e.credHashIndex[linkage.CredentialVal] = linkage
	}

	return nil
}

// firstHost returns the host for a given service type from the hosts map,
// falling back to the provided default if not found.
func firstHost(hosts map[string]string, svcType, defaultHost string) string {
	if h, ok := hosts[svcType]; ok && h != "" {
		return h
	}
	return defaultHost
}

// RegisterFromToken auto-registers linkages from a bait token.
// Returns a slice of linkages created.
func (e *LinkageEngine) RegisterFromToken(token *BaitToken, hosts map[string]string) []*BaitLinkage {
	if token == nil {
		return nil
	}
	if hosts == nil {
		hosts = make(map[string]string)
	}

	var linkages []*BaitLinkage

	switch token.Type {
	case "ssh_key":
		host := firstHost(hosts, "ssh", "127.0.0.1:2222")
		l := e.createSSHLinkage(token, host)
		if l != nil {
			e.Register(l)
			linkages = append(linkages, l)
		}

	case "db_creds":
		mysqlUser, mysqlPass := parseMySQLCredsFromDBConfig(token.Content)
		if mysqlUser != "" {
			host := firstHost(hosts, "mysql", "127.0.0.1:3306")
			ml := e.createMySQLLinkage(token, host, mysqlUser, mysqlPass)
			e.Register(ml)
			linkages = append(linkages, ml)
		}
		redisPass := parseRedisCredsFromDBConfig(token.Content)
		if redisPass != "" {
			host := firstHost(hosts, "redis", "127.0.0.1:6379")
			rl := e.createRedisLinkage(token, host, "", redisPass)
			e.Register(rl)
			linkages = append(linkages, rl)
		}

	case "aws_key":
		key, secret := parseAWSCreds(token.Content)
		if key != "" {
			host := firstHost(hosts, "http", "127.0.0.1:8081")
			l := e.createHTTPLinkage(token, host, key, secret)
			e.Register(l)
			linkages = append(linkages, l)
		}

	case "api_token":
		for _, kv := range parseAPITokens(token.Content) {
			host := firstHost(hosts, "http", "127.0.0.1:8081")
			l := e.createHTTPLinkage(token, host, kv[0], kv[1])
			e.Register(l)
			linkages = append(linkages, l)
		}

	case "wp_config":
		user, pass := parseWPCreds(token.Content)
		if user != "" {
			host := firstHost(hosts, "mysql", "127.0.0.1:3306")
			l := e.createMySQLLinkage(token, host, user, pass)
			e.Register(l)
			linkages = append(linkages, l)
		}

	case "env_file":
		user, pass := parseEnvMySQLCreds(token.Content)
		if user != "" {
			host := firstHost(hosts, "mysql", "127.0.0.1:3306")
			l := e.createMySQLLinkage(token, host, user, pass)
			e.Register(l)
			linkages = append(linkages, l)
		}
		rpass := parseEnvRedisCreds(token.Content)
		if rpass != "" {
			host := firstHost(hosts, "redis", "127.0.0.1:6379")
			l := e.createRedisLinkage(token, host, "", rpass)
			e.Register(l)
			linkages = append(linkages, l)
		}
		for _, kv := range parseEnvHTTPKeys(token.Content) {
			host := firstHost(hosts, "http", "127.0.0.1:8081")
			l := e.createHTTPLinkage(token, host, kv[0], kv[1])
			e.Register(l)
			linkages = append(linkages, l)
		}

	case "git_config":
		user, token_val := parseGitConfigCreds(token.Content)
		if user != "" {
			host := firstHost(hosts, "http", "127.0.0.1:8081")
			l := e.createHTTPLinkage(token, host, user, token_val)
			e.Register(l)
			linkages = append(linkages, l)
		}
	}

	return linkages
}

// GetByID returns a linkage by its ID
func (e *LinkageEngine) GetByID(id string) *BaitLinkage {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkages[id]
}

// GetByTokenID returns all linkages for a given bait token
func (e *LinkageEngine) GetByTokenID(tokenID string) []*BaitLinkage {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*BaitLinkage
	for _, l := range e.linkages {
		if l.TokenID == tokenID {
			result = append(result, l)
		}
	}
	return result
}

// GetByServiceType returns all linkages for a specific honeypot type
func (e *LinkageEngine) GetByServiceType(lt LinkageType) []*BaitLinkage {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*BaitLinkage
	for _, l := range e.linkages {
		if l.LinkageType == lt {
			result = append(result, l)
		}
	}
	return result
}

// GetAll returns all registered linkages
func (e *LinkageEngine) GetAll() []*BaitLinkage {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*BaitLinkage, 0, len(e.linkages))
	for _, l := range e.linkages {
		result = append(result, l)
	}
	return result
}

// MarkTriggered marks a linkage as triggered by an attacker
func (e *LinkageEngine) MarkTriggered(id string, sourceIP string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	l, ok := e.linkages[id]
	if !ok {
		return fmt.Errorf("linkage not found: %s", id)
	}

	l.IsTriggered = true
	now := time.Now()
	l.TriggeredAt = &now
	l.TriggerSource = sourceIP
	return nil
}

// CheckCredential checks if provided credentials match any bait linkage of the given type.
// Returns the matching linkage or nil.
func (e *LinkageEngine) CheckCredential(lt LinkageType, username, password string) *BaitLinkage {
	hashedPass := hashCredential(password)

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, l := range e.linkages {
		if l.LinkageType != lt {
			continue
		}
		// For Redis there is no username, only password
		if lt == LinkRedis {
			if l.CredentialVal == hashedPass {
				return l
			}
		} else {
			if l.CredentialKey == username && l.CredentialVal == hashedPass {
				return l
			}
		}
	}
	return nil
}

// Stats returns statistics about the linkage engine
func (e *LinkageEngine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	total := len(e.linkages)
	triggered := 0
	byServiceType := make(map[LinkageType]int)
	byBaitType := make(map[string]int)

	for _, l := range e.linkages {
		if l.IsTriggered {
			triggered++
		}
		byServiceType[l.LinkageType]++
		byBaitType[l.BaitType]++
	}

	triggerRate := 0.0
	if total > 0 {
		triggerRate = float64(triggered) / float64(total) * 100
	}

	return map[string]interface{}{
		"total_linkages":   total,
		"triggered":        triggered,
		"by_service_type":  byServiceType,
		"by_bait_type":     byBaitType,
		"trigger_rate_pct": triggerRate,
	}
}

// GetByCredentialHash looks up a linkage by credential hash for fast checking
func (e *LinkageEngine) GetByCredentialHash(hash string) *BaitLinkage {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.credHashIndex[hash]
}

// ---------------------------------------------------------------------------
// Helper constructors for creating BaitLinkage instances
// ---------------------------------------------------------------------------

func (e *LinkageEngine) createSSHLinkage(token *BaitToken, serviceHost string) *BaitLinkage {
	username := "honeypot"
	rawCred := extractSSHFingerprint(token.Content)
	if rawCred == "" {
		rawCred = token.SeedData
	}

	return &BaitLinkage{
		ID:            fmt.Sprintf("link_ssh_%s", randomID()),
		TokenID:       token.ID,
		BaitType:      token.Type,
		LinkageType:   LinkSSH,
		ServiceHost:   serviceHost,
		CredentialKey: username,
		CredentialVal: hashCredential(rawCred),
		SeedData:      token.SeedData,
	}
}

func (e *LinkageEngine) createMySQLLinkage(token *BaitToken, serviceHost, username, password string) *BaitLinkage {
	return &BaitLinkage{
		ID:            fmt.Sprintf("link_mysql_%s", randomID()),
		TokenID:       token.ID,
		BaitType:      token.Type,
		LinkageType:   LinkMySQL,
		ServiceHost:   serviceHost,
		CredentialKey: username,
		CredentialVal: hashCredential(password),
		SeedData:      token.SeedData,
	}
}

func (e *LinkageEngine) createRedisLinkage(token *BaitToken, serviceHost, username, password string) *BaitLinkage {
	return &BaitLinkage{
		ID:            fmt.Sprintf("link_redis_%s", randomID()),
		TokenID:       token.ID,
		BaitType:      token.Type,
		LinkageType:   LinkRedis,
		ServiceHost:   serviceHost,
		CredentialKey: username,
		CredentialVal: hashCredential(password),
		SeedData:      token.SeedData,
	}
}

func (e *LinkageEngine) createHTTPLinkage(token *BaitToken, serviceHost, keyName, keyValue string) *BaitLinkage {
	return &BaitLinkage{
		ID:            fmt.Sprintf("link_http_%s", randomID()),
		TokenID:       token.ID,
		BaitType:      token.Type,
		LinkageType:   LinkHTTP,
		ServiceHost:   serviceHost,
		CredentialKey: keyName,
		CredentialVal: hashCredential(keyValue),
		SeedData:      token.SeedData,
	}
}

// ---------------------------------------------------------------------------
// Content parsers – extract fake credentials from bait token content strings
// ---------------------------------------------------------------------------

// extractSSHFingerprint decodes the base64 body of a fake SSH private key
// and extracts the key comment / fingerprint material.
func extractSSHFingerprint(content string) string {
	lines := strings.Split(content, "\n")
	var b64Lines []string
	inBody := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "-----END OPENSSH PRIVATE KEY-----" {
			break
		}
		if inBody && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			b64Lines = append(b64Lines, trimmed)
		}
		if trimmed == "-----BEGIN OPENSSH PRIVATE KEY-----" {
			inBody = true
			continue
		}
	}
	if len(b64Lines) == 0 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(b64Lines, ""))
	if err != nil {
		return ""
	}
	return string(decoded)
}

// parseMySQLCredsFromDBConfig extracts MySQL username/password from db_creds content
func parseMySQLCredsFromDBConfig(content string) (string, string) {
	userRe := regexp.MustCompile(`username:\s*(\S+)`)
	passRe := regexp.MustCompile(`password:\s*(\S+)`)

	userMatch := userRe.FindStringSubmatch(content)
	passMatches := passRe.FindAllStringSubmatch(content, -1)

	username := ""
	password := ""
	if len(userMatch) >= 2 {
		username = userMatch[1]
	}
	if len(passMatches) >= 1 && len(passMatches[0]) >= 2 {
		password = passMatches[0][1]
	}
	return username, password
}

// parseRedisCredsFromDBConfig extracts Redis password from db_creds content
func parseRedisCredsFromDBConfig(content string) string {
	// Match the password under the redis: section
	re := regexp.MustCompile(`redis:[\s\S]*?password:\s*(\S+)`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseAWSCreds extracts AWS access key ID and secret from aws_key content
func parseAWSCreds(content string) (string, string) {
	keyRe := regexp.MustCompile(`"aws_access_key_id"\s*:\s*"([^"]+)"`)
	secretRe := regexp.MustCompile(`"aws_secret_access_key"\s*:\s*"([^"]+)"`)

	keyMatch := keyRe.FindStringSubmatch(content)
	secretMatch := secretRe.FindStringSubmatch(content)

	key := ""
	secret := ""
	if len(keyMatch) >= 2 {
		key = keyMatch[1]
	}
	if len(secretMatch) >= 2 {
		secret = secretMatch[1]
	}
	return key, secret
}

// parseAPITokens extracts API token key=value pairs from api_token content
func parseAPITokens(content string) [][2]string {
	re := regexp.MustCompile(`^(\w+)=(.+)$`)
	lines := strings.Split(content, "\n")
	var result [][2]string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if len(m) >= 3 {
			result = append(result, [2]string{m[1], m[2]})
		}
	}
	return result
}

// parseWPCreds extracts DB_USER and DB_PASSWORD from wp_config content
func parseWPCreds(content string) (string, string) {
	userRe := regexp.MustCompile(`define\('DB_USER',\s*'([^']+)'\)`)
	passRe := regexp.MustCompile(`define\('DB_PASSWORD',\s*'([^']+)'\)`)

	userMatch := userRe.FindStringSubmatch(content)
	passMatch := passRe.FindStringSubmatch(content)

	user := ""
	pass := ""
	if len(userMatch) >= 2 {
		user = userMatch[1]
	}
	if len(passMatch) >= 2 {
		pass = passMatch[1]
	}
	return user, pass
}

// parseGitConfigCreds extracts username and token from git_config URL
func parseGitConfigCreds(content string) (string, string) {
	re := regexp.MustCompile(`url\s*=\s*https://([^:]+):([^@]+)@`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 3 {
		return m[1], m[2]
	}
	return "", ""
}

// parseEnvMySQLCreds extracts MySQL credentials from env_file content
func parseEnvMySQLCreds(content string) (string, string) {
	// Try DATABASE_URL first
	urlRe := regexp.MustCompile(`DATABASE_URL=mysql://([^:]+):([^@]+)@`)
	m := urlRe.FindStringSubmatch(content)
	if len(m) >= 3 {
		return m[1], m[2]
	}
	// Fallback: DB_USER / DB_PASS
	userRe := regexp.MustCompile(`(?m)^DB_USER=(\S+)`)
	passRe := regexp.MustCompile(`(?m)^DB_PASS=(\S+)`)
	u := userRe.FindStringSubmatch(content)
	p := passRe.FindStringSubmatch(content)
	user := ""
	pass := ""
	if len(u) >= 2 {
		user = u[1]
	}
	if len(p) >= 2 {
		pass = p[1]
	}
	return user, pass
}

// parseEnvRedisCreds extracts Redis password from env_file content
func parseEnvRedisCreds(content string) string {
	// REDIS_URL=redis://:<password>@host:port
	re := regexp.MustCompile(`REDIS_URL=redis://:([^@]+)@`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseEnvHTTPKeys extracts HTTP-relevant API keys from env_file content
func parseEnvHTTPKeys(content string) [][2]string {
	var result [][2]string

	patterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`(?m)^AWS_ACCESS_KEY_ID=(\S+)`), "AWS_ACCESS_KEY_ID"},
		{regexp.MustCompile(`(?m)^AWS_SECRET_ACCESS_KEY=(\S+)`), "AWS_SECRET_ACCESS_KEY"},
		{regexp.MustCompile(`(?m)^STRIPE_KEY=(\S+)`), "STRIPE_KEY"},
		{regexp.MustCompile(`(?m)^MAILGUN_API_KEY=(\S+)`), "MAILGUN_API_KEY"},
		{regexp.MustCompile(`(?m)^SENTRY_DSN=(\S+)`), "SENTRY_DSN"},
	}

	for _, p := range patterns {
		m := p.re.FindStringSubmatch(content)
		if len(m) >= 2 {
			result = append(result, [2]string{p.name, m[1]})
		}
	}

	return result
}
