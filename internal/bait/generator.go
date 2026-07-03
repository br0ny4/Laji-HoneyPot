package bait

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	mathrand "math/rand"
	"strings"
)

// BaitToken represents a honey token/deceptive credential
type BaitToken struct {
	ID       string `json:"id"`        // unique token ID (UUID-style)
	Type     string `json:"type"`      // aws_key, db_creds, api_token, git_config, ssh_key, env_file
	FileName string `json:"file_name"` // e.g., ".env", "aws_credentials.json", "id_rsa"
	Content  string `json:"content"`   // the actual bait file content
	SeedData string `json:"seed_data"` // unique seed embedded in content for tracking
}

// Generator creates deceptive bait files
type Generator struct {
	tokens []BaitToken
}

// NewGenerator creates a new bait generator
func NewGenerator() *Generator {
	return &Generator{}
}

// newSeed generates a random tracking seed
func newSeed() string {
	b := make([]byte, 12)
	rand.Read(b)
	return fmt.Sprintf("hp_%x", b)
}

// randomChars generates a random alphanumeric string of given length
func randomChars(n int, charset string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateAll creates all standard bait tokens
func (g *Generator) GenerateAll() []BaitToken {
	types := []string{"aws_key", "db_creds", "api_token", "ssh_key", "git_config", "wp_config", "env_file"}
	tokens := make([]BaitToken, 0, len(types))
	for _, t := range types {
		tokens = append(tokens, g.Generate(t))
	}
	g.tokens = tokens
	return tokens
}

// Generate generates a single bait token of the given type with a tracking seed
func (g *Generator) Generate(baitType string) BaitToken {
	seed := newSeed()
	var token BaitToken

	switch baitType {
	case "aws_key":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_aws_%s", seed[:8]),
			Type:     "aws_key",
			FileName: "aws_credentials.json",
			SeedData: seed,
			Content:  g.genAWSCredentials(seed),
		}
	case "db_creds":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_db_%s", seed[:8]),
			Type:     "db_creds",
			FileName: "database.yml",
			SeedData: seed,
			Content:  g.genDBCredentials(seed),
		}
	case "api_token":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_api_%s", seed[:8]),
			Type:     "api_token",
			FileName: ".env.tokens",
			SeedData: seed,
			Content:  g.genAPITokens(seed),
		}
	case "ssh_key":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_ssh_%s", seed[:8]),
			Type:     "ssh_key",
			FileName: "id_rsa",
			SeedData: seed,
			Content:  g.genSSHKey(seed),
		}
	case "git_config":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_git_%s", seed[:8]),
			Type:     "git_config",
			FileName: ".git_config",
			SeedData: seed,
			Content:  g.genGitConfig(seed),
		}
	case "wp_config":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_wp_%s", seed[:8]),
			Type:     "wp_config",
			FileName: "wp-config.php.bak",
			SeedData: seed,
			Content:  g.genWPConfig(seed),
		}
	case "env_file":
		token = BaitToken{
			ID:       fmt.Sprintf("bait_env_%s", seed[:8]),
			Type:     "env_file",
			FileName: ".env",
			SeedData: seed,
			Content:  g.genEnvFile(seed),
		}
	default:
		token = BaitToken{
			ID:       fmt.Sprintf("bait_unknown_%s", seed[:8]),
			Type:     baitType,
			FileName: "unknown.txt",
			SeedData: seed,
			Content:  fmt.Sprintf("# unknown bait type: %s\n# x-tracking-id: %s\n", baitType, seed),
		}
	}

	return token
}

// GetURL returns the HTTP path where this bait token is served
func (t *BaitToken) GetURL() string {
	switch t.Type {
	case "aws_key":
		return fmt.Sprintf("/bait/aws_credentials_%s.json", t.SeedData[:8])
	case "db_creds":
		return fmt.Sprintf("/bait/database_%s.yml", t.SeedData[:8])
	case "api_token":
		return fmt.Sprintf("/bait/env_tokens_%s.txt", t.SeedData[:8])
	case "ssh_key":
		return fmt.Sprintf("/bait/id_rsa_%s", t.SeedData[:8])
	case "git_config":
		return fmt.Sprintf("/bait/git_config_%s.txt", t.SeedData[:8])
	case "wp_config":
		return fmt.Sprintf("/bait/wp_config_%s.php.bak", t.SeedData[:8])
	case "env_file":
		return fmt.Sprintf("/bait/env_%s.txt", t.SeedData[:8])
	default:
		return fmt.Sprintf("/bait/%s_%s.txt", t.Type, t.SeedData[:8])
	}
}

// genAWSCredentials generates fake AWS credentials JSON
func (g *Generator) genAWSCredentials(seed string) string {
	accessKey := "AKIA" + randomChars(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	secretKey := randomChars(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+")
	return fmt.Sprintf(`{
  "aws_access_key_id": "%s",
  "aws_secret_access_key": "%s",
  "region": "us-east-1",
  "output": "json",
  "x-tracking-id": "%s"
}
`, accessKey, secretKey, seed)
}

// genDBCredentials generates fake database connection string
func (g *Generator) genDBCredentials(seed string) string {
	return fmt.Sprintf(`# Database Configuration
# x-tracking-id: %s

development:
  adapter: mysql2
  encoding: utf8mb4
  pool: 5
  host: internal-db.prod.internal
  port: 3306
  database: app_production
  username: admin
  password: %s

production:
  url: mysql://admin:%s@internal-db.prod.internal:3306/app_production
  pool: 25
  timeout: 5000

redis:
  host: cache.prod.internal
  port: 6379
  password: %s
`, seed, randomChars(16, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"),
		randomChars(16, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"),
		randomChars(16, "abcdefghijklmnopqrstuvwxyz0123456789"))
}

// genAPITokens generates fake API tokens env file
func (g *Generator) genAPITokens(seed string) string {
	ghToken := "ghp_" + randomChars(36, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	stripeKey := "sk_live_" + randomChars(24, "abcdefghijklmnopqrstuvwxyz0123456789")
	return fmt.Sprintf(`# API Tokens - DO NOT COMMIT
# x-tracking-id: %s

GITHUB_TOKEN=%s
STRIPE_SECRET_KEY=%s
SENDGRID_API_KEY=SG.%s
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T%s/B%s/%s
JWT_SECRET=%s
ENCRYPTION_KEY=%s
`, seed, ghToken, stripeKey,
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(10, "0123456789"),
		randomChars(10, "0123456789"),
		randomChars(24, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"))
}

// genSSHKey generates a fake SSH private key
func (g *Generator) genSSHKey(seed string) string {
	fakeBody := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC%s fake-key-for-honeypot tracking:%s",
		randomChars(358, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
		seed,
	)))
	return fmt.Sprintf(`-----BEGIN OPENSSH PRIVATE KEY-----
# x-tracking-id: %s
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA%s
-----END OPENSSH PRIVATE KEY-----
`, seed, fakeBody)
}

// genGitConfig generates a fake git config file
func (g *Generator) genGitConfig(seed string) string {
	return fmt.Sprintf(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://%s:%s@github.com/internal/private-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = CI Bot
	email = ci-bot@internal.local
# x-tracking-id: %s
`, randomChars(8, "abcdefghijklmnopqrstuvwxyz"), randomChars(20, "abcdefghijklmnopqrstuvwxyz0123456789"), seed)
}

// genWPConfig generates a fake WordPress config backup
func (g *Generator) genWPConfig(seed string) string {
	return fmt.Sprintf(`<?php
/**
 * WordPress Configuration File - Backup
 * Auto-generated backup. DO NOT DELETE.
 * x-tracking-id: %s
 */

define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', '%s');
define('DB_HOST', 'internal-db.prod.internal:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         '%s');
define('SECURE_AUTH_KEY',  '%s');
define('LOGGED_IN_KEY',    '%s');
define('NONCE_KEY',        '%s');
define('AUTH_SALT',        '%s');
define('SECURE_AUTH_SALT', '%s');
define('LOGGED_IN_SALT',   '%s');
define('NONCE_SALT',       '%s');

$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);

define('DISALLOW_FILE_EDIT', true);
define('AUTOSAVE_INTERVAL', 300);

if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
`, seed,
		randomChars(20, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(64, "abcdefghijklmnopqrstuvwxyz0123456789"))
}

// genEnvFile generates a fake .env file with various secrets
func (g *Generator) genEnvFile(seed string) string {
	return fmt.Sprintf(`# Environment Configuration
# x-tracking-id: %s

# Database
DATABASE_URL=mysql://admin:%s@internal-db.prod.internal:3306/app_production
DB_HOST=internal-db.prod.internal
DB_PORT=3306
DB_USER=admin
DB_PASS=%s

# Redis
REDIS_URL=redis://:%s@cache.prod.internal:6379/0
REDIS_HOST=cache.prod.internal
REDIS_PORT=6379

# JWT / Auth
JWT_SECRET=%s
APP_KEY=base64:%s
ENCRYPTION_KEY=%s

# AWS
AWS_ACCESS_KEY_ID=AKIA%s
AWS_SECRET_ACCESS_KEY=%s
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=prod-uploads

# API Keys
STRIPE_KEY=sk_live_%s
MAILGUN_API_KEY=key-%s
SENTRY_DSN=https://%s@sentry.internal.local/3

# App
APP_ENV=production
APP_DEBUG=false
APP_URL=https://app.internal.local
`, seed,
		randomChars(20, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"),
		randomChars(20, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"),
		randomChars(16, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"),
		base64.StdEncoding.EncodeToString([]byte(randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"))),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
		randomChars(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"),
		randomChars(24, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"),
		randomChars(32, "abcdefghijklmnopqrstuvwxyz0123456789"))
}

// AllTokens returns all currently generated tokens
func (g *Generator) AllTokens() []BaitToken {
	return g.tokens
}

// GetByType finds a token by its bait type
func (g *Generator) GetByType(baitType string) *BaitToken {
	for i := range g.tokens {
		if g.tokens[i].Type == baitType {
			return &g.tokens[i]
		}
	}
	return nil
}

// GetByPath matches a URL path to a bait token.
// Paths look like /bait/aws_credentials_<seed>.json
func (g *Generator) GetByPath(path string) *BaitToken {
	// Strip /bait/ prefix
	trimmed := strings.TrimPrefix(path, "/bait/")
	for i := range g.tokens {
		if strings.Contains(trimmed, g.tokens[i].SeedData[:8]) && strings.Contains(trimmed, g.tokens[i].FileName[:4]) {
			return &g.tokens[i]
		}
	}
	// Fallback: try matching by type
	for i := range g.tokens {
		t := &g.tokens[i]
		if t.Type == "aws_key" && strings.Contains(trimmed, "aws_credentials") {
			return t
		}
		if t.Type == "db_creds" && strings.Contains(trimmed, "database") {
			return t
		}
		if t.Type == "api_token" && strings.Contains(trimmed, "env_tokens") {
			return t
		}
		if t.Type == "ssh_key" && strings.Contains(trimmed, "id_rsa") {
			return t
		}
		if t.Type == "git_config" && strings.Contains(trimmed, "git_config") {
			return t
		}
		if t.Type == "wp_config" && strings.Contains(trimmed, "wp_config") {
			return t
		}
		if t.Type == "env_file" && strings.Contains(trimmed, "env") {
			return t
		}
	}
	return nil
}
