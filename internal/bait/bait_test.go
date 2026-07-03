package bait

import (
	"strings"
	"testing"
)

func TestNewGenerator(t *testing.T) {
	g := NewGenerator()
	if g == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestGenerateAWSCredentials(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("aws_key")

	if token.ID == "" {
		t.Error("expected non-empty ID")
	}
	if token.Type != "aws_key" {
		t.Errorf("expected aws_key type, got %s", token.Type)
	}
	if token.FileName != "aws_credentials.json" {
		t.Errorf("expected aws_credentials.json, got %s", token.FileName)
	}
	if token.SeedData == "" {
		t.Error("expected non-empty seed data")
	}
	if !strings.HasPrefix(token.SeedData, "hp_") {
		t.Error("seed should start with hp_")
	}

	// Verify content has AWS key format
	if !strings.Contains(token.Content, "AKIA") {
		t.Error("AWS credentials should contain AKIA access key")
	}
	if !strings.Contains(token.Content, "aws_access_key_id") {
		t.Error("AWS credentials should contain aws_access_key_id")
	}
	if !strings.Contains(token.Content, "x-tracking-id") {
		t.Error("AWS credentials should contain x-tracking-id")
	}
	if !strings.Contains(token.Content, token.SeedData) {
		t.Error("content should contain seed data for tracking")
	}
}

func TestGenerateDBCredentials(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("db_creds")

	if token.Type != "db_creds" {
		t.Errorf("expected db_creds type, got %s", token.Type)
	}
	if token.FileName != "database.yml" {
		t.Errorf("expected database.yml, got %s", token.FileName)
	}

	content := token.Content
	if !strings.Contains(content, "mysql://") {
		t.Error("DB creds should contain mysql:// connection string")
	}
	if !strings.Contains(content, "internal-db.prod.internal") {
		t.Error("DB creds should contain internal hostname")
	}
	if !strings.Contains(content, "x-tracking-id") {
		t.Error("DB creds should contain x-tracking-id")
	}
}

func TestGenerateAPIToken(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("api_token")

	if token.Type != "api_token" {
		t.Errorf("expected api_token type, got %s", token.Type)
	}

	content := token.Content
	if !strings.Contains(content, "GITHUB_TOKEN=ghp_") {
		t.Error("API tokens should contain GitHub token")
	}
	if !strings.Contains(content, "STRIPE_SECRET_KEY=sk_live_") {
		t.Error("API tokens should contain Stripe key")
	}
	if !strings.Contains(content, "JWT_SECRET=") {
		t.Error("API tokens should contain JWT secret")
	}
}

func TestGenerateSSHKey(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("ssh_key")

	if token.Type != "ssh_key" {
		t.Errorf("expected ssh_key type, got %s", token.Type)
	}
	if token.FileName != "id_rsa" {
		t.Errorf("expected id_rsa, got %s", token.FileName)
	}

	content := token.Content
	if !strings.Contains(content, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("SSH key should have PEM header")
	}
	if !strings.Contains(content, "-----END OPENSSH PRIVATE KEY-----") {
		t.Error("SSH key should have PEM footer")
	}
	if !strings.Contains(content, "x-tracking-id") {
		t.Error("SSH key should contain x-tracking-id")
	}
}

func TestGenerateGitConfig(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("git_config")

	if token.Type != "git_config" {
		t.Errorf("expected git_config type, got %s", token.Type)
	}

	content := token.Content
	if !strings.Contains(content, "[remote \"origin\"]") {
		t.Error("Git config should contain remote section")
	}
	if !strings.Contains(content, "url = https://") {
		t.Error("Git config should contain HTTPS URL")
	}
	if !strings.Contains(content, "@github.com/internal/private-repo.git") {
		t.Error("Git config should contain fake repo URL")
	}
}

func TestGenerateWPConfig(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("wp_config")

	if token.Type != "wp_config" {
		t.Errorf("expected wp_config type, got %s", token.Type)
	}
	if token.FileName != "wp-config.php.bak" {
		t.Errorf("expected wp-config.php.bak, got %s", token.FileName)
	}

	content := token.Content
	if !strings.Contains(content, "<?php") {
		t.Error("WP config should be PHP file")
	}
	if !strings.Contains(content, "DB_NAME") {
		t.Error("WP config should contain DB_NAME")
	}
	if !strings.Contains(content, "DB_PASSWORD") {
		t.Error("WP config should contain DB_PASSWORD")
	}
}

func TestGenerateEnvFile(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("env_file")

	if token.Type != "env_file" {
		t.Errorf("expected env_file type, got %s", token.Type)
	}
	if token.FileName != ".env" {
		t.Errorf("expected .env, got %s", token.FileName)
	}

	content := token.Content
	if !strings.Contains(content, "DATABASE_URL=mysql://") {
		t.Error("env file should contain DATABASE_URL")
	}
	if !strings.Contains(content, "REDIS_URL=redis://") {
		t.Error("env file should contain REDIS_URL")
	}
	if !strings.Contains(content, "JWT_SECRET=") {
		t.Error("env file should contain JWT_SECRET")
	}
	if !strings.Contains(content, "AWS_ACCESS_KEY_ID=AKIA") {
		t.Error("env file should contain AWS key")
	}
}

func TestGenerateUnknownType(t *testing.T) {
	g := NewGenerator()
	token := g.Generate("custom_type")

	if token.Type != "custom_type" {
		t.Errorf("expected custom_type type, got %s", token.Type)
	}
	if token.FileName != "unknown.txt" {
		t.Errorf("expected unknown.txt, got %s", token.FileName)
	}
}

func TestGenerateAll(t *testing.T) {
	g := NewGenerator()
	tokens := g.GenerateAll()

	expectedTypes := map[string]bool{
		"aws_key":    false,
		"db_creds":   false,
		"api_token":  false,
		"ssh_key":    false,
		"git_config": false,
		"wp_config":  false,
		"env_file":   false,
	}

	if len(tokens) != len(expectedTypes) {
		t.Errorf("expected %d tokens, got %d", len(expectedTypes), len(tokens))
	}

	for _, token := range tokens {
		if _, ok := expectedTypes[token.Type]; !ok {
			t.Errorf("unexpected token type: %s", token.Type)
		}
		expectedTypes[token.Type] = true

		// All tokens should have seeds
		if token.SeedData == "" {
			t.Errorf("token %s has empty seed", token.Type)
		}
	}

	for tp, found := range expectedTypes {
		if !found {
			t.Errorf("missing token type: %s", tp)
		}
	}
}

func TestGetURL(t *testing.T) {
	g := NewGenerator()
	tokens := g.GenerateAll()

	for _, token := range tokens {
		url := token.GetURL()
		if !strings.HasPrefix(url, "/bait/") {
			t.Errorf("URL should start with /bait/: %s", url)
		}
	}
}

func TestGetByPath(t *testing.T) {
	g := NewGenerator()
	tokens := g.GenerateAll()

	// For each token, test that GetByPath finds it
	for _, token := range tokens {
		url := token.GetURL()
		found := g.GetByPath(url)
		if found == nil {
			t.Errorf("GetByPath should find token for URL: %s (type: %s)", url, token.Type)
		} else if found.Type != token.Type {
			t.Errorf("GetByPath returned wrong type: got %s, want %s", found.Type, token.Type)
		}
	}

	// Test non-existent path
	if g.GetByPath("/bait/nonexistent.txt") != nil {
		t.Error("GetByPath should return nil for non-existent path")
	}
}

func TestGetByType(t *testing.T) {
	g := NewGenerator()
	g.GenerateAll()

	token := g.GetByType("aws_key")
	if token == nil {
		t.Fatal("GetByType should find aws_key")
	}
	if token.Type != "aws_key" {
		t.Errorf("expected aws_key, got %s", token.Type)
	}

	if g.GetByType("nonexistent") != nil {
		t.Error("GetByType should return nil for non-existent type")
	}
}

func TestAllTokens(t *testing.T) {
	g := NewGenerator()
	g.GenerateAll()

	tokens := g.AllTokens()
	if len(tokens) != 7 {
		t.Errorf("expected 7 tokens, got %d", len(tokens))
	}
}

// Tracker tests

func TestNewTracker(t *testing.T) {
	tr := NewTracker(100)
	if tr == nil {
		t.Fatal("expected non-nil tracker")
	}
	if tr.maxSize != 100 {
		t.Errorf("expected maxSize 100, got %d", tr.maxSize)
	}

	// Test default max size
	tr2 := NewTracker(0)
	if tr2.maxSize != 10000 {
		t.Errorf("expected default maxSize 10000, got %d", tr2.maxSize)
	}
}

func TestTrackerRecord(t *testing.T) {
	tr := NewTracker(100)

	record := AccessRecord{
		TokenID:   "test-token-1",
		BaitType:  "aws_key",
		RemoteIP:  "10.0.0.1",
		UserAgent: "curl/7.88.1",
		Referer:   "http://example.com/",
	}

	tr.Record(record)

	all := tr.All(10)
	if len(all) != 1 {
		t.Fatalf("expected 1 record, got %d", len(all))
	}
	if all[0].TokenID != "test-token-1" {
		t.Errorf("expected token ID test-token-1, got %s", all[0].TokenID)
	}
}

func TestTrackerGetByIP(t *testing.T) {
	tr := NewTracker(100)

	tr.Record(AccessRecord{TokenID: "t1", BaitType: "aws_key", RemoteIP: "10.0.0.1"})
	tr.Record(AccessRecord{TokenID: "t2", BaitType: "ssh_key", RemoteIP: "10.0.0.2"})
	tr.Record(AccessRecord{TokenID: "t3", BaitType: "env_file", RemoteIP: "10.0.0.1"})

	records := tr.GetByIP("10.0.0.1")
	if len(records) != 2 {
		t.Fatalf("expected 2 records for IP 10.0.0.1, got %d", len(records))
	}

	records = tr.GetByIP("10.0.0.3")
	if len(records) != 0 {
		t.Fatalf("expected 0 records for IP 10.0.0.3, got %d", len(records))
	}
}

func TestTrackerGetByType(t *testing.T) {
	tr := NewTracker(100)

	tr.Record(AccessRecord{TokenID: "t1", BaitType: "aws_key", RemoteIP: "10.0.0.1"})
	tr.Record(AccessRecord{TokenID: "t2", BaitType: "ssh_key", RemoteIP: "10.0.0.2"})
	tr.Record(AccessRecord{TokenID: "t3", BaitType: "aws_key", RemoteIP: "10.0.0.3"})

	records := tr.GetByType("aws_key")
	if len(records) != 2 {
		t.Fatalf("expected 2 records for aws_key, got %d", len(records))
	}

	records = tr.GetByType("env_file")
	if len(records) != 0 {
		t.Fatalf("expected 0 records for env_file, got %d", len(records))
	}
}

func TestTrackerAllOrder(t *testing.T) {
	tr := NewTracker(100)

	tr.Record(AccessRecord{TokenID: "t1", BaitType: "aws_key", RemoteIP: "10.0.0.1"})
	tr.Record(AccessRecord{TokenID: "t2", BaitType: "ssh_key", RemoteIP: "10.0.0.2"})
	tr.Record(AccessRecord{TokenID: "t3", BaitType: "env_file", RemoteIP: "10.0.0.3"})

	all := tr.All(10)
	if len(all) != 3 {
		t.Fatalf("expected 3 records, got %d", len(all))
	}
	// Most recent first
	if all[0].TokenID != "t3" {
		t.Errorf("expected t3 first (most recent), got %s", all[0].TokenID)
	}
	if all[2].TokenID != "t1" {
		t.Errorf("expected t1 last (oldest), got %s", all[2].TokenID)
	}
}

func TestTrackerAllLimit(t *testing.T) {
	tr := NewTracker(100)

	for i := 0; i < 10; i++ {
		tr.Record(AccessRecord{TokenID: "t", BaitType: "test", RemoteIP: "10.0.0.1"})
	}

	all := tr.All(5)
	if len(all) != 5 {
		t.Errorf("expected 5 records with limit, got %d", len(all))
	}
}

func TestTrackerMaxSize(t *testing.T) {
	tr := NewTracker(3)

	tr.Record(AccessRecord{TokenID: "t1", BaitType: "aws_key", RemoteIP: "10.0.0.1"})
	tr.Record(AccessRecord{TokenID: "t2", BaitType: "ssh_key", RemoteIP: "10.0.0.2"})
	tr.Record(AccessRecord{TokenID: "t3", BaitType: "env_file", RemoteIP: "10.0.0.3"})
	tr.Record(AccessRecord{TokenID: "t4", BaitType: "git_config", RemoteIP: "10.0.0.4"})

	all := tr.All(10)
	if len(all) != 3 {
		t.Fatalf("expected 3 records after overflow, got %d", len(all))
	}
	// t1 should be dropped, t4 should be most recent
	if all[0].TokenID != "t4" {
		t.Errorf("expected t4 as most recent, got %s", all[0].TokenID)
	}
}

func TestTrackerStats(t *testing.T) {
	tr := NewTracker(100)

	tr.Record(AccessRecord{TokenID: "t1", BaitType: "aws_key", RemoteIP: "10.0.0.1"})
	tr.Record(AccessRecord{TokenID: "t2", BaitType: "aws_key", RemoteIP: "10.0.0.2"})
	tr.Record(AccessRecord{TokenID: "t3", BaitType: "ssh_key", RemoteIP: "10.0.0.1"})

	stats := tr.Stats()

	if total, ok := stats["total_accesses"].(int); !ok || total != 3 {
		t.Errorf("expected total_accesses 3, got %v", stats["total_accesses"])
	}

	topTypes, ok := stats["top_accessed"].([]TopEntry)
	if !ok {
		t.Fatal("expected top_accessed in stats")
	}
	if len(topTypes) < 1 {
		t.Fatal("expected at least 1 top type")
	}

	topIPs, ok := stats["top_ips"].([]TopEntry)
	if !ok {
		t.Fatal("expected top_ips in stats")
	}
	if len(topIPs) < 1 {
		t.Fatal("expected at least 1 top IP")
	}
}

func TestConcurrentTrackerAccess(t *testing.T) {
	tr := NewTracker(1000)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				tr.Record(AccessRecord{
					TokenID:  "concurrent",
					BaitType: "test",
					RemoteIP: "10.0.0.1",
				})
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic
	all := tr.All(100)
	stats := tr.Stats()
	_ = all
	_ = stats
}
