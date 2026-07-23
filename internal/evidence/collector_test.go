package evidence

import (
	"testing"
)

func TestCheckNewEvidence(t *testing.T) {
	c := NewCollector()
	hits := c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24")
	if len(hits) == 0 {
		t.Fatal("expected nmap to trigger subnet_scan evidence")
	}
	found := false
	for _, h := range hits {
		if h.Token == TokenSubnetScan {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected subnet_scan token in hits")
	}
}

func TestCheckDuplicateEvidence(t *testing.T) {
	c := NewCollector()
	// 首次触发
	hits1 := c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24")
	if len(hits1) == 0 {
		t.Fatal("first trigger should produce hits")
	}
	// 重复触发不应产生新命中
	hits2 := c.Check("192.168.1.1", "nmap -A 10.0.0.0/24")
	if len(hits2) != 0 {
		t.Errorf("duplicate trigger should not produce hits, got %d", len(hits2))
	}
}

func TestPerIPSolation(t *testing.T) {
	c := NewCollector()
	// IP1 触发 subnet_scan
	hits1 := c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24")
	if len(hits1) == 0 {
		t.Fatal("ip1 should trigger evidence")
	}
	// IP2 同样触发 subnet_scan（不同IP应独立计数）
	hits2 := c.Check("10.0.0.5", "nmap -sV 192.168.1.0/24")
	if len(hits2) == 0 {
		t.Fatal("ip2 should also trigger evidence independently")
	}
}

func TestMultipleEvidenceTypes(t *testing.T) {
	c := NewCollector()
	// 一条命令可能命中多个证据令牌
	hits := c.Check("192.168.1.1", "mysql -h 10.0.0.1 -u root -p && grep password .env")
	if len(hits) < 3 {
		t.Errorf("expected at least 3 evidence tokens, got %d: %v", len(hits), hits)
	}
}

func TestHasToken(t *testing.T) {
	c := NewCollector()
	c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24")
	if !c.HasToken("192.168.1.1", TokenSubnetScan) {
		t.Error("expected HasToken to return true for collected token")
	}
	if c.HasToken("192.168.1.1", TokenDBProbe) {
		t.Error("expected HasToken to return false for uncollected token")
	}
	if c.HasToken("10.0.0.1", TokenSubnetScan) {
		t.Error("expected HasToken to return false for different IP")
	}
}

func TestHitCount(t *testing.T) {
	c := NewCollector()
	if c.HitCount("192.168.1.1") != 0 {
		t.Error("initial hit count should be 0")
	}
	c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24 && mysql -h 10.0.0.1")
	if c.HitCount("192.168.1.1") == 0 {
		t.Error("hit count should be > 0 after evidence collection")
	}
}

func TestReset(t *testing.T) {
	c := NewCollector()
	c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24")
	if c.HitCount("192.168.1.1") == 0 {
		t.Fatal("should have collected evidence")
	}
	c.Reset("192.168.1.1")
	if c.HitCount("192.168.1.1") != 0 {
		t.Error("hit count should be 0 after reset")
	}
}

func TestCollectedTokens(t *testing.T) {
	c := NewCollector()
	c.Check("192.168.1.1", "nmap -sV 10.0.0.0/24 && mysql -h 10.0.0.1")
	tokens := c.CollectedTokens("192.168.1.1")
	if len(tokens) < 2 {
		t.Errorf("expected at least 2 tokens, got %d: %v", len(tokens), tokens)
	}
}

func TestAllEvidencePatterns(t *testing.T) {
	tests := []struct {
		input string
		token Token
	}{
		{"ip route", TokenRouteInfo},
		{"ip addr", TokenRouteInfo},
		{"arp -a", TokenARPTable},
		{"arp -an", TokenARPTable},
		{"nmap -sV 10.0.0.0/24", TokenSubnetScan},
		{"mysql -h 10.0.0.1 -u root", TokenDBProbe},
		{"redis-cli -h 10.0.0.1", TokenDBProbe},
		{"curl http://192.168.1.1/api", TokenHTTPProbe},
		{"wget https://example.com/file", TokenHTTPProbe},
		{"ldapsearch -x -h 192.168.1.1", TokenDomainProbe},
		{"smbclient //192.168.1.1/share", TokenDomainProbe},
		{"ssh 192.168.56.31", TokenLateralProbe},
		{"ssh root@192.168.56.31", TokenLateralProbe},
		{"cat .env", TokenAppConfig},
		{"cat .git/config", TokenAppConfig},
		{"cat .kube/config", TokenAppConfig},
		{"cat app.log", TokenAppLog},
		{"journalctl -u nginx", TokenAppLog},
		{"systemctl status nginx", TokenServiceEnum},
		{"ps aux", TokenServiceEnum},
		{"netstat -tlnp", TokenServiceEnum},
		{"docker ps", TokenServiceEnum},
		{"grep password .env", TokenPseudoProgress},
		{"grep secret *", TokenPseudoProgress},
		{"cat /etc/shadow", TokenPseudoProgress},
		{"find / -name *.key", TokenPseudoProgress},
		{"sudo su", TokenPrivEscalation},
	}

	for _, tt := range tests {
		c := NewCollector()
		hits := c.Check("test", tt.input)
		found := false
		for _, h := range hits {
			if h.Token == tt.token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("input %q should trigger token %q, got hits: %v", tt.input, tt.token, hits)
		}
	}
}
