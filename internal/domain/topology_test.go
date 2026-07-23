package domain

import (
	"testing"
)

func testTopologyConfig() TopologyConfig {
	return TopologyConfig{
		Segments: []Segment{
			{ID: "web", CIDR: "192.168.56.0/24", Gateway: "192.168.56.1"},
			{ID: "app", CIDR: "192.168.57.0/24", Gateway: "192.168.57.1"},
			{ID: "infra", CIDR: "192.168.58.0/24", Gateway: "192.168.58.1"},
		},
		Hosts: []VirtualHost{
			{IP: "192.168.56.10", Hostname: "web-01", Role: "web", OS: "Ubuntu 22.04", SubnetID: "web"},
			{IP: "192.168.56.20", Hostname: "jumpbox", Role: "jumpbox", OS: "CentOS 7", SubnetID: "web"},
			{IP: "192.168.57.10", Hostname: "db-01", Role: "db", OS: "CentOS 7", SubnetID: "app",
				VisibleAfter: []string{"subnet_scan"}},
			{IP: "192.168.57.20", Hostname: "app-01", Role: "app", OS: "Ubuntu 20.04", SubnetID: "app",
				VisibleAfter: []string{"subnet_scan"}},
			{IP: "192.168.58.10", Hostname: "dc01", Role: "dc", OS: "Windows Server 2019", SubnetID: "infra",
				VisibleAfter: []string{"subnet_scan", "domain_probe"}},
		},
		Edges: []Edge{
			{From: "192.168.56.20", To: "192.168.57.10", Via: "ssh"},
			{From: "192.168.56.20", To: "192.168.57.20", Via: "ssh"},
		},
	}
}

func TestNewTopology(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	if topo.HostCount() != 5 {
		t.Errorf("expected 5 hosts, got %d", topo.HostCount())
	}
}

func TestGetHost(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	h := topo.GetHost("192.168.56.10")
	if h == nil {
		t.Fatal("expected host for 192.168.56.10")
	}
	if h.Hostname != "web-01" {
		t.Errorf("expected web-01, got %s", h.Hostname)
	}

	h = topo.GetHost("10.0.0.1")
	if h != nil {
		t.Error("expected nil for non-existent host")
	}
}

func TestGetHostsForSession_NoEvidence(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	session := &SessionContext{Evidence: NewEvidenceSet()}
	hosts := topo.GetHostsForSession(session)

	// Without evidence tokens, only hosts without VisibleAfter should be visible
	// web-01 and jumpbox have no gates
	if len(hosts) < 2 {
		t.Errorf("expected at least 2 visible hosts (no gates), got %d", len(hosts))
	}

	foundJumpbox := false
	foundDB := false
	for _, h := range hosts {
		if h.Hostname == "jumpbox" {
			foundJumpbox = true
		}
		if h.Hostname == "db-01" {
			foundDB = true
		}
	}
	if !foundJumpbox {
		t.Error("jumpbox should be visible (no evidence gate)")
	}
	if foundDB {
		t.Error("db-01 should NOT be visible without subnet_scan token")
	}
}

func TestGetHostsForSession_WithEvidence(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	session := &SessionContext{Evidence: NewEvidenceSet()}
	session.Evidence.Add("subnet_scan")
	hosts := topo.GetHostsForSession(session)

	// With subnet_scan, app-tier hosts (db-01, app-01) should be visible
	foundApp := false
	for _, h := range hosts {
		if h.Hostname == "app-01" {
			foundApp = true
		}
	}
	if !foundApp {
		t.Error("app-01 should be visible with subnet_scan token")
	}

	// dc01 has VisibleAfter=["subnet_scan","domain_probe"] — OR logic, so subnet_scan alone unlocks it
	foundDC := false
	for _, h := range hosts {
		if h.Hostname == "dc01" {
			foundDC = true
		}
	}
	if !foundDC {
		t.Error("dc01 should be visible with subnet_scan (OR logic: any one token unlocks)")
	}
}

func TestGetHostsForSession_MultiToken(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	session := &SessionContext{Evidence: NewEvidenceSet()}
	session.Evidence.Add("subnet_scan")
	session.Evidence.Add("domain_probe")
	hosts := topo.GetHostsForSession(session)

	foundDC := false
	for _, h := range hosts {
		if h.Hostname == "dc01" {
			foundDC = true
		}
	}
	if !foundDC {
		t.Error("dc01 should be visible with subnet_scan + domain_probe")
	}
}

func TestIsVirtualIP(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	if !topo.IsVirtualIP("192.168.56.10") {
		t.Error("192.168.56.10 should be virtual IP")
	}
	if !topo.IsVirtualIP("192.168.57.10") {
		t.Error("192.168.57.10 should be virtual IP")
	}
	if !topo.IsVirtualIP("192.168.58.10") {
		t.Error("192.168.58.10 should be virtual IP")
	}
	if topo.IsVirtualIP("8.8.8.8") {
		t.Error("8.8.8.8 should NOT be virtual IP")
	}
}

func TestGetSubnet(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	seg := topo.GetSubnet("web")
	if seg == nil {
		t.Fatal("expected subnet 'web'")
	}
	if seg.CIDR != "192.168.56.0/24" {
		t.Errorf("expected 192.168.56.0/24, got %s", seg.CIDR)
	}

	seg = topo.GetSubnet("nonexistent")
	if seg != nil {
		t.Error("expected nil for nonexistent subnet")
	}
}

func TestGetHostsInSubnet(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	hosts := topo.GetHostsInSubnet("web")
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts in web subnet, got %d", len(hosts))
	}

	hosts = topo.GetHostsInSubnet("infra")
	if len(hosts) != 1 {
		t.Errorf("expected 1 host in infra subnet, got %d", len(hosts))
	}
}

func TestAppendShadowHost(t *testing.T) {
	topo := NewTopology(testTopologyConfig())
	initialCount := topo.HostCount()

	shadow := VirtualHost{
		IP:       "192.168.57.99",
		Hostname: "shadow-box",
		Role:     "shadow",
		OS:       "Ubuntu 22.04",
		SubnetID: "app",
	}
	topo.AppendShadowHost(shadow)

	if topo.HostCount() != initialCount+1 {
		t.Errorf("expected %d hosts after append, got %d", initialCount+1, topo.HostCount())
	}

	h := topo.GetHost("192.168.57.99")
	if h == nil {
		t.Fatal("expected shadow host to be retrievable")
	}
	if !h.IsShadow {
		t.Error("expected IsShadow=true for shadow host")
	}
	if h.Hostname != "shadow-box" {
		t.Errorf("expected shadow-box hostname, got %s", h.Hostname)
	}
}

func TestAllHosts(t *testing.T) {
	topo := NewTopology(testTopologyConfig())

	all := topo.AllHosts()
	if len(all) != 5 {
		t.Errorf("expected 5 hosts in AllHosts, got %d", len(all))
	}
}

func TestEvidenceSet(t *testing.T) {
	es := NewEvidenceSet()

	if es.Count() != 0 {
		t.Error("new EvidenceSet should be empty")
	}
	if es.Has("any") {
		t.Error("empty EvidenceSet should not have any token")
	}

	es.Add("subnet_scan")
	if !es.Has("subnet_scan") {
		t.Error("should have subnet_scan after Add")
	}
	if es.Count() != 1 {
		t.Errorf("expected 1 token, got %d", es.Count())
	}

	// Duplicate add should be idempotent
	es.Add("subnet_scan")
	if es.Count() != 1 {
		t.Errorf("expected still 1 token after duplicate add, got %d", es.Count())
	}

	es.Add("db_probe")
	if es.Count() != 2 {
		t.Errorf("expected 2 tokens, got %d", es.Count())
	}

	tokens := es.AllTokens()
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens in AllTokens, got %d", len(tokens))
	}
}

func TestEvidenceSetNil(t *testing.T) {
	var es *EvidenceSet
	if es.Has("any") {
		t.Error("nil EvidenceSet.Has should return false")
	}
	if es.Count() != 0 {
		t.Error("nil EvidenceSet.Count should return 0")
	}
	if es.AllTokens() != nil {
		t.Error("nil EvidenceSet.AllTokens should return nil")
	}
	// Add on nil should not panic
	es.Add("test")
}

func TestSessionContext(t *testing.T) {
	session := &SessionContext{
		SessionID:     "test:123",
		RemoteIP:      "10.0.0.1",
		Username:      "admin",
		SubnetLocalIP: "192.168.56.20",
		Evidence:      NewEvidenceSet(),
		ConnectedAt:   1000,
		LastActive:    2000,
	}

	if session.SessionID != "test:123" {
		t.Errorf("expected test:123, got %s", session.SessionID)
	}
	if session.Evidence.Count() != 0 {
		t.Error("new session should have empty evidence")
	}
}
