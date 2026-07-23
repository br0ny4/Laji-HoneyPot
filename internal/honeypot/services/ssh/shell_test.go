package ssh

import (
	"strings"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/domain"
)

func testTopology() *domain.VirtualTopology {
	return domain.NewTopology(domain.TopologyConfig{
		Segments: []domain.Segment{
			{ID: "web", CIDR: "192.168.56.0/24", Gateway: "192.168.56.1"},
			{ID: "app", CIDR: "192.168.57.0/24", Gateway: "192.168.57.1"},
		},
		Hosts: []domain.VirtualHost{
			{
				IP: "192.168.56.20", Hostname: "jumpbox", Role: "jumpbox",
				OS: "CentOS 7", SubnetID: "web",
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", ProcessName: "sshd"},
				},
			},
			{
				IP: "192.168.56.10", Hostname: "web-prod-01", Role: "web",
				OS: "Ubuntu 22.04 LTS", SubnetID: "web",
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", ProcessName: "sshd"},
					{Port: 80, Protocol: "http", ProcessName: "nginx"},
					{Port: 443, Protocol: "https", ProcessName: "nginx"},
				},
			},
			{
				IP: "192.168.57.10", Hostname: "db-master-01", Role: "db",
				OS: "CentOS 7", SubnetID: "app",
				VisibleAfter: []string{"subnet_scan"},
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", ProcessName: "sshd"},
					{Port: 3306, Protocol: "mysql", ProcessName: "mysqld"},
				},
			},
			{
				IP: "192.168.57.20", Hostname: "app-node-01", Role: "app",
				OS: "Ubuntu 20.04 LTS", SubnetID: "app",
				VisibleAfter: []string{"subnet_scan"},
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", ProcessName: "sshd"},
					{Port: 3000, Protocol: "http", ProcessName: "node"},
				},
			},
		},
	})
}

func TestShellSimulatorPrompt(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")

	prompt := shell.Prompt()
	if !strings.Contains(prompt, "ops@jumpbox") {
		t.Errorf("expected ops@jumpbox prompt, got: %s", prompt)
	}
}

func TestShellSimulatorWhoami(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("whoami", session)
	if !strings.Contains(out, "ops") {
		t.Errorf("expected 'ops' in whoami output, got: %s", out)
	}
}

func TestShellSimulatorHostname(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("hostname", session)
	if !strings.Contains(out, "jumpbox") {
		t.Errorf("expected 'jumpbox' in hostname output, got: %s", out)
	}
}

func TestShellSimulatorUname(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	tests := []struct {
		cmd  string
		want string
	}{
		{"uname", "Linux\n"},
		{"uname -a", "Linux web-prod-01 5.15.0-91-generic"},
		{"uname -r", "5.15.0-91-generic\n"},
		{"uname -s", "Linux\n"},
		{"uname -n", "web-prod-01\n"},
	}

	for _, tt := range tests {
		out := shell.Handle(tt.cmd, session)
		if !strings.Contains(out, tt.want) {
			t.Errorf("cmd=%q: expected output containing %q, got %q", tt.cmd, tt.want, out)
		}
	}
}

func TestShellSimulatorLs(t *testing.T) {
	topo := testTopology()

	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.56.10", "public_html"},   // web role
		{"192.168.57.10", ".my.cnf"},        // db role
		{"192.168.56.20", ".bash_history"},  // jumpbox
	}

	for _, tt := range tests {
		shell := NewShellSimulator(topo, tt.ip)
		session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}
		out := shell.Handle("ls", session)
		if !strings.Contains(out, tt.want) {
			t.Errorf("ip=%q: expected %q in ls output, got %q", tt.ip, tt.want, out)
		}
	}
}

func TestShellSimulatorCatHosts(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("cat /etc/hosts", session)
	if !strings.Contains(out, "jumpbox") {
		t.Errorf("expected 'jumpbox' in hosts output")
	}
	if !strings.Contains(out, "web-prod-01") {
		t.Errorf("expected 'web-prod-01' in hosts output")
	}
	if !strings.Contains(out, "db-master-01") {
		t.Errorf("expected 'db-master-01' in hosts output, got:\n%s", out)
	}
}

func TestShellSimulatorCatPasswd(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("cat /etc/passwd", session)
	if !strings.Contains(out, "ops:x:1000:1000") {
		t.Errorf("expected ops user in passwd, got: %s", out)
	}
}

func TestShellSimulatorCatShadow(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("cat /etc/shadow", session)
	if !strings.Contains(out, "Permission denied") {
		t.Errorf("expected permission denied, got: %s", out)
	}
}

func TestShellSimulatorCatEnv(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("cat .env", session)
	if !strings.Contains(out, "DB_HOST=192.168.57.10") {
		t.Errorf("expected DB_HOST in env output, got: %s", out)
	}
	if !strings.Contains(out, "JWT_SECRET") {
		t.Errorf("expected JWT_SECRET in env output")
	}
}

func TestShellSimulatorNetstat(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("netstat -tlnp", session)
	if !strings.Contains(out, "0.0.0.0:22") {
		t.Errorf("expected port 22 in netstat, got: %s", out)
	}
	if !strings.Contains(out, "0.0.0.0:80") {
		t.Errorf("expected port 80 in netstat")
	}
}

func TestShellSimulatorArpWithEvidenceGate(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")

	// Without evidence: only hosts without VisibleAfter or the local host
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}
	out := shell.Handle("arp -an", session)
	// web-prod-01 (no gate) should be visible
	if !strings.Contains(out, "192.168.56.10") {
		t.Errorf("expected 192.168.56.10 in arp (no evidence gate), got:\n%s", out)
	}
	// db-master-01 (needs subnet_scan) should NOT be visible
	if strings.Contains(out, "192.168.57.10") {
		t.Errorf("db-master-01 should NOT be visible without evidence token")
	}

	// With evidence: grant subnet_scan
	session.Evidence.Add("subnet_scan")
	out = shell.Handle("arp -an", session)
	if !strings.Contains(out, "192.168.57.10") {
		t.Errorf("expected 192.168.57.10 in arp after granting subnet_scan token")
	}
}

func TestShellSimulatorPs(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("ps aux", session)
	if !strings.Contains(out, "sshd") {
		t.Errorf("expected sshd in ps output")
	}
	if !strings.Contains(out, "nginx") {
		t.Errorf("expected nginx in ps output, got:\n%s", out)
	}
}

func TestShellSimulatorExit(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("exit", session)
	if !strings.Contains(out, "logout") {
		t.Errorf("expected logout on exit, got: %s", out)
	}
}

func TestShellSimulatorUnknownCommand(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("foobar123", session)
	if !strings.Contains(out, "command not found") {
		t.Errorf("expected 'command not found', got: %s", out)
	}
}

func TestShellSimulatorIPAddr(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("ip addr", session)
	if !strings.Contains(out, "192.168.56.20/24") {
		t.Errorf("expected local IP in ip addr output, got:\n%s", out)
	}
	if !strings.Contains(out, "eth0") {
		t.Errorf("expected eth0 interface")
	}
}

func TestShellSimulatorEmptyInput(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("", session)
	if out != "" {
		t.Errorf("expected empty output for empty input, got: %s", out)
	}

	out = shell.Handle("  ", session)
	if out != "" {
		t.Errorf("expected empty output for whitespace, got: %s", out)
	}
}

func TestShellSimulatorTopologyNil(t *testing.T) {
	// Test with nil topology (fallback defaults)
	shell := &ShellSimulator{
		localIP:    "10.0.0.1",
		hostname:   "web-prod-01",
		osInfo:     "Ubuntu 22.04 LTS",
		promptUser: "admin",
		promptHost: "web-prod-01",
	}
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("whoami", session)
	if !strings.Contains(out, "admin") {
		t.Errorf("expected 'admin' from fallback shell, got: %s", out)
	}

	out = shell.Handle("ls", session)
	if !strings.Contains(out, ".bash_history") {
		t.Errorf("expected .bash_history in fallback ls, got: %s", out)
	}
}

func TestShellSimulatorIfconfig(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("ifconfig", session)
	if !strings.Contains(out, "192.168.56.20") {
		t.Errorf("expected local IP in ifconfig, got:\n%s", out)
	}
}

func TestShellSimulatorSudo(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.20")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("sudo su", session)
	if !strings.Contains(out, "password for ops") {
		t.Errorf("expected sudo password prompt, got: %s", out)
	}

	out = shell.Handle("sudo rm -rf /", session)
	if !strings.Contains(out, "not in the sudoers file") {
		t.Errorf("expected sudoers denial, got: %s", out)
	}
}

func TestShellSimulatorWebRoleLs(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.56.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("ls", session)
	if !strings.Contains(out, ".env") {
		t.Errorf("web role should have .env file, got: %s", out)
	}
	if !strings.Contains(out, "public_html") {
		t.Errorf("web role should have public_html, got: %s", out)
	}
}

func TestShellSimulatorDbRoleLs(t *testing.T) {
	topo := testTopology()
	shell := NewShellSimulator(topo, "192.168.57.10")
	session := &domain.SessionContext{Evidence: domain.NewEvidenceSet()}

	out := shell.Handle("ls", session)
	if !strings.Contains(out, ".my.cnf") {
		t.Errorf("db role should have .my.cnf, got: %s", out)
	}
}

func TestIPLast3Bytes(t *testing.T) {
	a, b, c := ipLast3Bytes("192.168.1.100")
	if a != 168 || b != 1 || c != 100 {
		t.Errorf("ipLast3Bytes(192.168.1.100) = (%d,%d,%d), want (168,1,100)", a, b, c)
	}

	a, b, c = ipLast3Bytes("10.0.0.1")
	if a != 0 || b != 0 || c != 1 {
		t.Errorf("ipLast3Bytes(10.0.0.1) = (%d,%d,%d), want (0,0,1)", a, b, c)
	}

	// Invalid IP
	a, b, c = ipLast3Bytes("invalid")
	if a != 0 || b != 0 || c != 0 {
		t.Errorf("ipLast3Bytes(invalid) should return zeros")
	}
}
