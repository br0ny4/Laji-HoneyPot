package intent

import "testing"

func TestAnalyzeNetworkScan(t *testing.T) {
	tests := []struct {
		input    string
		expected Category
		minConf  float64
	}{
		{"nmap -sV 192.168.1.1", NetworkScan, 0.90},
		{"nmap -A 10.0.0.0/24", NetworkScan, 0.90},
		{"fscan -h 192.168.56.0/24", NetworkScan, 0.90},
		{"ping 192.168.1.1", NetworkScan, 0.75},
		{"traceroute 8.8.8.8", NetworkScan, 0.80},
		{"masscan -p1-65535 10.0.0.0/8", NetworkScan, 0.90},
	}

	for _, tt := range tests {
		result := Analyze(tt.input)
		if result.Category != tt.expected {
			t.Errorf("Analyze(%q) category = %s, want %s", tt.input, result.Category, tt.expected)
		}
		if result.Confidence < tt.minConf {
			t.Errorf("Analyze(%q) confidence = %.2f, want >= %.2f", tt.input, result.Confidence, tt.minConf)
		}
	}
}

func TestAnalyzeHTTPProbe(t *testing.T) {
	tests := []struct {
		input    string
		expected Category
	}{
		{"curl http://192.168.1.1/admin", HTTPProbe},
		{"wget https://example.com/backup.zip", HTTPProbe},
		{"gobuster dir -u http://target.com -w wordlist.txt", HTTPProbe},
		{"nikto -h http://192.168.1.1", HTTPProbe},
		{"ffuf -u http://target/FUZZ -w wordlist.txt", HTTPProbe},
		{"/admin/config.php", HTTPProbe},
		{"/wp-admin/install.php", HTTPProbe},
		{"/actuator/env", HTTPProbe},
		{"/shell.jsp", HTTPProbe},
		{"/cmd.jsp", HTTPProbe},
	}

	for _, tt := range tests {
		result := Analyze(tt.input)
		if result.Category != tt.expected {
			t.Errorf("Analyze(%q) category = %s, want %s", tt.input, result.Category, tt.expected)
		}
	}
}

func TestAnalyzeDBProbe(t *testing.T) {
	tests := []string{
		"mysql -h 192.168.1.1 -u root -p",
		"mysqldump -u admin -p database > dump.sql",
		"mysqladmin -u root -p status",
		"redis-cli -h 10.0.0.1 ping",
		"psql -h 192.168.1.1 -U postgres",
		"/phpmyadmin/index.php",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != DBProbe {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, DBProbe)
		}
	}
}

func TestAnalyzeLateralMovement(t *testing.T) {
	tests := []string{
		"ssh 192.168.56.31",
		"ssh root@192.168.1.100",
		"scp file.txt target:/tmp/",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != LateralMovement {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, LateralMovement)
		}
	}
}

func TestAnalyzePrivilegeEscalation(t *testing.T) {
	tests := []string{
		"sudo su",
		"su root",
		"chmod +s /bin/bash",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != PrivilegeEscalation {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, PrivilegeEscalation)
		}
	}
}

func TestAnalyzeEvidenceSearch(t *testing.T) {
	tests := []string{
		"cat .env",
		"cat /etc/shadow",
		"grep password *",
		"grep secret config/*",
		"find / -name *.key",
		"cat .git/config",
		"cat .kube/config",
		"/.git/config",
		"/.env",
		"/etc/passwd",
		"/backup/database.sql",
		"/.aws/credentials",
		"/swagger-ui.html",
		"/v2/api-docs",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != EvidenceSearch {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, EvidenceSearch)
		}
	}
}

func TestAnalyzeDomainProbe(t *testing.T) {
	tests := []string{
		"ldapsearch -x -h 192.168.1.1",
		"smbclient //192.168.1.1/share",
		"rpcclient -U admin 192.168.1.1",
		"enum4linux 192.168.1.1",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != DomainProbe {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, DomainProbe)
		}
	}
}

func TestAnalyzeDataExfiltration(t *testing.T) {
	tests := []string{
		"base64 /etc/passwd",
		"tar -czf data.tar.gz /var/www/",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != DataExfiltration {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, DataExfiltration)
		}
	}
}

func TestAnalyzeShellCommand(t *testing.T) {
	tests := []string{
		"ls -la",
		"whoami",
		"pwd",
		"ps aux",
	}

	for _, input := range tests {
		result := Analyze(input)
		if result.Category != ShellCommand {
			t.Errorf("Analyze(%q) category = %s, want %s", input, result.Category, ShellCommand)
		}
	}
}

func TestAnalyzeTargetIP(t *testing.T) {
	result := Analyze("ssh root@192.168.56.31")
	if result.TargetIP != "192.168.56.31" {
		t.Errorf("expected target IP 192.168.56.31, got %q", result.TargetIP)
	}

	result = Analyze("curl http://10.0.0.1/api")
	if result.TargetIP != "10.0.0.1" {
		t.Errorf("expected target IP 10.0.0.1, got %q", result.TargetIP)
	}
}

func TestTagName(t *testing.T) {
	tests := map[Category]string{
		NetworkScan:         "网络扫描",
		LateralMovement:     "横向移动",
		PrivilegeEscalation: "提权",
	}

	for cat, expected := range tests {
		if got := cat.TagName(); got != expected {
			t.Errorf("TagName(%s) = %s, want %s", cat, got, expected)
		}
	}
}
