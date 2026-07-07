package cluster

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCompiler(t *testing.T) {
	projectDir := "/tmp/test-project"
	c := NewCompiler(projectDir)

	if c.projectDir != projectDir {
		t.Errorf("expected projectDir %q, got %q", projectDir, c.projectDir)
	}

	expectedOutputDir := filepath.Join(projectDir, "data", "agents")
	if c.outputDir != expectedOutputDir {
		t.Errorf("expected outputDir %q, got %q", expectedOutputDir, c.outputDir)
	}

	if c.jobs == nil {
		t.Error("jobs map should be initialized")
	}
	if len(c.jobs) != 0 {
		t.Errorf("jobs map should be empty, got %d entries", len(c.jobs))
	}
}

func TestCompile(t *testing.T) {
	// 获取项目根目录 (test 文件位于 internal/cluster/, 项目根在上两级)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	projectDir := filepath.Join(cwd, "..", "..")

	// 确保 cmd/honeypot/ 存在
	if _, err := os.Stat(filepath.Join(projectDir, "cmd", "honeypot", "main.go")); err != nil {
		t.Skipf("skipping compile test: %v (run from project root)", err)
	}

	c := NewCompiler(projectDir)

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			NodeName:    "test-node",
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	result, err := c.Compile(req)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	// 验证初始状态字段
	if result.JobID == "" {
		t.Error("JobID should not be empty")
	}
	if !strings.HasPrefix(result.JobID, "agent-") {
		t.Errorf("JobID should start with 'agent-', got %q", result.JobID)
	}
	if result.Status != "compiling" {
		t.Errorf("initial status should be 'compiling', got %q", result.Status)
	}
	if result.Progress != 0 {
		t.Errorf("initial progress should be 0, got %d", result.Progress)
	}
	if result.OSTarget != "linux" {
		t.Errorf("OSTarget should be 'linux', got %q", result.OSTarget)
	}
	if result.GOARCH != "amd64" {
		t.Errorf("GOARCH should be 'amd64', got %q", result.GOARCH)
	}
	if result.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}

	// 轮询等待编译完成
	jobID := result.JobID
	var finalResult *CompileResult
	deadline := time.After(120 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-deadline:
			t.Fatal("compile timed out")
		case <-ticker.C:
			r := c.GetJob(jobID)
			if r == nil {
				t.Fatal("job not found during polling")
			}
			if r.Status == "complete" || r.Status == "failed" {
				finalResult = r
				break loop
			}
		}
	}

	if finalResult.Status != "complete" {
		t.Fatalf("compile failed: %s", finalResult.Error)
	}

	// 验证完成后的字段
	if finalResult.Progress != 100 {
		t.Errorf("final progress should be 100, got %d", finalResult.Progress)
	}
	if finalResult.BinaryName != "honeypot-agent" {
		t.Errorf("BinaryName should be 'honeypot-agent', got %q", finalResult.BinaryName)
	}
	if finalResult.BinarySize <= 0 {
		t.Errorf("BinarySize should be > 0, got %d", finalResult.BinarySize)
	}
	if finalResult.PackageSize <= 0 {
		t.Errorf("PackageSize should be > 0, got %d", finalResult.PackageSize)
	}
	if !strings.HasSuffix(finalResult.PackageName, ".tar.gz") {
		t.Errorf("PackageName should end with .tar.gz, got %q", finalResult.PackageName)
	}
	if finalResult.PackagePath == "" {
		t.Error("PackagePath should not be empty")
	}
	if finalResult.Duration <= 0 {
		t.Errorf("Duration should be > 0, got %f", finalResult.Duration)
	}
	if finalResult.FinishedAt == nil {
		t.Error("FinishedAt should be set")
	}
	if len(finalResult.Files) == 0 {
		t.Error("Files should not be empty")
	}
	if len(finalResult.Commands) == 0 {
		t.Error("Commands should not be empty")
	}

	// 验证 Files 包含必要文件
	fileNames := make(map[string]bool)
	for _, f := range finalResult.Files {
		fileNames[f.Name] = true
	}
	if !fileNames["honeypot-agent"] {
		t.Error("Files should contain honeypot-agent")
	}
	if !fileNames["config.yaml"] {
		t.Error("Files should contain config.yaml")
	}

	// 验证部署命令
	hasDeployStep := false
	for _, cmd := range finalResult.Commands {
		if strings.Contains(cmd.Command, "deploy.sh") || strings.Contains(cmd.Command, "sudo bash") {
			hasDeployStep = true
		}
	}
	if !hasDeployStep {
		t.Error("Commands should include deploy.sh step")
	}

	// 清理
	c.CleanJob(jobID)
}

func TestCompileWindows(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	projectDir := filepath.Join(cwd, "..", "..")

	if _, err := os.Stat(filepath.Join(projectDir, "cmd", "honeypot", "main.go")); err != nil {
		t.Skipf("skipping compile test: %v (run from project root)", err)
	}

	c := NewCompiler(projectDir)

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			OSTarget:    "windows",
		},
		GOARCH: "amd64",
	}

	result, err := c.Compile(req)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	jobID := result.JobID

	deadline := time.After(120 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var finalResult *CompileResult
loop:
	for {
		select {
		case <-deadline:
			t.Fatal("compile timed out")
		case <-ticker.C:
			r := c.GetJob(jobID)
			if r == nil {
				t.Fatal("job not found during polling")
			}
			if r.Status == "complete" || r.Status == "failed" {
				finalResult = r
				break loop
			}
		}
	}

	if finalResult.Status != "complete" {
		t.Fatalf("windows compile failed: %s", finalResult.Error)
	}

	if finalResult.BinaryName != "honeypot-agent.exe" {
		t.Errorf("windows BinaryName should be 'honeypot-agent.exe', got %q", finalResult.BinaryName)
	}
	if !strings.HasSuffix(finalResult.PackageName, ".zip") {
		t.Errorf("windows PackageName should end with .zip, got %q", finalResult.PackageName)
	}

	c.CleanJob(jobID)
}

func TestGetJob(t *testing.T) {
	c := NewCompiler("/tmp/test")

	// 不存在的 job 应返回 nil
	if c.GetJob("nonexistent") != nil {
		t.Error("GetJob for nonexistent job should return nil")
	}

	// 手动插入一个 job 并验证获取
	job := &CompileResult{
		JobID:  "test-job-123",
		Status: "compiling",
	}
	c.mu.Lock()
	c.jobs[job.JobID] = job
	c.mu.Unlock()

	retrieved := c.GetJob("test-job-123")
	if retrieved == nil {
		t.Fatal("GetJob should return the job")
	}
	if retrieved.JobID != "test-job-123" {
		t.Errorf("expected JobID 'test-job-123', got %q", retrieved.JobID)
	}
	if retrieved.Status != "compiling" {
		t.Errorf("expected status 'compiling', got %q", retrieved.Status)
	}

	// 验证仍然可以获取不存在的 job
	if c.GetJob("still-nonexistent") != nil {
		t.Error("GetJob for nonexistent job should return nil")
	}
}

func TestBuildAgentConfig(t *testing.T) {
	c := NewCompiler("/tmp/test")
	tmpDir := t.TempDir()

	// 创建临时证书文件, 确保 os.Stat 返回 nil
	certPath := filepath.Join(tmpDir, "agent-cert.pem")
	keyPath := filepath.Join(tmpDir, "agent-key.pem")
	caCertPath := filepath.Join(tmpDir, "ca-cert.pem")
	os.WriteFile(certPath, []byte("fake-cert"), 0644)
	os.WriteFile(keyPath, []byte("fake-key"), 0644)
	os.WriteFile(caCertPath, []byte("fake-ca"), 0644)

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "192.168.1.1:8443",
			Scenario:    "database",
			NodeName:    "db-node-01",
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, certPath, keyPath, caCertPath)

	// 验证关键字段
	checks := []struct {
		field string
		want  string
	}{
		{"节点名注释", "# 节点名: db-node-01"},
		{"目标平台", "# 目标平台: linux/amd64"},
		{"trap_scenario", `trap_scenario: "database"`},
		{"manager_addr", `manager_addr: "192.168.1.1:8443"`},
		{"role", `role: "node"`},
		{"tls_insecure", `tls_insecure: false`},
		{"cert_file", `cert_file: "/opt/honeypot/agent-cert.pem"`},
		{"key_file", `key_file: "/opt/honeypot/agent-key.pem"`},
		{"ca_file", `ca_file: "/opt/honeypot/ca-cert.pem"`},
		{"http_port", `http_port: 8081`},
		{"mysql_port", `mysql_port: 3306`},
		{"redis_port", `redis_port: 6379`},
		{"ssh_port", `ssh_port: 2222`},
		{"data_dir", `data_dir: "./data"`},
	}

	for _, ck := range checks {
		if !strings.Contains(config, ck.want) {
			t.Errorf("config missing %q (expected: %q)", ck.field, ck.want)
		}
	}
}

func TestBuildAgentConfig_TLSInsecure(t *testing.T) {
	c := NewCompiler("/tmp/test")
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "agent-cert.pem")
	keyPath := filepath.Join(tmpDir, "agent-key.pem")
	caCertPath := filepath.Join(tmpDir, "ca-cert.pem")
	os.WriteFile(certPath, []byte("fake-cert"), 0644)
	os.WriteFile(keyPath, []byte("fake-key"), 0644)
	os.WriteFile(caCertPath, []byte("fake-ca"), 0644)

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			TLSInsecure: true,
			OSTarget:    "linux",
		},
		GOARCH: "arm64",
	}

	config := c.buildAgentConfig(req, certPath, keyPath, caCertPath)

	if !strings.Contains(config, `tls_insecure: true`) {
		t.Error("config should contain tls_insecure: true")
	}
	if !strings.Contains(config, `# 目标平台: linux/arm64`) {
		t.Error("config should contain arm64 GOARCH")
	}
}

func TestBuildAgentConfig_Windows(t *testing.T) {
	c := NewCompiler("/tmp/test")
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "agent-cert.pem")
	keyPath := filepath.Join(tmpDir, "agent-key.pem")
	caCertPath := filepath.Join(tmpDir, "ca-cert.pem")
	os.WriteFile(certPath, []byte("fake-cert"), 0644)
	os.WriteFile(keyPath, []byte("fake-key"), 0644)
	os.WriteFile(caCertPath, []byte("fake-ca"), 0644)

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "remote_access",
			OSTarget:    "windows",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, certPath, keyPath, caCertPath)

	if !strings.Contains(config, `# 目标平台: windows/amd64`) {
		t.Error("config should contain windows target platform")
	}
	if !strings.Contains(config, `data_dir: "C:\Program Files\Honeypot\data"`) {
		t.Error("windows config should contain Program Files data dir")
	}
	if !strings.Contains(config, `cert_file: "C:\\Program Files\\Honeypot\\agent-cert.pem"`) {
		t.Error("windows config should contain Windows cert paths")
	}
	if !strings.Contains(config, `trap_scenario: "remote_access"`) {
		t.Error("config should contain remote_access scenario")
	}
}

func TestBuildAgentConfig_NoCertFiles(t *testing.T) {
	c := NewCompiler("/tmp/test")

	// 使用不存在的证书路径
	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, "/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")

	if !strings.Contains(config, `cert_file: ""`) {
		t.Error("config should have empty cert_file when cert is missing")
	}
	if !strings.Contains(config, `key_file: ""`) {
		t.Error("config should have empty key_file when cert is missing")
	}
	if !strings.Contains(config, `ca_file: ""`) {
		t.Error("config should have empty ca_file when cert is missing")
	}
}

func TestBuildAgentConfig_CustomServices(t *testing.T) {
	c := NewCompiler("/tmp/test")

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr:    "10.0.0.1:8443",
			Scenario:       "custom",
			CustomServices: []string{"http", "ssh", "mysql"},
			OSTarget:       "linux",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, "/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")

	if !strings.Contains(config, "custom_services") {
		t.Error("config should contain custom_services section")
	}
	if !strings.Contains(config, "- http") {
		t.Error("config should list http in custom_services")
	}
	if !strings.Contains(config, "- ssh") {
		t.Error("config should list ssh in custom_services")
	}
	if !strings.Contains(config, "- mysql") {
		t.Error("config should list mysql in custom_services")
	}
}

func TestBuildAgentConfig_EmptyScenarioDefaultsToFull(t *testing.T) {
	c := NewCompiler("/tmp/test")

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "", // empty should default to "full"
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, "/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")

	if !strings.Contains(config, `trap_scenario: "full"`) {
		t.Errorf("empty scenario should default to 'full', got config:\n%s", config)
	}
}

func TestBuildAgentConfig_DefaultNodeName(t *testing.T) {
	c := NewCompiler("/tmp/test")

	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			NodeName:    "", // empty should default to "agent-node"
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	config := c.buildAgentConfig(req, "/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")

	if !strings.Contains(config, "agent-node") {
		t.Error("config should contain default node name 'agent-node'")
	}
}

func TestBuildDeployCommands_Linux(t *testing.T) {
	c := NewCompiler("/tmp/test")

	req := AgentDeployRequest{
		ManagerAddr: "192.168.1.100:8443",
		OSTarget:    "linux",
	}

	commands := c.buildDeployCommands(req, "honeypot-agent", "honeypot-agent-linux-amd64.tar.gz", "agent-test")

	if len(commands) == 0 {
		t.Fatal("should generate commands for linux")
	}

	// 验证步骤计数正确
	if len(commands) != 5 {
		t.Errorf("linux should have 5 deploy commands, got %d", len(commands))
	}

	// 验证各步骤
	if commands[0].Step != 1 || commands[0].Title != "下载部署包" {
		t.Errorf("step 1 mismatch: Step=%d, Title=%q", commands[0].Step, commands[0].Title)
	}
	if !strings.Contains(commands[0].Command, "curl -o") {
		t.Error("step 1 should use curl")
	}
	if !strings.Contains(commands[0].Command, "192.168.1.100:8443") {
		t.Error("step 1 should contain manager address")
	}
	if !strings.Contains(commands[0].Command, "honeypot-agent-linux-amd64.tar.gz") {
		t.Error("step 1 should contain package name")
	}

	if commands[1].Step != 2 || commands[1].Title != "解压部署包" {
		t.Errorf("step 2 mismatch")
	}
	if !strings.Contains(commands[1].Command, "tar xzf") {
		t.Error("step 2 should use tar xzf")
	}

	if commands[2].Step != 3 || commands[2].Title != "以 root 权限运行部署脚本" {
		t.Errorf("step 3 mismatch")
	}
	if !strings.Contains(commands[2].Command, "sudo bash") {
		t.Error("step 3 should use sudo bash")
	}
	if !strings.Contains(commands[2].Command, "deploy.sh") {
		t.Error("step 3 should reference deploy.sh")
	}

	if commands[3].Step != 4 {
		t.Errorf("step 4 mismatch: Step=%d", commands[3].Step)
	}
	if !strings.Contains(commands[3].Command, "systemctl status") {
		t.Error("step 4 should check systemctl status")
	}

	if commands[4].Step != 5 || commands[4].Title != "查看实时日志" {
		t.Errorf("step 5 mismatch")
	}
	if !strings.Contains(commands[4].Command, "journalctl") {
		t.Error("step 5 should use journalctl")
	}
}

func TestBuildDeployCommands_Windows(t *testing.T) {
	c := NewCompiler("/tmp/test")

	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		OSTarget:    "windows",
	}

	commands := c.buildDeployCommands(req, "honeypot-agent.exe", "honeypot-agent-windows-amd64.zip", "agent-test-win")

	if len(commands) != 4 {
		t.Errorf("windows should have 4 deploy commands, got %d", len(commands))
	}

	if commands[0].Step != 1 {
		t.Errorf("step 1 mismatch: Step=%d", commands[0].Step)
	}
	if !strings.Contains(commands[0].Command, "curl -o") {
		t.Error("step 1 should use curl")
	}
	if !strings.Contains(commands[0].Command, "honeypot-agent-windows-amd64.zip") {
		t.Error("step 1 should contain package name")
	}

	if commands[1].Step != 2 || commands[1].Title != "解压部署包" {
		t.Errorf("step 2 mismatch")
	}
	if !strings.Contains(commands[1].Command, "Expand-Archive") {
		t.Error("step 2 should use Expand-Archive")
	}

	if commands[2].Step != 3 {
		t.Errorf("step 3 mismatch")
	}
	if !strings.Contains(commands[2].Command, "deploy.ps1") {
		t.Error("step 3 should reference deploy.ps1")
	}

	if commands[3].Step != 4 {
		t.Errorf("step 4 mismatch")
	}
	if !strings.Contains(commands[3].Command, "sc.exe query") {
		t.Error("step 4 should use sc.exe query")
	}
}

func TestPackTarGz(t *testing.T) {
	c := NewCompiler("/tmp/test")

	// 创建临时源目录
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// 创建一些测试文件
	testFiles := map[string]string{
		"hello.txt":       "Hello, World!",
		"config.yaml":     "key: value\nport: 8080",
		"subdir/data.bin": string(make([]byte, 1024)),
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(srcDir, path)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("write test file: %v", err)
		}
	}

	// 打包输出到 srcDir 外部的路径
	outputPath := filepath.Join(dstDir, "test.tar.gz")
	if err := c.packTarGz(srcDir, outputPath); err != nil {
		t.Fatalf("packTarGz failed: %v", err)
	}

	// 验证输出文件存在
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Error("tar.gz file should not be empty")
	}

	// 验证 tar.gz 内容
	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("open tar.gz: %v", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	foundFiles := make(map[string]bool)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		foundFiles[header.Name] = true

		// 读取内容验证
		content, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("read tar entry: %v", err)
		}

		if expected, ok := testFiles[header.Name]; ok {
			if string(content) != expected {
				t.Errorf("file %q content mismatch", header.Name)
			}
		}
	}

	// 验证所有文件都在存档中
	for path := range testFiles {
		if !foundFiles[path] {
			t.Errorf("file %q not found in tar.gz", path)
		}
	}

	// 验证目录不在存档中（仅文件）
	if foundFiles["subdir"] {
		t.Error("directories should not be in tar.gz")
	}
}

func TestPackZip(t *testing.T) {
	c := NewCompiler("/tmp/test")

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// 创建测试文件
	testFiles := map[string]string{
		"readme.md":     "# Test\nThis is a test.",
		"config.yaml":   "setting: enabled",
		"lib/helper.go": "package helper\n",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(srcDir, path)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("write test file: %v", err)
		}
	}

	outputPath := filepath.Join(dstDir, "test.zip")
	if err := c.packZip(srcDir, outputPath); err != nil {
		t.Fatalf("packZip failed: %v", err)
	}

	// 验证输出文件存在
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Error("zip file should not be empty")
	}

	// 验证 zip 内容
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer reader.Close()

	foundFiles := make(map[string]bool)
	for _, f := range reader.File {
		// zip 中的路径使用反斜杠（packZip 内部做了 ReplaceAll）
		name := strings.ReplaceAll(f.Name, "\\", "/")
		foundFiles[name] = true

		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry: %v", err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read zip entry: %v", err)
		}

		if expected, ok := testFiles[name]; ok {
			if string(content) != expected {
				t.Errorf("file %q content mismatch in zip", name)
			}
		}
	}

	for path := range testFiles {
		if !foundFiles[path] {
			t.Errorf("file %q not found in zip", path)
		}
	}
}

func TestPackTarGzEmptyDir(t *testing.T) {
	c := NewCompiler("/tmp/test")

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	outputPath := filepath.Join(dstDir, "empty.tar.gz")
	if err := c.packTarGz(srcDir, outputPath); err != nil {
		t.Fatalf("packTarGz on empty dir should not fail: %v", err)
	}

	// 验证文件存在但只有 gzip 头部
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Error("even empty dir should produce a valid gzip file")
	}
}

func TestPackZipEmptyDir(t *testing.T) {
	c := NewCompiler("/tmp/test")

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	outputPath := filepath.Join(dstDir, "empty.zip")
	if err := c.packZip(srcDir, outputPath); err != nil {
		t.Fatalf("packZip on empty dir should not fail: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Error("even empty dir should produce a valid zip file")
	}
}

func TestCompileFailedWhenBuildFails(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	projectDir := filepath.Join(cwd, "..", "..")

	if _, err := os.Stat(filepath.Join(projectDir, "cmd", "honeypot", "main.go")); err != nil {
		t.Skipf("skipping compile test: %v (run from project root)", err)
	}

	c := NewCompiler(projectDir)

	// 使用无效的 GOOS/GOARCH 组合使 go build 失败
	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			OSTarget:    "invalid_os",
		},
		GOARCH: "invalid_arch",
	}

	result, err := c.Compile(req)
	if err != nil {
		t.Fatalf("Compile should not error immediately: %v", err)
	}

	if result.Status != "compiling" {
		t.Errorf("initial status should be 'compiling', got %q", result.Status)
	}

	jobID := result.JobID

	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var finalResult *CompileResult
loop:
	for {
		select {
		case <-deadline:
			t.Fatal("compile did not finish in time")
		case <-ticker.C:
			r := c.GetJob(jobID)
			if r == nil {
				t.Fatal("job not found")
			}
			if r.Status == "complete" || r.Status == "failed" {
				finalResult = r
				break loop
			}
		}
	}

	if finalResult.Status != "failed" {
		t.Fatalf("expected status 'failed' with invalid GOOS, got %q", finalResult.Status)
	}
	if finalResult.Error == "" {
		t.Error("Error should not be empty for failed compile")
	}
	if !strings.Contains(finalResult.Error, "cross-compile") {
		t.Errorf("Error should mention cross-compile, got: %s", finalResult.Error)
	}
	if finalResult.Duration <= 0 {
		t.Errorf("Duration should be > 0 even on failure, got %f", finalResult.Duration)
	}
	if finalResult.FinishedAt == nil {
		t.Error("FinishedAt should be set even on failure")
	}
}

func TestCompileDefaultOSTarget(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	projectDir := filepath.Join(cwd, "..", "..")

	if _, err := os.Stat(filepath.Join(projectDir, "cmd", "honeypot", "main.go")); err != nil {
		t.Skipf("skipping compile test: %v (run from project root)", err)
	}

	c := NewCompiler(projectDir)

	// 不指定 OSTarget 和 GOARCH，验证默认值
	req := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
		},
		// GOARCH 留空，默认 "amd64"
	}

	result, err := c.Compile(req)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	// 验证默认值
	if result.OSTarget != "linux" {
		t.Errorf("default OSTarget should be 'linux', got %q", result.OSTarget)
	}
	if result.GOARCH != "amd64" {
		t.Errorf("default GOARCH should be 'amd64', got %q", result.GOARCH)
	}

	// 等待完成
	jobID := result.JobID
	deadline := time.After(120 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var finalResult *CompileResult
loop:
	for {
		select {
		case <-deadline:
			t.Fatal("compile timed out")
		case <-ticker.C:
			r := c.GetJob(jobID)
			if r == nil {
				t.Fatal("job not found")
			}
			if r.Status == "complete" || r.Status == "failed" {
				finalResult = r
				break loop
			}
		}
	}

	if finalResult.Status != "complete" {
		t.Fatalf("compile with defaults failed: %s", finalResult.Error)
	}

	c.CleanJob(jobID)
}

func TestCompileMultipleJobs(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	projectDir := filepath.Join(cwd, "..", "..")

	if _, err := os.Stat(filepath.Join(projectDir, "cmd", "honeypot", "main.go")); err != nil {
		t.Skipf("skipping compile test: %v (run from project root)", err)
	}

	c := NewCompiler(projectDir)

	// 同时启动两个不同的编译任务
	req1 := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			NodeName:    "node-1",
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	req2 := CompileRequest{
		AgentDeployRequest: AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "database",
			NodeName:    "node-2",
			OSTarget:    "linux",
		},
		GOARCH: "amd64",
	}

	r1, err := c.Compile(req1)
	if err != nil {
		t.Fatalf("compile 1 failed: %v", err)
	}
	r2, err := c.Compile(req2)
	if err != nil {
		t.Fatalf("compile 2 failed: %v", err)
	}

	if r1.JobID == r2.JobID {
		t.Error("job IDs should be unique")
	}

	// 等待两个任务都完成
	deadline := time.After(180 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	complete1 := false
	complete2 := false

	for !complete1 || !complete2 {
		select {
		case <-deadline:
			t.Fatal("compile timed out")
		case <-ticker.C:
			if !complete1 {
				j1 := c.GetJob(r1.JobID)
				if j1 != nil && (j1.Status == "complete" || j1.Status == "failed") {
					complete1 = true
					if j1.Status != "complete" {
						t.Errorf("job 1 failed: %s", j1.Error)
					}
				}
			}
			if !complete2 {
				j2 := c.GetJob(r2.JobID)
				if j2 != nil && (j2.Status == "complete" || j2.Status == "failed") {
					complete2 = true
					if j2.Status != "complete" {
						t.Errorf("job 2 failed: %s", j2.Error)
					}
				}
			}
		}
	}

	// 验证两个任务都完整且独立
	final1 := c.GetJob(r1.JobID)
	final2 := c.GetJob(r2.JobID)

	if final1.BinarySize <= 0 {
		t.Error("job 1 binary size should be > 0")
	}
	if final2.BinarySize <= 0 {
		t.Error("job 2 binary size should be > 0")
	}

	c.CleanJob(r1.JobID)
	c.CleanJob(r2.JobID)
}
