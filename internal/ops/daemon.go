package ops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// DaemonManager provides cross-platform background service management
type DaemonManager struct {
	BinaryPath  string
	ConfigPath  string
	DataDir     string
	ServiceName string // "laji-honeypot-agent"
}

// systemd unit template
const systemdUnitTemplate = `[Unit]
Description=Laji-HoneyPot Agent Node
After=network.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} --config {{.ConfigPath}}
Restart=always
RestartSec=10
StandardOutput=append:{{.DataDir}}/agent.log
StandardError=append:{{.DataDir}}/agent_error.log

[Install]
WantedBy=multi-user.target
`

// launchd plist template
const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>{{.ServiceName}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.BinaryPath}}</string>
		<string>--config</string><string>{{.ConfigPath}}</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardOutPath</key><string>{{.DataDir}}/agent.log</string>
	<key>StandardErrorPath</key><string>{{.DataDir}}/agent_error.log</string>
</dict>
</plist>
`

type daemonTemplateData struct {
	BinaryPath  string
	ConfigPath  string
	DataDir     string
	ServiceName string
}

// Install installs the agent as a background service
func (d *DaemonManager) Install() error {
	switch runtime.GOOS {
	case "linux":
		return d.installSystemd()
	case "darwin":
		return d.installLaunchd()
	case "windows":
		return d.installWindowsService()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Uninstall removes the background service
func (d *DaemonManager) Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return d.uninstallSystemd()
	case "darwin":
		return d.uninstallLaunchd()
	case "windows":
		return d.uninstallWindowsService()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Status returns the service status
func (d *DaemonManager) Status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return d.statusSystemd()
	case "darwin":
		return d.statusLaunchd()
	case "windows":
		return d.statusWindowsService()
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Restart restarts the service
func (d *DaemonManager) Restart() error {
	switch runtime.GOOS {
	case "linux":
		return d.restartSystemd()
	case "darwin":
		return d.restartLaunchd()
	case "windows":
		return d.restartWindowsService()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// ---------- systemd (Linux) ----------

func (d *DaemonManager) systemdUnitPath() string {
	return fmt.Sprintf("/etc/systemd/system/%s.service", d.ServiceName)
}

func (d *DaemonManager) installSystemd() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("systemd install requires root privileges")
	}

	tmpl, err := template.New("systemd").Parse(systemdUnitTemplate)
	if err != nil {
		return err
	}

	// Ensure data dir exists
	if err := os.MkdirAll(d.DataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	unitPath := d.systemdUnitPath()
	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("create unit file: %w", err)
	}
	defer f.Close()

	data := daemonTemplateData{
		BinaryPath:  d.BinaryPath,
		ConfigPath:  d.ConfigPath,
		DataDir:     d.DataDir,
		ServiceName: d.ServiceName,
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render unit template: %w", err)
	}

	// Reload systemd, enable and start
	commands := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", d.ServiceName},
		{"systemctl", "start", d.ServiceName},
	}
	for _, cmd := range commands {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w\nOutput: %s", strings.Join(cmd, " "), err, out)
		}
	}

	return nil
}

func (d *DaemonManager) uninstallSystemd() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("systemd uninstall requires root privileges")
	}

	commands := [][]string{
		{"systemctl", "stop", d.ServiceName},
		{"systemctl", "disable", d.ServiceName},
	}
	for _, cmd := range commands {
		exec.Command(cmd[0], cmd[1:]...).CombinedOutput() // ignore errors on stop/disable
	}

	os.Remove(d.systemdUnitPath())
	exec.Command("systemctl", "daemon-reload").CombinedOutput()
	return nil
}

func (d *DaemonManager) statusSystemd() (string, error) {
	out, err := exec.Command("systemctl", "is-active", d.ServiceName).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (d *DaemonManager) restartSystemd() error {
	return exec.Command("systemctl", "restart", d.ServiceName).Run()
}

// ---------- launchd (macOS) ----------

func (d *DaemonManager) launchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", d.ServiceName+".plist")
}

func (d *DaemonManager) installLaunchd() error {
	tmpl, err := template.New("launchd").Parse(launchdPlistTemplate)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(d.DataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	plistDir := filepath.Dir(d.launchdPlistPath())
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	f, err := os.Create(d.launchdPlistPath())
	if err != nil {
		return fmt.Errorf("create plist: %w", err)
	}
	defer f.Close()

	data := daemonTemplateData{
		BinaryPath:  d.BinaryPath,
		ConfigPath:  d.ConfigPath,
		DataDir:     d.DataDir,
		ServiceName: d.ServiceName,
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render plist template: %w", err)
	}

	// Unload first if exists, then load
	exec.Command("launchctl", "unload", d.launchdPlistPath()).CombinedOutput()
	if out, err := exec.Command("launchctl", "load", d.launchdPlistPath()).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %w\nOutput: %s", err, out)
	}

	return nil
}

func (d *DaemonManager) uninstallLaunchd() error {
	exec.Command("launchctl", "unload", d.launchdPlistPath()).CombinedOutput()
	os.Remove(d.launchdPlistPath())
	return nil
}

func (d *DaemonManager) statusLaunchd() (string, error) {
	out, err := exec.Command("launchctl", "list", d.ServiceName).CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return "", fmt.Errorf("not loaded: %s", output)
	}
	if strings.Contains(output, "Could not find service") {
		return "not_loaded", nil
	}
	return "running", nil
}

func (d *DaemonManager) restartLaunchd() error {
	plistPath := d.launchdPlistPath()
	exec.Command("launchctl", "unload", plistPath).CombinedOutput()
	return exec.Command("launchctl", "load", plistPath).Run()
}

// ---------- Windows Service (sc.exe) ----------

func (d *DaemonManager) installWindowsService() error {
	binPath := fmt.Sprintf(`"%s" --config "%s"`, d.BinaryPath, d.ConfigPath)

	out, err := exec.Command("sc", "create", d.ServiceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "Laji-HoneyPot Agent",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %w\nOutput: %s", err, out)
	}

	// Start the service
	exec.Command("sc", "start", d.ServiceName).CombinedOutput()
	return nil
}

func (d *DaemonManager) uninstallWindowsService() error {
	exec.Command("sc", "stop", d.ServiceName).CombinedOutput()
	out, err := exec.Command("sc", "delete", d.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete: %w\nOutput: %s", err, out)
	}
	return nil
}

func (d *DaemonManager) statusWindowsService() (string, error) {
	out, err := exec.Command("sc", "query", d.ServiceName).CombinedOutput()
	output := string(out)
	if err != nil {
		return "not_found", err
	}
	if strings.Contains(output, "RUNNING") {
		return "running", nil
	}
	if strings.Contains(output, "STOPPED") {
		return "stopped", nil
	}
	return "unknown", nil
}

func (d *DaemonManager) restartWindowsService() error {
	exec.Command("sc", "stop", d.ServiceName).CombinedOutput()
	return exec.Command("sc", "start", d.ServiceName).Run()
}
