//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// systemd unit template for Linux.
const systemdUnitTemplate = `[Unit]
Description=Laji-HoneyPot Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} agent run --config {{.ConfigPath}} --data {{.DataDir}}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
User=root

[Install]
WantedBy=multi-user.target
`

// launchd plist template for macOS.
const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>{{.ServiceName}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.BinaryPath}}</string>
		<string>agent</string>
		<string>run</string>
		<string>--config</string><string>{{.ConfigPath}}</string>
		<string>--data</string><string>{{.DataDir}}</string>
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

func (d *DaemonManager) install() error {
	switch runtime.GOOS {
	case "linux":
		return d.installSystemd()
	case "darwin":
		return d.installLaunchd()
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return d.uninstallSystemd()
	case "darwin":
		return d.uninstallLaunchd()
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return d.statusSystemd()
	case "darwin":
		return d.statusLaunchd()
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) start() error {
	switch runtime.GOOS {
	case "linux":
		return d.startSystemd()
	case "darwin":
		return d.startLaunchd()
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) stop() error {
	switch runtime.GOOS {
	case "linux":
		return d.stopSystemd()
	case "darwin":
		return d.stopLaunchd()
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) restart() error {
	switch runtime.GOOS {
	case "linux":
		return d.restartSystemd()
	case "darwin":
		return d.restartLaunchd()
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func (d *DaemonManager) isInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		return d.isInstalledSystemd()
	case "darwin":
		return d.isInstalledLaunchd()
	default:
		return false
	}
}

// ---------- systemd (Linux) ----------

func (d *DaemonManager) systemdUnitPath() string {
	return filepath.Join("/etc/systemd/system", d.ServiceName()+".service")
}

func (d *DaemonManager) installSystemd() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("systemd install requires root privileges")
	}

	tmpl, err := template.New("systemd").Parse(systemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("parse systemd template: %w", err)
	}

	if err := os.MkdirAll(d.dataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	unitPath := d.systemdUnitPath()
	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("create unit file: %w", err)
	}
	defer f.Close()

	data := daemonTemplateData{
		BinaryPath:  d.binPath,
		ConfigPath:  d.configPath,
		DataDir:     d.dataDir,
		ServiceName: d.ServiceName(),
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render unit template: %w", err)
	}

	d.logger.Infow("daemon: systemd unit written", "path", unitPath)

	// systemctl daemon-reload, enable, start
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", d.ServiceName()},
		{"systemctl", "start", d.ServiceName()},
	}
	for _, cmd := range cmds {
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w\nOutput: %s", strings.Join(cmd, " "), err, string(out))
		}
	}

	d.logger.Infow("daemon: systemd service installed and started", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) uninstallSystemd() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("systemd uninstall requires root privileges")
	}

	cmds := [][]string{
		{"systemctl", "stop", d.ServiceName()},
		{"systemctl", "disable", d.ServiceName()},
	}
	for _, cmd := range cmds {
		exec.Command(cmd[0], cmd[1:]...).CombinedOutput() // ignore errors
	}

	os.Remove(d.systemdUnitPath())
	exec.Command("systemctl", "daemon-reload").CombinedOutput()

	d.logger.Infow("daemon: systemd service uninstalled", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) statusSystemd() (string, error) {
	out, err := exec.Command("systemctl", "is-active", d.ServiceName()).CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil {
		return status, nil // "inactive" is not an error
	}
	return status, nil
}

func (d *DaemonManager) startSystemd() error {
	out, err := exec.Command("systemctl", "start", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) stopSystemd() error {
	out, err := exec.Command("systemctl", "stop", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) restartSystemd() error {
	out, err := exec.Command("systemctl", "restart", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) isInstalledSystemd() bool {
	_, err := os.Stat(d.systemdUnitPath())
	return err == nil
}

// ---------- launchd (macOS) ----------

func (d *DaemonManager) launchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", d.ServiceName()+".plist")
}

func (d *DaemonManager) installLaunchd() error {
	tmpl, err := template.New("launchd").Parse(launchdPlistTemplate)
	if err != nil {
		return fmt.Errorf("parse launchd template: %w", err)
	}

	if err := os.MkdirAll(d.dataDir, 0755); err != nil {
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
		BinaryPath:  d.binPath,
		ConfigPath:  d.configPath,
		DataDir:     d.dataDir,
		ServiceName: d.ServiceName(),
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render plist template: %w", err)
	}

	d.logger.Infow("daemon: launchd plist written", "path", d.launchdPlistPath())

	// Unload first if loaded, then load
	exec.Command("launchctl", "unload", d.launchdPlistPath()).CombinedOutput()
	out, err := exec.Command("launchctl", "load", d.launchdPlistPath()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w\nOutput: %s", err, string(out))
	}

	d.logger.Infow("daemon: launchd service installed and loaded", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) uninstallLaunchd() error {
	exec.Command("launchctl", "unload", d.launchdPlistPath()).CombinedOutput()
	os.Remove(d.launchdPlistPath())

	d.logger.Infow("daemon: launchd service uninstalled", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) statusLaunchd() (string, error) {
	out, err := exec.Command("launchctl", "list", d.ServiceName()).CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return "not_installed", nil
	}
	if strings.Contains(output, "Could not find service") || strings.Contains(output, "not found") {
		return "not_installed", nil
	}
	if strings.Contains(output, "\"PID\"") || strings.Contains(output, "PID") {
		return "running", nil
	}
	return "stopped", nil
}

func (d *DaemonManager) startLaunchd() error {
	out, err := exec.Command("launchctl", "load", d.launchdPlistPath()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) stopLaunchd() error {
	out, err := exec.Command("launchctl", "unload", d.launchdPlistPath()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl unload: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) restartLaunchd() error {
	plistPath := d.launchdPlistPath()
	exec.Command("launchctl", "unload", plistPath).CombinedOutput()
	out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl reload: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) isInstalledLaunchd() bool {
	_, err := os.Stat(d.launchdPlistPath())
	return err == nil
}
