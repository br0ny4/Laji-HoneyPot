// Package daemon provides cross-platform daemon/service management for the
// Laji-HoneyPot agent. It supports systemd (Linux), launchd (macOS), and
// Windows Service (via golang.org/x/sys/windows/svc).
package daemon

import (
	"fmt"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// DaemonManager manages the agent as a system service across platforms.
type DaemonManager struct {
	binPath    string
	configPath string
	dataDir    string
	logger     *log.Logger
}

// NewDaemonManager creates a new DaemonManager.
func NewDaemonManager(binPath, configPath, dataDir string, logger *log.Logger) *DaemonManager {
	return &DaemonManager{
		binPath:    binPath,
		configPath: configPath,
		dataDir:    dataDir,
		logger:     logger,
	}
}

// BinPath returns the configured binary path.
func (d *DaemonManager) BinPath() string { return d.binPath }

// ConfigPath returns the configured config path.
func (d *DaemonManager) ConfigPath() string { return d.configPath }

// DataDir returns the configured data directory.
func (d *DaemonManager) DataDir() string { return d.dataDir }

// ServiceName returns the system service name.
func (d *DaemonManager) ServiceName() string { return "com.laji-honeypot.agent" }

// ErrUnsupportedPlatform is returned when daemon operations are not supported on the current OS.
var ErrUnsupportedPlatform = fmt.Errorf("daemon: unsupported platform")

// Start starts the service.
func (d *DaemonManager) Start() error {
	d.logger.Infow("daemon: start requested")
	return d.start()
}

// Stop stops the service.
func (d *DaemonManager) Stop() error {
	d.logger.Infow("daemon: stop requested")
	return d.stop()
}

// Restart restarts the service.
func (d *DaemonManager) Restart() error {
	d.logger.Infow("daemon: restart requested")
	return d.restart()
}

// Install installs the agent as a system service.
func (d *DaemonManager) Install() error {
	d.logger.Infow("daemon: install requested", "bin", d.binPath, "config", d.configPath, "data", d.dataDir)
	return d.install()
}

// Uninstall removes the system service.
func (d *DaemonManager) Uninstall() error {
	d.logger.Infow("daemon: uninstall requested")
	return d.uninstall()
}

// Status returns the current service status.
func (d *DaemonManager) Status() (string, error) {
	st, err := d.status()
	d.logger.Debugw("daemon: status", "status", st, "error", err)
	return st, err
}

// IsInstalled checks if the agent is installed as a service.
func (d *DaemonManager) IsInstalled() bool {
	installed := d.isInstalled()
	d.logger.Debugw("daemon: isInstalled", "installed", installed)
	return installed
}
