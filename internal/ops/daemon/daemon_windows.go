//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func (d *DaemonManager) install() error {
	return d.installWindowsService()
}

func (d *DaemonManager) uninstall() error {
	return d.uninstallWindowsService()
}

func (d *DaemonManager) status() (string, error) {
	return d.statusWindowsService()
}

func (d *DaemonManager) start() error {
	return d.startWindowsService()
}

func (d *DaemonManager) stop() error {
	return d.stopWindowsService()
}

func (d *DaemonManager) restart() error {
	return d.restartWindowsService()
}

func (d *DaemonManager) isInstalled() bool {
	return d.isInstalledWindowsService()
}

// ---------- Windows Service (via sc.exe) ----------

func (d *DaemonManager) installWindowsService() error {
	binPath := fmt.Sprintf(`"%s" agent run --config "%s" --data "%s"`, d.binPath, d.configPath, d.dataDir)

	out, err := exec.Command("sc", "create", d.ServiceName(),
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "Laji-HoneyPot Agent",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %w\nOutput: %s", err, string(out))
	}

	// Start the service
	exec.Command("sc", "start", d.ServiceName()).CombinedOutput()

	d.logger.Infow("daemon: windows service installed", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) uninstallWindowsService() error {
	exec.Command("sc", "stop", d.ServiceName()).CombinedOutput()
	out, err := exec.Command("sc", "delete", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete: %w\nOutput: %s", err, string(out))
	}
	d.logger.Infow("daemon: windows service uninstalled", "service", d.ServiceName())
	return nil
}

func (d *DaemonManager) statusWindowsService() (string, error) {
	out, err := exec.Command("sc", "query", d.ServiceName()).CombinedOutput()
	output := string(out)
	if err != nil {
		return "not_installed", nil
	}
	if strings.Contains(output, "RUNNING") {
		return "running", nil
	}
	if strings.Contains(output, "STOPPED") {
		return "stopped", nil
	}
	return "unknown", nil
}

func (d *DaemonManager) startWindowsService() error {
	out, err := exec.Command("sc", "start", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc start: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) stopWindowsService() error {
	out, err := exec.Command("sc", "stop", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc stop: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) restartWindowsService() error {
	exec.Command("sc", "stop", d.ServiceName()).CombinedOutput()
	// Wait for stop
	time.Sleep(2 * time.Second)
	out, err := exec.Command("sc", "start", d.ServiceName()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc start after stop: %w\nOutput: %s", err, string(out))
	}
	return nil
}

func (d *DaemonManager) isInstalledWindowsService() bool {
	out, err := exec.Command("sc", "query", d.ServiceName()).CombinedOutput()
	if err != nil {
		return false
	}
	return !strings.Contains(string(out), "FAILED") && !strings.Contains(string(out), "1060")
}

// WindowsService implements the svc.Handler interface for running as a true
// Windows service. When RunWindowsService is called, it blocks until the
// service stop signal is received.
type WindowsService struct {
	logger  *log.Logger
	runFunc func() error
}

// NewWindowsService creates a Windows service handler.
// The runFunc is the application's main loop function.
func NewWindowsService(logger *log.Logger, runFunc func() error) *WindowsService {
	return &WindowsService{
		logger:  logger,
		runFunc: runFunc,
	}
}

// Execute implements the svc.Handler interface.
func (ws *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}

	// Start the application in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- ws.runFunc()
	}()

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Wait for stop signal or application exit
	for {
		select {
		case err := <-errCh:
			if err != nil {
				ws.logger.Errorw("windows service: run error", "error", err)
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				ws.logger.Warnw("windows service: unexpected control",
					"cmd", c.Cmd)
			}
		}
	}
}

// RunWindowsService runs the application as a Windows service.
// Call this from main() on Windows to run interactively or as a service.
func RunWindowsService(name string, handler svc.Handler) error {
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("detect session: %w", err)
	}
	if isInteractive {
		// Run interactively so the user can see output
		return svc.Run(name, handler)
	}
	return svc.Run(name, handler)
}

// Ensure mgr is imported for completeness.
var _ = mgr.Mgr{}
var _ = os.Args
