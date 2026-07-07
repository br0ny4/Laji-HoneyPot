package upgrade

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// AgentUpgrader handles the agent-side upgrade flow: download, verify,
// install, and rollback.
type AgentUpgrader struct {
	binPath    string
	backupDir  string
	logger     *log.Logger
	httpClient *http.Client
	currentVer string
}

// NewAgentUpgrader creates a new AgentUpgrader.
func NewAgentUpgrader(binPath, backupDir string, logger *log.Logger) *AgentUpgrader {
	return &AgentUpgrader{
		binPath:    binPath,
		backupDir:  backupDir,
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Minute}, // large packages may take a while
		currentVer: readVersionFile(filepath.Join(filepath.Dir(binPath), ".version")),
	}
}

// CurrentVersion returns the current agent version.
func (a *AgentUpgrader) CurrentVersion() string { return a.currentVer }

// Download downloads the upgrade package with resume support (Range headers).
// It returns the path to the downloaded package file.
func (a *AgentUpgrader) Download(packageURL, sha256Hash string) (string, error) {
	a.logger.Infow("upgrade: downloading package", "url", packageURL)

	// Determine download path
	dlDir := filepath.Join(a.backupDir, "downloads")
	if err := os.MkdirAll(dlDir, 0755); err != nil {
		return "", fmt.Errorf("create download dir: %w", err)
	}

	dlPath := filepath.Join(dlDir, "upgrade-package.tar.gz")

	// Check if partial download exists for resume
	var existingSize int64
	if fi, err := os.Stat(dlPath); err == nil {
		existingSize = fi.Size()
		a.logger.Infow("upgrade: found partial download, resuming", "existing_bytes", existingSize)

		// Verify the partial content hash doesn't mismatch (simple check: just make sure the file isn't corrupted)
		if existingSize > 0 {
			if err := a.verifyPartial(dlPath, sha256Hash); err != nil {
				a.logger.Warnw("upgrade: partial download corrupted, restarting", "error", err)
				os.Remove(dlPath)
				existingSize = 0
			}
		}
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", packageURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	// Set Range header for resume
	if existingSize > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existingSize))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	switch resp.StatusCode {
	case http.StatusOK:
		// Full download - overwrite the file
		os.Remove(dlPath)
	case http.StatusPartialContent:
		// Resume supported - append to existing file
		a.logger.Infow("upgrade: server supports resume, continuing download", "offset", existingSize)
	case http.StatusRequestedRangeNotSatisfiable:
		// Range not satisfiable - file may be complete
		if existingSize > 0 {
			a.logger.Info("upgrade: range not satisfiable, file may be complete")
			return dlPath, nil
		}
		os.Remove(dlPath)
	default:
		return "", fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	// Open file for writing (append mode if resuming)
	var file *os.File
	if existingSize > 0 && resp.StatusCode == http.StatusPartialContent {
		file, err = os.OpenFile(dlPath, os.O_APPEND|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(dlPath)
	}
	if err != nil {
		return "", fmt.Errorf("open download file: %w", err)
	}
	defer file.Close()

	// Copy with progress logging
	totalSize := resp.ContentLength
	if totalSize > 0 {
		a.logger.Infow("upgrade: downloading", "total_bytes", totalSize+existingSize)
	}

	written, err := io.Copy(file, resp.Body)
	if err != nil {
		os.Remove(dlPath) // clean up partial download on error
		return "", fmt.Errorf("download copy: %w", err)
	}

	totalWritten := existingSize + written
	a.logger.Infow("upgrade: download complete", "total_bytes", totalWritten)
	return dlPath, nil
}

// verifyPartial checks if the partial download is a valid tar.gz file.
func (a *AgentUpgrader) verifyPartial(path, expectedHash string) error {
	// Just check that the file is a valid tar.gz (can be opened)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not valid gzip: %w", err)
	}
	gzr.Close()
	return nil
}

// Verify checks the downloaded package SHA256 against the expected hash.
func (a *AgentUpgrader) Verify(packagePath, expectedHash string) error {
	a.logger.Infow("upgrade: verifying package", "path", packagePath, "expected_hash", expectedHash)

	f, err := os.Open(packagePath)
	if err != nil {
		return fmt.Errorf("open package: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash package: %w", err)
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	a.logger.Info("upgrade: package verified successfully")
	return nil
}

// Install extracts the package and prepares the new binary atomically.
// 1. Creates backup of current binary
// 2. Extracts new binary from package
// 3. Atomically replaces the running binary
// 4. Records version in .version file
func (a *AgentUpgrader) Install(packagePath, version string) error {
	a.logger.Infow("upgrade: installing", "version", version, "package", packagePath)

	// Ensure backup directory exists
	if err := os.MkdirAll(a.backupDir, 0755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	// 1. Backup current binary
	backupPath := filepath.Join(a.backupDir, fmt.Sprintf("honeypot-agent.bak.%s", version))
	if _, err := os.Stat(a.binPath); err == nil {
		if err := copyFile(a.binPath, backupPath); err != nil {
			return fmt.Errorf("backup current binary: %w", err)
		}
		a.logger.Infow("upgrade: backup created", "path", backupPath)
	}

	// 2. Extract new binary from tar.gz
	tmpDir, err := os.MkdirTemp("", "honeypot-upgrade-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	newBin, err := extractBinaryFromTarGz(packagePath, tmpDir)
	if err != nil {
		// Rollback: restore from backup
		if _, err2 := os.Stat(backupPath); err2 == nil {
			a.logger.Warnw("upgrade: extract failed, restoring backup", "error", err)
			copyFile(backupPath, a.binPath)
		}
		return fmt.Errorf("extract binary: %w", err)
	}

	// 3. Atomic replace: copy to a temp name, then rename
	tmpBin := a.binPath + ".new"
	if err := copyFile(newBin, tmpBin); err != nil {
		return fmt.Errorf("stage new binary: %w", err)
	}
	if err := os.Chmod(tmpBin, 0755); err != nil {
		os.Remove(tmpBin)
		return fmt.Errorf("chmod new binary: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpBin, a.binPath); err != nil {
		os.Remove(tmpBin)
		return fmt.Errorf("atomic replace binary: %w", err)
	}

	// 4. Record version
	versionFile := filepath.Join(filepath.Dir(a.binPath), ".version")
	if err := os.WriteFile(versionFile, []byte(version), 0644); err != nil {
		a.logger.Warnw("upgrade: failed to write version file", "error", err)
	}

	a.currentVer = version
	a.logger.Infow("upgrade: install complete", "version", version)
	return nil
}

// Rollback reverts to the previous version backup.
func (a *AgentUpgrader) Rollback() error {
	a.logger.Warn("upgrade: rolling back to previous version")

	// Find the most recent backup
	backups, err := filepath.Glob(filepath.Join(a.backupDir, "honeypot-agent.bak.*"))
	if err != nil || len(backups) == 0 {
		return fmt.Errorf("no backup found for rollback")
	}

	// Use the most recent backup (sorted by name, which includes version)
	latestBackup := backups[len(backups)-1]

	// Replace current binary with backup
	if err := copyFile(latestBackup, a.binPath); err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}
	if err := os.Chmod(a.binPath, 0755); err != nil {
		return fmt.Errorf("chmod restored binary: %w", err)
	}

	// Extract version from backup filename
	base := filepath.Base(latestBackup)
	prevVersion := ""
	if len(base) > len("honeypot-agent.bak.") {
		prevVersion = base[len("honeypot-agent.bak."):]
	}
	if prevVersion != "" {
		a.currentVer = prevVersion
	}

	a.logger.Infow("upgrade: rollback complete", "restored_version", prevVersion)
	return nil
}

// PerformUpgrade executes the full upgrade flow: Download -> Verify -> Install.
// If any step fails, it attempts rollback.
func (a *AgentUpgrader) PerformUpgrade(packageURL, sha256Hash, version string) error {
	a.logger.Infow("upgrade: starting full upgrade flow",
		"version", version,
		"current", a.currentVer,
	)

	// 1. Download
	pkgPath, err := a.Download(packageURL, sha256Hash)
	if err != nil {
		return fmt.Errorf("upgrade download: %w", err)
	}
	defer os.Remove(pkgPath) // clean up package after install

	// 2. Verify
	if err := a.Verify(pkgPath, sha256Hash); err != nil {
		return fmt.Errorf("upgrade verify: %w", err)
	}

	// 3. Install
	if err := a.Install(pkgPath, version); err != nil {
		a.logger.Errorw("upgrade: install failed, rolling back", "error", err)
		if rbErr := a.Rollback(); rbErr != nil {
			a.logger.Errorw("upgrade: rollback also failed!", "error", rbErr)
			return fmt.Errorf("install failed (%w) and rollback failed (%w)", err, rbErr)
		}
		return fmt.Errorf("upgrade install (rolled back): %w", err)
	}

	a.logger.Infow("upgrade: complete", "version", version)
	return nil
}

// extractBinaryFromTarGz extracts the first binary from a tar.gz archive.
func extractBinaryFromTarGz(tgzPath, destDir string) (string, error) {
	f, err := os.Open(tgzPath)
	if err != nil {
		return "", fmt.Errorf("open package: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar read: %w", err)
		}

		// Skip directories
		if hdr.Typeflag == tar.TypeDir {
			continue
		}

		// Extract the file
		destPath := filepath.Join(destDir, filepath.Base(hdr.Name))
		outFile, err := os.Create(destPath)
		if err != nil {
			return "", fmt.Errorf("create extracted file: %w", err)
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return "", fmt.Errorf("write extracted file: %w", err)
		}
		outFile.Close()

		// Make executable
		os.Chmod(destPath, 0755)
		return destPath, nil
	}

	return "", fmt.Errorf("no binary found in package")
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// readVersionFile reads the version from a .version file.
func readVersionFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return string(data)
}
