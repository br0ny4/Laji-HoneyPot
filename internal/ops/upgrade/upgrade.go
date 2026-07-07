// Package upgrade provides agent upgrade management for the Laji-HoneyPot
// manager and agent components. It supports package generation, download with
// resume, SHA256 verification, atomic install with backup/rollback, and
// progress tracking.
package upgrade

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
)

// UpgradeManager manages upgrade jobs on the manager side.
type UpgradeManager struct {
	store      *store.Store
	logger     *log.Logger
	dataDir    string
	mu         sync.RWMutex
	activeJobs map[string]*store.UpgradeJob
}

// NewUpgradeManager creates a new UpgradeManager.
func NewUpgradeManager(st *store.Store, logger *log.Logger, dataDir string) *UpgradeManager {
	return &UpgradeManager{
		store:      st,
		logger:     logger,
		dataDir:    dataDir,
		activeJobs: make(map[string]*store.UpgradeJob),
	}
}

// CreateUpgradeJob creates a new upgrade task for a specific node.
func (u *UpgradeManager) CreateUpgradeJob(nodeID, version, packageURL, sha256Hash string) (*store.UpgradeJob, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")
	job := &store.UpgradeJob{
		ID:          newJobID(),
		Version:     version,
		Status:      "pending",
		NodeID:      nodeID,
		PackageURL:  packageURL,
		PackageHash: sha256Hash,
		Progress:    0.0,
		CreatedAt:   now,
	}

	if err := u.store.CreateUpgradeJob(job); err != nil {
		return nil, fmt.Errorf("create upgrade job in store: %w", err)
	}

	u.activeJobs[job.ID] = job
	u.logger.Infow("upgrade: job created",
		"job_id", job.ID,
		"node", nodeID,
		"version", version,
	)
	return job, nil
}

// GetJobStatus returns the status of an upgrade job.
func (u *UpgradeManager) GetJobStatus(jobID string) (*store.UpgradeJob, error) {
	u.mu.RLock()
	if job, ok := u.activeJobs[jobID]; ok {
		u.mu.RUnlock()
		return job, nil
	}
	u.mu.RUnlock()

	job, err := u.store.GetUpgradeJob(jobID)
	if err != nil {
		return nil, fmt.Errorf("get upgrade job: %w", err)
	}
	return job, nil
}

// ListJobs lists all upgrade jobs, optionally filtered by node.
func (u *UpgradeManager) ListJobs(nodeID string) ([]*store.UpgradeJob, error) {
	jobs, err := u.store.ListUpgradeJobs(nodeID)
	if err != nil {
		return nil, fmt.Errorf("list upgrade jobs: %w", err)
	}
	return jobs, nil
}

// CancelJob cancels a pending or running upgrade job.
func (u *UpgradeManager) CancelJob(jobID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	job, ok := u.activeJobs[jobID]
	if !ok {
		var err error
		job, err = u.store.GetUpgradeJob(jobID)
		if err != nil {
			return fmt.Errorf("job not found: %s", jobID)
		}
	}

	if job.Status == "complete" || job.Status == "failed" {
		return fmt.Errorf("cannot cancel job in status: %s", job.Status)
	}

	if err := u.store.UpdateUpgradeJobStatus(job.ID, "cancelled", job.Progress, ""); err != nil {
		return fmt.Errorf("update job status: %w", err)
	}

	delete(u.activeJobs, jobID)
	u.logger.Infow("upgrade: job cancelled", "job_id", jobID)
	return nil
}

// NotifyProgress is called by the agent to report download/install progress.
func (u *UpgradeManager) NotifyProgress(jobID string, progress float64, status string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if job, ok := u.activeJobs[jobID]; ok {
		job.Progress = progress
		job.Status = status
		if status == "complete" || status == "failed" {
			delete(u.activeJobs, jobID)
		}
	}

	if err := u.store.UpdateUpgradeJobStatus(jobID, status, progress, ""); err != nil {
		return fmt.Errorf("update job progress: %w", err)
	}

	u.logger.Debugw("upgrade: progress", "job_id", jobID, "progress", progress, "status", status)
	return nil
}

// GeneratePackage builds an upgrade package (tar.gz) containing the compiled
// binary for the target OS/ARCH. Returns the package path and its SHA256 hash.
func (u *UpgradeManager) GeneratePackage(targetOS, targetArch, version string) (string, string, error) {
	u.logger.Infow("upgrade: generating package",
		"os", targetOS,
		"arch", targetArch,
		"version", version,
	)

	// Determine the source binary path
	srcBin := u.detectBinaryPath()
	if srcBin == "" {
		return "", "", fmt.Errorf("cannot detect source binary path")
	}

	// Create package output directory
	pkgDir := filepath.Join(u.dataDir, "packages")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		return "", "", fmt.Errorf("create package dir: %w", err)
	}

	pkgName := fmt.Sprintf("honeypot-agent-%s-%s-%s.tar.gz", version, targetOS, targetArch)
	pkgPath := filepath.Join(pkgDir, pkgName)

	// Build the binary for the target platform
	tmpBin := filepath.Join(os.TempDir(), fmt.Sprintf("honeypot-build-%s-%s-%s", version, targetOS, targetArch))
	cmd := exec.Command("go", "build",
		"-o", tmpBin,
		"-ldflags", fmt.Sprintf("-X github.com/Laji-HoneyPot/honeypot/internal/core.Version=%s", version),
		"./cmd/honeypot/",
	)
	cmd.Env = append(os.Environ(),
		"GOOS="+targetOS,
		"GOARCH="+targetArch,
		"CGO_ENABLED=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("go build: %w\nOutput: %s", err, string(out))
	}
	defer os.Remove(tmpBin)

	// Create tar.gz package
	if err := createTarGz(pkgPath, tmpBin, "honeypot-agent"); err != nil {
		return "", "", fmt.Errorf("create package: %w", err)
	}

	// Calculate SHA256
	hash, err := fileSHA256(pkgPath)
	if err != nil {
		return "", "", fmt.Errorf("hash package: %w", err)
	}

	u.logger.Infow("upgrade: package generated",
		"path", pkgPath,
		"sha256", hash,
		"size", fileSizeStr(pkgPath),
	)
	return pkgPath, hash, nil
}

// detectBinaryPath attempts to find the current running binary path.
func (u *UpgradeManager) detectBinaryPath() string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	candidates := []string{
		"/usr/local/bin/honeypot",
		"/usr/bin/honeypot",
		"./honeypot",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// newJobID generates a unique job ID.
func newJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("upgrade-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("upg-%x", b)
}

// createTarGz creates a tar.gz archive containing the given binary.
func createTarGz(dst, src, name string) error {
	tmpDir, err := os.MkdirTemp("", "honeypot-pkg-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	stagedBin := filepath.Join(tmpDir, name)
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source binary: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(stagedBin)
	if err != nil {
		return fmt.Errorf("create staged binary: %w", err)
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		return fmt.Errorf("copy binary: %w", err)
	}
	dstFile.Close()

	os.Chmod(stagedBin, 0755)

	cmd := exec.Command("tar", "-czf", dst, "-C", tmpDir, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar create: %w\nOutput: %s", err, string(out))
	}
	return nil
}

// fileSHA256 computes the SHA256 hash of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileSizeStr returns a human-readable file size string.
func fileSizeStr(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	size := fi.Size()
	switch {
	case size > 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	case size > 1024:
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	default:
		return fmt.Sprintf("%d B", size)
	}
}
