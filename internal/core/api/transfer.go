package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/traceability/countermeasure"
)

// TransferRecord 文件传输记录
type TransferRecord struct {
	ID         string `json:"id"`
	TargetIP   string `json:"target_ip"`
	Direction  string `json:"direction"` // upload / download
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path,omitempty"`
	FileSize   int64  `json:"file_size"`
	Transferred int64 `json:"transferred"`
	Status     string `json:"status"` // pending / transferring / completed / failed / paused
	Checksum   string `json:"checksum,omitempty"`
	StartedAt  string `json:"started_at"`
	UpdatedAt  string `json:"updated_at"`
}

// TransferHub 管理文件传输会话
type TransferHub struct {
	mu        sync.RWMutex
	transfers map[string]*TransferRecord
	baseDir   string // 文件存储根目录
	auditFn   func(opType countermeasure.OpType, targetIP, actor, action, result string)
}

// NewTransferHub 创建文件传输管理器
func NewTransferHub(baseDir string) *TransferHub {
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	dir := filepath.Join(baseDir, "honeypot_transfers")
	os.MkdirAll(dir, 0755)
	return &TransferHub{
		transfers: make(map[string]*TransferRecord),
		baseDir:   dir,
	}
}

// SetAuditRecorder 设置审计回调
func (h *TransferHub) SetAuditRecorder(fn func(opType countermeasure.OpType, targetIP, actor, action, result string)) {
	h.auditFn = fn
}

// recordAudit 记录审计
func (h *TransferHub) recordAudit(targetIP, action, result string) {
	if h.auditFn != nil {
		h.auditFn(countermeasure.OpFileScan, targetIP, "transfer_hub", action, result)
	}
}

// HandleTransferUpload 分块文件上传
// POST /api/countermeasure/transfer/upload
// Headers: X-Target-IP, X-File-Path, X-Offset, X-Total-Size, X-Chunk-Checksum
// Body: raw chunk bytes
func (h *TransferHub) HandleTransferUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	targetIP := r.Header.Get("X-Target-IP")
	remotePath := r.Header.Get("X-File-Path")
	if targetIP == "" || remotePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Target-IP and X-File-Path required"})
		return
	}

	offset, _ := strconv.ParseInt(r.Header.Get("X-Offset"), 10, 64)
	totalSize, _ := strconv.ParseInt(r.Header.Get("X-Total-Size"), 10, 64)

	// 生成传输 ID 和本地存储路径
	transferID := fmt.Sprintf("tx_%s_%d", strings.ReplaceAll(targetIP, ".", "_"), time.Now().UnixNano())
	localPath := filepath.Join(h.baseDir, targetIP, sanitizePath(remotePath))
	os.MkdirAll(filepath.Dir(localPath), 0755)

	// 注册或恢复传输记录
	h.mu.Lock()
	var tr *TransferRecord
	var flag int
	if offset == 0 {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		tr = &TransferRecord{
			ID:         transferID,
			TargetIP:   targetIP,
			Direction:  "upload",
			RemotePath: remotePath,
			LocalPath:  localPath,
			FileSize:   totalSize,
			Status:     "transferring",
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		h.transfers[transferID] = tr
	} else {
		flag = os.O_CREATE | os.O_WRONLY
		// 恢复已有传输
		for _, t := range h.transfers {
			if t.TargetIP == targetIP && t.RemotePath == remotePath && t.Status == "paused" {
				transferID = t.ID
				tr = t
				break
			}
		}
		if tr == nil {
			tr = &TransferRecord{
				ID:         transferID,
				TargetIP:   targetIP,
				Direction:  "upload",
				RemotePath: remotePath,
				LocalPath:  localPath,
				FileSize:   totalSize,
				Status:     "transferring",
				StartedAt:  time.Now().UTC().Format(time.RFC3339),
				UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			}
			h.transfers[transferID] = tr
		}
		tr.Status = "transferring"
	}
	h.mu.Unlock()

	// 打开文件写入
	f, err := os.OpenFile(localPath, flag, 0644)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("open file: %v", err)})
		return
	}
	defer f.Close()

	if offset > 0 {
		f.Seek(offset, io.SeekStart)
	}

	// 流式写入
	written, err := io.Copy(f, r.Body)
	if err != nil {
		h.mu.Lock()
		tr.Status = "failed"
		tr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		h.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("write: %v", err)})
		return
	}

	// 更新进度
	h.mu.Lock()
	tr.Transferred = offset + written
	if totalSize > 0 && tr.Transferred >= totalSize {
		tr.Status = "completed"
	}
	tr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	h.mu.Unlock()

	h.recordAudit(targetIP, "upload_chunk",
		fmt.Sprintf("transfer_id=%s path=%s offset=%d written=%d total=%d/%d status=%s",
			transferID, remotePath, offset, written, tr.Transferred, totalSize, tr.Status))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"transfer_id":   transferID,
		"offset":        offset + written,
		"transferred":   tr.Transferred,
		"total":         totalSize,
		"status":        tr.Status,
		"next_offset":   offset + written,
	})
}

// HandleTransferDownload 文件下载（支持断点续传 Range）
// GET /api/countermeasure/transfer/download?target={ip}&path={remote_path}
func (h *TransferHub) HandleTransferDownload(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")
	remotePath := r.URL.Query().Get("path")
	if targetIP == "" || remotePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target and path required"})
		return
	}

	localPath := filepath.Join(h.baseDir, targetIP, sanitizePath(remotePath))
	info, err := os.Stat(localPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file not found on server"})
		return
	}

	fileSize := info.Size()
	transferID := fmt.Sprintf("tx_%s_%s_%d", targetIP, filepath.Base(remotePath), time.Now().UnixNano())

	// 注册下载传输
	h.mu.Lock()
	tr := &TransferRecord{
		ID:         transferID,
		TargetIP:   targetIP,
		Direction:  "download",
		RemotePath: remotePath,
		LocalPath:  localPath,
		FileSize:   fileSize,
		Status:     "transferring",
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	h.transfers[transferID] = tr
	h.mu.Unlock()

	// 打开文件
	f, err := os.Open(localPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "open failed"})
		return
	}
	defer f.Close()

	// Range 支持（断点续传）
	startOffset := int64(0)
	endOffset := fileSize - 1
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// 解析 Range: bytes=start-end
		fmt.Sscanf(rangeHeader, "bytes=%d-%d", &startOffset, &endOffset)
		if endOffset == 0 {
			endOffset = fileSize - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startOffset, endOffset, fileSize))
		w.WriteHeader(http.StatusPartialContent)
		f.Seek(startOffset, io.SeekStart)
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(remotePath)))
	w.Header().Set("X-Transfer-ID", transferID)

	written, err := io.CopyN(w, f, endOffset-startOffset+1)
	if err != nil {
		h.mu.Lock()
		tr.Status = "failed"
		tr.Transferred = written
		tr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		h.mu.Unlock()
		return
	}

	h.mu.Lock()
	tr.Transferred = written
	tr.Status = "completed"
	tr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	h.mu.Unlock()

	h.recordAudit(targetIP, "download",
		fmt.Sprintf("transfer_id=%s path=%s size=%d", transferID, remotePath, written))
}

// HandleTransferStatus 查询传输状态
// GET /api/countermeasure/transfer/status?id={transfer_id}
func (h *TransferHub) HandleTransferStatus(w http.ResponseWriter, r *http.Request) {
	transferID := r.URL.Query().Get("id")

	h.mu.RLock()
	defer h.mu.RUnlock()

	if transferID != "" {
		tr, ok := h.transfers[transferID]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "transfer not found"})
			return
		}
		writeJSON(w, http.StatusOK, tr)
		return
	}

	// 列出所有传输
	list := make([]*TransferRecord, 0, len(h.transfers))
	for _, tr := range h.transfers {
		list = append(list, tr)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":     len(list),
		"transfers": list,
	})
}

// HandleTransferPause 暂停传输
// POST /api/countermeasure/transfer/pause
func (h *TransferHub) HandleTransferPause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		TransferID string `json:"transfer_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.TransferID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "transfer_id required"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	tr, ok := h.transfers[req.TransferID]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "transfer not found"})
		return
	}
	if tr.Status == "transferring" {
		tr.Status = "paused"
		tr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, tr)
}

// HandleTransferList 列出指定目标的传输记录
// GET /api/countermeasure/transfer/list?target={ip}
func (h *TransferHub) HandleTransferList(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")

	h.mu.RLock()
	defer h.mu.RUnlock()

	list := make([]*TransferRecord, 0)
	for _, tr := range h.transfers {
		if targetIP == "" || tr.TargetIP == targetIP {
			list = append(list, tr)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":     len(list),
		"transfers": list,
	})
}

// sanitizePath 路径安全清理
func sanitizePath(p string) string {
	p = filepath.Clean(p)
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimPrefix(p, "..")
	return p
}
