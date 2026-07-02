package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/Laji-HoneyPot/honeypot/internal/traceability/countermeasure"
)

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	CmdLine string `json:"cmd_line"`
	User    string `json:"user,omitempty"`
	CPU     string `json:"cpu,omitempty"`
	Memory  string `json:"memory,omitempty"`
	Status  string `json:"status"`
}

// ProcessAction 进程操作请求
type ProcessAction struct {
	TargetIP string `json:"target_ip"`
	PID      int    `json:"pid,omitempty"`
	Name     string `json:"name,omitempty"`
	Command  string `json:"command,omitempty"`
	Path     string `json:"path,omitempty"`
}

// ProcessHub 进程管理
type ProcessHub struct {
	mu      sync.RWMutex
	auditFn func(opType countermeasure.OpType, targetIP, actor, action, result string)
	// 命令转发器（用于集群 Agent 代理执行）
	cmdForwarder func(targetIP, command string) (output string, exitCode int, err error)
}

// NewProcessHub 创建进程管理器
func NewProcessHub() *ProcessHub {
	return &ProcessHub{}
}

// SetAuditRecorder 设置审计回调
func (h *ProcessHub) SetAuditRecorder(fn func(opType countermeasure.OpType, targetIP, actor, action, result string)) {
	h.auditFn = fn
}

// SetCmdForwarder 设置命令转发器
func (h *ProcessHub) SetCmdForwarder(fn func(targetIP, command string) (output string, exitCode int, err error)) {
	h.cmdForwarder = fn
}

// recordAudit 记录审计
func (h *ProcessHub) recordAudit(targetIP, action, result string) {
	if h.auditFn != nil {
		h.auditFn(countermeasure.OpProcessList, targetIP, "process_hub", action, result)
	}
}

// HandleProcessList 列出目标主机进程
// GET /api/countermeasure/processes?target={ip}&filter={name}
func (h *ProcessHub) HandleProcessList(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")
	filter := r.URL.Query().Get("filter")

	output, _, err := h.execOnTarget(targetIP, "ps aux || tasklist /FO CSV")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("exec failed: %v", err)})
		return
	}

	procs := parseProcessList(output, filter)
	h.recordAudit(targetIP, "list", fmt.Sprintf("count=%d filter=%s", len(procs), filter))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":    targetIP,
		"total":     len(procs),
		"processes": procs,
	})
}

// HandleProcessStart 启动进程
// POST /api/countermeasure/processes/start
func (h *ProcessHub) HandleProcessStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req ProcessAction
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if req.TargetIP == "" || req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_ip and command required"})
		return
	}

	// 构建后台启动命令
	var startCmd string
	if req.Path != "" {
		startCmd = fmt.Sprintf("cd %s && nohup %s > /dev/null 2>&1 & echo $!", req.Path, req.Command)
	} else {
		startCmd = fmt.Sprintf("nohup %s > /dev/null 2>&1 & echo $!", req.Command)
	}

	output, _, err := h.execOnTarget(req.TargetIP, startCmd)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("start failed: %v", err)})
		return
	}

	pid := strings.TrimSpace(output)
	h.recordAudit(req.TargetIP, "start", fmt.Sprintf("cmd=%s pid=%s", req.Command, pid))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":  req.TargetIP,
		"command": req.Command,
		"pid":     pid,
		"status":  "started",
	})
}

// HandleProcessStop 停止/杀死进程
// POST /api/countermeasure/processes/stop
func (h *ProcessHub) HandleProcessStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req ProcessAction
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if req.TargetIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_ip required"})
		return
	}

	var killCmd string
	if req.PID > 0 {
		killCmd = fmt.Sprintf("kill -9 %d || taskkill /F /PID %d", req.PID, req.PID)
	} else if req.Name != "" {
		killCmd = fmt.Sprintf("pkill -9 %s || taskkill /F /IM %s", req.Name, req.Name)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pid or name required"})
		return
	}

	output, exitCode, err := h.execOnTarget(req.TargetIP, killCmd)

	result := "stopped"
	if exitCode != 0 || err != nil {
		result = fmt.Sprintf("warning: exit=%d err=%v output=%s", exitCode, err, output)
	}
	h.recordAudit(req.TargetIP, "stop", fmt.Sprintf("pid=%d name=%s %s", req.PID, req.Name, result))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":    req.TargetIP,
		"pid":       req.PID,
		"name":      req.Name,
		"status":    "stopped",
		"exit_code": exitCode,
	})
}

// HandleProcessDelete 删除进程可执行文件
// POST /api/countermeasure/processes/delete
func (h *ProcessHub) HandleProcessDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req ProcessAction
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if req.TargetIP == "" || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_ip and path required"})
		return
	}

	// 先停止进程，再删除文件
	var delCmd string
	if req.Name != "" {
		delCmd = fmt.Sprintf("pkill -9 %s 2>/dev/null; taskkill /F /IM %s 2>nul; rm -f %s; del /F /Q %s 2>nul", req.Name, req.Name, req.Path, req.Path)
	} else {
		delCmd = fmt.Sprintf("rm -f %s; del /F /Q %s 2>nul", req.Path, req.Path)
	}

	output, exitCode, err := h.execOnTarget(req.TargetIP, delCmd)

	result := "deleted"
	if exitCode != 0 || err != nil {
		result = fmt.Sprintf("warning: exit=%d err=%v output=%s", exitCode, err, output)
	}
	h.recordAudit(req.TargetIP, "delete", fmt.Sprintf("path=%s name=%s %s", req.Path, req.Name, result))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":    req.TargetIP,
		"path":      req.Path,
		"name":      req.Name,
		"status":    "deleted",
		"exit_code": exitCode,
	})
}

// execOnTarget 在目标主机上执行命令
func (h *ProcessHub) execOnTarget(targetIP, command string) (output string, exitCode int, err error) {
	if h.cmdForwarder != nil {
		return h.cmdForwarder(targetIP, command)
	}

	// 本地执行
	cmd := exec.Command("sh", "-c", command)
	outBytes, err := cmd.CombinedOutput()
	output = string(outBytes)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			err = nil
		}
	}
	return output, exitCode, err
}

// parseProcessList 解析进程列表输出
func parseProcessList(output, filter string) []ProcessInfo {
	lines := strings.Split(output, "\n")
	procs := make([]ProcessInfo, 0, len(lines))

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}

		// 简单的 ps aux 解析
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}

		pid := 0
		fmt.Sscanf(fields[1], "%d", &pid)
		name := fields[10]
		if len(fields) > 11 {
			name = strings.Join(fields[10:], " ")
		}

		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}

		procs = append(procs, ProcessInfo{
			PID:     pid,
			User:    fields[0],
			CPU:     fields[2],
			Memory:  fields[3],
			Name:    name,
			CmdLine: strings.Join(fields[10:], " "),
			Status:  "running",
		})
	}

	return procs
}
