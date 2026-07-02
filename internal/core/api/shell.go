package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/countermeasure"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // 管理端本地访问
	},
}

// ShellMessage WebSocket 通信协议消息
type ShellMessage struct {
	Action   string `json:"action"`              // exec, ping, close, set_target, connected, output, error
	TargetIP string `json:"target_ip,omitempty"` // 目标主机 IP
	Command  string `json:"command,omitempty"`   // 要执行的命令
	CmdID    string `json:"cmd_id,omitempty"`    // 命令唯一 ID
	Output   string `json:"output,omitempty"`    // 命令输出（响应）
	ExitCode int    `json:"exit_code,omitempty"` // 命令退出码
	Error    string `json:"error,omitempty"`     // 错误信息
	Duration string `json:"duration,omitempty"`  // 执行耗时
	TS       int64  `json:"ts,omitempty"`        // 时间戳
}

// ShellSession 一个活跃的远程 Shell 会话
type ShellSession struct {
	ID        string
	TargetIP  string
	Conn      *websocket.Conn
	CreatedAt time.Time
	LastCmd   time.Time
	CmdCount  int
	mu        sync.Mutex
	done      chan struct{}
}

// ShellHub 管理所有活跃 Shell 会话
type ShellHub struct {
	mu            sync.RWMutex
	sessions      map[string]*ShellSession
	logger        *log.Logger
	auditRecorder func(opType countermeasure.OpType, targetIP, actor, action, result string)
	cmdForwarder  func(targetIP, command string) (output string, exitCode int, err error)
}

// NewShellHub 创建 Shell 会话管理器
func NewShellHub(logger *log.Logger) *ShellHub {
	return &ShellHub{
		sessions: make(map[string]*ShellSession),
		logger:   logger,
	}
}

// SetAuditRecorder 设置审计回调
func (h *ShellHub) SetAuditRecorder(fn func(opType countermeasure.OpType, targetIP, actor, action, result string)) {
	h.auditRecorder = fn
}

// SetCmdForwarder 设置命令转发器（用于集群 Agent 代理执行）
func (h *ShellHub) SetCmdForwarder(fn func(targetIP, command string) (output string, exitCode int, err error)) {
	h.cmdForwarder = fn
}

// ActiveSessions 返回活跃会话数
func (h *ShellHub) ActiveSessions() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.sessions)
}

// HandleShell WebSocket 升级处理 — 建立交互式远程 Shell
// GET /api/countermeasure/shell?target={ip}
func (h *ShellHub) HandleShell(w http.ResponseWriter, r *http.Request) {
	targetIP := r.URL.Query().Get("target")
	if targetIP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target IP required"})
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Errorw("shell ws upgrade failed", "error", err)
		return
	}

	sessionID := fmt.Sprintf("sh_%d", time.Now().UnixNano())
	sess := &ShellSession{
		ID:        sessionID,
		TargetIP:  targetIP,
		Conn:      conn,
		CreatedAt: time.Now(),
		LastCmd:   time.Now(),
		done:      make(chan struct{}),
	}

	h.mu.Lock()
	h.sessions[sessionID] = sess
	h.mu.Unlock()

	h.logger.Infow("shell session opened", "session", sessionID, "target", targetIP)

	// 发送欢迎消息
	h.sendMsg(conn, ShellMessage{
		Action:   "connected",
		TargetIP: targetIP,
		Output:   fmt.Sprintf("=== Remote Shell Connected ===\nTarget: %s\nSession: %s\nCommands: help, whoami, ps, ls, netstat, ...\nType 'exit' to close\n", targetIP, sessionID),
		TS:       time.Now().Unix(),
	})

	// 记录审计
	h.recordAudit(countermeasure.OpEnvDetect, targetIP, "shell", fmt.Sprintf("session_started session=%s", sessionID))

	// 启动会话管理循环
	h.sessionLoop(sess)

	// 清理
	h.mu.Lock()
	delete(h.sessions, sessionID)
	h.mu.Unlock()

	h.recordAudit(countermeasure.OpEnvDetect, targetIP, "shell", fmt.Sprintf("session_closed session=%s cmd_count=%d", sessionID, sess.CmdCount))
	h.logger.Infow("shell session closed", "session", sessionID, "cmds", sess.CmdCount)
}

// sessionLoop 会话主循环 — 读取命令、执行、返回结果
func (h *ShellHub) sessionLoop(sess *ShellSession) {
	defer sess.Conn.Close()

	// 空闲超时 goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sess.mu.Lock()
				idle := time.Since(sess.LastCmd)
				sess.mu.Unlock()
				if idle > 5*time.Minute {
					h.logger.Infow("shell session idle timeout", "session", sess.ID, "idle", idle)
					sess.Conn.Close()
					return
				}
				// 心跳 ping
				sess.mu.Lock()
				err := sess.Conn.WriteMessage(websocket.PingMessage, nil)
				sess.mu.Unlock()
				if err != nil {
					return
				}
			case <-sess.done:
				return
			}
		}
	}()

	for {
		_, msgBytes, err := sess.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Warnw("shell ws error", "session", sess.ID, "error", err)
			}
			close(sess.done)
			return
		}

		var msg ShellMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			h.sendMsg(sess.Conn, ShellMessage{
				Action: "error",
				Error:  "invalid message format",
				TS:     time.Now().Unix(),
			})
			continue
		}

		switch msg.Action {
		case "exec":
			h.handleExec(sess, &msg)
		case "ping":
			h.sendMsg(sess.Conn, ShellMessage{
				Action: "pong",
				TS:     time.Now().Unix(),
			})
		case "close", "exit":
			h.sendMsg(sess.Conn, ShellMessage{
				Action: "closed",
				Output: "Session terminated.",
				TS:     time.Now().Unix(),
			})
			close(sess.done)
			return
		case "set_target":
			if msg.TargetIP != "" {
				sess.TargetIP = msg.TargetIP
				h.sendMsg(sess.Conn, ShellMessage{
					Action:   "target_set",
					TargetIP: msg.TargetIP,
					Output:   fmt.Sprintf("Target switched to: %s", msg.TargetIP),
					TS:       time.Now().Unix(),
				})
			}
		default:
			h.sendMsg(sess.Conn, ShellMessage{
				Action: "error",
				Error:  fmt.Sprintf("unknown action: %s", msg.Action),
				TS:     time.Now().Unix(),
			})
		}
	}
}

// handleExec 执行命令并返回结果
func (h *ShellHub) handleExec(sess *ShellSession, msg *ShellMessage) {
	if msg.Command == "" {
		h.sendMsg(sess.Conn, ShellMessage{
			Action:   "error",
			CmdID:    msg.CmdID,
			Error:    "empty command",
			TS:       time.Now().Unix(),
		})
		return
	}

	sess.mu.Lock()
	sess.LastCmd = time.Now()
	sess.CmdCount++
	cmdID := msg.CmdID
	if cmdID == "" {
		cmdID = fmt.Sprintf("cmd_%d", sess.CmdCount)
	}
	sess.mu.Unlock()

	h.logger.Infow("shell exec", "session", sess.ID, "target", sess.TargetIP, "cmd", msg.Command)

	// 审计记录
	h.recordAudit(countermeasure.OpEnvDetect, sess.TargetIP, "shell_exec", fmt.Sprintf("session=%s cmd=%s", sess.ID, msg.Command))

	start := time.Now()

	output, exitCode, err := h.executeCommand(sess.TargetIP, msg.Command)
	duration := time.Since(start)

	resp := ShellMessage{
		Action:   "output",
		CmdID:    cmdID,
		Command:  msg.Command,
		Duration: duration.String(),
		TS:       time.Now().Unix(),
	}

	if err != nil {
		resp.ExitCode = -1
		resp.Error = err.Error()
		resp.Output = fmt.Sprintf("Error: %s", err.Error())
	} else {
		resp.ExitCode = exitCode
		resp.Output = output
	}

	h.sendMsg(sess.Conn, resp)

	// 审计执行结果
	result := fmt.Sprintf("ok exit=%d duration=%s", exitCode, duration)
	if err != nil {
		result = fmt.Sprintf("error: %s duration=%s", err.Error(), duration)
	}
	h.recordAudit(countermeasure.OpEnvDetect, sess.TargetIP, "shell_result", fmt.Sprintf("session=%s cmd=%s %s", sess.ID, msg.Command, result))
}

// executeCommand 执行命令（支持本地执行和集群 Agent 转发）
func (h *ShellHub) executeCommand(targetIP, command string) (output string, exitCode int, err error) {
	// 优先使用集群 Agent 转发
	if h.cmdForwarder != nil {
		return h.cmdForwarder(targetIP, command)
	}

	// 本地执行（用于测试/直接管理场景）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	outBytes, err := cmd.CombinedOutput()
	output = string(outBytes)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			err = nil // 命令执行失败不算系统错误
		}
		if ctx.Err() == context.DeadlineExceeded {
			output += "\n[命令执行超时 (30s)]"
			exitCode = -1
			err = fmt.Errorf("command timeout")
		}
	}

	if len(output) > 65536 {
		output = output[:65536] + "\n[输出已截断，超过 64KB]"
	}

	return output, exitCode, err
}

// sendMsg 发送 JSON 消息到 WebSocket 连接
func (h *ShellHub) sendMsg(conn *websocket.Conn, msg ShellMessage) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		h.logger.Warnw("shell msg marshal failed", "error", err)
		return
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		h.logger.Warnw("shell msg send failed", "error", err)
	}
}

// recordAudit 记录审计日志
func (h *ShellHub) recordAudit(opType countermeasure.OpType, targetIP, action, result string) {
	if h.auditRecorder != nil {
		h.auditRecorder(opType, targetIP, "shell_hub", action, result)
	}
}

// CloseAll 关闭所有活跃会话
func (h *ShellHub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sess := range h.sessions {
		sess.Conn.Close()
		delete(h.sessions, id)
	}
}
