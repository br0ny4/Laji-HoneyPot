// Package alerter 多通道告警模块 — Webhook/DingTalk/Feishu/邮件
package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ChannelType 告警通道类型
type ChannelType string

const (
	ChannelWebhook  ChannelType = "webhook"
	ChannelDingTalk ChannelType = "dingtalk"
	ChannelFeishu   ChannelType = "feishu"
)

// ChannelConfig 单个告警通道配置
type ChannelConfig struct {
	Type    ChannelType `json:"type"`
	URL     string      `json:"url"`
	Enabled bool        `json:"enabled"`
	// 事件过滤：只订阅特定事件类型，空=全部
	EventFilter []string `json:"event_filter,omitempty"`
}

// AlertEvent 告警事件
type AlertEvent struct {
	Type      string    `json:"type"` // connection / attack / breadcrumb / scan
	Title     string    `json:"title"`
	RemoteIP  string    `json:"remote_ip"`
	Service   string    `json:"service,omitempty"`
	Path      string    `json:"path,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Payload   string    `json:"payload,omitempty"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // info / warn / critical
}

// Alerter 多通道告警器
type Alerter struct {
	logger     *zap.SugaredLogger
	channels   []ChannelConfig
	client     *http.Client
	mu         sync.Mutex
	lastAlert  map[string]time.Time // key: "type:ip" — 按事件类型+IP 去重限流
	cooldown   time.Duration        // 同一 IP+事件类型的最小告警间隔
	webhookCfg *WebhookConfig       // 外部 Webhook 配置
}

// New 创建告警器
func New(logger *zap.SugaredLogger, channels []ChannelConfig) *Alerter {
	return &Alerter{
		logger:    logger,
		channels:  channels,
		client:    &http.Client{Timeout: 10 * time.Second},
		lastAlert: make(map[string]time.Time),
		cooldown:  5 * time.Minute, // 同一 IP+事件类型 5 分钟内不重复告警
	}
}

// SetCooldown 设置告警冷却时间
func (a *Alerter) SetCooldown(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cooldown = d
}

// SetWebhook 设置外部 Webhook 配置
func (a *Alerter) SetWebhook(cfg *WebhookConfig) {
	a.webhookCfg = cfg
}

// ShouldAlert 检查是否应该发送告警（冷却期内跳过）
func (a *Alerter) ShouldAlert(event AlertEvent) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := event.Type + ":" + event.RemoteIP
	last, exists := a.lastAlert[key]
	if exists && time.Since(last) < a.cooldown {
		return false
	}
	a.lastAlert[key] = time.Now()
	return true
}

// Send 向所有启用的通道发送告警
func (a *Alerter) Send(event AlertEvent) {
	if !a.ShouldAlert(event) {
		a.logger.Debugw("alert throttled (cooldown)", "type", event.Type, "ip", event.RemoteIP)
		return
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// 自动设置告警等级
	if event.Level == "" {
		event.Level = classifySeverity(event.Type)
	}

	for _, ch := range a.channels {
		if !ch.Enabled {
			continue
		}
		// 事件过滤
		if len(ch.EventFilter) > 0 && !contains(ch.EventFilter, event.Type) {
			continue
		}
		switch ch.Type {
		case ChannelWebhook:
			a.sendWebhook(ch.URL, event)
		case ChannelDingTalk:
			a.sendDingTalk(ch.URL, event)
		case ChannelFeishu:
			a.sendFeishu(ch.URL, event)
		}
	}

	// 通过外部 Webhook 发送 critical/warn 级别告警
	if a.webhookCfg != nil && a.webhookCfg.Enabled && a.webhookCfg.URL != "" {
		if event.Level == "critical" || event.Level == "warn" {
			category := classifyWebhookCategory(event)
			content := map[string]interface{}{
				"category":   category,
				"type":       event.Type,
				"level":      event.Level,
				"remote_ip":  event.RemoteIP,
				"service":    event.Service,
				"path":       event.Path,
				"detail":     event.Detail,
				"user_agent": event.UserAgent,
				"timestamp":  event.Timestamp.Format("2006-01-02 15:04:05"),
			}
			if err := SendWebhookAlert(a.logger, a.webhookCfg, event.Title, content); err != nil {
				a.logger.Warnw("webhook alert send failed", "error", err)
			}
		}
	}
}

func (a *Alerter) sendWebhook(url string, event AlertEvent) {
	payload := map[string]interface{}{
		"type":      event.Type,
		"title":     event.Title,
		"remote_ip": event.RemoteIP,
		"service":   event.Service,
		"path":      event.Path,
		"detail":    event.Detail,
		"level":     event.Level,
		"timestamp": event.Timestamp.Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	resp, err := a.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		a.logger.Warnw("webhook send failed", "error", err, "url", url)
		return
	}
	resp.Body.Close()
	a.logger.Infow("webhook sent", "url", url, "status", resp.StatusCode)
}

func (a *Alerter) sendDingTalk(url string, event AlertEvent) {
	// 钉钉机器人 Markdown 消息格式
	levelEmoji := map[string]string{
		"critical": "🔴", "warn": "🟡", "info": "🔵",
	}
	emoji := levelEmoji[event.Level]
	if emoji == "" {
		emoji = "🔵"
	}

	markdown := fmt.Sprintf(
		"%s **%s**\n\n"+
			"> 类型: %s\n"+
			"> 来源: %s\n"+
			"> 目标: %s\n"+
			"> 路径: %s\n"+
			"> 详情: %s\n"+
			"> 时间: %s\n"+
			"> UA: %s",
		emoji, event.Title,
		event.Type, event.RemoteIP, event.Service,
		event.Path, event.Detail,
		event.Timestamp.Format("2006-01-02 15:04:05"),
		truncate(event.UserAgent, 100),
	)

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": event.Title,
			"text":  markdown,
		},
	}
	data, _ := json.Marshal(payload)
	resp, err := a.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		a.logger.Warnw("dingtalk send failed", "error", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// 钉钉返回 {"errcode":0} 表示成功
	var result struct{ Errcode int }
	json.Unmarshal(body, &result)
	if result.Errcode != 0 {
		a.logger.Warnw("dingtalk send failed", "errcode", result.Errcode, "body", string(body))
	} else {
		a.logger.Infow("dingtalk sent")
	}
}

func (a *Alerter) sendFeishu(url string, event AlertEvent) {
	// 飞书 自定义机器人 富文本格式
	levelTag := map[string]string{
		"critical": "red", "warn": "yellow", "info": "blue",
	}
	tag := levelTag[event.Level]
	if tag == "" {
		tag = "blue"
	}

	elements := []map[string]interface{}{
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": fmt.Sprintf("**%s**", event.Title),
			},
		},
		{
			"tag": "div",
			"fields": []map[string]interface{}{
				{"is_short": true, "text": map[string]interface{}{"tag": "lark_md", "content": fmt.Sprintf("**类型**\n%s", event.Type)}},
				{"is_short": true, "text": map[string]interface{}{"tag": "lark_md", "content": fmt.Sprintf("**等级**\n%s", event.Level)}},
			},
		},
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag": "lark_md",
				"content": fmt.Sprintf("来源IP: %s\n目标服务: %s\n触发路径: %s\n时间: %s",
					event.RemoteIP, event.Service, event.Path,
					event.Timestamp.Format("2006-01-02 15:04:05")),
			},
		},
	}
	if event.Detail != "" {
		elements = append(elements, map[string]interface{}{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": fmt.Sprintf("详情: %s", event.Detail),
			},
		})
	}

	payload := map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"header": map[string]interface{}{
				"title": map[string]string{
					"tag":     "plain_text",
					"content": event.Title,
				},
				"template": tag,
			},
			"elements": elements,
		},
	}
	data, _ := json.Marshal(payload)
	resp, err := a.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		a.logger.Warnw("feishu send failed", "error", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	json.Unmarshal(body, &result)
	if result.Code != 0 {
		a.logger.Warnw("feishu send failed", "code", result.Code, "msg", result.Msg)
	} else {
		a.logger.Infow("feishu sent")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// classifySeverity 根据事件类型自动分级
func classifySeverity(eventType string) string {
	switch eventType {
	case "breadcrumb", "countermeasure":
		return "warn"
	case "attack", "scan":
		return "critical"
	case "connection":
		return "info"
	case "post_body":
		return "warn"
	default:
		return "info"
	}
}

// classifyWebhookCategory 根据告警事件分类 Webhook 类别
func classifyWebhookCategory(event AlertEvent) string {
	switch event.Type {
	case "attack":
		return "attack"
	case "scan":
		return "scan"
	case "breadcrumb":
		return "breadcrumb"
	case "connection":
		return "connection"
	default:
		return "other"
	}
}

// BuildAlertEvent 从总线事件构建告警事件
func BuildAlertEvent(topic string, payload []byte) *AlertEvent {
	var data map[string]interface{}
	json.Unmarshal(payload, &data)

	remoteIP, _ := data["remote_ip"].(string)
	path, _ := data["path"].(string)
	ua, _ := data["user_agent"].(string)
	service, _ := data["service"].(string)

	event := &AlertEvent{
		RemoteIP:  remoteIP,
		Service:   service,
		Path:      path,
		UserAgent: ua,
		Timestamp: time.Now(),
	}

	switch {
	case strings.Contains(topic, "breadcrumb"):
		event.Type = "breadcrumb"
		event.Title = "面包屑触发"
		event.Level = "warn"
		event.Detail = fmt.Sprintf("攻击者 %s 触发了隐藏路径 %s", remoteIP, path)
	case strings.Contains(topic, "attack"):
		event.Type = "attack"
		event.Title = "攻击事件"
		event.Level = "critical"
		event.Detail = fmt.Sprintf("检测到来自 %s 的攻击行为 (路径: %s)", remoteIP, path)
	case strings.Contains(topic, "connection"):
		event.Type = "connection"
		event.Title = "新连接"
		event.Level = "info"
		event.Detail = fmt.Sprintf("新连接: %s → %s", remoteIP, service)
	case strings.Contains(topic, "portscan"):
		event.Type = "scan"
		event.Title = "端口扫描"
		event.Level = "warn"
		event.Detail = fmt.Sprintf("检测到来自 %s 的端口扫描行为", remoteIP)
	default:
		return nil
	}

	return event
}
