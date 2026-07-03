package alerter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// WebhookType 外部 Webhook 平台类型
type WebhookType string

const (
	WebhookDingTalk WebhookType = "dingtalk"
	WebhookFeishu   WebhookType = "feishu"
	WebhookGeneric  WebhookType = "generic"
)

// WebhookConfig 外部 Webhook 配置
type WebhookConfig struct {
	URL     string      `yaml:"url"`
	Type    WebhookType `yaml:"type"`
	Secret  string      `yaml:"secret"`
	Enabled bool        `yaml:"enabled"`
}

// SendWebhookAlert 向配置的 Webhook 发送告警
// title: 告警标题
// content: 告警内容，key 为字段名，value 为字段值
func SendWebhookAlert(logger *zap.SugaredLogger, cfg *WebhookConfig, title string, content map[string]interface{}) error {
	if cfg == nil || !cfg.Enabled || cfg.URL == "" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}

	switch cfg.Type {
	case WebhookDingTalk:
		return sendDingTalkWebhook(client, cfg, title, content)
	case WebhookFeishu:
		return sendFeishuWebhook(client, cfg, title, content)
	case WebhookGeneric:
		return sendGenericWebhook(client, cfg, title, content)
	default:
		logger.Warnw("unknown webhook type", "type", cfg.Type)
		return fmt.Errorf("unknown webhook type: %s", cfg.Type)
	}
}

func sendDingTalkWebhook(client *http.Client, cfg *WebhookConfig, title string, content map[string]interface{}) error {
	// 构建 Markdown 文本
	text := fmt.Sprintf("### %s\n\n", title)
	for k, v := range content {
		text += fmt.Sprintf("- **%s**: %v\n", k, v)
	}

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  text,
		},
	}
	data, _ := json.Marshal(payload)

	targetURL := cfg.URL
	if cfg.Secret != "" {
		timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
		sign := dingTalkSign(timestamp, cfg.Secret)
		targetURL = fmt.Sprintf("%s&timestamp=%s&sign=%s", cfg.URL, timestamp, sign)
	}

	resp, err := client.Post(targetURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("dingtalk webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct{ Errcode int }
	json.Unmarshal(body, &result)
	if result.Errcode != 0 {
		return fmt.Errorf("dingtalk error: errcode=%d, body=%s", result.Errcode, string(body))
	}
	return nil
}

func sendFeishuWebhook(client *http.Client, cfg *WebhookConfig, title string, content map[string]interface{}) error {
	// 使用简单文本格式
	text := title + "\n"
	for k, v := range content {
		text += fmt.Sprintf("%s: %v\n", k, v)
	}

	payload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": text,
		},
	}

	// HMAC 签名（飞书安全设置）
	targetURL := cfg.URL
	if cfg.Secret != "" {
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		sign := feishuSign(timestamp, cfg.Secret)
		payload["timestamp"] = timestamp
		payload["sign"] = sign
	}

	data, _ := json.Marshal(payload)
	resp, err := client.Post(targetURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("feishu webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	json.Unmarshal(body, &result)
	if result.Code != 0 {
		return fmt.Errorf("feishu error: code=%d, msg=%s", result.Code, result.Msg)
	}
	return nil
}

func sendGenericWebhook(client *http.Client, cfg *WebhookConfig, title string, content map[string]interface{}) error {
	payload := map[string]interface{}{
		"title":     title,
		"content":   content,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)

	resp, err := client.Post(cfg.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("generic webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("generic webhook returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// dingTalkSign 钉钉 HMAC-SHA256 签名
// 签名算法: Base64(HmacSHA256(timestamp+"\n"+secret, secret))
func dingTalkSign(timestamp string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp + "\n" + secret))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
}

// feishuSign 飞书签名
// 签名算法: Base64(HmacSHA256(timestamp+"\n"+secret, secret)) 不对特殊字符转义
// 飞书文档：sign = timestamp + "\n" + secret，使用 HMAC-SHA256 计算后 Base64
func feishuSign(timestamp string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp + "\n" + secret))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
