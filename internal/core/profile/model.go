package profile

import "time"

// CountermeasureSummary 反制措施摘要（用于攻击者画像）
type CountermeasureSummary struct {
	OpType    string    `json:"op_type"`    // screen_capture, file_scan, etc.
	Score     int       `json:"score"`
	Timestamp time.Time `json:"timestamp"`
	TargetIP  string    `json:"target_ip"`
}
