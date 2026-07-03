package bait

import (
	"sync"
	"time"
)

// AccessRecord records when a bait file is accessed
type AccessRecord struct {
	TokenID   string            `json:"token_id"`
	BaitType  string            `json:"bait_type"`
	RemoteIP  string            `json:"remote_ip"`
	UserAgent string            `json:"user_agent"`
	Referer   string            `json:"referer"`
	Timestamp time.Time         `json:"timestamp"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// Tracker tracks bait file access events
type Tracker struct {
	mu      sync.RWMutex
	records []AccessRecord
	maxSize int
}

// TopEntry represents an aggregated count entry for stats
type TopEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// NewTracker creates a new bait access tracker
func NewTracker(maxSize int) *Tracker {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &Tracker{
		records: make([]AccessRecord, 0, maxSize),
		maxSize: maxSize,
	}
}

// Record logs a bait access event
func (t *Tracker) Record(record AccessRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.records) >= t.maxSize {
		// Drop oldest records (keep most recent)
		t.records = t.records[len(t.records)-t.maxSize+1:]
	}
	t.records = append(t.records, record)
}

// GetByIP returns all access records for a given IP
func (t *Tracker) GetByIP(ip string) []AccessRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var results []AccessRecord
	for i := len(t.records) - 1; i >= 0; i-- {
		if t.records[i].RemoteIP == ip {
			results = append(results, t.records[i])
		}
	}
	return results
}

// GetByType returns all access records for a bait type
func (t *Tracker) GetByType(baitType string) []AccessRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var results []AccessRecord
	for i := len(t.records) - 1; i >= 0; i-- {
		if t.records[i].BaitType == baitType {
			results = append(results, t.records[i])
		}
	}
	return results
}

// All returns all access records (most recent first)
func (t *Tracker) All(limit int) []AccessRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit <= 0 || limit > len(t.records) {
		limit = len(t.records)
	}

	results := make([]AccessRecord, limit)
	for i := 0; i < limit; i++ {
		results[i] = t.records[len(t.records)-1-i]
	}
	return results
}

// Stats returns aggregated bait access statistics
func (t *Tracker) Stats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	typeCount := make(map[string]int)
	ipCount := make(map[string]int)

	for _, r := range t.records {
		typeCount[r.BaitType]++
		ipCount[r.RemoteIP]++
	}

	// Find top types
	topTypes := make([]TopEntry, 0, len(typeCount))
	for k, v := range typeCount {
		topTypes = append(topTypes, TopEntry{Key: k, Count: v})
	}
	// Sort descending
	for i := 0; i < len(topTypes); i++ {
		for j := i + 1; j < len(topTypes); j++ {
			if topTypes[j].Count > topTypes[i].Count {
				topTypes[i], topTypes[j] = topTypes[j], topTypes[i]
			}
		}
	}

	topIPs := make([]TopEntry, 0, len(ipCount))
	for k, v := range ipCount {
		topIPs = append(topIPs, TopEntry{Key: k, Count: v})
	}
	for i := 0; i < len(topIPs); i++ {
		for j := i + 1; j < len(topIPs); j++ {
			if topIPs[j].Count > topIPs[i].Count {
				topIPs[i], topIPs[j] = topIPs[j], topIPs[i]
			}
		}
	}

	// Limit to top 10
	if len(topTypes) > 10 {
		topTypes = topTypes[:10]
	}
	if len(topIPs) > 10 {
		topIPs = topIPs[:10]
	}

	return map[string]interface{}{
		"total_tokens":    len(t.allBaitTypes()),
		"total_accesses":  len(t.records),
		"top_accessed":    topTypes,
		"top_ips":         topIPs,
	}
}

func (t *Tracker) allBaitTypes() []string {
	return []string{"aws_key", "db_creds", "api_token", "ssh_key", "git_config", "wp_config", "env_file"}
}
