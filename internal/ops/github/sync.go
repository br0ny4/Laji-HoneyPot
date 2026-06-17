package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Syncer GitHub 仓库同步器
type Syncer struct {
	logger *log.Logger
	client *http.Client
	token  string
	owner  string
	repo   string
}

// NewSyncer 创建同步器
func NewSyncer(logger *log.Logger, token, owner, repo string) *Syncer {
	return &Syncer{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
		owner:  owner,
		repo:   repo,
	}
}

// CreateRelease 通过 GitHub API 创建 Release
func (s *Syncer) CreateRelease(tagName, name, body string) error {
	type releaseReq struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		Body    string `json:"body"`
		Draft   bool   `json:"draft"`
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", s.owner, s.repo)
	payload := releaseReq{
		TagName: tagName,
		Name:    name,
		Body:    body,
		Draft:   false,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("create release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	s.logger.Infow("release created", "tag", tagName)
	return nil
}

// GetLatestRelease 获取最新 Release 信息
func (s *Syncer) GetLatestRelease() (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", s.owner, s.repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.TagName, nil
}
