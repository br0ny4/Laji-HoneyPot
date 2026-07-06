package github

import (
	"bytes"
	"encoding/base64"
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
	branch string
}

// NewSyncer 创建同步器
func NewSyncer(logger *log.Logger, token, owner, repo, branch string) *Syncer {
	if branch == "" {
		branch = "master"
	}
	return &Syncer{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
		owner:  owner,
		repo:   repo,
		branch: branch,
	}
}

// CommitContent 单文件提交内容
type CommitContent struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Message string `json:"message,omitempty"`
}

// CommitFiles 提交文件到仓库分支（使用 GitHub Contents API）
// 对每个文件执行 PUT /repos/{owner}/{repo}/contents/{path}
func (s *Syncer) CommitFiles(files []CommitContent) error {
	baseURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents", s.owner, s.repo)

	for _, f := range files {
		if err := s.putFile(baseURL, f); err != nil {
			return fmt.Errorf("commit %s: %w", f.Path, err)
		}
	}

	s.logger.Infow("files committed",
		"count", len(files),
		"branch", s.branch,
	)
	return nil
}

// putFile 通过 Contents API 上传/更新单个文件
func (s *Syncer) putFile(baseURL string, f CommitContent) error {
	// 先获取现有文件的 SHA（更新时需要）
	type shaResp struct {
		SHA string `json:"sha"`
	}
	getURL := fmt.Sprintf("%s/%s?ref=%s", baseURL, f.Path, s.branch)
	sha := ""
	req, _ := http.NewRequest("GET", getURL, nil)
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		var sr shaResp
		json.NewDecoder(resp.Body).Decode(&sr)
		sha = sr.SHA
		resp.Body.Close()
	}

	type putBody struct {
		Message string `json:"message"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha,omitempty"`
	}

	msg := f.Message
	if msg == "" {
		msg = fmt.Sprintf("auto: update %s", f.Path)
	}

	body := putBody{
		Message: msg,
		Content: base64.StdEncoding.EncodeToString([]byte(f.Content)),
		Branch:  s.branch,
		SHA:     sha,
	}

	jsonData, _ := json.Marshal(body)
	putURL := fmt.Sprintf("%s/%s", baseURL, f.Path)
	req, err = http.NewRequest("PUT", putURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err = s.client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", f.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("GitHub API returned %d for %s: %s", resp.StatusCode, f.Path, errResp.Message)
	}

	s.logger.Infow("file updated", "path", f.Path, "sha", sha)
	return nil
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
