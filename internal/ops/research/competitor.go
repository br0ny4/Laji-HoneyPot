package research

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Competitor 竞品信息
type Competitor struct {
	Name        string   `json:"name"`
	RepoURL     string   `json:"repo_url"`
	Stars       int      `json:"stars"`
	Language    string   `json:"language"`
	Description string   `json:"description"`
	Topics      []string `json:"topics"`
	UpdatedAt   string   `json:"updated_at"`

	Protocols     []string `json:"protocols"`
	Traceability  bool     `json:"traceability"`
	Containerized bool     `json:"containerized"`
}

// Comparator 竞品对比器
type Comparator struct {
	logger      *log.Logger
	client      *http.Client
	competitors []*Competitor
}

// NewComparator 创建竞品对比器
func NewComparator(logger *log.Logger) *Comparator {
	return &Comparator{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchFromGitHub 从 GitHub 搜索蜜罐项目
func (c *Comparator) FetchFromGitHub() error {
	queries := []string{"honeypot", "蜜罐", "honeypot-framework", "t-pot"}
	seen := make(map[string]bool)

	for _, q := range queries {
		url := fmt.Sprintf(
			"https://api.github.com/search/repositories?q=%s+topic:honeypot&sort=stars&order=desc&per_page=10",
			q,
		)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.client.Do(req)
		if err != nil {
			c.logger.Warnw("github search failed", "query", q, "error", err)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Items []struct {
				FullName    string   `json:"full_name"`
				HTMLURL     string   `json:"html_url"`
				Stars       int      `json:"stargazers_count"`
				Language    string   `json:"language"`
				Description string   `json:"description"`
				Topics      []string `json:"topics"`
				UpdatedAt   string   `json:"updated_at"`
			} `json:"items"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			continue
		}

		for _, item := range result.Items {
			if seen[item.FullName] {
				continue
			}
			seen[item.FullName] = true

			comp := &Competitor{
				Name:        item.FullName,
				RepoURL:     item.HTMLURL,
				Stars:       item.Stars,
				Language:    item.Language,
				Description: item.Description,
				Topics:      item.Topics,
				UpdatedAt:   item.UpdatedAt,
			}

			comp.Traceability = c.detectTraceability(item.Description, item.Topics)
			comp.Protocols = c.detectProtocols(item.Description, item.Topics)
			comp.Containerized = c.detectContainerized(item.Description, item.Topics)

			c.competitors = append(c.competitors, comp)
		}
	}

	sort.Slice(c.competitors, func(i, j int) bool {
		return c.competitors[i].Stars > c.competitors[j].Stars
	})

	c.logger.Infow("competitor fetch complete", "count", len(c.competitors))
	return nil
}

func (c *Comparator) detectTraceability(desc string, topics []string) bool {
	keywords := []string{"溯源", "traceability", "traceback", "attribution", "fingerprint"}
	all := desc + " " + strings.Join(topics, " ")
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(all), kw) {
			return true
		}
	}
	return false
}

func (c *Comparator) detectProtocols(desc string, topics []string) []string {
	all := strings.ToLower(desc + " " + strings.Join(topics, " "))
	protoMap := map[string]string{
		"http": "HTTP", "https": "HTTPS", "mysql": "MySQL",
		"redis": "Redis", "ssh": "SSH", "ftp": "FTP",
		"smb": "SMB", "telnet": "Telnet", "smtp": "SMTP",
		"dns": "DNS", "ldap": "LDAP", "rdp": "RDP",
	}

	var result []string
	for key, label := range protoMap {
		if strings.Contains(all, key) {
			result = append(result, label)
		}
	}
	return result
}

func (c *Comparator) detectContainerized(desc string, topics []string) bool {
	all := strings.ToLower(desc + " " + strings.Join(topics, " "))
	kw := []string{"docker", "container", "kubernetes", "k8s"}
	for _, k := range kw {
		if strings.Contains(all, k) {
			return true
		}
	}
	return false
}

// GenerateReport 生成 Markdown 格式对比报告
func (c *Comparator) GenerateReport() string {
	var sb strings.Builder
	sb.WriteString("# 蜜罐竞品分析报告\n\n")
	sb.WriteString(fmt.Sprintf("> 自动生成于 %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("| 项目 | Stars | 语言 | 协议支持 | 溯源能力 | 容器化 |\n")
	sb.WriteString("|------|-------|------|---------|---------|--------|\n")

	for _, comp := range c.competitors {
		trace := "否"
		if comp.Traceability {
			trace = "是"
		}
		contain := "否"
		if comp.Containerized {
			contain = "是"
		}
		proto := strings.Join(comp.Protocols, ", ")
		if proto == "" {
			proto = "-"
		}

		sb.WriteString(fmt.Sprintf("| [%s](%s) | %d | %s | %s | %s | %s |\n",
			comp.Name, comp.RepoURL, comp.Stars, comp.Language, proto, trace, contain))
	}

	sb.WriteString("\n---\n*本报告由 Laji-HoneyPot 竞品调研引擎自动生成*\n")
	return sb.String()
}
