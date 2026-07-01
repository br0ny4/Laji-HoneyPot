package vulndb

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// NVDCrawler NVD (National Vulnerability Database) API 爬虫
// 支持定期扫描 + CVE 详情获取 + 浏览器漏洞专项跟踪
type NVDCrawler struct {
	logger    *log.Logger
	client    *http.Client
	apiKey    string
	lastFetch time.Time // 上次拉取时间，用于增量查询
	mu        sync.RWMutex
}

// NewNVDCrawler 创建 NVD 爬虫
func NewNVDCrawler(logger *log.Logger, apiKey string) *NVDCrawler {
	return &NVDCrawler{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

// nvdCVEItem 单个 CVE 条目
type nvdCVEItem struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Published string `json:"published"`
	Metrics   struct {
		CVSSv31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CVSSv30 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
	} `json:"metrics"`
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	StartIndex      int `json:"startIndex"`
	ResultsPerPage  int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		CVE nvdCVEItem `json:"cve"`
	} `json:"vulnerabilities"`
}

// mapKeywordToTool 根据 NVD 关键词映射到工具类型
func mapKeywordToTool(keyword string) string {
	browserKeywords := map[string]string{
		"chrome v8":       "chrome",
		"chrome chromium": "chrome",
		"google chrome":   "chrome",
		"chromium":        "chrome",
		"chrome angle":    "chrome",
		"chrome skia":     "chrome",
		"webkit":          "chrome",
		"blink":           "chrome",
		"firefox":         "firefox",
		"mozilla firefox": "firefox",
		"edge chromium":   "chrome",
		"microsoft edge":  "chrome",
		"brave browser":   "chrome",
		"opera browser":   "chrome",
		"safari webkit":   "chrome",
		"cef chromium":    "chrome",
		"electron":        "chrome",
		"burp suite":      "burpsuite",
		"cobalt strike":   "cobaltstrike",
		"metasploit":      "metasploit",
		"behinder":        "behinder",
	}
	for k, v := range browserKeywords {
		if strings.Contains(strings.ToLower(keyword), k) {
			return v
		}
	}
	return keyword
}

// extractCVSS 从 NVD CVE 条目提取 CVSS v3 评分
func extractCVSS(item nvdCVEItem) float64 {
	if item.Metrics.CVSSv31 != nil && len(item.Metrics.CVSSv31) > 0 {
		return item.Metrics.CVSSv31[0].CVSSData.BaseScore
	}
	if item.Metrics.CVSSv30 != nil && len(item.Metrics.CVSSv30) > 0 {
		return item.Metrics.CVSSv30[0].CVSSData.BaseScore
	}
	return 0
}

// extractSeverity 从 CVSS 分数映射危害等级
func extractSeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "unknown"
	}
}

// FetchRecent 获取最近的漏洞信息（基于关键字）
// 支持增量查询：若 lastFetch 已设置，添加 pubStartDate 参数过滤
func (c *NVDCrawler) FetchRecent(keywords []string) ([]*VulnEntry, error) {
	c.mu.Lock()
	lf := c.lastFetch
	c.mu.Unlock()

	var results []*VulnEntry

	for _, kw := range keywords {
		func(keyword string) {
			url := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + url.QueryEscape(keyword) + "&resultsPerPage=5"
			// 增量查询：仅拉取上次拉取后新发布的 CVE
			if !lf.IsZero() {
				url += "&pubStartDate=" + lf.Format("2006-01-02T15:04:05")
			}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			if c.apiKey != "" {
				req.Header.Set("apiKey", c.apiKey)
			}

			resp, err := c.client.Do(req)
			if err != nil {
				c.logger.Warnw("nvd fetch failed", "keyword", keyword, "error", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				c.logger.Warnw("nvd rate limit (403), consider adding apiKey", "keyword", keyword)
				return
			}
			if resp.StatusCode != 200 {
				c.logger.Warnw("nvd non-200 response", "keyword", keyword, "status", resp.StatusCode)
				return
			}

			var nvdResp nvdResponse
			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
				return
			}

			for _, v := range nvdResp.Vulnerabilities {
				desc := ""
				for _, d := range v.CVE.Descriptions {
					if d.Lang == "en" {
						desc = d.Value
						break
					}
				}

				published, _ := time.Parse("2006-01-02T15:04:05", v.CVE.Published[:19])
				cvss := extractCVSS(v.CVE)
				severity := extractSeverity(cvss)
				tool := mapKeywordToTool(keyword)

				// 推断利用类型
				et := inferExploitType(desc, keyword)

				results = append(results, &VulnEntry{
					ID:               v.CVE.ID,
					Tool:             tool,
					Title:            v.CVE.ID + " - " + truncateDesc(desc, 60),
					Description:      desc,
					CVE:              v.CVE.ID,
					Severity:         severity,
					Discovered:       published,
					CVSS:             cvss,
					ExploitType:      et,
					IsActive:         false, // NVD 新增条目默认未集成利用链
					AffectedVersions: extractAffectedVersions(desc),
					ExploitScenario:  string(et),
					References:       []string{"https://nvd.nist.gov/vuln/detail/" + v.CVE.ID},
				})
			}
		}(kw)
	}

	c.mu.Lock()
	c.lastFetch = time.Now()
	c.mu.Unlock()

	c.logger.Infow("nvd crawl complete", "results", len(results))
	return results, nil
}

// inferExploitType 根据描述推断利用类型分类
func inferExploitType(desc, keyword string) ExploitType {
	descLower := strings.ToLower(desc)
	kwLower := strings.ToLower(keyword)

	// 沙箱逃逸
	if strings.Contains(descLower, "sandbox escape") || strings.Contains(descLower, "sandbox bypass") {
		return ExploitSandboxEscape
	}
	// 远程代码执行
	if strings.Contains(descLower, "remote code execution") || strings.Contains(descLower, "rce") ||
		strings.Contains(descLower, "arbitrary code") {
		return ExploitRCE
	}
	// 跨域
	if strings.Contains(descLower, "cross-origin") || strings.Contains(descLower, "cross origin") ||
		strings.Contains(descLower, "site isolation") || strings.Contains(descLower, "same-origin") {
		return ExploitCrossOrigin
	}
	// 信息泄露
	if strings.Contains(descLower, "information disclosure") || strings.Contains(descLower, "information leak") ||
		strings.Contains(descLower, "data leak") || strings.Contains(descLower, "information exposure") {
		return ExploitInfoLeak
	}
	// XSS
	if strings.Contains(descLower, "cross-site scripting") || strings.Contains(descLower, "xss") {
		return ExploitXSS
	}
	// 浏览器内核关键词
	if strings.Contains(kwLower, "chrome") || strings.Contains(kwLower, "firefox") ||
		strings.Contains(kwLower, "webkit") || strings.Contains(kwLower, "blink") ||
		strings.Contains(kwLower, "chromium") || strings.Contains(kwLower, "edge") {
		return ExploitRCE // 浏览器 CVE 默认为 RCE 类型
	}
	return ExploitInfoLeak
}

// extractAffectedVersions 从描述中提取受影响版本信息
func extractAffectedVersions(desc string) string {
	// 尝试提取 Chrome 版本
	if strings.Contains(strings.ToLower(desc), "chrome") {
		re := versionRegex()
		if re != "" {
			if matches := versionRegexMatches(re, desc); len(matches) > 0 {
				return "Chrome < " + matches[0]
			}
		}
		return "Google Chrome (版本待确认)"
	}
	// Firefox
	if strings.Contains(strings.ToLower(desc), "firefox") {
		return "Mozilla Firefox (版本待确认)"
	}
	return "待确认"
}

// 简单版本号正则辅助
var chromeVersionPattern = `Chrome\s+(prior to|before|<)\s+[\d.]+`

func versionRegex() string {
	return chromeVersionPattern
}

func versionRegexMatches(pattern, desc string) []string {
	// 简单实现：返回空（完整正则需 regexp 包）
	return nil
}

func truncateDesc(desc string, maxLen int) string {
	if len(desc) <= maxLen {
		return desc
	}
	return desc[:maxLen] + "..."
}

// 浏览器漏洞专项关键词 — 覆盖 Chrome/Chromium/Firefox/Edge/WebKit
var BrowserKeywords = []string{
	"chrome v8",
	"chrome angle",
	"chrome skia",
	"chrome sandbox escape",
	"chrome use after free",
	"chrome type confusion",
	"chrome out of bounds",
	"chrome heap buffer overflow",
	"firefox sandbox",
	"firefox use after free",
	"firefox type confusion",
	"webkit memory corruption",
	"chromium sandbox",
	"chromium v8",
	"microsoft edge chromium",
	"brave browser vulnerability",
}

// 红队工具及常见浏览器/工具关键字 — 覆盖渗透工具和通用访问工具
var RedTeamKeywords = []string{
	"cobalt strike",
	"burp suite",
	"metasploit",
	"behinder",
	"godzilla",
	"webshell",
	"command and control",
	"c2 framework",
	"chrome v8",
	"firefox",
	"webkit",
	"sqlmap",
	"nuclei",
	"nessus",
}

// SetLastFetch 设置上次拉取时间（用于初始化增量查询）
func (c *NVDCrawler) SetLastFetch(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFetch = t
}

// GetLastFetch 获取上次拉取时间
func (c *NVDCrawler) GetLastFetch() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastFetch
}
