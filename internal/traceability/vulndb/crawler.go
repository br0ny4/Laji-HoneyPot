package vulndb

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// NVDCrawler NVD (National Vulnerability Database) API 爬虫
type NVDCrawler struct {
	logger *log.Logger
	client *http.Client
	apiKey string
}

// NewNVDCrawler 创建 NVD 爬虫
func NewNVDCrawler(logger *log.Logger, apiKey string) *NVDCrawler {
	return &NVDCrawler{
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Published string `json:"published"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// FetchRecent 获取最近的漏洞信息（基于关键字）
func (c *NVDCrawler) FetchRecent(keywords []string) ([]*VulnEntry, error) {
	var results []*VulnEntry

	for _, kw := range keywords {
		url := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + kw + "&resultsPerPage=5"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			c.logger.Warnw("nvd fetch failed", "keyword", kw, "error", err)
			continue
		}
		defer resp.Body.Close()

		var nvdResp nvdResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			continue
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

			results = append(results, &VulnEntry{
				ID:          v.CVE.ID,
				Tool:        kw,
				Title:       v.CVE.ID,
				Description: desc,
				CVE:         v.CVE.ID,
				Discovered:  published,
			})
		}
	}

	c.logger.Infow("nvd crawl complete", "results", len(results))
	return results, nil
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
