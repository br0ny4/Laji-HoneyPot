package ops

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/core"
	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/github"
	"github.com/Laji-HoneyPot/honeypot/internal/ops/research"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

// Engine 运维引擎插件
type Engine struct {
	plugin.Base
	logger        *log.Logger
	bus           *bus.Bus
	syncer        *github.Syncer
	readmeUpdater *ReadMeUpdater
	comparator    *research.Comparator
	projectDir    string
}

// NewEngine 创建运维引擎
func NewEngine(logger *log.Logger, bus *bus.Bus) *Engine {
	return &Engine{
		logger:     logger,
		bus:        bus,
		comparator: research.NewComparator(logger),
	}
}

func (e *Engine) Name() string    { return "ops-engine" }
func (e *Engine) Version() string { return "0.5.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("ops engine initializing")

	// 推测项目根目录
	e.projectDir = e.detectProjectDir()

	// 初始化 GitHub Syncer（优先环境变量 GITHUB_TOKEN，其次 config）
	token := cfg.Get("github_token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	owner := cfg.Get("github_owner")
	if owner == "" {
		owner = os.Getenv("GITHUB_REPOSITORY_OWNER")
	}
	repo := cfg.Get("github_repo")
	branch := cfg.Get("github_branch")
	if branch == "" {
		branch = "main"
	}
	if token != "" && owner != "" && repo != "" {
		e.syncer = github.NewSyncer(e.logger, token, owner, repo, branch)
		e.logger.Info("github syncer initialized",
			"repo", owner+"/"+repo,
			"branch", branch,
		)
	}

	// 初始化 README 自动更新器（始终可用）
	readmePath := filepath.Join(e.projectDir, "README.md")
	e.readmeUpdater = NewReadMeUpdater(readmePath)
	e.logger.Infow("readme updater initialized", "path", readmePath)

	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("ops engine started")

	// 1. 启动后异步拉取竞品情报（不阻塞主流程）
	go func() {
		e.logger.Info("starting competitor intelligence gathering")
		if err := e.comparator.FetchFromGitHub(); err != nil {
			e.logger.Warnw("competitor fetch failed", "error", err)
			return
		}
		report := e.comparator.GenerateReport()
		e.logger.Infow("competitor report generated")
		e.bus.Publish("ops.competitor_report", []byte(report))
	}()

	// 2. 自动更新 README.md + 提交到 GitHub（异步，不阻塞主流程）
	go e.autoUpdateReadme()

	return nil
}

// autoUpdateReadme 自动更新 README.md 中的版本号、测试统计、路线图，并提交到 GitHub
func (e *Engine) autoUpdateReadme() {
	if e.readmeUpdater == nil {
		return
	}

	version := core.Version
	testPkgCount := e.countTestPackages()

	// 路线图新增项检测（从最近的 git 提交中提取）
	roadmapItems := e.detectRoadmapItems()

	e.logger.Infow("auto-updating README.md",
		"version", version,
		"test_packages", testPkgCount,
		"roadmap_items", len(roadmapItems),
	)

	if err := e.readmeUpdater.Update(version, testPkgCount, roadmapItems); err != nil {
		e.logger.Warnw("README update failed", "error", err)
		return
	}

	e.logger.Info("README.md updated successfully")

	// 如果有 GitHub Syncer，提交 README.md 到仓库
	if e.syncer != nil {
		e.commitReadmeToGitHub()
	}
}

// commitReadmeToGitHub 读取更新后的 README.md 并推送到 GitHub
// 优先使用 GitHub API（需要 GITHUB_TOKEN），不可用时 fallback 到本地 git 命令
func (e *Engine) commitReadmeToGitHub() {
	readmePath := filepath.Join(e.projectDir, "README.md")
	content, err := os.ReadFile(readmePath)
	if err != nil {
		e.logger.Warnw("failed to read README for commit", "error", err)
		return
	}

	version := core.Version

	// 优先：GitHub Contents API（需要 token）
	if e.syncer != nil {
		files := []github.CommitContent{{
			Path:    "README.md",
			Content: string(content),
			Message: "auto: update README.md for v" + version,
		}}
		if err := e.syncer.CommitFiles(files); err != nil {
			e.logger.Warnw("GitHub API commit failed, falling back to local git", "error", err)
		} else {
			e.logger.Info("README.md committed to GitHub via API")
			return
		}
	}

	// Fallback: 本地 git add + commit + push（支持 SSH remote，无需 token）
	e.logger.Info("committing README via local git")
	commitMsg := "auto: update README.md for v" + version
	cmds := [][]string{
		{"git", "add", "README.md"},
		{"git", "commit", "-m", commitMsg},
		{"git", "push"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = e.projectDir
		if out, err := cmd.CombinedOutput(); err != nil {
			// commit 可能因无变更而失败，这是正常的
			if args[1] == "commit" && strings.Contains(string(out), "nothing to commit") {
				continue
			}
			e.logger.Warnw("git command failed", "cmd", args[1], "output", string(out), "error", err)
		}
	}
}

// countTestPackages 统计通过测试的包数量
func (e *Engine) countTestPackages() int {
	cmd := exec.Command("go", "test", "-count=1", "-timeout=30s", "./...")
	cmd.Dir = e.projectDir
	out, _ := cmd.CombinedOutput()

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ok") {
			count++
		}
	}
	return count
}

// detectRoadmapItems 从最近版本迭代中检测新的路线图项
func (e *Engine) detectRoadmapItems() []string {
	// 尝试从 git log 中提取最近带 v 前缀的 tag 之间的提交作为路线图项
	cmd := exec.Command("git", "log", "--oneline", "-20", "--no-merges", "HEAD")
	cmd.Dir = e.projectDir
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var items []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 12 {
			// 截取提交消息（去除 hash 前缀）
			msg := line[8:] // 跳过 hash 前8位
			// 过滤掉无关的提交消息
			lower := strings.ToLower(msg)
			if strings.Contains(lower, "wip") || strings.Contains(lower, "tmp") {
				continue
			}
			items = append(items, "- [x] "+msg)
		}
	}
	return items
}

// detectProjectDir 推测项目根目录
func (e *Engine) detectProjectDir() string {
	// 优先从环境变量读取
	if dir := os.Getenv("HP_PROJECT_DIR"); dir != "" {
		return dir
	}
	// 尝试从当前工作目录找到 go.mod 所在的目录
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

func (e *Engine) Stop() error {
	e.logger.Info("ops engine stopped")
	return nil
}

func (e *Engine) GetComparator() *research.Comparator { return e.comparator }
func (e *Engine) GetSyncer() *github.Syncer           { return e.syncer }

// 确保 strconv 被使用（go test 统计需要）
var _ = strconv.Itoa
