// 独立 README 同步工具 (v0.20)
// 用法: go run ./cmd/tools/readme-sync/
//
// 该工具读取 internal/core/version.go 中的版本号，使用 ops 包中的
// ReadMeUpdater 更新 README.md 中的 <!-- BEGIN-AUTO:* --> 标记区域，
// 并可选通过 GITHUB_TOKEN 环境变量推送至远程仓库。
//
// 环境变量:
//
//	GITHUB_TOKEN       - GitHub Personal Access Token (可选，设置后自动推送)
//	GITHUB_REPOSITORY  - 仓库路径 (如 "owner/repo")，默认从 git remote 推断
//
// 退出码: 0=成功, 1=更新失败, 2=推送失败
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/core"
	"github.com/Laji-HoneyPot/honeypot/internal/ops"
)

func main() {
	version := core.Version

	// 统计测试包数量
	testPkgCount := countTestPackages()

	// 更新 README.md
	updater := ops.NewReadMeUpdater("README.md")
	if err := updater.Update(version, testPkgCount, nil); err != nil {
		fmt.Fprintf(os.Stderr, "README update failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("README.md updated (version=%s, test_packages=%d)\n", version, testPkgCount)

	// 如果有 GITHUB_TOKEN 环境变量，本地 git 提交 + 推送
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("GITHUB_TOKEN not set — skip remote push")
		return
	}

	// 配置 git 用户信息（CI 环境）
	authorName := os.Getenv("GIT_AUTHOR_NAME")
	if authorName == "" {
		authorName = "github-actions[bot]"
	}
	authorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	if authorEmail == "" {
		authorEmail = "github-actions[bot]@users.noreply.github.com"
	}

	// git add README.md
	if err := runCmd("git", "config", "user.name", authorName); err != nil {
		fmt.Fprintf(os.Stderr, "git config user.name failed: %v\n", err)
	}
	if err := runCmd("git", "config", "user.email", authorEmail); err != nil {
		fmt.Fprintf(os.Stderr, "git config user.email failed: %v\n", err)
	}

	// 检查是否有变更
	diffOut, _ := exec.Command("git", "diff", "--exit-code", "README.md").Output()
	if string(diffOut) == "" {
		fmt.Println("No changes to README.md — skip commit")
		return
	}

	// git add + commit + push
	if err := runCmd("git", "add", "README.md"); err != nil {
		fmt.Fprintf(os.Stderr, "git add failed: %v\n", err)
		os.Exit(2)
	}

	commitMsg := fmt.Sprintf("auto: sync README.md for v%s", version)
	if err := runCmd("git", "commit", "-m", commitMsg); err != nil {
		fmt.Fprintf(os.Stderr, "git commit failed: %v\n", err)
		os.Exit(2)
	}

	// 设置 remote URL 带 token 认证
	if err := setupGitRemote(token); err != nil {
		fmt.Fprintf(os.Stderr, "git remote setup failed: %v\n", err)
		os.Exit(2)
	}

	if err := runCmd("git", "push"); err != nil {
		fmt.Fprintf(os.Stderr, "git push failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("README.md pushed to remote successfully")
}

func countTestPackages() int {
	cmd := exec.Command("go", "test", "-count=1", "-timeout=30s", "./...")
	out, _ := cmd.CombinedOutput()

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ok") {
			count++
		}
	}
	return count
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func setupGitRemote(token string) error {
	// 获取当前 remote URL
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return fmt.Errorf("get remote url: %w", err)
	}
	remoteURL := strings.TrimSpace(string(out))

	// SSH remote (git@github.com:...) 不需要 token，直接 push
	if strings.HasPrefix(remoteURL, "git@") {
		return nil
	}

	// HTTPS remote: 替换为带 token 的 URL
	// https://github.com/owner/repo => https://x-access-token:TOKEN@github.com/owner/repo
	remoteURL = strings.Replace(remoteURL, "https://", "https://x-access-token:"+token+"@", 1)

	return runCmd("git", "remote", "set-url", "origin", remoteURL)
}
