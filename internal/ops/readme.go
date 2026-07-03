// Package ops README 自动更新工具
// 从源码中提取当前版本号、测试统计等信息，自动更新 README.md 中的对应标注区域。
//
// 标注区域使用 HTML 注释标记：
//
//	<!-- BEGIN-AUTO:VERSION --> ... <!-- END-AUTO:VERSION -->
//	<!-- BEGIN-AUTO:TESTS -->  ... <!-- END-AUTO:TESTS -->
//	<!-- BEGIN-AUTO:ROADMAP --> ... <!-- END-AUTO:ROADMAP -->
//
// 标记区域外的手写内容完全保留，不会自动修改。
package ops

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ReadMeUpdater handles README.md auto-update logic
type ReadMeUpdater struct {
	filePath string
}

// NewReadMeUpdater creates a ReadMeUpdater for the given README path
func NewReadMeUpdater(filePath string) *ReadMeUpdater {
	return &ReadMeUpdater{filePath: filePath}
}

// Update updates the README.md with auto-generated content.
// version: current version string (e.g. "0.17.0")
// testPkgCount: number of test packages passed
// newRoadmapItems: new roadmap items to append (e.g. "- [x] feature description")
func (u *ReadMeUpdater) Update(version string, testPkgCount int, newRoadmapItems []string) error {
	data, err := os.ReadFile(u.filePath)
	if err != nil {
		return fmt.Errorf("read README.md: %w", err)
	}

	content := string(data)

	// 1. Update version badge: <!-- BEGIN-AUTO:VERSION --> ... <!-- END-AUTO:VERSION -->
	content = u.replaceVersionBlock(content, version)

	// 2. Update test badge: <!-- BEGIN-AUTO:TESTS --> ... <!-- END-AUTO:TESTS -->
	content = u.replaceTestBlock(content, testPkgCount)

	// 3. Append new roadmap items: <!-- BEGIN-AUTO:ROADMAP --> ... <!-- END-AUTO:ROADMAP -->
	if len(newRoadmapItems) > 0 {
		content = u.appendRoadmapItems(content, newRoadmapItems)
	}

	if err := os.WriteFile(u.filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write README.md: %w", err)
	}

	return nil
}

// replaceVersionBlock replaces the version badge block
func (u *ReadMeUpdater) replaceVersionBlock(content, version string) string {
	re := regexp.MustCompile(
		`(?s)<!-- BEGIN-AUTO:VERSION -->.*?<!-- END-AUTO:VERSION -->`,
	)

	replacement := fmt.Sprintf(
		`<!-- BEGIN-AUTO:VERSION -->
  <a href="./internal/core/version.go"><img src="https://img.shields.io/badge/version-%s-blue" alt="Version" /></a>
  <!-- END-AUTO:VERSION -->`,
		version,
	)

	return re.ReplaceAllString(content, replacement)
}

// replaceTestBlock replaces the test stats badge block
func (u *ReadMeUpdater) replaceTestBlock(content string, testPkgCount int) string {
	re := regexp.MustCompile(
		`(?s)<!-- BEGIN-AUTO:TESTS -->.*?<!-- END-AUTO:TESTS -->`,
	)

	replacement := fmt.Sprintf(
		`<!-- BEGIN-AUTO:TESTS -->
  <a href="https://github.com/br0ny4/Laji-HoneyPot/actions"><img src="https://img.shields.io/badge/tests-%d%%2F%d%%20PASS-brightgreen" alt="Tests" /></a>
  <!-- END-AUTO:TESTS -->`,
		testPkgCount, testPkgCount,
	)

	return re.ReplaceAllString(content, replacement)
}

// appendRoadmapItems inserts new roadmap items into the marker block.
// Items are inserted after the BEGIN marker line.
func (u *ReadMeUpdater) appendRoadmapItems(content string, items []string) string {
	re := regexp.MustCompile(
		`(?s)(<!-- BEGIN-AUTO:ROADMAP -->\n)(.*?)(\n<!-- END-AUTO:ROADMAP -->)`,
	)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		prefix := parts[1]
		existing := parts[2]
		suffix := parts[3]

		// Only add new items that aren't already present
		for _, item := range items {
			if !strings.Contains(existing, item) {
				existing += item + "\n"
			}
		}

		return prefix + existing + suffix
	})
}
