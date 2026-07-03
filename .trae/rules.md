# Laji-HoneyPot 项目自动化规则

## 规则 1：自动提交 (Auto-Commit)
- 每次完成一个完整的代码修改任务后，**自动执行** `scripts/auto-commit.sh` 提交变更到 GitHub
- 脚本会自动更新 README.md（版本号、测试统计、路线图），然后暂存所有变更并提交
- 提交格式遵循 Conventional Commits：`feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `chore:`
- 提交信息需包含中文说明，banner 格式为 `feat: vX.Y.Z 简短描述`
- 绝不修改 `.gitconfig` 或运行 `git push --force`

## 规则 2：README 自动同步
- README.md 中的版本号、测试统计等区域使用 `<!-- BEGIN-AUTO:XXX -->` / `<!-- END-AUTO:XXX -->` 标记
- 这些标记区域由 `scripts/auto-update-readme.sh` 自动维护
- 标记区域外的手写内容完全保留，不受自动更新影响
- 包括三个自动区域：
  - `VERSION` — 版本号徽章
  - `TESTS` — 测试通过徽章
  - `ROADMAP` — 开发路线图（新条目自动追加）

## 规则 3：测试要求
- 提交前确保 `go build ./...` 和 `go vet ./...` 通过
- 提交前确保 `go test ./... -count=1` 全部通过
- 新增功能需包含对应的 `_test.go` 文件

## 规则 4：版本号管理
- 版本号统一在 `internal/core/version.go` 中定义 (`core.Version`)
- README.md 和 ISSUES.md 中的版本引用由自动脚本同步
- 禁止在其他文件中硬编码版本号

## 规则 5：安全边界
- 绝不提交 `.env`、`credentials.json` 等包含真实凭据的文件
- 项目使用 `config.yaml` 管理配置（不含敏感信息）
- GitHub Token 仅通过 CI Secrets 注入
