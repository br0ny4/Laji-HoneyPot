#!/bin/bash
# ============================================================
# Laji-HoneyPot 自动提交脚本
# 流程: 1. 验证构建 2. 更新 README 3. 暂存变更 4. 提交推送
#
# 用法: bash scripts/auto-commit.sh "<feat|fix|docs|refactor|test|chore>: <描述>" [--dry-run]
# 示例: bash scripts/auto-commit.sh "feat: v0.17.0 Agent部署升级 + 蜜饵联动引擎"
#       bash scripts/auto-commit.sh "feat: v0.17.0 Agent部署升级" --dry-run
# ============================================================
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

COMMIT_MSG="${1:-}"
DRY_RUN=false
if [ "$2" = "--dry-run" ]; then
    DRY_RUN=true
    echo ">>> DRY RUN MODE — 不会实际提交 <<<"
    echo ""
fi

if [ -z "$COMMIT_MSG" ]; then
    echo "ERROR: 请提供提交信息"
    echo "用法: bash scripts/auto-commit.sh \"<type>: <description>\" [--dry-run]"
    echo "示例: bash scripts/auto-commit.sh \"feat: v0.17.0 Agent部署升级\""
    exit 1
fi

# 检查 type 是否符合 Conventional Commits
COMMIT_TYPE=$(echo "$COMMIT_MSG" | cut -d':' -f1)
VALID_TYPES="feat fix docs refactor test chore perf ci build style"
if ! echo "$VALID_TYPES" | grep -qw "$COMMIT_TYPE"; then
    echo "ERROR: 提交类型 '$COMMIT_TYPE' 不在有效类型列表中"
    echo "有效类型: $VALID_TYPES"
    exit 1
fi

echo "============================================"
echo "  Laji-HoneyPot Auto-Commit"
echo "============================================"
echo ""

# Step 1: 提取当前版本号
VERSION=$(grep 'const Version' internal/core/version.go | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "[Step 1/6] 当前版本: v$VERSION"

# Step 2: 构建验证
echo "[Step 2/6] 代码构建验证..."
if ! go build ./... 2>&1; then
    echo "ERROR: go build 失败，终止提交"
    exit 1
fi
echo "  -> go build PASS"

if ! go vet ./... 2>&1; then
    echo "ERROR: go vet 失败，终止提交"
    exit 1
fi
echo "  -> go vet PASS"

# Step 3: 测试验证
echo "[Step 3/6] 运行测试..."
if ! go test ./... -count=1 2>&1; then
    echo "ERROR: go test 失败，终止提交"
    exit 1
fi
echo "  -> go test PASS"

# Step 4: 更新 README.md
echo "[Step 4/6] 自动更新 README.md..."
bash "$PROJECT_DIR/scripts/auto-update-readme.sh"

# 检查 README 是否有变更
README_CHANGED=false
if git diff --name-only | grep -q "README.md"; then
    README_CHANGED=true
    echo "  -> README.md 已更新"
else
    echo "  -> README.md 无变更"
fi

# Step 5: 查看变更
echo "[Step 5/6] 当前变更文件:"
git status --short

UNSTAGED=$(git diff --name-only 2>/dev/null | wc -l)
UNTRACKED=$(git ls-files --others --exclude-standard 2>/dev/null | wc -l)
STAGED=$(git diff --cached --name-only 2>/dev/null | wc -l)

TOTAL_CHANGES=$((UNSTAGED + UNTRACKED + STAGED))
if [ "$TOTAL_CHANGES" -eq 0 ]; then
    echo "  -> 无变更需要提交"
    exit 0
fi

echo "  -> 未暂存: $UNSTAGED, 未跟踪: $UNTRACKED, 已暂存: $STAGED"

# Step 6: 暂存并提交
echo "[Step 6/6] 暂存所有变更并提交..."
if [ "$DRY_RUN" = true ]; then
    echo "  [DRY-RUN] git add -A"
    echo "  [DRY-RUN] git commit -m \"$COMMIT_MSG\""
    echo "  [DRY-RUN] git push origin master"
    echo ""
    echo "=== DRY RUN 完成 ==="
    echo "如果一切正常，运行以下命令实际提交:"
    echo "  bash scripts/auto-commit.sh '$COMMIT_MSG'"
    exit 0
fi

git add -A
git commit -m "$COMMIT_MSG"
git push origin master

echo ""
echo "============================================"
echo "  自动提交完成"
echo "  版本: v$VERSION"
echo "  提交信息: $COMMIT_MSG"
echo "============================================"
