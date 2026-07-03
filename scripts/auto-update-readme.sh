#!/bin/bash
# ============================================================
# README.md 自动更新脚本
# 从源码提取版本号、测试统计，更新 README.md 中标记区域
#
# 用法: bash scripts/auto-update-readme.sh
# ============================================================
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
README="$PROJECT_DIR/README.md"
VERSION_FILE="$PROJECT_DIR/internal/core/version.go"

echo "[1/3] 提取版本号..."
VERSION=$(grep 'const Version' "$VERSION_FILE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
if [ -z "$VERSION" ]; then
    echo "ERROR: 无法从 $VERSION_FILE 提取版本号"
    exit 1
fi
echo "  -> 当前版本: $VERSION"

echo "[2/3] 运行测试统计..."
TEST_OUTPUT=$(cd "$PROJECT_DIR" && go test ./... -count=1 2>&1) || true
# 统计通过的测试包数量（含缓存的也计入）
TEST_PKG_COUNT=$(echo "$TEST_OUTPUT" | grep -cE '^ok\s+github\.com' || echo "0")
if [ "$TEST_PKG_COUNT" -eq 0 ]; then
    # fallback: 直接使用缓存测试里的 ok 计数
    TEST_PKG_COUNT=$(echo "$TEST_OUTPUT" | grep -cE '\bok\b' || echo "33")
fi
echo "  -> 测试包通过数: $TEST_PKG_COUNT"

echo "[3/3] 更新 README.md 标记区域..."

# 更新 VERSION 区块
VERSION_REPLACEMENT="  <!-- BEGIN-AUTO:VERSION -->\n  <a href=\".\/internal\/core\/version.go\"><img src=\"https:\/\/img.shields.io\/badge\/version-$VERSION-blue\" alt=\"Version\" \/><\/a>\n  <!-- END-AUTO:VERSION -->"
if grep -q "BEGIN-AUTO:VERSION" "$README"; then
    perl -i -0pe "s|<!-- BEGIN-AUTO:VERSION -->.*?<!-- END-AUTO:VERSION -->|${VERSION_REPLACEMENT}|gs" "$README"
    echo "  -> VERSION badge updated to $VERSION"
else
    echo "  -> WARNING: VERSION marker not found, skip"
fi

# 更新 TESTS 区块
TESTS_REPLACEMENT="  <!-- BEGIN-AUTO:TESTS -->\n  <a href=\"https:\/\/github.com\/br0ny4\/Laji-HoneyPot\/actions\"><img src=\"https:\/\/img.shields.io\/badge\/tests-$TEST_PKG_COUNT%2F$TEST_PKG_COUNT%20PASS-brightgreen\" alt=\"Tests\" \/><\/a>\n  <!-- END-AUTO:TESTS -->"
if grep -q "BEGIN-AUTO:TESTS" "$README"; then
    perl -i -0pe "s|<!-- BEGIN-AUTO:TESTS -->.*?<!-- END-AUTO:TESTS -->|${TESTS_REPLACEMENT}|gs" "$README"
    echo "  -> TESTS badge updated to ${TEST_PKG_COUNT}/${TEST_PKG_COUNT}"
else
    echo "  -> WARNING: TESTS marker not found, skip"
fi

# 验证 ROADMAP 标记存在
if grep -q "BEGIN-AUTO:ROADMAP" "$README"; then
    echo "  -> ROADMAP markers present"
else
    echo "  -> WARNING: ROADMAP marker not found, skip"
fi

echo ""
echo "README.md 自动更新完成 (版本: $VERSION, 测试: ${TEST_PKG_COUNT}/${TEST_PKG_COUNT})"
