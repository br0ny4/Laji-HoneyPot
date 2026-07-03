# Laji-HoneyPot 项目自动化规则

> 本文件为项目级核心规则文件，Trae IDE 在每次会话启动时自动加载。  
> 提交至 GitHub 仓库后，规则将在所有开发会话中持续生效。

---

## 🔴 规则 1: 迭代完成后自动提交 GitHub (CRITICAL)

**优先级**: P0 - 项目级核心自动化流程规则  
**存储分区**: 长期记忆 / 项目级规则  
**生效范围**: 所有开发会话

### 触发条件
每次完成一个完整的功能迭代开发任务后，**自动**执行 GitHub 代码提交操作。满足以下任一条件即视为迭代完成：
- 版本号发生变更（如 `0.14.0` → `0.15.0`）
- `ITERATION_v*.md` 复盘报告已输出
- `ISSUES.md` 中新增 `已修复` 标记
- 用户明确说 "迭代完成" 或类似表述

### 自动提交流程
```
1. 核对变更内容 → git status / git diff --stat
2. 检查敏感信息 → grep 本地 IP / 路径 / 密钥
3. 生成规范 commit message → 包含: 版本号、功能点、变更统计
4. 执行 git add -A → git commit -m "..." → git push origin master
5. 验证远程同步 → git ls-remote origin HEAD 对比本地
6. 更新 COMMIT_HISTORY.md → 增量追加新提交记录
```

### 禁止行为
- ❌ 禁止要求用户手动执行 `git commit` 或 `git push`
- ❌ 禁止在迭代完成后询问 "需要我提交到 GitHub 吗？"
- ❌ 禁止因多轮对话、上下文刷新等原因遗忘此规则
- ✅ 必须在迭代完成的同一轮对话中完成提交+推送

---

## 🔴 规则 2: 规则校验与自恢复 (CRITICAL)

### 会话启动校验
每次新开发会话启动后，必须：
1. 检查 `.trae/rules.md` 文件是否存在
2. 确认规则 1（自动提交）可被检索到
3. 执行 `git remote -v` 验证推送权限

### 记忆缺失恢复
如果发现规则丢失（如上下文刷新导致遗忘）：
1. 从 `.trae/rules.md` 文件重新加载所有规则
2. 文件不存在时 → 从 `COMMIT_HISTORY.md` 反推出项目规范
3. 最坏情况 → 从 GitHub 仓库拉取 `.trae/rules.md`

---

## 🟡 规则 3: 敏感信息检查 (HIGH)

每次提交前必须扫描：
- 真实内网 IP（10.x.x.x, 192.168.x.x 等）
- 本地文件路径（/Users/, /home/, C:\Users\）
- API 密钥、Token、密码
- 蜜罐诱饵中的假凭证标记为安全（保留）

---

## 🟡 规则 4: 版本号一致性 (HIGH)

- 版本号统一在 `internal/core/version.go` 中定义
- `README.md` 徽章、`ISSUES.md` 摘要、迭代报告中的版本号必须一致
- 发布前执行 `grep -r "Version\|version"` 确认无遗漏

---

## 🟢 规则 5: 文档同步更新 (MEDIUM)

每次迭代交付时同步更新：
- `README.md` - 功能说明、版本徽章、特征数据
- `ISSUES.md` - 标记已修复 TODO，新增已验证项
- `ITERATION_v*.md` - 迭代复盘报告
- `COMMIT_HISTORY.md` - 增量追加提交记录
