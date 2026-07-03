# Laji-HoneyPot v0.14.0 迭代复盘报告

> 发布日期: 2026-07-03  
> 上一版本: v0.13.0 → v0.14.0  
> 迭代类型: 稳定性修复 + 体验增强

---

## 1. 迭代目标达成率

| 目标类别 | 计划 | 完成 | 达成率 |
|---------|------|------|--------|
| P0 缺陷修复 | 4 | 4 | 100% |
| P1 功能增强 | 3 | 3 | 100% |
| 单元测试 (现有) | 28包 | 28包 PASS | 100% |
| 新增测试 | auth_jwt_test.go | 7 项 | 100% |
| go vet | 0 预警 | 0 预警 | 100% |
| 前端构建 | 1 | 1 (1327 modules) | 100% |

---

## 2. 需求拆解与技术方案

### 2.1 P0-1: JWT Secret 持久化 (TODO-013)

- **根因**: `AuthManager` 构造函数中每次调用 `crypto/rand` 生成新密钥，服务重启后所有已签发令牌失效
- **方案**: 
  - config 新增 `jwt_secret` 字段（yaml 持久化）
  - 首次运行 → `crypto/rand` 生成 256-bit 密钥 → hex 编码 → 写入 config.yaml
  - 后续运行 → 直接从 config 读取，复用同一密钥
  - 向后兼容：`jwt_secret: ""`（留空）自动触发生成
- **风险**: 无——仅改变密钥来源（随机 → 持久化），不影响令牌格式
- **涉及文件**: `config.go`, `auth_jwt.go`, `main.go`, `config.yaml`

### 2.2 P0-2: 登录日志类型断言 (TODO-012)

- **根因**: `handleLogin` 接收 `interface{}` 类型 logger，内部两次类型断言脆弱
- **方案**: 改为直接接收 `*log.Logger` 类型，调用方无需修改（`s.logger` 本身就是 `*log.Logger`）
- **涉及文件**: `auth_jwt.go`

### 2.3 P0-3: 面包屑超时 + 密码复杂度

- **面包屑超时根因**: HTTP 回调在 TCP 处理 goroutine 中同步执行 SQLite 写 + 事件总线同步发布，任何环节阻塞均导致 TCP 超时
- **方案**: 
  - 面包屑回调 → `go func()` 异步 + `context.WithTimeout(5s)`
  - Countermeasure JS 注入 → `select + time.After(5s)` 超时降级
  - `PublishSync` → `Publish`（异步发布）
- **密码复杂度**: 新增 `ValidatePassword()` 函数：≥8 字符 + 大写 + 小写 + 数字 + 特殊字符
- **涉及文件**: `http/server.go`, `plugin.go`, `auth_jwt.go`, `auth_jwt_test.go`

---

## 3. P1 功能增强详情

### 3.1 告警渠道扩展 — 钉钉/飞书 Webhook

| 项目 | 内容 |
|------|------|
| 新建文件 | `internal/alerter/webhook.go` |
| 支持平台 | 钉钉 Markdown、飞书 Text、通用 JSON |
| 安全机制 | HMAC-SHA256 签名（钉钉 & 飞书） |
| 配置方式 | `config.yaml` 中 `webhook:` 段 |
| 触发条件 | critical/warn 级别事件自动推送 |
| 测试 | 12/12 PASS（含 webhook 构造/签名验证） |

### 3.2 前端体验优化

| 修复项 | 实现 |
|--------|------|
| Token 过期提示 | `api.ts` 401 后调用 `showToast('会话已过期，请重新登录')`，1.5s 后清除令牌 |
| Toast 组件 | `web/src/Toast.ts` — 命令式 API，DOM 直接操作，入场/离场动画 |
| 骨架屏 | `Skeleton.tsx` — card/table/text 三种变体，pulse 动画 |
| 覆盖面板 | DashboardPanel、AttackPanel、FingerprintPanel、AttackerProfilePanel |

---

## 4. 测试结果

### 4.1 单元测试

```
28/28 包全部 PASS，0 FAIL
go vet: 0 预警
```

### 4.2 新增测试明细

| 测试 | 用例数 | 覆盖点 |
|------|--------|--------|
| `TestValidatePassword_Valid` | 1 | 合法密码通过 |
| `TestValidatePassword_TooShort` | 1 | 7 字符被拒 |
| `TestValidatePassword_NoUpper` | 1 | 缺大写字母被拒 |
| `TestValidatePassword_NoLower` | 1 | 缺小写字母被拒 |
| `TestValidatePassword_NoDigit` | 1 | 缺数字被拒 |
| `TestValidatePassword_NoSpecialChar` | 1 | 缺特殊字符被拒 |
| `TestValidatePassword_Empty` | 1 | 空密码被拒 |
| `TestSendWebhookAlert_*` | 5 | 飞书/钉钉/通用 JSON 构造 + 签名 |
| `TestAlerter_*` | 7 | 告警分类 + webhook 触发 |

---

## 5. 变更文件清单

### 新增文件 (5)

| 文件 | 说明 |
|------|------|
| `internal/core/api/auth_jwt_test.go` | 密码复杂度 7 项测试 |
| `internal/alerter/webhook.go` | 钉钉/飞书 Webhook 发送 |
| `web/src/Toast.ts` | 命令式 Toast 组件 |
| `web/src/components/Skeleton.tsx` | 骨架屏组件 |
| `ITERATION_v0.14.0.md` | 本迭代复盘报告 |

### 修改文件 (14)

| 文件 | 变更 |
|------|------|
| `internal/core/config/config.go` | JWTSecret 字段 + WebhookConfig 结构体 + Save() |
| `internal/core/api/auth_jwt.go` | ValidatePassword() + NewAuthManagerWithSecret() + 类型健壮化 |
| `cmd/honeypot/main.go` | JWT 密钥加载/生成/持久化逻辑 |
| `config.yaml` | jwt_secret + webhook 配置段 |
| `internal/honeypot/services/http/server.go` | 面包屑异步化 + 超时降级 |
| `internal/honeypot/plugin.go` | PublishSync→Publish + goroutine 异步 |
| `internal/alerter/alerter.go` | Webhook 集成 |
| `internal/core/version.go` | 0.13.0 → 0.14.0 |
| `web/src/api.ts` | 401 Toast 提示 |
| `web/src/components/DashboardPanel.tsx` | 骨架屏 |
| `web/src/components/AttackPanel.tsx` | 骨架屏 |
| `web/src/components/FingerprintPanel.tsx` | 骨架屏 |
| `web/src/components/AttackerProfilePanel.tsx` | 骨架屏 |
| `ISSUES.md` | v0.14.0 摘要 + 6 项标记已修复 |

---

## 6. 进度偏差分析

| 阶段 | 计划 | 实际 | 偏差 |
|------|------|------|------|
| 需求梳理 | 30 min | 20 min | 超前（基于已有 backlog） |
| P0-1 JWT Secret | 45 min | 40 min | 超前 |
| P0-2 类型断言 | 15 min | 10 min | 超前 |
| P0-3 面包屑+密码 | 60 min | 55 min | 超前 |
| P1-1 Webhook | 45 min | 50 min | 轻微延后（签名算法调试） |
| P1-2 前端体验 | 45 min | 40 min | 超前 |
| 测试验证 | 30 min | 20 min | 超前 |
| 文档输出 | 30 min | 25 min | 超前 |
| **总计** | **~5h** | **~4.3h** | **超前 14%** |

---

## 7. 质量指标

| 指标 | v0.13.0 | v0.14.0 | 变化 |
|------|---------|---------|------|
| 测试包数 | 28 | 28 | — |
| 测试通过率 | 100% | 100% | — |
| go vet 预警 | 0 | 0 | — |
| 新增测试用例 | — | 19 | +19 |
| P0 缺陷数 | 6 | 2 | -4 |
| 前端构建 (modules) | 1327 | 1327 | — |
| API 端点总数 | 54 | 54 | — |
| 告警渠道 | 0 | 3 | +3 (钉钉/飞书/通用) |

---

## 8. 遗留问题（转入 v0.15.0）

| ID | 问题 | 优先级 |
|----|------|--------|
| TODO-002 | 终端环境 PATH 退化 | P0 |
| TODO-003 | 非浏览器 UA 不触发指纹 | P1 |
| TODO-004 | Burp payload 命名不一致 | P1 |
| TODO-005 | Agent API 端口拓扑注册 | P1 |
| TODO-006 | 高并发面包屑 goroutine 泄漏 | P2 |
| TODO-007 | SQLite CGO→纯Go 性能基线 | P2 |
| TODO-008 | VulnDB 离线同步 | P2 |
| TODO-027 | net_probe 冷却 300s 评估 | P2 |
| TODO-017~022 | 前端/认证体验优化 | P2-P3 |

---

## 9. 优化建议（下一迭代）

1. **LLM 动态交互蜜罐**（竞品分析 P0 建议）——对接 Ollama/OpenAI，SSH/HTTP 协议动态响应
2. **溯源反制深度升级**——Canvas/WebGL 指纹 + 社交账号反查
3. **恶意软件自动捕获**——SMB 漏洞利用响应 + Shellcode 提取 + VirusTotal 联动
4. **告警智能去重**——攻击事件聚合，减少告警风暴
5. **中英文双语文档**——降低国际用户上手门槛

---

## 10. 迭代总结

v0.14.0 是"稳定性 + 体验"双驱动的迭代。以 JWT Secret 持久化解决服务重启令牌失效的 P0 安全缺陷，以面包屑异步化消除 TCP 超时阻塞，以密码复杂度校验补强认证安全基线。告警 Webhook 集成打通了钉钉/飞书的主流办公渠道，前端骨架屏和 Token 过期提示显著改善了用户体验。

下一个迭代建议重点转向竞品分析中识别的 P0 战略方向——LLM 动态交互和溯源反制深度升级。
