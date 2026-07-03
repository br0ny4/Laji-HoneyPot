# Laji-HoneyPot v0.15.0 迭代复盘报告

> 发布日期: 2026-07-03  
> 上一版本: v0.14.0 → v0.15.0  
> 迭代主题: 溯源反制深度升级

---

## 1. 迭代目标达成率

| 目标类别 | 计划 | 完成 | 达成率 |
|---------|------|------|--------|
| P0 指纹增强 (Canvas/WebGL 升级) | 1 | 1 | 100% |
| P1 非浏览器 UA 兜底 (TODO-003) | 1 | 1 | 100% |
| P1 命名统一 (TODO-004) | 1 | 1 | 100% |
| P2 冷却策略 (TODO-027) | 1 | 1 | 100% |
| 单元测试 (现有) | 28包 | 28包 PASS | 100% |
| go vet | 0 | 0 预警 | 100% |

---

## 2. 需求拆解与技术方案

### 2.1 P0: Canvas/WebGL 指纹深度升级

- **背景**: 现有 JS payload 只采集基础 Canvas 哈希 + WebGL vendor/renderer。`AttackerFingerprint` 结构体已预留 AudioHash、MathPrecision、HardwareConcurrency 等 11 个字段但未被采集
- **方案**: 扩展 `GenerateBrowserFingerprint()` JS payload，新增 11 个指纹维度，全部 try/catch 包裹
- **新增字段**: audio_hash（音频指纹）、math_precision（数学精度）、hw_concurrency（CPU核数）、device_memory（内存）、platform（OS）、connection_type（网络类型）、touch_support/max_touch_points（触屏）、ad_blocker（拦截器检测）、cookie_enabled、do_not_track
- **风险**: AudioContext 在部分浏览器会失败 → try/catch 降级，不影响其他字段
- **涉及文件**: `generator.go`, `generator_test.go`

### 2.2 P1: 非浏览器 UA 服务端指纹兜底 (TODO-003)

- **背景**: curl/sqlmap/nmap 等 CLI 工具不执行 JS，无法触发浏览器端指纹采集
- **方案**: 在 `handleCollect` 中检测请求数据稀疏性（字段数 ≤2），触发 `extractHeaderFingerprint()` 从 HTTP 头部提取可用指纹
- **提取维度**: User-Agent→tool_name、Accept-Language→languages、Referer→referrer
- **涉及文件**: `server.go`

### 2.3 P1: Burp Payload 命名统一 (TODO-004)

- **背景**: screencap JS 载荷使用 `t:'screen_cap'`（短形式），与 Go 侧常量 `screen_capture` 不一致。filescan/netprobe 已使用规范命名
- **方案**: 将 screencap.go 中 JS payload 的 `screen_cap`→`screen_capture`
- **涉及文件**: `screencap.go`

### 2.4 P2: net_probe 冷却策略优化 (TODO-027)

- **背景**: 300s（5分钟）冷却周期过长，合理探测频率下得分归零
- **方案**: 默认冷却 300s→120s（2分钟）；新增 `SetCooldownOverride()` 运行时方法；支持 `config.yaml` 中配置覆盖
- **涉及文件**: `types.go`, `scoring.go`, `plugin.go`, `config.yaml`

---

## 3. 变更文件清单

### 修改文件 (7)

| 文件 | 变更 |
|------|------|
| `internal/traceability/payload/generator.go` | JS payload 新增 11 个指纹采集字段（AudioContext/Math/触屏/广告拦截器等） |
| `internal/traceability/payload/generator_test.go` | 新增对所有新字段的内容验证 |
| `internal/core/api/server.go` | `extractHeaderFingerprint()` + `detectToolFromUA()` 服务端 UA 兜底 |
| `internal/traceability/countermeasure/screencap.go` | `screen_cap`→`screen_capture` 命名统一 |
| `internal/traceability/countermeasure/types.go` | `OpNetProbe` 冷却 300s→120s |
| `internal/traceability/countermeasure/scoring.go` | 新增 `SetCooldownOverride()` 运行时方法 |
| `internal/traceability/plugin.go` | `Init` 中读取 `countermeasure_cooldowns` 配置并应用覆盖 |
| `config.yaml` | 添加 `countermeasure_cooldowns` 配置示例注释 |
| `internal/core/version.go` | 0.14.0 → 0.15.0 |

---

## 4. 测试结果

### 4.1 全量测试

```
28/28 包全部 PASS，0 FAIL
go vet: 0 预警
go build: 编译成功
```

### 4.2 关键测试明细

| 测试包 | 用例数 | 结果 |
|--------|--------|------|
| `internal/traceability/payload` | 5 | PASS（含新增字段验证） |
| `internal/core/api` | 23 | PASS（无回归） |
| `internal/traceability/countermeasure` | 全部 | PASS |
| `internal/traceability` | 全部 | PASS |

---

## 5. 迭代对比

| 指标 | v0.14.0 | v0.15.0 | 变化 |
|------|---------|---------|------|
| 浏览器指纹维度 | 9 | 20 | +11 |
| 非浏览器指纹采集 | 不支持 | HTTP 头部兜底 | 新增 |
| 命名一致性 | screen_cap/ screen_capture 混用 | 统一 screen_capture | 修复 |
| net_probe 冷却 | 300s | 120s（可配置） | -60% |
| JS Payload 大小 | ~1.8KB | ~4.2KB | +133%（更丰富） |

---

## 6. 遗留问题（转入 v0.16.0）

| ID | 问题 | 优先级 |
|----|------|--------|
| TODO-002 | 终端环境 PATH 退化 | P0 |
| TODO-005 | Agent API 端口拓扑注册（Agent端推送） | P1 |
| TODO-006 | 高并发面包屑 goroutine 泄漏 | P2 |
| TODO-007 | SQLite CGO→纯Go 性能基线 | P2 |
| TODO-008 | VulnDB 离线同步 | P2 |
| TODO-017~022 | 前端/认证体验优化 | P2-P3 |

---

## 7. 迭代总结

v0.15.0 以"溯源反制深度升级"为主题，聚焦 Laji-HoneyPot 的核心差异化竞争力。浏览器指纹采集维度从 9 个扩展至 20 个（AudioContext/数学精度/触屏/广告拦截器等），非浏览器工具的服务端 HTTP 头部兜底填补了 CLI 攻击者的指纹盲区。Burp payload 命名统一消除了 Go/JS 两端的标识符不一致。net_probe 冷却策略从 5 分钟优化为 2 分钟并支持运行时配置覆盖，提升了反制操作的实战可用性。

下一步：v0.16.0 建议继续溯源反制方向的深入——蜜饵投放系统（虚假凭证文件/AWS Key/DNS 蜜标）+ 攻击者画像 MVP（基于已积累指纹和溯源数据）。
