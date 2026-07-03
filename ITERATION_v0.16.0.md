# v0.16.0 迭代复盘报告

> 日期: 2026-07-03 | 版本: v0.15.0 → v0.16.0

---

## 迭代目标

| 优先级 | 目标 | 说明 |
|--------|------|------|
| P0 | 蜜饵投放系统 | 虚假凭证/API密钥/敏感文件诱饵，增强溯源链闭环 |
| P1 | 攻击者画像 MVP | 基于指纹+溯源数据的聚合分析，风险评分+行为标签 |

---

## 完成情况

### P0 蜜饵投放系统 ✅

- **bait.Generator**: 7 类虚假凭证诱饵（aws_key/db_creds/api_token/ssh_key/git_config/wp_config/env_file）
- **bait.Tracker**: 环形缓冲访问追踪，支持按 IP/类型过滤，统计 API
- **HTTP 蜜罐集成**: `/bait/*` 路径自动服务 + 隐藏 `<a>` 链接注入 + `robots.txt` 声明
- **管理 API**: `/api/bait/tokens` + `/api/bait/access` + `/api/bait/stats`
- **测试**: 23/23 PASS

### P1 攻击者画像 MVP ✅

- **profile.Builder**: 聚合攻击/指纹/反制/蜜饵数据 → 风险评分(0-100) + 行为标签
- **行为标签**: scanner, credential_harvester, vulnerability_probe, brute_force, ransomware_interest
- **管理 API**: `/api/profile/attackers?limit=` + `/api/profile/attacker?ip=`
- **测试**: 5/5 PASS

---

## 回归测试

```
go build ./cmd/honeypot/  ✅ PASS
go vet ./...              ✅ PASS (0 warnings)
go test ./... -short      ✅ 30/30 packages PASS, 0 FAIL
```

---

## 变更文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/bait/generator.go` | 新增 | 蜜饵生成器 |
| `internal/bait/tracker.go` | 新增 | 访问追踪器 |
| `internal/bait/bait_test.go` | 新增 | 23 项单元测试 |
| `internal/core/profile/model.go` | 新增 | 画像数据模型 |
| `internal/core/profile/builder.go` | 新增 | 画像构建器 |
| `internal/core/profile/builder_test.go` | 新增 | 5 项单元测试 |
| `internal/core/profile/engine.go` | 修改 | +Countermeasures 字段 |
| `internal/honeypot/services/http/server.go` | 修改 | 集成蜜饵系统 |
| `internal/core/api/server.go` | 修改 | 新增 bait/profile API 端点 |
| `cmd/honeypot/main.go` | 修改 | 创建并注入 bait/profile 组件 |
| `internal/core/version.go` | 修改 | 0.15.0 → 0.16.0 |
| `README.md` | 修改 | 版本徽章、蜜饵章节、画像 API |
| `ISSUES.md` | 修改 | v0.16.0 迭代摘要 |
| `ITERATION_v0.16.0.md` | 新增 | 本报告 |

---

## 遗留项

| 优先级 | 内容 | 说明 |
|--------|------|------|
| P2 | 前端蜜饵/画像面板 | 管理后台可视化展示蜜饵访问和攻击者画像 |
| P2 | 蜜饵文件下载实时预警 | 攻击者下载蜜饵时触发 Webhook 告警 |
| P3 | 画像趋势分析 | 攻击者行为变化的时间序列追踪 |

---

## 经验总结

1. **蜜饵设计要点**: 文件名贴近真实生产环境（`.env.production`/`wp-config.php.bak`），追踪种子隐式嵌入而非显式 ID，提高欺骗性
2. **画像聚合效率**: 跨多表聚合（attacks/fingerprints/countermeasures/bait）适合用内存聚合而非 SQL JOIN，避免锁竞争
3. **接口一致性**: bait/profile 的 API 设计与现有 countermeasure API 保持一致的分页/过滤参数风格
