# Laji-HoneyPot v0.17.3 迭代复盘报告

> 发布日期: 2026-07-04  
> 上一版本: v0.17.2 → v0.17.3  
> 迭代主题: 工程稳定性 + 可观测性增强

---

## 1. 迭代目标达成率

| 目标类别 | 计划 | 完成 | 达成率 |
|---------|------|------|--------|
| P0 PATH退化修复 (TODO-002) | 1 | 1 | 100% |
| P1 Agent自注册IP (TODO-005) | 1 | 1 | 100% |
| P1 浏览器图标优化 (TODO-015) | 1 | 1 | 100% |
| P2 SQLite性能基线 (TODO-007) | 1 | 1 | 100% |
| 单元测试 (现有) | 30包 | 30包 PASS | 100% |
| go vet | 0 | 0 预警 | 100% |

---

## 2. 修复详情

### 2.1 P0: PATH 退化恢复 (TODO-002)

- **根因**: `trae-sandbox` 环境长时间会话后 PATH 退化，`curl`/`go`/`python3` 等命令不可用
- **方案**: 在 `install.sh`、`honeypot-ctl`、`scripts/auto-update-readme.sh` 中新增 `ensure_path()` 函数
  - 检测 go/node/npm/git/curl 是否可用
  - 缺失时预置常见 PATH: `/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:$HOME/go/bin`
  - 仅 WARN 不 ERROR，不阻塞脚本执行
- **涉及文件**: `install.sh`, `honeypot-ctl`, `scripts/auto-update-readme.sh`

### 2.2 P1: Agent 自动探测本机 IP (TODO-005)

- **根因**: `NodeInfo.IP` 字段存在但从未被填充，Agent 注册时缺少自身 IP
- **方案**: 新增 `outboundIP(managerAddr)` 工具函数——通过尝试 TCP Dial 管理端地址，从 `LocalAddr()` 反向推导本机出网 IP
  - 成功 → 返回本机 IP
  - 失败 → fallback `127.0.0.1`
- **涉及文件**: `internal/cluster/agent.go`

### 2.3 P1: 浏览器 SVG 图标 (TODO-015)

- **根因**: 指纹面板使用单字母染色 badge，Chrome/Firefox/Safari/Edge 同时存在时辨识度不足
- **方案**: 新建 `BrowserIcons.tsx`，为 Chrome/Firefox/Safari/Edge/Opera 提供 18×18 内联 SVG 图标
  - Chrome → 红/绿/黄圆形三色
  - Firefox → 橙色弧线
  - Safari → 蓝色罗盘指针
  - Edge → 蓝色漩涡
  - Opera → 红色 O 形
- 替换 `FingerprintPanel.tsx` 中所有 4 处图标使用位置
- **涉及文件**: `web/src/components/BrowserIcons.tsx` (新建), `FingerprintPanel.tsx`

### 2.4 P2: SQLite 性能基线 (TODO-007)

- **背景**: `go-sqlite3` (CGO) → `modernc.org/sqlite` (纯 Go) 迁移后缺少量化性能对比
- **方案**: 新建 `bench_test.go`，4 个 benchmark:
  - `BenchmarkRecordConnection` — 单条连接插入
  - `BenchmarkGetStats` — stats 聚合查询
  - `BenchmarkGetFingerprints` — 指纹列表查询
  - `BenchmarkConcurrentWrites` — 10 goroutine 并发写入
- 全部使用 `:memory:` 模式，注释说明 CGO vs pure-Go 的执行方式
- **涉及文件**: `internal/core/store/bench_test.go` (新建)

---

## 3. 变更文件清单

| 文件 | 变更 |
|------|------|
| `internal/core/version.go` | 0.17.2 → 0.17.3 |
| `internal/cluster/agent.go` | `outboundIP()` + `NodeInfo.IP` 填充 |
| `install.sh` | `ensure_path()` PATH 恢复 |
| `honeypot-ctl` | `ensure_path()` PATH 恢复 |
| `scripts/auto-update-readme.sh` | `ensure_path()` PATH 恢复 |
| `web/src/components/BrowserIcons.tsx` | **新建** — 6 种浏览器 SVG 图标 |
| `web/src/components/FingerprintPanel.tsx` | 替换 4 处 badge 为 SVG 图标 |
| `internal/core/store/bench_test.go` | **新建** — 4 个 SQLite benchmark |
| `ISSUES.md` | TODO-002/005/007/015 标记已修复 |

---

## 4. 测试结果

```
30/30 包全部 PASS，0 FAIL
go vet: 0 预警
go build: 编译成功
bash syntax: install.sh / honeypot-ctl / auto-update-readme.sh OK
TypeScript: tsc --noEmit OK
```

---

## 5. 迭代对比

| 指标 | v0.17.2 | v0.17.3 | 变化 |
|------|---------|---------|------|
| P0 遗留问题 | 1 (TODO-002) | 0 | -1 |
| P1 遗留问题 | 4 | 2 | -2 |
| P2 遗留问题 | 6 | 5 | -1 |
| 浏览器图标 | 单字母染色 | 6种 SVG 图标 | 升级 |
| SQLite 基准 | 无 | 4 个 bench | 新增 |
| Agent 本机 IP | 缺失 | 自动探测 | 新增 |

---

## 6. 遗留问题（转入 v0.17.4+）

| ID | 问题 | 优先级 |
|----|------|--------|
| TODO-006 | 高并发面包屑 goroutine 泄漏 | P2 |
| TODO-008 | VulnDB 离线同步 (Manager→Agent) | P2 |
| TODO-017 | Safari/Edge EventSource 重连 | P2 |
| TODO-018 | CSS gap Safari 15 回退 | P2 |
| TODO-019 | UA 解析器覆盖 Tor/Brave/Opera | P2 |
| TODO-010 | TLS 证书自动续签 (365天) | P3 |
| TODO-011 | EXE GitHub Releases 自动发布 | P3 |
| TODO-020 | atob Node SSR 兼容 | P3 |
| TODO-022 | 令牌黑名单持久化到 SQLite | P3 |

---

## 7. 迭代总结

v0.17.3 以"工程稳定性"为主题，解决了最后一项 P0 遗留问题（sandbox PATH 退化），补全了 Agent 自注册 IP 的 P1 功能缺口，为指纹面板带来了 SVG 浏览器图标提升 U 辨识度，同时建立了 SQLite 性能基线为后续优化提供量化依据。
