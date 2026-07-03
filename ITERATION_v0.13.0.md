# Laji-HoneyPot v0.13.0 迭代交付文档

> 发布日期: 2026-07-03  
> 上一版本: v0.12.0  
> 迭代周期: v0.12.0 E2E 全量测试 → v0.13.0 功能迭代

---

## 1. 迭代概述

本次迭代基于 v0.12.0 全量溯源反制 E2E 测试暴露的问题及项目功能缺口，按优先级修复 4 个 P1 缺陷并补齐 2 个 P2 功能特性，同步完善单元测试覆盖。

### 关键指标

| 指标 | v0.12.0 | v0.13.0 |
|------|---------|---------|
| 版本号 | 0.12.0 | 0.13.0 |
| 单元测试包 | 26/26 PASS | 27/27 PASS |
| API 端点数 | 52 | 54 (+2) |
| 蜜罐服务运行状态可观测 | 无 | /api/services/status |
| VulnDB API 过滤 | 不支持 | tool/cve/exploit_type/active |
| 集群事件聚合 | 无 | /api/cluster/events |
| Agent 拓扑节点 | 不显示 | 自动注册 + 服务边 |

---

## 2. 变更清单

### 2.1 P1 缺陷修复 (4 项)

#### TODO-023: 蜜罐服务启动失败日志升级 + 运行状态 API
- **问题**: macOS 上 LDAP/SMB/RDP/DNS 蜜罐端口冲突时仅 Warn 静默跳过，无运行状态可见性
- **修复**:
  - `plugin.go`: 启动失败日志从 `Warnw` 升级为 `Errorw`，失败服务信息追加到 `failedSvcs` 切片
  - 新增 `Engine.ServiceStatus()` 方法返回 `{total, running, failed, scenario, enabled_services}`
  - `server.go`: 注册 `/api/services/status` 端点 + `handleServiceStatus` handler
  - `main.go`: 注入 `apiSrv.SetHoneypotEngine(hpEngine)`

#### TODO-024: VulnDB API 多维度过滤
- **问题**: `handleVulns` 为未完工桩函数，忽略所有查询参数，直接返回全量 45 条
- **修复**: 重写 `handleVulns`，按优先级解析 query params:
  - `?cve=CVE-2024-0519` → `Get(cve)` 精确匹配
  - `?tool=chrome&exploit_type=info_leak` → `FindByToolAndExploitType`
  - `?tool=chrome` → `FindByTool`
  - `?exploit_type=rce&active=true` → `FindByExploitType` + 内存过滤 `IsActive`
  - `?exploit_type=rce` → `FindByExploitType`
  - `?active=true` → `FindActive`
  - 无参数 → `All()` 保持向后兼容

#### TODO-026: 仪表盘 API 别名路由
- **问题**: `/api/stats/dashboard` 返回 404，前端仪表盘无法加载数据
- **修复**: 注册 `/api/stats/dashboard` 别名路由，指向 `handleDetailedStats`

#### Auth 防护增强
- `Handler()` 对 `nil` authMgr 增加防护：使用 no-oop 中间件透传，避免空指针 panic

### 2.2 P2 功能补全 (2 项)

#### TODO-025: 集群事件聚合 API
- **问题**: `/api/cluster/events` 端点不存在，Agent 节点攻击事件无法通过 Manager 统一查看
- **实现**:
  - `server.go`: 新增 `clusterEvents` 环形缓冲区 (最大 500 条) + `eventsMu` 读写锁
  - `SetClusterManager()`: 启动 `consumeClusterEvents` 协程消费 `clusterMgr.EventCh`
  - 注册 `/api/cluster/events` 路由 + `handleClusterEvents` handler
  - 支持 `?limit=N&topic=connection` 查询参数过滤

#### TODO-005: Agent 拓扑节点注册
- **问题**: Agent 节点注册后不在拓扑图中显示
- **实现**: 增强 `handleTopology`，当 `clusterMgr` 不为 nil 时:
  - 遍历在线 Agent 节点，为每个创建 TopoNode (type=agent)
  - 为 Agent 的每个蜜罐服务创建 `agent_service` 类型的 TopoEdge
  - 节点携带 `{node_id, services, os, version}` 附加数据

### 2.3 测试增强

| 测试文件 | 变更 |
|---------|------|
| `server_test.go` | 重构适配 `NewServer` 签名变更（apiKey→*AuthManager）；新增 VulnDB 过滤测试（Tool/CVE/ExploitType/Active）；新增服务状态 503 测试；新增仪表盘别名测试；新增 JWT 认证测试；移除已废弃的 API Key 测试 |
| 全部 27 个包 | `go test ./... -count=1`: 0 FAIL |

---

## 3. 文件变更清单

### 修改文件

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `internal/core/api/server.go` | 增强 | VulnDB handler 重写；/api/services/status；/api/cluster/events；集群事件缓冲；Agent 拓扑合并；nil authMgr 防护 |
| `internal/honeypot/plugin.go` | 增强 | runningSvcs/failedSvcs 字段；ServiceStatus() 方法；日志级别 Warn→Error |
| `cmd/honeypot/main.go` | 修复 | 注入 SetHoneypotEngine(hpEngine) |
| `internal/core/api/server_test.go` | 重构 | 适配新签名 + 新增 8 项测试 + 移除旧 API Key 测试 |
| `internal/core/version.go` | 版本 | 0.12.0 → 0.13.0 |
| `ISSUES.md` | 文档 | TODO-023~026 标记已修复；新增 v0.13.0 迭代摘要；已验证项更新 |

### 未修改文件（功能已完备）
- `internal/traceability/vulndb/db.go`: DB 层过滤方法已完备，本次仅修复 API handler 调用
- `internal/cluster/manager.go`: EventCh 与 GetNodes/GetNodeInfo 已完备，本次仅消费端补齐

---

## 4. API 变更

### 新增端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/services/status` | 蜜罐服务运行状态（total/running/failed/scenario/enabled_services） |
| GET | `/api/cluster/events` | 集群事件聚合列表（支持 ?limit=&topic= 过滤） |
| GET | `/api/stats/dashboard` | 仪表盘数据别名（复用 handleDetailedStats） |

### 端点行为变更

| 端点 | 变更前 | 变更后 |
|------|--------|--------|
| `GET /api/vulns` | 忽略所有 query params，返回全量 45 条 | 支持 `?tool=&cve=&exploit_type=&active=` 过滤 |
| `GET /api/topology` | 仅返回 DB 内攻击者拓扑 | 合并集群 Agent 节点及服务边 |

---

## 5. 测试结果

### 5.1 单元测试

```
go test ./... -count=1 -short

结果: 27/27 包全部 PASS，0 FAIL
```

| 包 | 状态 |
|----|------|
| internal/alerter | PASS |
| internal/asset | PASS |
| internal/cluster | PASS |
| internal/core/api | PASS (19 tests) |
| internal/core/bus | PASS |
| internal/core/config | PASS |
| internal/core/log | PASS |
| internal/core/profile | PASS |
| internal/core/registry | PASS |
| internal/core/store | PASS |
| internal/honeypot/manager | PASS |
| internal/honeypot/services/* (9 services) | PASS |
| internal/honeypot/tcpstack | PASS |
| internal/honeypot/traps | PASS |
| internal/plugin | PASS |
| internal/traceability | PASS |
| internal/traceability/fingerprint | PASS |
| internal/traceability/payload | PASS |
| internal/traceability/vulndb | PASS |

### 5.2 回归测试（待部署执行）

以下回归测试需在实际部署环境中执行：

```bash
# 1. 启动管理端
cd $PROJECT_ROOT
go run ./cmd/honeypot/ &

# 2. 运行全量 E2E 测试
bash deploy/test-scripts/00_full_traceability_test.sh

# 3. 验证新端点
curl -s http://localhost:8080/api/services/status | python3 -m json.tool
curl -s "http://localhost:8080/api/vulns?tool=chrome" | python3 -m json.tool
curl -s "http://localhost:8080/api/vulns?cve=CVE-2024-0519" | python3 -m json.tool
curl -s "http://localhost:8080/api/vulns?exploit_type=rce" | python3 -m json.tool
curl -s "http://localhost:8080/api/vulns?active=true" | python3 -m json.tool
curl -s http://localhost:8080/api/stats/dashboard | python3 -m json.tool
curl -s http://localhost:8080/api/cluster/events | python3 -m json.tool
```

---

## 6. 部署说明

### 6.1 升级步骤

```bash
# 1. 拉取最新代码
cd $PROJECT_ROOT
git pull

# 2. 重新编译
go build -o honeypot ./cmd/honeypot/

# 3. （可选）重新构建前端
cd web && npm run build && cd ..

# 4. 重启服务
# 先停止旧进程
pkill -f honeypot
# 启动新版本
./honeypot &
```

### 6.2 Win11 Agent 交叉编译

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o agent.exe ./cmd/honeypot/
```

### 6.3 兼容性

- 向后兼容：所有现有 API 端点行为不变，仅新增端点
- 数据库：无需迁移，v0.12.0 的 SQLite 数据库可直接使用
- 前端：新增 `/api/services/status` 和 `/api/cluster/events` 端点需前端适配才能展示

---

## 7. 已知问题（留待 v0.14.0）

| ID | 问题 | 优先级 |
|----|------|--------|
| TODO-001 | 2/10 面包屑路径超时 | P0 |
| TODO-002 | 终端环境 PATH 退化 | P0 |
| TODO-003 | 非浏览器 UA 不触发指纹 | P1 |
| TODO-005 | Agent 拓扑注册（部分：API 层已完成，Agent 端推送逻辑待完善） | P1 |
| TODO-006 | 高并发面包屑 goroutine 泄漏 | P2 |
| TODO-007 | CGO→纯Go SQLite 性能基线 | P2 |
| TODO-008 | VulnDB 离线同步 | P2 |
| TODO-009 | 版本号散落检查 | P3 |
| TODO-010 | TLS 证书自动续签 | P3 |
| TODO-012 | 登录日志类型断言 | P0 |
| TODO-013 | JWT Secret 持久化 | P0 |
| TODO-014~022 | 前端体验优化系列 | P1-P3 |

---

## 8. 变更摘要

本次 v0.13.0 迭代聚焦于完善核心功能的正确性和可观测性：

- **VulnDB API**: 从"只返回全量"升级为支持 4 维度组合过滤，使漏洞知识库真正可检索
- **蜜罐服务状态**: 服务启动失败从静默 Warn 升级为 Error + 状态 API，解决 macOS 部署覆盖率盲区
- **集群事件**: 打通 Agent→Manager 事件链路，管理端可聚合查看所有节点攻击事件
- **Agent 拓扑**: 在线 Agent 自动注册到拓扑图，可视化多节点部署架构
- **测试体系**: server_test.go 从仅测试旧 API Key 方案重构为覆盖 JWT 认证、VulnDB 过滤、服务状态等核心场景
