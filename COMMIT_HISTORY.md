# Laji-HoneyPot 提交历史持久化记录

> 本文件采用**增量追加**模式，新提交记录插入文件顶部（## 最新提交 之后），旧记录不被覆盖。  
> 记录格式: `| 短Hash | 完整Hash | 时间 | 作者 | 类别 | 变更统计 | 描述 |`

---

## 最新提交

| Short | Full Hash | Time | Category | Stats | Description |
|-------|-----------|------|----------|-------|-------------|
| d6ed416 | d6ed416c9a73a1ca5b792a38bf75d1810044141e | 2026-07-03 10:53 | chore | 1 file, -41 lines | remove temp commit message file |
| **70fe4cf** | 70fe4cfd762eaf89c2421d092a4b0fced7e3bfc8 | 2026-07-03 10:52 | **chore** | **61 files, +3530/-357** | **v0.13.0 - v0.15.0 three-iteration merge** |

### 70fe4cf 迭代详情

#### v0.13.0 - 缺陷修复与API补全
- P1: VulnDB API 多维度过滤 (tool/cve/exploit_type/active)
- P1: /api/services/status 蜜罐服务运行状态端点 + hpEngine 注入
- P1: /api/stats/dashboard 仪表盘别名路由
- P1: 蜜罐启动失败升级为 Errorw 日志 + failedSvcs 追踪
- P1: Handler() nil authMgr 防护 + server_test 19项测试重写
- P2: /api/cluster/events 集群事件聚合 (500条环形缓冲 + topic过滤)
- P2: Agent 拓扑节点自动注册 (handleTopology增强 + 服务边)

#### v0.14.0 - 安全加固与前端体验
- P0: JWT Secret 持久化 (config.jwt_secret → 重启后令牌不失效)
- P0: 登录日志类型断言健壮化 (interface{} → *log.Logger)
- P0: 面包屑 HTTP 回调异步化 (goroutine + 5s超时 + 优雅降级)
- P0: 密码复杂度强制校验 (大写+小写+数字+特殊字符 ≥8)
- P1: 告警渠道扩展: 钉钉/飞书 Webhook + HMAC-SHA256 签名
- P1: 前端 Token 过期 Toast 提示 + Loading 骨架屏 (card/table/text)
- feat: honeypot-ctl 管理端 CLI 运维工具 (start/stop/restart/status/update/logs)
- chore: 全项目敏感信息清理 (IP→变量占位符, 路径→$PROJECT_ROOT, 67处)

#### v0.15.0 - 溯源反制深度升级
- P0: Canvas/WebGL 指纹 9→20 维度 (AudioContext/Math/触屏/广告拦截器)
- P1: 非浏览器 UA 服务端指纹兜底 (extractHeaderFingerprint)
- P1: Burp payload 命名统一 (screen_cap→screen_capture)
- P2: net_probe 冷却 300s→120s + SetCooldownOverride() 运行时覆盖

#### Agent 端口冲突解决方案
- portcheck.go: IsPortAvailable / FindAvailablePort / CheckServicePorts
- HP_PORT_OFFSET 环境变量整体偏移 + 端口冲突自动回退
- main.go: Graceful Shutdown 信号处理 (SIGINT/SIGTERM → Close())

#### 竞品分析
- docs/HONEYPOT_ANALYSIS.md: 15款蜜罐产品对比 + P0-P3 Roadmap (596行)

#### 文档 & 测试
- README.md 全面翻新 (JWT认证/CLI工具/版本号/fingerprint 20维/冷却120s)
- ITERATION_v0.13.0/14.0/15.0.md 迭代复盘报告
- ISSUES.md: TODO-001/003/004/012/013/014/016/021/023-027 标记已修复
- 测试: 28/28包 PASS, go vet 0预警, 前端1327 modules

---

## 历史提交 (v0.12.0 及之前)

| Short | Full Hash | Time | Category | Description |
|-------|-----------|------|----------|-------------|
| 9db4132 | 9db4132fde94718291721c55686eb4a404741550 | 2026-07-02 18:05 | test | 溯源反制全量E2E测试通过(44/44) + 问题归档 + 部署脚本全套 |
| 983a25c | 983a25c6ffb8c347068077c4e8bcd465f9b88b1c | 2026-07-02 15:25 | feat | JWT登录鉴权体系 + 管理端UI优化 + 问题追踪更新 v0.12.0 |
| 9922279 | 9922279927db594c8d7ea7f09b34b5dcdc304cc2 | 2026-07-02 14:41 | feat | 反制模块全链路实现 v0.12.0 |
| 10fe6d2 | 10fe6d256172f76809d69fef10338f3a8b4340dc | 2026-07-02 11:08 | test | traceability + countermeasure test suites + issue tracker |
| cd27816 | cd278167e1d9df3c17515f9289e12abefdc67f67 | 2026-07-02 10:55 | feat | cluster Agent node registration support |
| 5d85280 | 5d8528086ffa019e4de44e94c7f62c6441eedf8c | 2026-07-02 10:15 | fix | switch SQLite driver to pure-Go modernc.org/sqlite + fix Windows encoding |
| 5d270b3 | 5d270b375d7c92202e6ab322917eb0313c21319b | 2026-07-02 10:01 | feat | cross-machine deploy — cluster TLS + Agent packaging + full test suite |
| d45b641 | d45b64159fc363263bcf2d38249de8d8c58294c5 | 2026-07-01 17:54 | docs | add GitHub sync section, update API exemption list, bump to v0.11.1 |
| adf8487 | adf848789d78c70e57304741cab7fe305b1afb7b | 2026-07-01 17:23 | fix | exfil API auth + cooldown + POST JSON support v0.11.1 |
| bb40826 | bb4082642174d1e0a6364b75ad3220248d0e910f | 2026-07-01 17:04 | fix | trace engine wiring + Burp priority reorder |
| 3d0aff9 | 3d0aff98f0ae3fc033ed274c9197af91eba2456d | 2026-07-01 16:52 | feat | browser vulndb expansion + deep countermeasure implant system |
| fb50002 | fb500023cddf92d4b4e1331f2e37f0af0920a090 | 2026-07-01 15:36 | docs | update README for merged trap config into AgentDeploy panel |
| 90a8601 | 90a8601fba55f430d21d2ae1d4bb97e03fed4fdb | 2026-07-01 15:34 | refactor | merge trap config into AgentDeploy panel as deployment preview |
| b88cdba | b88cdbac69e34d46ba563b287648a45215833c8a | 2026-07-01 15:25 | fix | UI bugs found during Chrome DevTools testing |
| f5f09fd | f5f09fdcc646b595ed8212dabc7f5e3527e4d9f1 | 2026-07-01 15:10 | docs | remove MCP-specific config from README, keep only standard DevTools guide |
| 647f411 | 647f4111f55aab4b8a25057898d950af82788834 | 2026-07-01 15:02 | docs | fix README chrome-devtools-mcp package name and setup instructions |
| 15fa9c8 | 15fa9c83d0f15f8af5b58f0dc7c07e3a223f525f | 2026-07-01 14:52 | fix | v0.10.2 - UI verification fixes and documentation update |
| 93f50be | 93f50be67731d0767df00965a75e120dfdd2d412 | 2026-07-01 14:25 | feat | v0.10.2 - agent generation engine with modular deployment |
| 40d6bce | 40d6bce64265dcb4fdb78643a89cbe71c35465e7 | 2026-07-01 11:35 | feat | v0.10.1 - modular trap scenario selection system |
| 11d990a | 11d990a15156963e6f00b5574c0c9affd4517621 | 2026-07-01 09:51 | feat | v0.10.0 - distributed cluster architecture foundation |
| c1069c9 | c1069c9aeb22f43481cfeea1c74348bde0952011 | 2026-06-30 17:18 | feat | v0.9.7 - mobile fingerprint + asset detection module |
| 1831897 | 18318979b850f3e05fd2760b2864e77948ef6fc7 | 2026-06-25 16:00 | docs | sync README roadmap - countermeasure enhancement checked off, breadcrumb 30->50 |
| 73d874f | 73d874f009e09b041d2df4db631550909ad97e0c | 2026-06-25 16:00 | test | profile engine unit tests 24 cases + README sync roadmap |
| 9cb1970 | 9cb19700976a6461683194e27687690a4c734794 | 2026-06-25 10:41 | feat | countermeasure enhancement - screenshot detection, file-read exploit defense, risk level system |
| 77b60b1 | 77b60b1cdf54ed2038144a86e0e881b0b1ff8ca1 | 2026-06-25 10:21 | feat | 攻击者画像与威胁标签系统 (v0.9.5) |
| de84251 | de84251b6a2ba1fa63f25ac17df7adb1754772ec | 2026-06-25 09:18 | feat | 溯源反制模块深度强化 — 全维度浏览器指纹+行为追踪+安全合规 |
| 106e598 | 106e59885b247855f0c58df23748d96eeda940ad | 2026-06-24 17:57 | fix | 拓扑图 countermeasure 边 IP:port 格式不一致导致渲染崩溃 |
| dd6754b | dd6754b10a8aff8d0f30aadf28f8c8269d47e7b8 | 2026-06-24 17:40 | fix | dev 脚本添加 --host 参数，解决 npm run dev 无法访问后台的问题 |

---

## 提交类别统计

| Category | Count |
|----------|-------|
| feat (新功能) | 13 |
| fix (修复) | 7 |
| docs (文档) | 5 |
| test (测试) | 3 |
| refactor (重构) | 1 |
| chore (杂项) | 2 |
| **Total** | **31** |

---

## 版本演进

| 版本 | 日期 | 关键里程碑 |
|------|------|-----------|
| v0.9.5 | 2026-06-25 | 攻击者画像与威胁标签系统 |
| v0.9.7 | 2026-06-30 | 移动端指纹 + 资产探测模块 |
| v0.10.0 | 2026-07-01 | 分布式集群架构 |
| v0.10.1 | 2026-07-01 | 陷阱模块化选配 |
| v0.10.2 | 2026-07-01 | Agent 一键生成引擎 |
| v0.11.0-v0.11.1 | 2026-07-01 | 深度反制系统 v2.0 |
| v0.12.0 | 2026-07-02 | 截屏/Shell/传输/桌面远控全链路 + JWT 认证 |
| **v0.13.0** | **2026-07-03** | **VulnDB过滤+蜜罐状态API+集群事件+Agent拓扑** |
| **v0.14.0** | **2026-07-03** | **JWT持久化+密码复杂度+告警Webhook+CLI工具+敏感信息清理** |
| **v0.15.0** | **2026-07-03** | **指纹20维+UA兜底+命名统一+冷却优化** |

---

> **增量规则**: 新提交记录插入到 "## 最新提交" 行下方、"## 历史提交" 行上方。  
> "版本演进" 表仅在涉及版本号变更时追加新行。  
> "提交类别统计" 每次提交后更新计数。  
> 本文件首次创建于 2026-07-03，基于 git log --all 完全重建。
