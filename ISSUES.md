# 优化 TODO 清单 — Laji-HoneyPot v0.12.0

> 生成时间: 2026-07-02 | 测试环境: macOS 10.111.31.103 (Manager) + Win11 10.111.29.4 (Agent)

---

## P0 — 阻断性缺陷

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-001 | `/wp-admin/setup-config.php` 和 `/grafana/login` 两个面包屑路径持续超时 | 面包屑覆盖缺口 2/10，降低 20% 诱捕面 | 高并发访问时触发，单次请求也偶现超时 | 检查 honeybreadcrumb 路由注册逻辑，确认路径处理是否存在阻塞或死循环 |
| TODO-002 | 终端环境 PATH 丢失导致 `curl`/`lsof`/`python3` 等命令不可用 | 管理端运维、自动化测试脚本执行失败 | 长时间会话后沙箱环境退化 | 排查 sandbox/trae 包装层，考虑增加 PATH 恢复机制或使用绝对路径调用 |

---

## P1 — 功能缺陷

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-003 | 指纹采集依赖浏览器端 JS 执行，curl/nmap/sqlmap 等非浏览器工具访问时不触发指纹采集 | 溯源覆盖率不足，CLI 工具攻击者无法被指纹识别 | 任何非浏览器 User-Agent 的 HTTP 请求 | 服务端增加 UA 解析指纹兜底逻辑，从 HTTP Headers（UA/Accept-Language/Accept-Encoding）直接提取可用指纹字段 |
| TODO-004 | Burp payload 中 implant 关键字为 JS 变量小写形式（`screen_cap`/`exfil`），而非 Go 侧结构体名（`ScreenCapture`/`FileScan`/`NetProbe`） | 测试脚本关键字匹配失败，不影响功能 | 无（命名不一致为设计问题） | 统一命名规范：Go 侧与 JS 侧使用一致的标识符命名约定 |
| TODO-005 | Agent 节点的 API 端口 (8080) 未将 agent 自身 IP 注册到拓扑中 | 拓扑图中不会显示 Agent 节点自身的攻击面 | Agent 注册后，仅作为集群节点显示，不参与攻击者拓扑 | 在 agent 注册时将自身 service 端口信息推送至拓扑端点 |

---

## P2 — 性能与稳定性

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-006 | 高并发面包屑测试时 2/10 路径超时（疑似 goroutine 泄漏或连接池耗尽） | 面包屑可靠性下降 | 连续 30+ 请求后出现 | 增加 HTTP client 超时控制、连接池大小配置、goroutine leak detector |
| TODO-007 | `go-sqlite3` → `modernc.org/sqlite` 迁移后缺少性能基线对比 | 不确定纯 Go SQLite 性能是否满足生产需求 | 始终存在 | 建立 SQLite 压测脚本，对比 CGO/纯 Go 版本 QPS 差异 |
| TODO-008 | VulnDB NVD 爬虫在 Win11 Agent 侧因网络限制报错 "github search failed" | Agent 漏洞库更新依赖外网，内网 Agent 无法自更新 | 无外网的 Agent 节点 | 支持从 Manager 节点同步 VulnDB 数据到 Agent |

---

## P3 — 规范与工程化

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-009 | 版本号散落多处硬编码（已部分修复，确认无遗漏） | 版本升级遗漏风险 | 已修复至 `core.Version` 统一引用 | 全量 grep `0\.[0-9]+\.[0-9]+` 确认无残留 |
| TODO-010 | Cluster TLS 自签证书有效期仅 365 天，到期后 Agent 断开 | Windows Agent 1 年后自动断连 | 365 天后 | 支持证书自动续签或配置化有效期 |
| TODO-011 | `deploy/win-agent/` 中 EXE 不纳入 git (`.gitignore`)，需手动拷贝 | 二进制分发需额外步骤 | 始终存在 | CI/CD 构建 pipeline 或 GitHub Releases 自动发布 |


## P0 — 认证安全缺陷 (v0.12.0 新增)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-012 | `handleLogin` 中 `logger` 参数类型为 `interface{}`，类型断言不够健壮 | 登录日志可能静默丢失 | 传入非预期的 logger 类型时 | 改为直接接收 `*log.Logger` 类型，在 `RegisterRoutes` 时绑定 |
| TODO-013 | JWT Secret 通过 `crypto/rand` 随机生成，服务重启后所有令牌失效 | 服务重启导致所有用户需重新登录 | 每次重启 | 增加 Secret 持久化存储（config 文件或 DB），支持配置不变 |

## P1 — 用户体验缺陷 (v0.12.0 新增)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-014 | 前端未对令牌过期做 UI 提示，401 后仅重定向到登录页 | 用户体验差，未保存工作可能丢失 | 令牌过期后继续操作 | 在 `apiFetch` 401 处理前弹出 Toast 提示"会话已过期，请重新登录" |
| TODO-015 | 指纹分组视图的浏览器图标区分度有限（单字母染色） | 多浏览器场景下辨识度不足 | 同时存在 Chrome/Firefox/Safari/Edge 时 | 引入 SVG 浏览器图标或更精细的颜色编码方案 |
| TODO-016 | 部分 Panel 数据加载无 Loading 骨架屏 | 初始加载时显示空白，体验生硬 | 所有数据首次加载场景 | 增加统一的 Loading Skeleton 组件 |

## P2 — 兼容性与跨浏览器 (v0.12.0 新增)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-017 | Safari/Edge 中 `EventSource` 重连机制可能不一致 | SSE 事件推送在部分浏览器中不稳定 | Safari 长时间闲置后 | 增加 SSE 心跳保活 + 前端手动重连逻辑 |
| TODO-018 | 部分 CSS 变量在旧版 Safari (<15) 不支持 `gap` 属性 | 指纹分组视图布局交错 | Safari 14 及以下 | 添加 `@supports` 回退样式或使用 margin 替代 gap |
| TODO-019 | `getUAInfo()` 解析器未覆盖 Tor Browser、Brave、Opera 等小众浏览器 | 浏览器识别覆盖率约 80% | 攻击者使用小众浏览器 | 扩展 UA 解析规则表，覆盖 Top 15 浏览器 |

## P3 — 工程优化 (v0.12.0 新增)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-020 | 前端 `api.ts` 中 `isTokenExpired()` 的 `atob` 在 Node SSR 环境不可用 | 未来如需 SSR 渲染 | SSR 场景 | 使用 `Buffer.from(token.split('.')[1], 'base64').toString()` |
| TODO-021 | 密码复杂度未强制校验（当前仅要求 >=8 字符） | 弱密码风险 | 用户自主修改密码时 | 增加大小写+数字+特殊字符的复杂性校验 |
| TODO-022 | `AuthManager.refreshBlacklist` 使用内存 map，重启后丢失 | 服务重启后已撤销的令牌可被重用 | 每次重启 | 将黑名单持久化到 SQLite 或 Redis |

---

## P2 — v0.12.0 溯源反制全量测试暴露问题 (2026-07-02)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-023 | macOS 上 LDAP(3890)/SMB(4450)/RDP(33890)/DNS(5354) 蜜罐端口可能因系统服务冲突静默启动失败 | 4/9 蜜罐服务不可用，macOS 部署覆盖率仅 56% | macOS 环境部署时 | 1) 增加启动失败 ERROR 级别日志(当前仅 Warn) 2) 端口冲突时自动尝试备用端口 3) 管理面板显示各服务运行状态 |
| TODO-024 | VulnDB API 按 `exploit_type`/`tool`/`active` 筛选时返回全部条目(total=45)，分类过滤未生效 | CVE 查询、漏洞分类筛选功能不可用 | 任何带筛选参数的 VulnDB 查询 | 检查 API handler 中 SQL 查询的 WHERE 子句拼接逻辑 |
| TODO-025 | `/api/cluster/events` 端点未注册，集群事件转发功能缺失 | Agent 节点攻击事件无法通过 Manager 统一查看 | Agent 接入后查询集群事件 | 在 server.go 中注册 `/api/cluster/events` 路由并实现事件聚合查询 |
| TODO-026 | `/api/stats/dashboard` 返回 HTTP 404，仪表盘 API 端点路由未注册或路径错误 | 管理面板仪表盘无实时数据 | 始终存在 | 检查路由注册，确认 handler 绑定正确 |
| TODO-027 | `net_probe` Exfil 冷却时间 300s，连续测试导致得分归零 | 测试脚本中需用唯一 IP 规避冷却(已临时绕过) | 同一 target_ip 在 300s 内重复提交 | 评估生产环境中 300s 冷却是否合理，考虑按场景分级冷却(测试环境可缩短) |

---

## P3 — 测试脚本兼容性 (v0.12.0 已修复)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| ~~TODO-FIXED-01~~ | bash 3.2 (macOS 默认) 不支持 `declare -A` 关联数组 | ✅ 已修复 — 改为并行数组+索引遍历 | macOS bash 3.2 | — |
| ~~TODO-FIXED-02~~ | `((var++))` 在 `set -e` 下当 var=0 时退出码为 1 导致脚本终止 | ✅ 已修复 — 改为 `var=$((var+1))` | 全部环境 | — |
| ~~TODO-FIXED-03~~ | JWT 刷新测试向 `/api/auth/refresh` 发送空 body `{}`，端点要求 `{"refresh_token":"..."}` | ✅ 已修复 — 从登录响应提取 refresh_token | 全部环境 | — |
| ~~TODO-FIXED-04~~ | UA 识别测试残留旧变量 `UA_TESTS` 导致 `UA_TOTAL=0` | ✅ 已修复 — 改为 `UA_NAMES` | 全部环境 | — |
| ~~TODO-FIXED-05~~ | 健康检查 `[ "$HTTP_CODE" = "200" ]` 因 curl 输出含不可见字符导致比对失败 | ✅ 已修复 — 改用 `case *200*` 通配匹配 | macOS bash 3.2 | — |

---

## 已验证通过项

| 验证项 | 状态 | 说明 |
|--------|------|------|
| 15 种 UA 识别 | ✅ PASS | burp/chrome/firefox/sqlmap/nuclei/nmap/nikto/gobuster/curl/wget/python + 多种 chrome 变体 + 空 UA |
| Burp UA 载荷差异化 | ✅ PASS | Burp 32,099 bytes (含 implant) > Chrome 17,149 bytes |
| 面包屑 8/10 路径 | ✅ PASS | 8 条路径全部 200 OK |
| VulnDB 45 条目 | ✅ PASS | 含 NVD 自动抓取条目 |
| 连接追踪 | ✅ PASS | 62 connections, 49 counter hits |
| Agent 集群注册 | ✅ PASS | WIN-20260228QEM-3bbc47c5 在线 |
| 反制得分引擎 | ✅ PASS | 150 pts, 冷却防刷生效 |
| SHA256 审计 | ✅ PASS | 全部条目 compliant=true |
| 拓扑生成 | ✅ PASS | team_size > 0 |
| Exfil POST/GET 双模式 | ✅ PASS | JSON + Image Beacon 均可接收 |
| modernc.org/sqlite | ✅ PASS | 纯 Go 交叉编译 Windows 无 CGO |
| 9 服务蜜罐端口 | ⚠️ 5/9 | HTTP(80)/MySQL(3306)/SSH(2222)/Redis(6379)/FTP(2121) ✅ | LDAP/SMB/RDP/DNS macOS端口冲突 → TODO-023 |
| JWT 登录鉴权 | ✅ PASS | 令牌签发/刷新/登出/全局拦截/豁免端点 |
| 密码 bcrypt 加密存储 | ✅ PASS | cost=12, SQLite users 表 |
| 登录失败限流(5次/15min) | ✅ PASS | 按 IP+用户名维度限流 |
| MFA 二次认证 | ✅ PASS | TOTP Challenge/Verify 双因子认证 |
| SHA256 审计链完整性 | ✅ PASS | 链式哈希，Verify API valid=True |
| 前端登录页 | ✅ PASS | React LoginPage 组件,表单验证,错误提示 |
| 指纹分组折叠视图 | ✅ PASS | 按IP分组/展开折叠/搜索过滤/列表视图双模式 |
| UI 响应式适配 | ✅ PASS | @media max-width 768px 移动端适配 |
| Go 构建(纯Go CGO=0) | ✅ PASS | 编译通过 |
| React 构建(TypeScript) | ✅ PASS | tsc + vite build 通过 |
| macOS M1 交叉编译 Win11 Agent | ✅ PASS | GOOS=windows GOARCH=amd64 CGO_ENABLED=0 |
| 溯源反制全量 E2E (12阶段) | ✅ 44/44 PASS | 0 Fail — 指纹采集/UA识别/Exfil截屏50pts+文件扫描30pts+网络探测40pts/冷却防刷/审计/MFA/拓扑 |
