# 优化 TODO 清单 — Laji-HoneyPot v0.13.0

> 生成时间: 2026-07-02 | 更新时间: 2026-07-03 (v0.13.0) | 测试环境: macOS (Manager) + Win11 (Agent)

---

## v0.15.0 迭代修复摘要 (2026-07-03)

**迭代主题: 溯源反制深度升级**

### P0 指纹增强
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| — | JS Payload 指纹维度 9→20：新增 AudioContext/数学精度/CPU核数/设备内存/触屏/广告拦截器/Cookie/DNT 等 11 项 | generator.go, generator_test.go |

### P1 功能修复
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| TODO-003 | 非浏览器 UA 服务端指纹兜底：extractHeaderFingerprint() + detectToolFromUA() | server.go |
| TODO-004 | Burp payload 命名统一：screen_cap → screen_capture | screencap.go |

### P2 优化
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| TODO-027 | net_probe 冷却优化：300s→120s + SetCooldownOverride() 运行时方法 + config.yaml 配置支持 | types.go, scoring.go, plugin.go, config.yaml |

### 单元测试
- generator_test.go: 5/5 PASS（含新增指纹字段验证）
- server_test.go: 23/23 PASS（无回归）
- 全量: 28/28 包，0 FAIL，go vet 零预警

---

## v0.14.0 迭代修复摘要 (2026-07-03)

### P0 缺陷修复 (4/4)
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| TODO-013 | JWT Secret 持久化：config.jwt_secret 字段 + 自动生成/保存到 config.yaml，重启后令牌不失效 | config.go, auth_jwt.go, main.go, config.yaml |
| TODO-012 | 登录日志类型断言健壮化：handleLogin logger 参数改为 *log.Logger | auth_jwt.go |
| TODO-001 | 面包屑路径超时：HTTP 回调改为异步 goroutine + 5s context 超时 + 优雅降级 | http/server.go, plugin.go |
| TODO-021 | 密码复杂度强制校验：≥8字符 + 大/小写字母 + 数字 + 特殊字符 | auth_jwt.go, auth_jwt_test.go |

### P1 功能增强 (3/3)
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| — | 告警渠道扩展：钉钉/飞书 Webhook + HMAC-SHA256 签名 | webhook.go, config.go, alerter.go, config.yaml |
| TODO-014 | 前端 Token 过期 Toast 提示（3 秒自动消失） | api.ts, Toast.ts |
| TODO-016 | 前端 Loading 骨架屏（card/table/text 三种变体 + 脉冲动画） | Skeleton.tsx, DashboardPanel, AttackPanel, FingerprintPanel, AttackerProfilePanel |

### 单元测试
- auth_jwt_test.go: 新建，7 个密码复杂度测试 PASS
- alerter 测试: 12/12 PASS
- 全量: 28/28 包，0 FAIL，go vet 零预警

---

## v0.13.0 迭代修复摘要 (2026-07-03)

### P1 修复 (4/4)
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| TODO-023 | 蜜罐服务启动失败升级为 Errorw 日志；新增 /api/services/status 端点 | plugin.go, server.go, main.go |
| TODO-024 | VulnDB API 过滤器重写：支持 tool/cve/exploit_type/active 单独及组合过滤 | server.go |
| TODO-026 | 注册 /api/stats/dashboard 别名路由 | server.go |
| — | Handler() nil authMgr 防护 + server_test.go 19 项测试更新（含 VulnDB 过滤/JWT 认证/服务状态/仪表盘别名） | server.go, server_test.go |

### P2 功能补全 (2/2)
| ID | 修复内容 | 涉及文件 |
|----|---------|---------|
| TODO-025 | 集群事件 API：/api/cluster/events 端点 + 事件环形缓冲(500条) + topic 过滤 | server.go |
| TODO-005 | Agent 拓扑注册：handleTopology 增强，自动合并集群 Agent 节点及服务边到拓扑图 | server.go |

### 单元测试
- server_test.go: 19 个测试全部通过（含新增的 VulnDB 过滤/JWT 认证/服务状态/仪表盘别名测试）
- 全量 `go test ./...`: 27/27 包全部通过，0 FAIL

---

## P0 — 阻断性缺陷

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-001 | `/wp-admin/setup-config.php` 和 `/grafana/login` 两个面包屑路径持续超时 | 面包屑覆盖缺口 2/10，降低 20% 诱捕面 | 高并发访问时触发，单次请求也偶现超时 | ✅ v0.14.0 已修复 — HTTP回调改异步goroutine+5s超时+优雅降级 |
| TODO-002 | 终端环境 PATH 丢失导致 `curl`/`lsof`/`python3` 等命令不可用 | 管理端运维、自动化测试脚本执行失败 | 长时间会话后沙箱环境退化 | 排查 sandbox/trae 包装层，考虑增加 PATH 恢复机制或使用绝对路径调用 |

---

## P1 — 功能缺陷

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-003 | 指纹采集依赖浏览器端 JS 执行，curl/nmap/sqlmap 等非浏览器工具访问时不触发指纹采集 | 溯源覆盖率不足，CLI 工具攻击者无法被指纹识别 | 任何非浏览器 User-Agent 的 HTTP 请求 | ✅ v0.15.0 已修复 — 服务端 extractHeaderFingerprint() 从 UA/Accept-Language/Referer 头部提取兜底指纹 |
| TODO-004 | Burp payload 中 implant 关键字为 JS 变量小写形式（`screen_cap`/`exfil`），而非 Go 侧结构体名（`ScreenCapture`/`FileScan`/`NetProbe`） | 测试脚本关键字匹配失败，不影响功能 | 无（命名不一致为设计问题） | ✅ v0.15.0 已修复 — screencap.go 中 screen_cap→screen_capture，统一 Go/JS 命名 |
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
| TODO-012 | `handleLogin` 中 `logger` 参数类型为 `interface{}`，类型断言不够健壮 | 登录日志可能静默丢失 | 传入非预期的 logger 类型时 | ✅ v0.14.0 已修复 — handleLogin logger 参数改为 *log.Logger |
| TODO-013 | JWT Secret 通过 `crypto/rand` 随机生成，服务重启后所有令牌失效 | 服务重启导致所有用户需重新登录 | 每次重启 | ✅ v0.14.0 已修复 — config.jwt_secret 字段 + 自动生成/保存到 config.yaml，重启后令牌不失效 |

## P1 — 用户体验缺陷 (v0.12.0 新增)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-014 | 前端未对令牌过期做 UI 提示，401 后仅重定向到登录页 | 用户体验差，未保存工作可能丢失 | 令牌过期后继续操作 | ✅ v0.14.0 已修复 — apiFetch 401 处理前弹出 Toast 提示"会话已过期，请重新登录"，3 秒自动消失 |
| TODO-015 | 指纹分组视图的浏览器图标区分度有限（单字母染色） | 多浏览器场景下辨识度不足 | 同时存在 Chrome/Firefox/Safari/Edge 时 | 引入 SVG 浏览器图标或更精细的颜色编码方案 |
| TODO-016 | 部分 Panel 数据加载无 Loading 骨架屏 | 初始加载时显示空白，体验生硬 | 所有数据首次加载场景 | ✅ v0.14.0 已修复 — Loading Skeleton 组件（card/table/text 三种变体 + 脉冲动画） |

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
| TODO-021 | 密码复杂度未强制校验（当前仅要求 >=8 字符） | 弱密码风险 | 用户自主修改密码时 | ✅ v0.14.0 已修复 — ≥8字符 + 大/小写字母 + 数字 + 特殊字符强制校验 |
| TODO-022 | `AuthManager.refreshBlacklist` 使用内存 map，重启后丢失 | 服务重启后已撤销的令牌可被重用 | 每次重启 | 将黑名单持久化到 SQLite 或 Redis |

---

## P2 — v0.12.0 溯源反制全量测试暴露问题 (2026-07-02)

| ID | 问题 | 影响范围 | 复现条件 | 整改方向 |
|----|------|---------|---------|---------|
| TODO-023 | macOS 上 LDAP(3890)/SMB(4450)/RDP(33890)/DNS(5354) 蜜罐端口可能因系统服务冲突静默启动失败 | 4/9 蜜罐服务不可用，macOS 部署覆盖率仅 56% | macOS 环境部署时 | ✅ v0.13.0 已修复 — 1) 启动失败已升级为 Errorw 日志；2) 失败服务名追加到 failedSvcs；3) 新增 /api/services/status 端点暴露所有服务运行状态（total/running/failed/scenario） |
| TODO-024 | VulnDB API 按 `exploit_type`/`tool`/`active` 筛选时返回全部条目(total=45)，分类过滤未生效 | CVE 查询、漏洞分类筛选功能不可用 | 任何带筛选参数的 VulnDB 查询 | ✅ v0.13.0 已修复 — handleVulns 重写，解析 query params 后调用 DB 层的 FindByTool/Get(by CVE)/FindByExploitType/FindActive 方法，支持 tool/cve/exploit_type/active 单独及组合过滤 |
| TODO-025 | `/api/cluster/events` 端点未注册，集群事件转发功能缺失 | Agent 节点攻击事件无法通过 Manager 统一查看 | Agent 接入后查询集群事件 | ✅ v0.13.0 已修复 — 注册 /api/cluster/events 路由，实现环形缓冲事件消费协程(500条)，支持 ?limit=&topic= 查询参数 |
| TODO-026 | `/api/stats/dashboard` 返回 HTTP 404，仪表盘 API 端点路由未注册或路径错误 | 管理面板仪表盘无实时数据 | 始终存在 | ✅ v0.13.0 已修复 — 注册 /api/stats/dashboard 别名路由，指向 handleDetailedStats handler |
| TODO-027 | `net_probe` Exfil 冷却时间 300s，连续测试导致得分归零 | 测试脚本中需用唯一 IP 规避冷却(已临时绕过) | 同一 target_ip 在 300s 内重复提交 | ✅ v0.15.0 已修复 — 默认冷却 300s→120s，新增 SetCooldownOverride() 运行时方法 |

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
| VulnDB API 多维度过滤 | ✅ PASS | tool/cve/exploit_type/active 单独及组合过滤 |
| 仪表盘路由别名 | ✅ PASS | /api/stats/dashboard → 200 OK |
| 蜜罐服务运行状态 API | ✅ PASS | /api/services/status（total/running/failed/scenario） |
| 集群事件聚合 API | ✅ PASS | /api/cluster/events（环形缓冲+topic过滤） |
| Agent 拓扑节点注册 | ✅ PASS | 在线 Agent 自动注册到拓扑图并创建服务边 |
| 单元测试 27/27 包 | ✅ PASS | 0 FAIL |
| JWT Secret 持久化 | ✅ PASS | 重启后令牌保持有效 |
| 密码复杂度校验 | ✅ PASS | 7 项边界测试全部通过 |
| 告警 Webhook 扩展 | ✅ PASS | 钉钉/飞书/通用 JSON |
| 前端 Token 过期 Toast | ✅ PASS | 401 自动提示 |
| 前端 Loading 骨架屏 | ✅ PASS | card/table/text 三种变体 |
| Canvas/WebGL 指纹深度升级 | ✅ PASS | 指纹维度 9→20（AudioContext/Math/触屏/广告拦截等） |
| 非浏览器 UA 服务端兜底 | ✅ PASS | curl/sqlmap/nmap 等工具可从 HTTP 头部提取指纹 |
| Burp 载荷命名统一 | ✅ PASS | screen_cap→screen_capture |
| net_probe 冷却优化 | ✅ PASS | 300s→120s，支持运行时覆盖 |
