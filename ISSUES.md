# 优化 TODO 清单 — Laji-HoneyPot v0.11.1

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
| 9 服务蜜罐端口 | ✅ PASS | HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP |
