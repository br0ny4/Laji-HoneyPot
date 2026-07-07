# Laji-HoneyPot v0.18.1 安全审计报告

> 审计日期: 2026-07-04  
> 审计范围: 全量核心代码 + 蜜罐服务 + 认证体系 + 网络交互 + 依赖模块  
> 版本: v0.17.3 (审计) → v0.18.1 (修复)

---

## 1. 审计方法

采用 **四维度并行审计** 策略，覆盖：

| 维度 | 审计内容 | 发现数 |
|------|---------|--------|
| 认证与权限控制 | JWT/Pwd/bcrypt/会话/前端令牌/RBAC | 15 |
| 输入输出过滤 | 注入/SSRF/路径穿越/反序列化/XSS | 9 |
| 敏感数据保护 | 密钥存储/明文传输/TLS/日志脱敏/SQLite加密 | 14 |
| 蜜罐跳板风险 | 反制功能滥用/端口暴露/横向移动/合规 | 4 |
| **合计** | | **42** |

---

## 2. 风险清单

### 2.1 Critical (严重) — 3 项

| # | 问题 | 文件 | 状态 |
|---|------|------|------|
| C-1 | JWT Secret + API Key 明文存储于 config.yaml (0644) | config.go:111, main.go:169 | ✅ v0.18.1 已修复 — Save() 改为 0600 |
| C-2 | 密码复杂度验证前后端不一致：API 端仅要求 ≥8 字符，前端显示 16 | auth_jwt.go:331 | ✅ v0.18.1 已修复 — Changepassword 改用 ValidateStrongPassword |
| C-3 | 植入体 AES 加密密钥硬编码 (`laji-honeypot-key-2025`) | exfil.go:109, implant.go:79 | ⚠️ KB — JS Payload 公开交付给攻击者，默认不可信 |

### 2.2 High (高危) — 7 项

| # | 问题 | 文件 | 状态 |
|---|------|------|------|
| H-1 | transfer.go sanitizePath 路径穿越 (....// 绕过) | transfer.go:348 | ✅ v0.18.1 已修复 — 循环移除 + 最终检查 |
| H-2 | X-Forwarded-For IP 伪造（3 处直接取 header） | server.go:588,871,1486 | ✅ v0.18.1 已修复 — getClientIP() 仅取第一个 IP |
| H-3 | HTTP 蜜罐反射型 XSS（路径回显到 HTML 未转义） | http/server.go:696,525,778,1191 | ✅ v0.18.1 已修复 — html.EscapeString() |
| H-4 | exfil 端点无请求体大小限制 (DoS) | server.go:1551 | ✅ v0.18.1 已修复 — MaxBytesReader 5MB |
| H-5 | 部署脚本硬编码测试密码 admin123 | deploy/*.sh | ⚠️ 仅测试用途 — 标注后保留 |
| H-6 | Agent 模板 tls_insecure: true 默认为开启 | deploy/win-agent/config.yaml | ✅ v0.18.1 已添加 WARN 日志 |
| H-7 | 自签名证书分支强制 InsecureSkipVerify | main.go:375 | ✅ v0.18.1 已添加 WARN 日志 |

### 2.3 Medium (中危) — 7 项

| # | 问题 | 状态 |
|---|------|------|
| M-1 | must_change_password 仅前端校验，API 可绕过 | ✅ v0.18.1 已修复 — JWTAuthMiddleware 强制检查 |
| M-2 | 攻击者 POST body (含潜在凭据) 明文存入 SQLite | KB — 蜜罐设计预期行为 |
| M-3 | CORS 通配符 `*` (server.go:312) | 待评估 |
| M-4 | 用户名枚举时序攻击 (bcrypt 耗时差异) | 待修复 |
| M-5 | refresh token 黑名单仅存内存，重启清空 | 待修复 |
| M-6 | netprobe 自动扫描攻击者内网 (合规风险) | KB |
| M-7 | clipboard sniffing 采集攻击者敏感数据 | KB |

### 2.4 Low (低危) — 5 项

| # | 问题 |
|---|------|
| L-1 | 错误消息泄露剩余重试次数 (attempts remaining) |
| L-2 | 初始密码明文输出到 stdout (终端历史残留) |
| L-3 | SSE 端点 CORS `*` |
| L-4 | SQLite 数据库无加密 |
| L-5 | data_dir 目录权限 0755 |

---

## 3. 修复详情 (v0.18.1)

### 修复 1: config.yaml 权限保护
- **config.go S:111**: `os.WriteFile(p, data, 0644)` → `0600`
- 防止同组用户读取 JWT Secret / 密码哈希

### 修复 2: 密码复杂度统一
- **auth_jwt.go L:331**: `Changepassword` 调用从 `ValidatePassword` (≥8) → `ValidateStrongPassword` (≥16)
- 消除 API 绕过前端强密码检查的漏洞

### 修复 3: 路径穿越修复
- **transfer.go L:348-362**: `sanitizePath` 重写
  - 循环移除所有 `..` 前缀（防止 `....//....//` 绕过）
  - 最终检查确保结果不含 `..`
  - 失败返回空字符串

### 修复 4: IP 伪造防护
- **server.go**: 新增 `getClientIP()` 函数
  - 从 `X-Forwarded-For` 仅取第一个 IP
  - `net.ParseIP` 验证格式
  - 更新 `handleCollect` / `rateLimitMiddleware` / `handleCountermeasureExfil`

### 修复 5: HTTP 蜜罐 XSS
- **http/server.go**: 三处路径回显使用 `html.EscapeString()` 转义
  - `renderPage()` 页面主体
  - `fakeAPIResponse()` JSON path 字段
  - `fakeDirListing()` 标题

### 修复 6: exfil 端点 DoS 防护
- **server.go L:1551**: `r.Body = http.MaxBytesReader(w, r.Body, 5<<20)` (5MB)

### 修复 7: 强制改密中间件
- **auth_jwt.go L:428-442**: `JWTAuthMiddleware` 检查 `must_change_password`
  - 仅放行 `/api/auth/changepassword` 和 `/api/auth/logout`
  - 其他接口返回 403

---

## 4. 已验证安全项（正面发现）

经过审计确认以下方面安全：

1. **SQL 注入**: 所有数据库操作使用 `?` 参数化查询 ✅
2. **bcrypt 成本因子**: 12 (OWASP 推荐 ≥10) ✅
3. **JWT 密钥生成**: `crypto/rand` 256-bit ✅
4. **JWT 算法验证**: 强制 HMAC，拒收非对称算法 ✅
5. **Token 有效期**: Access 15min / Refresh 24h ✅
6. **登录限流**: 5 次/15 分钟 (IP + username) ✅
7. **密码不记录日志** ✅
8. **SSH/FTP/LDAP/DNS/SMB/RDP**: 仅记录输入，无命令执行 ✅
9. **截屏 base64 校验**: 存储前验证 ✅
10. **文件扫描截断**: contentPreview ≤1024 字符 ✅
11. **queryInt 上限**: limit ≤1000 ✅
12. **蜜罐响应头**: 均为仿真数据，不泄露真实系统信息 ✅

---

## 5. 文档修订记录

### README.md
移除全部 Chrome 浏览器调试相关内容：

| 位置 | 内容 | 行数 |
|------|------|------|
| 目录 | `[Chrome 浏览器调试]` 条目 | 1 行 |
| 前置依赖表 | `Chrome \| 120+ \| 浏览器调试（DevTools）` | 1 行 |
| 完整章节 | `## Chrome 浏览器调试` + 子节 | 49 行 |
| 路线图 | `Chrome DevTools 调试指南（v0.10.2）` | 1 行 |
| **合计** | | **52 行** |

---

## 6. 验证结果

```
go build: PASS
go vet:   0 预警
go test:  30/30 包 PASS, 0 FAIL
tsc:      TypeScript 无错误
```

---

## 7. 待解决风险（留待 v0.19.0）

| 优先级 | 编号 | 问题 |
|--------|------|------|
| P1 | M-4 | 用户名枚举时序攻击 — 添加恒时比较 |
| P1 | M-5 | refresh token 黑名单持久化到 SQLite |
| P2 | M-3 | CORS 通配符修复 |
| P2 | L-2 | 初始密码 stdout 输出防护 |
| P3 | L-4 | SQLite 加密扩展 |
| P3 | L-5 | data_dir 权限收紧 |

---

> 审计范围: `cmd/` `internal/` `web/src/` `config.yaml` `deploy/` 全部文件  
> 审计工具: 静态代码分析 + 数据流追踪 + 四维度并行扫描  
> 关键词: `XSS` `SQLi` `SSRF` `path traversal` `IDOR` `privilege escalation` `credentials` `hardcoded`
