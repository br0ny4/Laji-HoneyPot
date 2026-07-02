# Laji-HoneyPot（辣鸡蜜罐）

<p align="center">
  <b>面向网络安全攻防场景中防守方<em>溯源反制</em>环节的高性能蜜罐系统</b>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" /></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go" alt="Go" /></a>
  <a href="https://react.dev"><img src="https://img.shields.io/badge/React-18-61DAFB?logo=react" alt="React" /></a>
  <a href="#一键部署"><img src="https://img.shields.io/badge/deploy-one%20click-green" alt="Deploy" /></a>
</p>

---

## 目录

- [一键部署](#一键部署)
- [快速开始](#快速开始)
- [核心特性](#核心特性)
- [管理后台](#管理后台)
- [陷阱模块选配](#陷阱模块选配)
- [Agent 部署](#agent-部署)
- [测试验证](#测试验证)
- [漏洞库](#漏洞库)
- [项目架构](#项目架构)
- [本地开发环境](#本地开发环境)
- [Chrome 浏览器调试](#chrome-浏览器调试)
- [开发路线图](#开发路线图)
- [同类对比](#同类对比)
- [致谢](#致谢)
- [免责声明](#免责声明)

---

## 一键部署

```bash
# 克隆仓库
git clone https://github.com/br0ny4/Laji-HoneyPot.git && cd Laji-HoneyPot

# 一键安装（自动检测系统、安装依赖、编译前后端）
bash install.sh

# 启动蜜罐
./bin/honeypot

# 浏览器打开管理后台 → http://127.0.0.1:8080
```

脚本自动完成以下 7 步：

| 步骤 | 内容 |
|------|------|
| 检测环境 | 识别 OS（Linux/macOS/Windows）、CPU 架构（amd64/arm64） |
| 安装 Git | 自动安装（apt/yum/dnf/brew） |
| 安装 Go | 自动下载 Go 1.22+（Linux/macOS） |
| 安装 Node.js | 通过 nvm 安装 Node 18+ |
| 编译后端 | `go build` → `bin/honeypot` |
| 构建前端 | `npm install && npm run build` → `web/dist/` |
| 生成配置 | 自动创建 `config.yaml`（如不存在） |

> **Windows 用户**：请使用 Git Bash 或 WSL 运行。原生 CMD/PowerShell 暂不支持。

---

## 快速开始

### 环境要求

| 依赖 | 最低版本 |
|------|---------|
| Go | 1.22+ |
| Node.js | 18+（仅前端构建需要） |
| Git | 任意版本 |

### 手动安装

```bash
git clone https://github.com/br0ny4/Laji-HoneyPot.git
cd Laji-HoneyPot

# 后端
go build -o bin/honeypot ./cmd/honeypot/

# 前端（可选，不构建则使用 API 端口访问，提示构建）
cd web && npm install && npm run build && cd ..

# 启动
./bin/honeypot
```

### Docker 部署

```bash
cd deployments
docker compose up -d
```

### GitHub 代码同步

项目代码自动同步至 GitHub 仓库 `git@github.com:br0ny4/Laji-HoneyPot.git`：

```bash
# 查看远程仓库状态
git remote -v
git log --oneline -5

# 提交变更并推送（遵循 Conventional Commits 规范）
git add <files>
git commit -m "feat: description" -m "详细说明"
git push origin master
```

**提交规范**：采用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：
- `feat:` 新功能、`fix:` 修复、`docs:` 文档、`refactor:` 重构、`test:` 测试

**远程仓库**：https://github.com/br0ny4/Laji-HoneyPot

### 服务端口

| 端口 | 蜜罐服务 | 伪装指纹 |
|------|---------|---------|
| 8081 | HTTP | nginx/1.24.0 + PHP/8.1 |
| 3306 | MySQL | MySQL 8.0.35 |
| 6379 | Redis | Redis 6.2.13 |
| 2222 | SSH | OpenSSH 9.3 |
| 2121 | FTP | vsFTPd 3.0.3 |
| 3890 | LDAP | OpenLDAP 2.6 |
| 5354 | DNS | BIND 9.18 (UDP) |
| 4450 | SMB | Windows SMB 3.1.1 |
| 33890 | RDP | Windows RDP 10.0 |
| 8080 | API 管理端 | — |
| 8443 | Cluster | 集群 TLS 端口 (管理端↔节点) |

---

## 核心特性

### 高交互业务仿真
- 自研 TCP 协议栈 + 被动 TLS ClientHello 检测，绕过 Shodan/ZoomEye
- **9 大主流协议**：HTTP / MySQL / Redis / SSH / FTP / LDAP / DNS / SMB / RDP
- 高度贴合真实生产环境的交互逻辑

### 面包屑引流 — 访问即攻击者
页面嵌入天然不可见的"面包屑"路径（HTML 注释、robots.txt 隐藏路径），**正常用户无动机触碰，触碰即判定为攻击者**，零误报。

### 溯源反制引擎

| 触发条件 | 反制手段 | 采集信息 |
|---------|---------|---------|
| 面包屑路径访问 | JS 浏览器指纹采集（19维 + 截屏检测） | WebRTC 内网 IP、Canvas/WebGL 指纹、GPU 型号、屏幕分辨率、截屏/录屏行为 |
| Cobalt Strike Beacon | CVE-2022-39197 XSS 回击 | CS 团队服务器 IP + 证书信息 |
| 冰蝎 WebShell 连接 | Java JSP 反制 Payload | 主机名、OS、用户名、Java 版本 |
| Burp Collaborator 请求 | DNSLOG + WebRTC STUN 泄露 | 内网 IP、浏览器指纹 |
| curl/wget 扫描 | DNS 重绑定 Payload | 攻击者 DNS 解析链路 |
| Burp Suite / Chromium 旧版浏览器 | 深度反制植入体（三层能力） | 屏幕截获(≥1920×1080@1帧/5秒)、文件探测(25种工具)、网络拓扑(角色推断) |

**20+ 种反制 Payload 类型，11 级智能优先级：** 根据攻击者 User-Agent、访问路径、工具特征自动选择最优载荷，Burp Suite / Java 攻击者自动投递全量深度反制植入体。

### 深度反制系统 (v2.0)

对高价值攻击者（Burp Suite 用户、旧版浏览器等）自动投递全量三层反制植入体：

| 能力 | 技术实现 | 采集数据 |
|------|---------|---------|
| 屏幕截获 | Canvas DPR 自适应 + 多显示器检测 + GPU 渲染采集 | 分辨率≥1920×1080、1帧/5秒周期、手动即时触发 |
| 目录遍历与文件探测 | 25 种攻击工具目录特征检测 + 8 类敏感文件模式匹配 + 剪贴板嗅探 | 思维导图、攻击链路文档、工具配置文件、团队聊天记录 |
| 横向网络探测 | 多 STUN 全网卡 IP 枚举 + WebSocket/Fetch 内网点扫描 | 攻击者团队网络拓扑、主机角色推断（指挥节点/攻击节点/中继） |

**加密传输：** 全量数据通过 AES-256-GCM 加密，Web Crypto API 浏览器端 + Go 服务端双端加解密，分片回传支持大数据量场景。

**反制得分体系：**

| 能力 | 单次得分 | 冷却时间 |
|------|---------|---------|
| 屏幕截获 | 50 分 | 5 秒 |
| 敏感文件扫描 | 30 分 | 60 秒 |
| 横向网络探测 | 40 分 | 300 秒 |
| 浏览器指纹 | 15 分 | 10 秒 |
| 环境检测 | 20 分 | 30 秒 |

**合规保障：** 所有反制操作留痕可追溯，SHA256 防篡改签名，操作生命周期完整记录（initiate/complete/error/terminate），非合规能力告警但不执行。

**C2 API 端点：**

| 端点 | 功能 |
|------|------|
| `GET/POST /api/countermeasure/exfil` | 植入体加密数据回传（GET: Image Beacon 分片回传 + POST: JSON 结构化回传，自动数据类型识别并计分，含冷却防刷机制） |
| `GET /api/countermeasure/scoreboard` | 防守方得分总表（按类别+按目标统计） |
| `POST /api/countermeasure/score` | 手动注册得分事件 |
| `GET /api/countermeasure/audit?target=` | 合规审计记录查询 |
| `GET /api/countermeasure/topology` | 攻击者团队资产拓扑图 |

**管理端全链路 API（v0.12.0）：**

| 端点 | 功能 |
|------|------|
| **截屏链路** | |
| `GET /api/countermeasure/screencaps?ip=&limit=&offset=` | 截屏记录分页列表（含缩略图 base64） |
| `GET /api/countermeasure/screencaps/{id}` | 截屏详情（分辨率/格式/哈希/大小） |
| `GET /api/countermeasure/screencaps/{id}/download` | 截屏缩略图下载 |
| `GET /api/countermeasure/filescans?ip=&category=&limit=&offset=` | 文件扫描记录分页列表 |
| **远程权限接管** | |
| `WS /api/countermeasure/shell?target={ip}` | 远程 Shell WebSocket 交互（命令实时回显、30s超时、5min空闲回收） |
| `POST /api/countermeasure/transfer/upload` | 分块文件上传（X-Offset/X-Total-Size 断点续传） |
| `GET /api/countermeasure/transfer/download?target=&path=` | 文件下载（支持 Range 断点续传） |
| `GET /api/countermeasure/transfer/status?id=` | 传输状态查询 |
| `POST /api/countermeasure/transfer/pause` | 暂停传输 |
| `GET /api/countermeasure/transfer/list?target=` | 传输记录列表 |
| `GET /api/countermeasure/processes?target=&filter=` | 进程列表（ps/tasklist 跨平台） |
| `POST /api/countermeasure/processes/start` | 启动进程（nohup 后台启动） |
| `POST /api/countermeasure/processes/stop` | 停止进程（kill/taskkill） |
| `POST /api/countermeasure/processes/delete` | 删除进程二进制文件 |
| `WS /api/countermeasure/desktop?target=&quality=&fps=` | 桌面远控 Viewer WebSocket（帧流推送） |
| `WS /api/countermeasure/desktop/agent?target=` | 桌面远控 Agent WebSocket（帧源接入） |
| **安全合规** | |
| `POST /api/mfa/challenge` | MFA 二次认证挑战码（TOTP RFC 6238） |
| `POST /api/mfa/verify` | 验证 MFA 码并签发 5 分钟操作令牌 |
| `GET /api/audit/chain?limit=` | 不可篡改审计链列表（SHA256 链式哈希） |
| `GET /api/audit/chain/verify` | 审计链完整性独立校验 |

### 模块化插件架构
- **微内核**：注册中心 + 事件总线 + 配置中心 + 结构化日志（zap）
- **插件化**：蜜罐引擎 / 溯源引擎 / 运维引擎，独立启停
- 嵌入式事件总线（零外部依赖），引擎间异步通信

### 安全加固
- 容器安全配置校验（Seccomp Profile + CapDrop + 只读根文件系统）
- 禁止特权模式、非 root 运行
- 全流程排查容器逃逸、权限越权

---

## 管理后台

React 18 + TypeScript 可视化后台，支持实时监控、攻击事件、反制日志、拓扑图。

### 启动方式

**生产模式（推荐）**：Go 后端直接托管前端

```bash
cd web && npm install && npm run build && cd ..
go run ./cmd/honeypot
# 浏览器打开 http://127.0.0.1:8080
```

**开发模式**：前后端分离，Vite HMR 热更新

```bash
# 终端 1
go run ./cmd/honeypot

# 终端 2
cd web && npm run dev
# 浏览器打开 http://127.0.0.1:3000
```

> **安全提示**：Vite 开发服务器仅绑定 `127.0.0.1`，禁止暴露到公网，防止被扫描流量压垮。

### API 认证

管理后台 API 通过 `X-API-Key` Header 认证，默认密钥 `hp-admin-2024`。修改 `config.yaml`：

```yaml
api_key: "your-custom-key"
```

以下端点无需认证（面向攻击者浏览器自动触发）：`/healthz`、`/api/collect`、`/api/events`、`/api/countermeasure/exfil`

---

## 陷阱模块选配

蜜罐 Agent 支持陷阱功能的模块化选配，用户可根据部署场景自主选择开启对应陷阱，无需默认启用全部诱捕陷阱。

### 部署场景

| 场景 | 启用服务 | 适用环境 |
|------|---------|---------|
| `web` | HTTP | Web 业务场景 — 面包屑引流 + 浏览器指纹 + 反制载荷 |
| `database` | MySQL, Redis | 数据库场景 — 捕获 SQL 注入/未授权访问 |
| `remote_access` | SSH, RDP, FTP | 主机远程访问场景 — 捕获暴力破解/横向移动 |
| `infrastructure` | DNS, LDAP, SMB | 基础设施场景 — 捕获扫描探测 |
| `full` | 全部 9 种 | 全量部署（默认模式，向后兼容） |
| `custom` | 手动选择 | 自定义选配 — 配合 `custom_services` 精准控制 |

### 配置方式

陷阱选配在" **Agent部署** "面板中完成，选配结果将被写入 Agent 的 `config.yaml`：

- 在管理面板中选择陷阱场景（Web/数据库/主机/基础设施/全量/自定义）
- 9 服务实时预览网格显示各服务的启用状态
- 点击"生成 Agent 部署命令"后，`trap_scenario` 将嵌入生成的配置

也可直接编辑 `config.yaml` 中的 `honeypot-engine` 段：

```yaml
honeypot-engine:
  enabled: true
  trap_scenario: "web"    # 改为 web / database / remote_access / infrastructure / full / custom
  # 自定义选配 (仅 trap_scenario=custom 时生效)
  # custom_services:
  #   - http
  #   - mysql
  #   - ssh
```

### 验证

```bash
# 启动后查看启用的服务列表
curl -H "X-API-Key: hp-admin-2024" http://127.0.0.1:8080/api/traps/config
# {"current_scenario":"web","enabled_services":["http"],"all_services":[...]}
```

**设计原则**：未选配的陷阱不会监听端口，不产生无效资源占用。HTTP 蜜罐未启用时，面包屑路径和反制载荷均不会生效。

---

## Agent 部署

在 Management Node 平台上一键生成 Agent 配置与部署命令，**陷阱场景选配集成在部署流程中**：

### 部署方式

**方式一：前端手动部署**

1. 打开管理面板 → "Agent部署" Tab
2. 填写 / 自动检测管理端地址
3. 选择陷阱场景（Web/数据库/主机/基础设施）— 9 服务网格实时预览
4. 选择二进制获取方式（Release 预编译 / 源码编译 / 自定义 URL）
5. 点击"生成 Agent 部署命令"
6. 在 CLI / 部署脚本 / config.yaml 三 Tab 中复制对应命令
7. 在目标主机上执行命令完成部署

**方式二：命令行直接部署**

生成的 CLI 命令示例（Web 场景）：

```bash
curl -sSL https://github.com/br0ny4/Laji-HoneyPot/releases/latest/download/honeypot-linux-amd64 \
  -o honeypot && chmod +x honeypot && mkdir -p data && cat > config.yaml <<'HPEOF'
# --- 自动生成的 Agent 配置（含 manager_addr 和 trap_scenario）---
HPEOF
./honeypot
```

### 注册校验

Agent 部署后将在管理端"集群管理"面板自动上线，心跳周期 30 秒。可通过以下方式验证：

```bash
# 查看集群节点列表
curl -H "X-API-Key: hp-admin-2024" http://127.0.0.1:8443/api/cluster/nodes
# 检查 Agent 日志
tail -f data/honeypot.log | grep "registered"
```

### 功能模块

| 标签页 | 功能 | 数据来源 |
|--------|------|---------|
| 仪表盘 | 实时统计 + 服务分布 + 工具分布 + 最近连接 | `/api/stats/detailed` + SSE 推送 |
| 拓扑图 | G6 力导向图（攻击路径=红色 / 反制路径=蓝色） | `/api/topology` |
| 攻击事件 | 面包屑触发记录列表 | `/api/attacks` |
| 指纹采集 | 浏览器指纹详情（Canvas/GPU/屏幕/时区） | `/api/fingerprints` |
| 反制日志 | 反制部署记录 + 效果追踪 + 载荷详情 | `/api/countermeasures` |
| 资产台账 | 攻击者 IP 汇总 + 端口扫描 + 服务清单（风险评级/Banner识别） | `/api/attackers` + `/api/assets/scan` |
| 集群管理 | 分布式节点监控 + 在线状态 + Agent 部署指引 | `/api/cluster/nodes` |
| **Agent 部署** | **一键生成 Agent 配置与部署命令 — 含陷阱场景选配预览** | `/api/cluster/agent/generate` |
| 运维管理 | 系统状态 + 部署指南 + 性能指标 | `/api/system` + `/api/metrics` |
| 攻击者画像 | 多维度画像 + 威胁标签 + TTPs图谱 + 智能筛选 | `/api/profiles` + `/api/profiles/stats` |

### 前端 API 认证修复

生产模式下 Go 后端直接托管前端 SPA 时，`apiKeyMiddleware` 已豁免所有非 `/api/` 开头的路径（如 `/`、`/assets/`），确保浏览器首次加载 HTML/JS/CSS 时不会被 401 拦截。仅对 `/api/` 开头的管理 API 要求 `X-API-Key` 认证。

### 运行时监控

```bash
curl -H "X-API-Key: hp-admin-2024" http://127.0.0.1:8080/api/metrics
# {"uptime_seconds":3600,"goroutines":42,"memory":{"alloc_mb":12.5,...},"go_version":"go1.23.0","num_cpu":8}
```

### 页面底部状态栏

前端内置调试状态栏，实时显示：
- API 连接指示灯（绿/红）
- SSE 实时推送指示灯（绿/红）
- 可展开的最近 50 条请求日志（含 URL、状态码、耗时）
- 最近错误高亮 + 排查提示

---

## 测试验证

### 快速验证蜜罐是否正常工作

```bash
# 1. 验证 HTTP 蜜罐 + 指纹伪装
curl -sI http://127.0.0.1:8081/ | grep Server
# 预期: Server: nginx/1.24.0

# 2. 验证面包屑 + 反制触发
curl -v http://127.0.0.1:8081/admin/config.php
# 检查前端 → 攻击事件页面应有记录

# 3. 验证指纹采集
curl 'http://127.0.0.1:8081/api/collect?d=%7B%22canvas%22%3A%22test%22%7D'
# 预期: HTTP 200, Content-Type: image/gif
# 检查前端 → 仪表盘"指纹采集"数应增加

# 4. 验证协议蜜罐
echo -e "USER admin\nPASS test" | nc 127.0.0.1 2121   # FTP
echo "PING" | nc 127.0.0.1 6379                        # Redis
echo -e "\x16\x03\x01" | nc 127.0.0.1 2222 | xxd       # SSH (TLS handshake)
dig @127.0.0.1 -p 5354 example.com                      # DNS

# 5. 查看 API 统计数据
curl -H "X-API-Key: hp-admin-2024" http://127.0.0.1:8080/api/stats/detailed
```

### 浏览器验证

用浏览器访问 `http://127.0.0.1:8081/`，打开 F12 → Network 标签：

1. 过滤 `collect` → 应看到 `/api/collect?d=...` 请求返回 200
2. 过滤 `events` → 应看到 SSE 流持续连接
3. 前端页面底部状态栏 → API/SSE 指示灯应为绿色

---

## 漏洞库

### 反制漏洞（攻击者工具/浏览器中的真实缺陷）

| ID | 目标 | 严重度 | 利用方式 | 测试环境 |
|----|------|--------|---------|---------|
| CVE-2022-39197 | Cobalt Strike ≤ 4.7.1 | critical | 特制 HTML 触发 XSS，回传团队服务器 IP | CS Team Server 4.7.1 + 客户端访问蜜罐 |
| BD-2023-001 | 冰蝎 3.x/4.x | high | 识别 AES 流量特征，返回 Java 反序列化 Payload | 冰蝎客户端 + Tomcat JSP Shell |
| BS-2024-001 | Burp Suite Pro | medium | Collaborator 回调 + WebRTC STUN 收集内网 IP | Burp Pro 开启 Collaborator |
| CVE-2024-0519 | Chrome ≤ 119 | critical | V8 引擎越界访问 PoC | Chrome ≤ 119 |
| CH-2024-001 | Chrome/Firefox | medium | WebRTC STUN 绕过 NAT 泄露内网 IP | 任意 Chrome/Firefox 访问蜜罐 |

### 反制 Payload 类型

| Payload | 适用目标 | 采集信息 |
|---------|---------|---------|
| `js_browser` | 所有浏览器 | 19维指纹(Canvas/WebGL深度/OfflineAudioContext/字体/WebRTC) |
| `ios_fingerprint` | Safari/iOS | 平台/Battery/DeviceOrientation/ApplePay/Safari独立模式/Canvas/Connection |
| `android_fingerprint` | Chrome/Android | Battery/WebGL GPU/AudioContext/Connection/Canvas/字体 |
| `chrome_exploit` | Chrome ≤ 119 | 设备硬件信息 + 社工诱饵下载 |
| `firefox_exploit` | Firefox ≤ 121 | buildID + oscpu 信息 |
| `cs_xss` | Cobalt Strike | 团队服务器 IP + 证书 |
| `behinder_jsp` | 冰蝎 | 主机名 + OS + 用户名 + Java 版本 |
| `dns_rebinding` | curl/wget/Python | DNS 解析链路追踪 |

### 攻击者画像与威胁标签

基于多维度数据聚合的攻击者智能画像系统，自动匹配威胁标签并量化威胁等级。

| 维度 | 内容 |
|------|------|
| **基础属性** | IP / 地理位置 / 常用端口 / 工具偏好 / 活跃时段 / 攻击频次 |
| **攻击技术** | TTPs 签名(MITRE ATT&CK) / 战术覆盖 / 攻击成功率 / 交互深度 |
| **主观特征** | 技术水平(新手~高级) / 行为性格(谨慎/激进) / 攻击目的(数据窃取/WebShell/侦查等) |

**威胁标签引擎**：
- 8因子加权技能评分（多服务扫描、端口扫描、多路径探测、活跃天数、高频攻击、交互深度、多工具、TTP广度）
- 行为特征双语评分（谨慎5因子 vs 激进4因子）
- 路径语义分析判定攻击动机（数据窃取/权限提升/API探测/WebShell/凭据爆破/侦查）
- User-Agent 工具指纹检测（Nuclei/SQLMap/Burp Suite/Chrome/Firefox/脚本）


---

## 项目架构

```
Laji-HoneyPot/
├── cmd/honeypot/              # 主入口
├── internal/
│   ├── core/                  # 微内核（注册中心、事件总线、配置、日志、存储、API）
│   ├── honeypot/              # 蜜罐引擎
│   │   ├── tcpstack/          # 自研 TCP 协议栈
│   │   ├── services/          # 9 大协议仿真 (HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP)
│   │   ├── traps/             # 陷阱模块注册中心 (场景化选配)
│   │   └── manager/           # 容器安全管理
│   ├── traceability/          # 溯源反制引擎
│   │   ├── vulndb/            # 漏洞数据库 & NVD 爬虫
│   │   ├── fingerprint/       # 攻击者指纹采集
│   │   └── payload/           # Payload 生成与投递
│   ├── asset/                 # 资产探测模块 (端口扫描/服务识别/Banner抓取)
│   ├── cluster/               # 分布式集群 (管理端/节点代理/TLS通信/Agent生成器)
│   ├── alerter/               # 多通道告警 (Webhook/钉钉/飞书)
│   └── ops/                   # 运维引擎 (GitHub同步/竞品调研)
├── web/                       # React 18 管理面板
├── deployments/               # Docker Compose 部署
├── install.sh                 # 一键部署脚本
└── config.yaml                # 配置文件
```

| 层面 | 选型 |
|------|------|
| 语言 | Go 1.22+ |
| 存储 | SQLite (WAL) |
| 事件总线 | 自研（零外部依赖） |
| 日志 | zap（结构化） |
| 配置 | YAML + 环境变量覆盖 |
| 前端 | React 18 + TypeScript + Vite 5 |
| 容器 | Docker + Docker Compose |
| CI/CD | GitHub Actions |

---

## 本地开发环境

### 前置依赖

| 工具 | 版本 | 用途 |
|------|------|------|
| Go | 1.22+ | 后端编译与运行 |
| Node.js | 18+ | 前端构建 (`npm run build`) |
| npm | 9+ | 前端依赖管理 |
| Git | 任意 | 版本控制 |
| Chrome | 120+ | 浏览器调试（DevTools） |

### 开发模式启动

```bash
# 1. 克隆仓库
git clone https://github.com/br0ny4/Laji-HoneyPot.git
cd Laji-HoneyPot

# 2. 启动后端（带热重载：修改代码后 go install + 重启）
cd cmd/honeypot && go install && cd ../..
# 或使用 air 热重载工具：
# go install github.com/air-verse/air@latest && air

# 3. 终端 2 — 启动前端 Vite 开发服务器
cd web
npm install
npm run dev
# → http://127.0.0.1:3000 （HMR 热更新）

# 4. 浏览器打开 http://127.0.0.1:3000
```

### 开发模式架构

```
浏览器 (localhost:3000)
  ├── /api/*      → Vite Proxy → Go Backend (localhost:8080)
  ├── /healthz    → Vite Proxy → Go Backend (localhost:8080)
  └── /*          → Vite HMR 前端资源
```

> **注意**：开发模式使用 Vite 代理转发 API 请求，无需在浏览器中携带 `X-API-Key`（前端 `apiFetch` 自动附加）。生产模式使用 Go 后端直接托管前端静态文件，`apiKeyMiddleware` 已豁免非 `/api/` 路径。

### 目录结构

```
project-root/
├── cmd/honeypot/main.go     # 后端入口
├── internal/                # Go 业务逻辑
│   ├── core/                # 微内核
│   ├── honeypot/            # 蜜罐引擎 + 陷阱注册中心
│   ├── traceability/        # 溯源引擎
│   ├── cluster/             # 集群 + Agent 生成器
│   └── ...
├── web/                     # React 前端
│   ├── src/
│   │   ├── components/      # UI 组件
│   │   │   ├── AgentDeployPanel.tsx  # Agent 部署面板（含陷阱选配预览）
│   │   │   └── ...
│   │   ├── api.ts           # API 封装
│   │   ├── App.tsx          # 主路由
│   │   └── App.css          # 全局样式
│   ├── vite.config.ts       # Vite 配置（含代理）
│   └── package.json
├── config.yaml              # 主配置文件
└── data/                    # SQLite 数据库 + 日志
```

### 常用开发命令

```bash
# 后端
go build ./...                    # 编译检查
go test ./... -count=1            # 全量测试
go test ./internal/cluster/... -v # 集群模块测试
go vet ./...                      # 静态分析

# 前端
cd web && npm run dev             # Vite 开发服务器
cd web && npm run build           # 生产构建
cd web && npm run lint            # ESLint 检查
```

---

## Chrome 浏览器调试

本节介绍如何在本地开发环境中借助 Chrome DevTools 进行前端 UI 开发与调试。

### Chrome DevTools 调试流程

1. **启动开发环境**
   ```bash
   # 终端 1: 后端
   go run ./cmd/honeypot
   # 终端 2: 前端 (Vite HMR)
   cd web && npm run dev
   ```

2. **打开 Chrome 并导航到开发页面**
   - 打开 Chrome 浏览器
   - 访问 `http://127.0.0.1:3000`
   - 按 `F12` 或 `Cmd+Option+I` 打开 DevTools

3. **实时预览与调试**
   - **Elements 面板**：检查 DOM 结构和 CSS 样式
   - **Console 面板**：查看日志输出、API 请求结果
   - **Network 面板**：监控 API 请求/响应（过滤 `/api/`）
   - **Application 面板**：检查 localState、IndexedDB
   - **Performance 面板**：录制页面加载性能

4. **前端热重载验证**
   - 修改 `web/src/` 下的任意 `tsx` 或 `css` 文件
   - 保存后浏览器自动刷新（HMR 热更新）
   - DevTools 中的修改可立即预览

5. **验证 API 连通性**
   - 打开前端页面底部的状态栏
   - 检查 "API" 指示灯为绿色 → 后端连通
   - 检查 "SSE" 指示灯为绿色 → 实时推送连通
   - 点击状态栏展开查看最近 50 条请求日志

### 常见调试场景

| 场景 | DevTools 操作 |
|------|-------------|
| 新 Tab 功能正常 | Console 中无报错，Network 中对应 API 返回 200 |
| 样式异常 | Elements → 选中元素 → Styles 面板排查 CSS |
| API 请求慢 | Network → 查看请求耗时 → 后端优化 |
| 数据不刷新 | 检查 SSE 连接状态 → Console 中查看 EventSource 日志 |
| 前端构建失败 | Terminal 中 `cd web && npm run build` 查看错误详情 |

---

## 开发路线图

- [x] 微内核架构 + 事件总线 + 配置中心
- [x] HTTP / MySQL / Redis / SSH 四大蜜罐服务
- [x] 被动 TLS ClientHello 检测
- [x] 面包屑引流机制（50 个隐藏路径）
- [x] 漏洞数据库 + 攻击者指纹采集
- [x] 反制 Payload 生成器（CS / 冰蝎 / Chrome / Firefox）
- [x] React 管理面板 + SSE 实时推送
- [x] FTP + DNS + LDAP 协议仿真
- [x] SMB + RDP 协议仿真（v0.4）
- [x] 浏览器被动指纹（Canvas/WebGL/WebRTC）（v0.4）
- [x] 面包屑→反制注入全链路闭环（v0.4）
- [x] 可视化拓扑图（G6 攻击/反制路径）（v0.5）
- [x] Heapdump 蜜标反制链（v0.5）
- [x] DNS 重绑定 + WebRTC 内网扫描（v0.6）
- [x] 反制日志面板 + 效果追踪（v0.6）
- [x] 竞品自动研究 + TLS 被动检测（v0.7）
- [x] 多告警通道（Webhook/钉钉/飞书）（v0.8）
- [x] 全端口扫描感知（v0.8）
- [x] 自定义 HTTP 蜜罐模板 YAML 扩展（v0.9）
- [x] 前后端日志系统 + 调试状态栏（v0.9.1）
- [x] 浏览器被动指纹增强至19维（Canvas/WebGL深度/OfflineAudioContext/字体/WebRTC多STUN）
- [x] 攻击者画像与威胁标签系统（v0.9.5）
- [x] 多维度分析引擎（基础属性/攻击技术/主观特征）
- [x] 8因子技能评分 + 行为双语评分 + 动机路径分析
- [x] 画像可视化面板（标签筛选/TTPs图谱/详情Modal/威胁等级大盘）
- [x] 反制能力增强 -- 截屏/录屏检测 + 敏感文件读取Exp防御（v0.9.6）
- [x] 面包屑路径30->50条（新增敏感文件/加密分区/路径穿越/云凭证）
- [x] 风险等级系统（攻击事件+反制事件四级判定）
- [x] VulnDB 45条（NVD 爬虫增强 + Chrome/Firefox/Chromium 浏览器 CVE 持续追踪）
- [x] 智能载荷选择扩展到 iOS/Android 指纹（v0.9.7）
- [x] 资产探测模块 — TCP端口扫描 + 服务识别 + Banner抓取（v0.9.7）
- [x] 分布式集群架构 — 管理端 + 远程蜜罐节点（v0.10.0）
- [x] 陷阱模块化选配 — 场景化陷阱选配系统（v0.10.1）
  - 6 种部署场景：web / database / remote_access / infrastructure / full / custom
  - TrapRegistry 注册中心 + 前端选配面板 + API 配置端点
  - 未选配陷阱不监听端口，零资源浪费
- [x] Agent 生成引擎 — 一键部署与模块选配（v0.10.2）
  - Management Node 平台生成 Agent 配置与部署命令
  - 3 种部署方式：Release 预编译 / 源码编译 / 自定义 URL
  - CLI 命令 / Bash 脚本 / Docker 命令三模式输出
  - Agent 部署面板：场景选配 + 配置预览 + 一键复制
- [x] 前端 API 认证修复 — 生产模式 SPA 路由豁免（v0.10.2）
- [x] 开发体验优化 — Vite /healthz 代理 + Chrome DevTools 调试指南（v0.10.2）
- [x] 深度反制系统 v2.0 — 屏幕截获/文件扫描/网络探测三层植入体（v0.11.0）
- [x] 反制得分体系 + 冷却防刷 + SHA256 合规审计（v0.11.0）
- [x] C2 数据外传 API — Image Beacon 分片重组 + JSON 双模式（v0.11.0）
- [x] 本地部署模拟攻击测试 — 3 Bug修复 + 冷却机制校准（v0.11.1）

---

## 同类对比

| 维度 | Laji-HoneyPot | [HFish](https://github.com/hacklcx/HFish) |
|------|:---:|:---:|
| 蜜罐服务数 | 9 协议 | **90+ 服务** |
| 架构 | 单体多服务 | **集群(管理端+节点)** |
| **溯源反制** | **11 种载荷 + 智能选择 + 效果闭环** | 基础内置溯源 |
| **反制深度** | **DNS 重绑定 / WebRTC 扫描 / VPN 诱饵 / Heapdump** | 未涉及 |
| **拓扑可视化** | **G6 双向攻击/反制路径图** | 基础展示 |
| **面包屑机制** | **50 个隐藏路径 + 自动注入** | 蜜饵配置 |
| 全端口扫描 | **连接频率检测(5端口/60s)** | TCP/UDP/ICMP 感知 |
| 告警通道 | **Webhook/钉钉/飞书** | 邮件/Syslog/钉钉/飞书/企微 |
| 跨平台 | Linux/macOS | **Linux/Win/ARM/国产OS+CPU** |
| 部署方式 | **一键脚本 + Docker** | 一键脚本 + 集群部署 |
| 代码质量 | **微内核 + 事件总线 + 全量测试** | 传统结构 |

> **核心结论**：Laji-HoneyPot 在**溯源反制深度**和**工程化质量**上领先；HFish 在**蜜罐数量、分布式架构、企业就绪度**上更强。两者互补。

---

## 致谢

感谢以下贡献者和支持者的帮助与反馈，使这个项目得以不断完善。

<p align="center">
  <a href="https://github.com/br0ny4" title="br0ny4 — 项目作者 & 核心开发者">
    <img src="https://github.com/br0ny4.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="br0ny4" />
  </a>
  <a href="https://github.com/Trae-AI" title="Trae AI — AI 辅助开发">
    <img src="https://github.com/Trae-AI.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="Trae AI" />
  </a>
  <a href="https://github.com/hacklcx" title="hacklcx — HFish 项目作者，竞品参考与启发">
    <img src="https://github.com/hacklcx.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="hacklcx" />
  </a>
  <a href="https://github.com/storyxie" title="storyxie — 贡献者">
    <img src="https://github.com/storyxie.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="storyxie" />
  </a>
  <a href="https://github.com/lenawook313-sketch" title="lenawook313-sketch — 贡献者">
    <img src="https://github.com/lenawook313-sketch.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="lenawook313-sketch" />
  </a>
  <a href="https://github.com/laohuan12138" title="laohuan12138 — 贡献者">
    <img src="https://github.com/laohuan12138.png" width="64" height="64" style="border-radius:50%;margin:4px" alt="laohuan12138" />
  </a>
</p>

<p align="center">
  <sub>所有头像由 GitHub 自动提供，点击头像可跳转至对应主页。</sub>
</p>

> 想加入致谢名单？提交 PR 改进文档、修复 Bug 或提出有价值的 Issue 即可。

---

## 免责声明

本项目仅用于**合法的网络安全防护、授权红蓝对抗演练及安全研究**。使用者须遵守所在国家/地区的法律法规，自行承担因使用本项目而产生的一切法律责任。

---

<p align="center">
  <b>Laji-HoneyPot</b> — 从诱捕到反制，让攻击者无处遁形。
</p>
