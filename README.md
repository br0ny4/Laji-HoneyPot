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
- [测试验证](#测试验证)
- [漏洞库](#漏洞库)
- [项目架构](#项目架构)
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
| 面包屑路径访问 | JS 浏览器指纹采集 | WebRTC 内网 IP、Canvas/WebGL 指纹、GPU 型号、屏幕分辨率 |
| Cobalt Strike Beacon | CVE-2022-39197 XSS 回击 | CS 团队服务器 IP + 证书信息 |
| 冰蝎 WebShell 连接 | Java JSP 反制 Payload | 主机名、OS、用户名、Java 版本 |
| Burp Collaborator 请求 | DNSLOG + WebRTC STUN 泄露 | 内网 IP、浏览器指纹 |
| curl/wget 扫描 | DNS 重绑定 Payload | 攻击者 DNS 解析链路 |

**11 种反制 Payload 类型，10 级智能优先级：** 根据攻击者 User-Agent、访问路径、工具特征自动选择最优载荷。

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

以下端点无需认证（面向攻击者指纹回传）：`/healthz`、`/api/collect`、`/api/events`

### 功能模块

| 标签页 | 功能 | 数据来源 |
|--------|------|---------|
| 仪表盘 | 实时统计 + 服务分布 + 工具分布 + 最近连接 | `/api/stats/detailed` + SSE 推送 |
| 拓扑图 | G6 力导向图（攻击路径=红色 / 反制路径=蓝色） | `/api/topology` |
| 攻击事件 | 面包屑触发记录列表 | `/api/attacks` |
| 指纹采集 | 浏览器指纹详情（Canvas/GPU/屏幕/时区） | `/api/fingerprints` |
| 反制日志 | 反制部署记录 + 效果追踪 + 载荷详情 | `/api/countermeasures` |
| 资产台账 | 攻击者 IP 维度汇总（风险评级） | `/api/attackers` |
| 端口扫描 | 端口扫描感知记录 | `/api/portscans` |
| 运维管理 | 系统状态 + 部署指南 + 性能指标 | `/api/system` + `/api/metrics` |
| **攻击者画像** | **多维度画像 + 威胁标签 + TTPs图谱 + 智能筛选** | `/api/profiles` + `/api/profiles/stats` |

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
│   │   └── manager/           # 容器安全管理
│   ├── traceability/          # 溯源反制引擎
│   │   ├── vulndb/            # 漏洞数据库 & NVD 爬虫
│   │   ├── fingerprint/       # 攻击者指纹采集
│   │   └── payload/           # Payload 生成与投递
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

## 开发路线图

- [x] 微内核架构 + 事件总线 + 配置中心
- [x] HTTP / MySQL / Redis / SSH 四大蜜罐服务
- [x] 被动 TLS ClientHello 检测
- [x] 面包屑引流机制（20 个隐藏路径）
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
- [ ] 分布式集群架构（管理端 + 远程蜜罐节点）
- [ ] 反制能力增强（截屏、文件读取 PoC）
- [ ] 智能载荷选择扩展到 iOS/Android 指纹

---

## 同类对比

| 维度 | Laji-HoneyPot | [HFish](https://github.com/hacklcx/HFish) |
|------|:---:|:---:|
| 蜜罐服务数 | 9 协议 | **90+ 服务** |
| 架构 | 单体多服务 | **集群(管理端+节点)** |
| **溯源反制** | **11 种载荷 + 智能选择 + 效果闭环** | 基础内置溯源 |
| **反制深度** | **DNS 重绑定 / WebRTC 扫描 / VPN 诱饵 / Heapdump** | 未涉及 |
| **拓扑可视化** | **G6 双向攻击/反制路径图** | 基础展示 |
| **面包屑机制** | **20 个隐藏路径 + 自动注入** | 蜜饵配置 |
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
