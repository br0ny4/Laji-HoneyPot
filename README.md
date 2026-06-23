# Laji-HoneyPot（辣鸡蜜罐）

> 面向网络安全攻防场景中防守方**溯源反制**环节的高性能蜜罐系统。

Laji-HoneyPot 是一款开源的高交互蜜罐系统，核心差异化在于：**不仅仿真诱捕，更能对攻击者使用的红队工具及浏览器实施精准溯源与反制**。

---

## 核心特性

### 高交互业务仿真
- 自研 TCP 协议栈 + TLS 指纹伪装（绕过 Shodan/ZoomEye 识别）
- 首批覆盖 **HTTP、MySQL、Redis、SSH、FTP、LDAP、DNS、SMB、RDP** 九大主流服务协议仿真
- 高度贴合真实生产环境的交互逻辑

### 面包屑引流 — 访问即攻击者
- 页面中嵌入天然不可见的"面包屑"路径（HTML注释、robots.txt 隐藏路径等）
- 正常用户无动机访问这些路径，**默认所有访问者都是攻击者**
- 零误报：触碰面包屑即触发溯源反制流程

### 溯源反制引擎
- **红队工具反制**：Burp Suite / Cobalt Strike / 冰蝎 / SQLMap 等主流工具漏洞利用
- **浏览器反制**：Chrome / Firefox 指纹采集 + WebRTC 内网 IP 泄露利用
- **反制能力**：截取屏幕截图（后续）、读取文件信息、设备指纹、社交账号关联

| 触发条件 | 反制手段 | 采集信息 |
|---------|---------|---------|
| 面包屑路径访问 | JS 浏览器指纹采集 | WebRTC 内网 IP、Canvas/WebGL 指纹 |
| Cobalt Strike Beacon | CVE-2022-39197 XSS 回击 | CS 团队服务器信息 |
| 冰蝎 WebShell 连接 | Java JSP 反制 Payload | 主机名、OS、用户名、Java 版本 |
| Burp Collaborator 请求 | DNSLOG + WebRTC 泄露 | 内网 IP、浏览器指纹 |

### 漏洞库详情 & 测试环境指南

系统预置漏洞分为两大类：

- **诱捕漏洞**：蜜罐对外模拟的虚假漏洞/敏感信息，用于吸引攻击者触碰面包屑
- **反制漏洞**：攻击者工具/浏览器中的真实安全缺陷，蜜罐利用其对攻击者实施溯源反制

---

#### 一、诱捕漏洞（蜜罐对外伪装的虚假弱点）

##### 面包屑路径清单

以下路径嵌入蜜罐 HTTP 响应的 HTML 注释和 robots.txt 中，正常用户不可见，**仅扫描器和攻击者会触碰**：

| 路径 | 模拟目标 | 伪装类型 | 攻击场景 |
|------|---------|---------|---------|
| `/admin/config.php` | PHP 管理后台 | 虚假敏感路径 | 扫描器目录爆破 |
| `/wp-admin/install.php` | WordPress | 虚假 CMS 入口 | CMS 漏洞扫描 |
| `/.git/config` | Git 仓库 | 虚假源码泄露 | 源码泄露探测 |
| `/api/v1/internal/users` | REST API | 虚假 API 接口 | API 未授权访问 |
| `/backup/database.sql` | 数据库备份 | 虚假备份文件 | 备份文件下载 |
| `/debug/pprof/` | Go 应用 | 虚假调试接口 | 调试接口暴露 |
| `/actuator/env` | Spring Boot | 虚假 Actuator | Java 框架信息泄露 |
| `/swagger-ui.html` | Swagger | 虚假 API 文档 | API 文档暴露 |
| `/druid/index.html` | Druid | 虚假监控面板 | 中间件监控面板 |
| `/phpmyadmin/index.php` | phpMyAdmin | 虚假数据库管理 | 数据库管理工具 |

##### 服务指纹伪装

蜜罐对外模拟的虚假服务版本信息，使目标看起来像真实生产环境：

| 服务 | 伪装指纹 | 真实版本特征 |
|------|---------|-------------|
| HTTP | nginx/1.24.0 + PHP/8.1 | Server 头、错误页格式 |
| MySQL | 8.0.35 | 握手包版本号、认证插件列表 |
| Redis | 6.2.13 | INFO 命令返回的版本字符串 |
| SSH | OpenSSH_9.3p1 Ubuntu | Banner 字符串 |
| TLS | nginx-1.24 / apache-2.4.37 / openssh-9.3 | JA3/JA4 指纹（CipherSuites + TLS 版本） |

> **验证方法**：用 `curl -v` 访问蜜罐 HTTP 端口或 `nmap -sV` 扫描蜜罐端口，观察返回的虚假服务指纹。

---

#### 二、反制漏洞（攻击者工具/浏览器中的真实缺陷）

##### 红队工具漏洞

| ID | 目标工具 | 严重度 | 影响版本 | 利用方式 | 测试环境要求 |
|----|---------|--------|---------|---------|-------------|
| CVE-2022-39197 | Cobalt Strike | critical | CS ≤ 4.7.1 | 蜜罐返回特制 HTML，CS 客户端渲染时触发 XSS，回传团队服务器 IP 及证书信息 | CS Team Server 4.7.1 + 客户端浏览器访问蜜罐 HTTP |
| BD-2023-001 | 冰蝎 Behinder | high | 3.x / 4.x | 识别冰蝎 AES 加密流量固定特征，返回构造的 Java 反序列化 Payload | 冰蝎客户端 + Java Tomcat JSP Shell 环境 |
| BS-2024-001 | Burp Suite Pro | medium | 2023.x / 2024.x | 利用 Collaborator DNS/HTTP 回调配合 WebRTC STUN 收集攻击者内网 IP | Burp Pro 开启 Collaborator，对蜜罐域名主动扫描 |
| CVE-2023-32784 | SQLMap | low | 全版本 | 识别 SQLMap User-Agent 和请求模式特征，返回虚假注入结果引导深入 | SQLMap 对蜜罐 HTTP 发起 SQL 注入扫描 |

##### 浏览器漏洞

| ID | 目标浏览器 | 严重度 | 影响版本 | 利用方式 | 测试环境要求 |
|----|----------|--------|---------|---------|-------------|
| CVE-2024-0519 | Chrome | critical | < 120.0.6099.129 | 蜜罐页面嵌入针对 V8 引擎的 PoC，触发越界内存访问实现 RCE | Windows/macOS + Chrome ≤ 119 |
| CH-2024-001 | Chrome / Firefox | medium | 全版本（WebRTC 原生行为） | WebRTC STUN 请求绕过 NAT 泄露攻击者真实内网 IP | 任意 Chrome/Firefox 访问蜜罐 HTTP |
| FF-2024-001 | Firefox | low | < 122 | 跨域 iframe 信息泄露，读取攻击者浏览器扩展安装列表 | Firefox ≤ 121 访问蜜罐 HTTP |

##### 反制 Payload 类型

| Payload | 适用目标 | 触发方式 | 反制效果 | 前置条件 |
|---------|---------|---------|---------|---------|
| `js_browser` | 所有浏览器 | 访问蜜罐 HTTP | Canvas/WebGL/WebRTC 内网 IP/插件列表回传 | 无需额外配置 |
| `chrome_exploit` | Chrome | 面包屑触发 | 设备硬件信息 + 触发下载（社工诱饵） | Chrome ≤ 119 |
| `firefox_exploit` | Firefox | 面包屑触发 | buildID + oscpu 信息回传 | Firefox ≤ 121 |
| `cs_xss` | Cobalt Strike | 访问蜜罐 HTTP | CS 客户端 XSS，回传团队服务器信息 | CS 4.7.1 |
| `behinder_jsp` | 冰蝎 | WebShell 连接 | 主机名 + OS + 用户名 + Java 版本回传 | Tomcat + JSP Shell |

---

#### 测试环境快速搭建

```bash
# 1. 启动蜜罐
./honeypot

# 2. 验证诱捕漏洞 — 模拟扫描器访问面包屑路径
curl -v http://127.0.0.1:8081/admin/config.php
curl -v http://127.0.0.1:8081/.git/config

# 3. 验证服务指纹伪装
curl -sI http://127.0.0.1:8081/ | grep Server
# 预期输出: Server: nginx/1.24.0

# 4. 验证 FTP/DNS/LDAP 协议仿真
echo -e "USER admin\nPASS test" | nc 127.0.0.1 2121
dig @127.0.0.1 -p 5354 example.com

# 5. 验证浏览器反制 — 被动指纹采集
# 用浏览器访问 http://127.0.0.1:8081/
# 打开开发者工具 Network 标签，观察 Canvas/WebGL/WebRTC 指纹采集回传

# 6. 查看 API 统计数据
curl http://127.0.0.1:8080/api/stats
curl http://127.0.0.1:8080/api/attacks
```

### 模块化插件架构
- **微内核**：注册中心 + 事件总线 + 配置中心 + 结构化日志
- **插件化引擎**：蜜罐引擎 / 溯源引擎 / 运维引擎，支持快速插拔迭代
- 嵌入式事件总线（零外部依赖），引擎间异步通信

### 安全加固
- 容器安全配置校验（Seccomp Profile + CapDrop + 只读根文件系统）
- 禁止特权模式、非 root 用户运行
- 全流程排查容器逃逸、权限越权隐患

---

## 快速开始

### 前置要求
- Go 1.22+
- Docker & Docker Compose（可选）

### 从源码编译

```bash
git clone https://github.com/YOUR_USERNAME/Laji-HoneyPot.git
cd Laji-HoneyPot

# 编译
go build -o honeypot ./cmd/honeypot/

# 直接运行
./honeypot
```

### Docker 部署

```bash
cd deployments
docker compose up -d
```

启动后，蜜罐服务将监听以下端口：

| 端口 | 服务 | 指纹 |
|------|------|------|
| 8081 | HTTP | nginx/1.24.0 |
| 3306 | MySQL | MySQL 8.0.35 |
| 6379 | Redis | Redis 6.2.13 |
| 2222 | SSH | OpenSSH 9.3 |
| 2121 | FTP | vsFTPd 3.0.3 |
| 3890 | LDAP | OpenLDAP 2.6 |
| 5354 | DNS | BIND 9.18 (UDP) |
| 4450 | SMB | Windows SMB 3.1.1 (Server 2019) |
| 33890 | RDP | Windows RDP 10.0 |
| 8080 | API | — |

---

## 项目架构

```
Laji-HoneyPot/
├── cmd/honeypot/              # 主入口
├── internal/
│   ├── core/                  # 微内核（注册中心、事件总线、配置、日志、存储、API）
│   ├── plugin/                # 插件接口契约
│   ├── honeypot/              # 蜜罐引擎
│   │   ├── tcpstack/          # 自研 TCP 协议栈
│   │   ├── tls/               # TLS 指纹伪装
│   │   ├── services/          # 服务仿真（HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP）
│   │   └── manager/           # 容器安全管理
│   ├── traceability/          # 溯源反制引擎
│   │   ├── vulndb/            # 漏洞数据库 & NVD 爬虫
│   │   ├── fingerprint/       # 攻击者指纹采集
│   │   └── payload/           # Payload 生成与投递
│   └── ops/                   # 运维引擎
│       ├── github/            # GitHub 同步
│       └── research/          # 竞品调研
├── web/                       # React 管理面板
├── deployments/               # Docker Compose 部署
└── .github/workflows/         # CI/CD
```

---

## 技术栈

| 层面 | 选型 |
|------|------|
| 主语言 | Go 1.22+ |
| 持久化 | SQLite (WAL 模式) |
| 事件总线 | 自研（零外部依赖） |
| 日志 | zap（结构化日志） |
| 配置 | YAML + 环境变量覆盖 |
| 前端 | React 18 + TypeScript + Vite |
| 容器化 | Docker + Docker Compose |
| CI/CD | GitHub Actions |

---

## 开发路线图

- [x] 微内核架构（注册中心、事件总线、配置、日志）
- [x] HTTP/MySQL/Redis/SSH 四大蜜罐服务
- [x] TLS 指纹伪装（nginx/apache/openssh）
- [x] 面包屑引流机制
- [x] 漏洞数据库（红队工具 + 浏览器漏洞）
- [x] 攻击者指纹采集（工具识别 + 浏览器识别）
- [x] 反制 Payload 生成器（CS / 冰蝎 / Chrome / Firefox）
- [x] HTTP API 服务器 + SQLite 持久化
- [x] 事件总线串联（蜜罐 → 溯源引擎）
- [x] React 管理面板（动态 API 数据）
- [x] CI/CD & Docker 部署
- [x] SSE 实时推送
- [x] FTP+DNS+LDAP 协议仿真
- [x] SMB/RDP 协议仿真（v0.4）
- [x] 浏览器被动指纹采集（Canvas/WebGL/WebRTC 自动注入）
- [x] 面包屑→反制 Payload 注入全链路（v0.4）
- [x] 追踪 Cookie (`_hp_track`) 持久化攻击者追踪
- [x] 指纹数据 `/api/collect` 端点 + SQLite 持久化（v0.4）
- [x] API 速率限制（令牌桶算法）
- [x] RESP 协议解析器重写
- [x] 全量服务单元测试覆盖（90+ 项测试，v0.4）
- [x] 前端面板动态化（9 服务实时数据，v0.4）
- [ ] 自动化威胁情报聚合
- [ ] 反制能力增强（截屏、文件读取 PoC）
- [ ] gVisor 容器运行时集成

---

## 免责声明

本项目仅用于**合法的网络安全防护、授权红蓝对抗演练及安全研究**。使用者须遵守所在国家/地区的法律法规，自行承担因使用本项目而产生的一切法律责任。

---

## License

[MIT](LICENSE)

---

<p align="center">
  <b>Laji-HoneyPot</b> — 从诱捕到反制，让攻击者无处遁形。
</p>
