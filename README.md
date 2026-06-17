# Laji-HoneyPot（辣鸡蜜罐）

<img src="https://coresg-normal.trae.ai/api/ide/v1/text_to_image?prompt=A%20dark%20themed%20cybersecurity%20logo%20for%20a%20honeypot%20project%20named%20Laji-HoneyPot%20featuring%20a%20honeycomb%20with%20a%20digital%20circuit%20pattern%20inside%20glowing%20blue%20and%20red%20accents&image_size=square_hd" alt="Laji-HoneyPot" width="200" />

> 面向网络安全攻防场景中防守方**溯源反制**环节的高性能蜜罐系统。

Laji-HoneyPot 是一款开源的高交互蜜罐系统，核心差异化在于：**不仅仿真诱捕，更能对攻击者使用的红队工具及浏览器实施精准溯源与反制**。

---

## 核心特性

### 高交互业务仿真
- 自研 TCP 协议栈 + TLS 指纹伪装（绕过 Shodan/ZoomEye 识别）
- 首批覆盖 **HTTP、MySQL、Redis、SSH** 四大主流服务协议仿真
- 高度贴合真实生产环境的交互逻辑

### 面包屑引流 — 访问即攻击者
- 页面中嵌入天然不可见的"面包屑"路径（HTML注释、robots.txt 隐藏路径等）
- 正常用户无动机访问这些路径，**默认所有访问者都是攻击者**
- 零误报：触碰面包屑即触发溯源反制流程

### 溯源反制引擎
- **红队工具反制**：Burp Suite / Cobalt Strike / 冰蝎 / SQLMap 等主流工具漏洞利用
- **浏览器反制**：Chrome / Firefox 指纹采集 + WebRTC 内网 IP 泄露利用

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

#### 一、诱捕漏洞（蜜罐对外伪装的虚假弱点）

**面包屑路径清单** — 嵌入 HTTP 响应的 HTML 注释和 robots.txt 中，**仅扫描器和攻击者会触碰**：

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

**服务指纹伪装** — 蜜罐对外模拟的虚假服务版本信息：

| 服务 | 伪装指纹 | 真实版本特征 |
|------|---------|-------------|
| HTTP | nginx/1.24.0 + PHP/8.1 | Server 头、错误页格式 |
| MySQL | 8.0.35 | 握手包版本号、认证插件列表 |
| Redis | 6.2.13 | INFO 命令返回的版本字符串 |
| SSH | OpenSSH_9.3p1 Ubuntu | Banner 字符串 |
| TLS | nginx-1.24/apache-2.4.37/openssh-9.3 | JA3/JA4 指纹 |

> 验证：`curl -sI http://127.0.0.1:8081/ | grep Server`，预期输出 nginx/1.24.0

#### 二、反制漏洞（攻击者工具/浏览器中的真实缺陷）

**红队工具漏洞**

| ID | 目标工具 | 严重度 | 影响版本 | 利用方式 | 测试环境 |
|----|---------|--------|---------|---------|---------|
| CVE-2022-39197 | Cobalt Strike | critical | CS <= 4.7.1 | 蜜罐返回特制 HTML，CS 客户端渲染时 XSS 回传服务器信息 | CS Team Server 4.7.1 + 客户端访问蜜罐 HTTP |
| BD-2023-001 | 冰蝎 Behinder | high | 3.x / 4.x | 识别 AES 流量特征后返回 Java 反序列化 Payload | 冰蝎 + Tomcat JSP Shell |
| BS-2024-001 | Burp Suite Pro | medium | 2023.x / 2024.x | Collaborator 回调 + WebRTC STUN 收集内网 IP | Burp Pro 开启 Collaborator |
| CVE-2023-32784 | SQLMap | low | 全版本 | 识别 User-Agent 和请求模式，返回虚假注入结果 | SQLMap 扫描蜜罐 HTTP |

**浏览器漏洞**

| ID | 目标浏览器 | 严重度 | 影响版本 | 利用方式 | 测试环境 |
|----|----------|--------|---------|---------|---------|
| CVE-2024-0519 | Chrome | critical | < 120.0.6099.129 | V8 引擎 PoC 触发越界内存访问 RCE | Windows/macOS + Chrome <= 119 |
| CH-2024-001 | Chrome / Firefox | medium | 全版本 | WebRTC STUN 泄露真实内网 IP | 任意浏览器访问蜜罐 |
| FF-2024-001 | Firefox | low | < 122 | 跨域 iframe 泄露浏览器扩展信息 | Firefox <= 121 |

**反制 Payload 类型**

| Payload | 适用目标 | 触发方式 | 反制效果 | 前置条件 |
|---------|---------|---------|---------|---------|
| `js_browser` | 所有浏览器 | 访问蜜罐 HTTP | Canvas/WebGL/WebRTC 内网 IP/插件列表回传 | 无需配置 |
| `chrome_exploit` | Chrome | 面包屑触发 | 硬件信息 + 自动下载诱饵 | Chrome <= 119 |
| `firefox_exploit` | Firefox | 面包屑触发 | buildID + oscpu 回传 | Firefox <= 121 |
| `cs_xss` | Cobalt Strike | 访问蜜罐 | CS 客户端 XSS 回传服务器信息 | CS 4.7.1 |
| `behinder_jsp` | 冰蝎 | WebShell 连接 | 主机名 + OS + 用户名 + Java 版本 | Tomcat + JSP |

#### 测试环境快速搭建

```
# 启动蜜罐
./honeypot

# 验证诱捕漏洞 — 模拟扫描器
curl -v http://127.0.0.1:8081/admin/config.php

# 验证服务指纹
curl -sI http://127.0.0.1:8081/ | grep Server

# 验证 API
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

---

## 快速开始

### 前置要求
- Go 1.22+
- Docker & Docker Compose（可选）

### 从源码编译

```bash
git clone https://github.com/br0ny4/Laji-HoneyPot.git
cd Laji-HoneyPot
go build -o honeypot ./cmd/honeypot/
./honeypot
```

### Docker 部署

```bash
cd deployments
docker compose up -d
```

| 端口 | 服务 | 指纹 |
|------|------|------|
| 8081 | HTTP | nginx/1.24.0 |
| 3306 | MySQL | MySQL 8.0.35 |
| 6379 | Redis | Redis 6.2.13 |
| 2222 | SSH | OpenSSH 9.3 |
| 8080 | API | - |

---

## 技术栈

| 层面 | 选型 |
|------|------|
| 主语言 | Go 1.22+ |
| 持久化 | SQLite (WAL 模式) |
| 前端 | React 18 + TypeScript + Vite |
| 容器化 | Docker + Docker Compose |
| CI/CD | GitHub Actions |

---

## 开发路线图

- [x] 微内核架构
- [x] HTTP/MySQL/Redis/SSH 四大蜜罐
- [x] TLS 指纹伪装
- [x] 面包屑引流
- [x] 漏洞数据库（7 条预置）
- [x] 指纹采集 + Payload 生成器
- [x] API 服务器 + SQLite 持久化
- [x] React 管理面板
- [x] CI/CD
- [ ] WebSocket 实时告警
- [ ] FTP/SMB/LDAP/RDP/DNS 协议仿真
- [ ] 反制能力增强（截屏、文件读取 PoC）

---

## 免责声明

本项目仅用于**合法的网络安全防护、授权红蓝对抗演练及安全研究**。

---

## License

[MIT](LICENSE)

---

<p align="center">
  <b>Laji-HoneyPot</b> — 从诱捕到反制，让攻击者无处遁形。
</p>
