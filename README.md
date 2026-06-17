# Laji-HoneyPot

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
- **反制能力**：截取屏幕截图（后续）、读取文件信息、设备指纹、社交账号关联

| 触发条件 | 反制手段 | 采集信息 |
|---------|---------|---------|
| 面包屑路径访问 | JS 浏览器指纹采集 | WebRTC 内网 IP、Canvas/WebGL 指纹 |
| Cobalt Strike Beacon | CVE-2022-39197 XSS 回击 | CS 团队服务器信息 |
| 冰蝎 WebShell 连接 | Java JSP 反制 Payload | 主机名、OS、用户名、Java 版本 |
| Burp Collaborator 请求 | DNSLOG + WebRTC 泄露 | 内网 IP、浏览器指纹 |

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
| 8080 | API（预留） | — |

---

## 项目架构

```
Laji-HoneyPot/
├── cmd/honeypot/              # 主入口
├── internal/
│   ├── core/                  # 微内核（注册中心、事件总线、配置、日志）
│   ├── plugin/                # 插件接口契约
│   ├── honeypot/              # 蜜罐引擎
│   │   ├── tcpstack/          # 自研 TCP 协议栈
│   │   ├── tls/               # TLS 指纹伪装
│   │   ├── services/          # 服务仿真（HTTP/MySQL/Redis/SSH）
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
- [x] CI/CD & Docker 部署
- [x] React 管理面板
- [ ] HTTP API 服务器
- [ ] 数据库持久化（SQLite/PostgreSQL）
- [ ] WebSocket 实时告警
- [ ] 更多协议仿真（FTP/SMB/LDAP/RDP/DNS）
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
