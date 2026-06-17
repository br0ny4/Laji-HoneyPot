# Laji-HoneyPot 溯源型蜜罐系统 — 设计文档

> 版本: v0.1.0 | 日期: 2026-06-17 | 状态: 已审批

---

## 1. 项目定位

面向网络安全攻防场景中防守方溯源反制环节的高性能开源蜜罐系统。核心差异化在于：不仅仿真诱捕，更能对攻击者使用的红队工具实施精准溯源与反制。

## 2. 技术选型

| 层面 | 选型 | 理由 |
|------|------|------|
| 主语言 | Go 1.22+ | 高并发、静态编译、单二进制部署、成熟的网络安全生态 |
| 前端面板 | React 18 + TypeScript + Vite | 管理面板可视化 |
| 数据库 | SQLite (默认) / PostgreSQL (集群) | 轻量到生产无缝切换 |
| 容器运行时 | Docker SDK + gVisor | 成熟隔离；gVisor 提供内核级加固 |
| 事件总线 | 嵌入式 NATS | Pub/Sub 串联引擎，零外部依赖 |
| CI/CD | GitHub Actions | 开源仓库原生集成 |
| 协议栈 | 自研 TCP + TLS 指纹伪装 | 避免系统内核特征被 Shodan/ZoomEye 识别 |

## 3. 整体架构

```
┌─────────────────────────────────────────────────┐
│              Web 管理面板 (React)                 │
├─────────────────────────────────────────────────┤
│                 API Gateway                     │
├─────────────────────────────────────────────────┤
│    微内核 Core                                    │
│    ┌──────────┬──────────┬──────────┬─────────┐ │
│    │ 注册中心  │ 事件总线  │ 配置中心  │ 日志    │ │
│    └──────────┴──────────┴──────────┴─────────┘ │
├──────────┬──────────┬──────────┬────────────────┤
│ 蜜罐引擎  │ 溯源引擎  │ 反制引擎  │  运维引擎       │
│ Plugin   │ Plugin   │ Plugin   │  Plugin        │
├──────────┼──────────┼──────────┼────────────────┤
│• HTTP    │• 漏洞库   │• Payload │ • CI/CD        │
│• MySQL   │• 指纹采集 │  投递     │ • 竞品调研     │
│• Redis   │• 关联分析 │• 截屏    │ • GitHub同步   │
│• SSH     │          │• 文件读取 │                │
│• ...     │          │• ...     │                │
└──────────┴──────────┴──────────┴────────────────┘
```

## 4. 子系统设计

### 4.1 微内核 Core

**插件接口契约：**

```go
type Plugin interface {
    Name() string
    Version() string
    Init(cfg Config) error
    Start() error
    Stop() error
}
```

**核心服务：**
- **注册中心**：插件生命周期管理（注册→初始化→启动→停止→卸载）
- **事件总线**：嵌入式 NATS Pub/Sub，支持 Topic 隔离
- **配置中心**：YAML 文件 + 环境变量覆盖，支持热重载
- **日志系统**：结构化日志(zap)，分级输出，支持远程投递

### 4.2 蜜罐引擎（子系统 A）

**协议仿真：**
- 自研 TCP 协议栈（基于 gopacket/google/gopacket），绕过内核特征
- TLS 指纹伪装模块，模拟 JA3/JA4 指纹（nginx、apache、OpenSSH 等）
- 首批服务：HTTP (nginx/apache 指纹)、MySQL 5.7/8.0、Redis 6.x、SSH (OpenSSH 指纹)

**容器安全隔离：**
- 每个蜜罐实例独立 Docker 容器 + gVisor runsc runtime
- Seccomp Profile（白名单 syscall）
- 只读根文件系统
- 禁止特权模式、限制 capabilities
- 独立网络命名空间 + iptables 出站限制

### 4.3 溯源反制引擎（子系统 B）

**漏洞库：**
- 结构化存储红队工具 CVE/NDay/0Day 信息
- 自动爬取模块：GitHub Advisory、NVD、Exploit-DB、Twitter 安全研究员
- 版本匹配引擎：根据攻击流量特征识别工具版本→匹配漏洞

**首批反制链：**

| 触发条件 | 反制手段 | 采集信息 |
|---------|---------|---------|
| Burp Suite 主动扫描特征（Collaborator 域名请求） | DNSLOG + WebRTC STUN 内网泄露 | 内网 IP、浏览器指纹、User-Agent |
| Cobalt Strike Beacon 特征（HTTP GET /ga.js 等） | 利用 CVE-2022-39197 CS 客户端 XSS 漏洞回击 | 攻击者公网 IP、CS 团队服务器地址 |
| 冰蝎/哥斯拉 webshell 连接特征 | 反序列化 gadget chain RCE 回击 | 设备信息、截屏、文件列表 |

**信息采集模块：**
- 社交账号交叉关联（通过 IP → 域名 Whois → 社交平台搜索）
- 设备指纹（Canvas/WebGL/WebRTC/Font 指纹）
- Payload 投递引擎：生成 JS/Java/.NET 多语言 Payload

### 4.4 运维引擎（子系统 C）

**CI/CD (GitHub Actions)：**
- `ci.yml`：推送→lint→test→build 多平台二进制
- `release.yml`：tag 推送→构建 Docker 镜像→发布 GitHub Release
- `sync.yml`：自动同步到 GitHub 仓库

**竞品调研自动化：**
- 定时脚本抓取 GitHub API：topic:honeypot,蜜罐 → 按 Star 排序
- 对比维度：支持协议数、溯源能力、社区活跃度、架构设计
- 生成 Markdown 分析报告（可集成到项目 Wiki）

## 5. 项目目录结构

```
Laji-HoneyPot/
├── cmd/honeypot/              # 主入口 main.go
├── internal/
│   ├── core/                  # 微内核
│   │   ├── registry/          # 插件注册中心
│   │   ├── bus/               # 事件总线封装
│   │   ├── config/            # 配置中心
│   │   └── log/               # 日志系统
│   ├── plugin/                # 插件接口契约
│   ├── honeypot/              # [A] 蜜罐引擎
│   │   ├── manager/           # 容器生命周期管理
│   │   ├── tcpstack/          # 自研 TCP 协议栈
│   │   ├── tls/               # TLS 指纹伪装
│   │   └── services/          # 各服务仿真
│   │       ├── http/
│   │       ├── mysql/
│   │       ├── redis/
│   │       └── ssh/
│   ├── traceability/          # [B] 溯源反制引擎
│   │   ├── vulndb/            # 漏洞库 & 爬虫
│   │   ├── fingerprint/       # 攻击者指纹采集
│   │   ├── payload/           # Payload 生成与投递
│   │   └── analysis/          # 关联分析
│   └── ops/                   # [C] 运维引擎
│       ├── github/            # GitHub 同步
│       └── research/          # 竞品调研
├── pkg/                       # 公共库
│   ├── container/             # Docker/gVisor 封装
│   └── protocol/              # 通用协议解析工具
├── web/                       # React 管理面板
├── deployments/               # Docker Compose / K8s 配置
├── scripts/                   # 构建/自动化脚本
└── docs/                      # 文档
```

## 6. 非功能性要求

- **性能**：单实例支持 500+ 并发连接，Go 协程模型天然满足
- **安全**：严格遵循最小权限原则；容器使用非 root 用户；代码强制 lint (golangci-lint)
- **可观测性**：结构化日志 + Prometheus metrics 端点
- **跨平台**：Linux (主) / macOS (开发)，amd64 + arm64

## 7. License

MIT License。无限制开源，使用者自行承担法律责任。
