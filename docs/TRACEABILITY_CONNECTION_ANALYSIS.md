# Laji-HoneyPot 分布式溯源反制连接逻辑分析报告

> 版本: v0.19.0  
> 日期: 2026-07-04  
> 分析对象: Manager-Agent 分布式部署场景下的溯源反制全链路

---

## 1. 核心结论

| 问题 | 答案 |
|------|------|
| 反制 JS 载荷由谁投递？ | **Agent 本地生成并投递**，Manager 不参与 |
| 载荷投递是主动还是被动？ | **被动注入** — Agent 复用攻击者已建立的 HTTP 连接，将 JS 注入响应体 |
| Manager-Agent 连接模式？ | **Agent 主动建立** TCP TLS 长连接 → Manager 被动监听，单向推送事件 |
| 蜜标触发的载荷回传？ | 蜜标文件由 Agent HTTP 蜜罐**本地提供**，访问事件通过集群通道**上报 Manager** |

---

## 2. 反制 JS 载荷投递链路

### 2.1 完整调用链

当攻击者访问 Agent1 节点上的 HTTP 蜜罐面包屑路径时：

```
攻击者浏览器
  │ HTTP GET /wp-admin/setup-config.php
  ▼
Agent1 HTTP 蜜罐 (port 8081)
  │ server.go:234 → isBreadcrumb("/wp-admin/setup-config.php") → true
  │ server.go:241 → onBreadcrumb 回调
  ▼
honeypot.Engine.onBreadcrumb (plugin.go:589)
  │ 异步 goroutine:
  │   → store.RecordAttack (本地 SQLite)
  │   → store.MarkCountermeasureEffective
  │   → bus.Publish("honeypot.breadcrumb")
  │   → bus.Publish("honeypot.attack")
  ▼
HTTP 蜜罐 buildResponse (server.go:573-613)
  │ 若 countermeasureCB != nil:
  │   go func() { js = countermeasureCB(path, ua, ip) }()
  │   select case js := <-ch: 注入到 </body> 前
  │   case <-time.After(5s): 超时降级，仅返回普通响应
  ▼
traceability.Engine.SelectPayload (traceability/plugin.go:258)
  │ 根据 UA/path/工具 选择 Payload:
  │   Chrome  → 全维度指纹 (Canvas/WebGL/Audio/Math/触屏/广告拦截)
  │   Firefox → 全维度指纹
  │   Burp    → Burp 检测 + Java 版本 + 系统属性
  │   curl    → 最小化指纹 (仅 UA/TLS 解析)
  │   ... (30+ 变体)
  │ 返回纯 JS 字符串
  ▼
Agent1 HTTP 蜜罐将 JS 注入 HTML 响应 → 返回攻击者浏览器
```

### 2.2 关键设计特征

1. **载荷本地生成**: `SelectPayload` 在 Agent 本地执行，利用本地 VulnDB、指纹库、Payload 模板
2. **零 Manager 参与**: Manager 在整个 JS 载荷生成/投递链路中**完全不参与**
3. **复用攻击者连接**: JS 通过 `</body>` 前注入方式，**复用攻击者已建立的 HTTP 连接**返回，不建立新连接
4. **异步回调**: `countermeasureCB` 在 goroutine 中执行，5 秒超时降级，不影响正常响应

---

## 3. Manager-Agent 集群连接模式

### 3.1 连接建立

```
Agent 启动
  │ agent.Connect() (agent.go:89)
  │ tls.Dial("tcp", managerAddr, tlsCfg)
  ▼
Manager TLS :8443
  │ manager.acceptLoop() (manager.go:74)
  │ Accept TLS 连接
  │ 接收 RegisterRequest {NodeInfo}
  ▼
Manager 返回 RegisterResponse {Accepted: true, HeartbeatSec: 30}
  │
Agent 注册成功，启动三个循环:
  ├── heartbeatLoop: 每 30s 发送心跳 (携带运行时统计)
  ├── eventFlushLoop: 每 5s 批量推送事件
  └── reconnectLoop: 断线时指数退避重连 (2s → 5min, 最多 20 次)
```

### 3.2 消息协议

文件: `internal/cluster/proto.go`

```
Frame Format: [4 bytes BigEndian Length][JSON Body]

Message Types:
  Agent → Manager:
    - "register"      : {NodeInfo}              节点注册
    - "heartbeat"     : {HeartbeatStats}         心跳 + 运行时统计
    - "event_push"    : [{ClusterEvent}, ...]    批量事件推送

  Manager → Agent:
    - "register_ack"  : {RegisterResponse}       注册确认
    - "heartbeat_ack" : {HeartbeatResponse}      心跳应答
    - (config_sync    : 协议已定义，当前未实现)
```

### 3.3 事件数据流

```
Agent 事件循环:
  蜜罐引擎 → bus.Publish("honeypot.attack")
    → traceability 引擎处理 (工具识别/指纹采集)
      → agent.PushEvent(event) 加入缓冲队列
        → eventFlushLoop (5s ticker)
          → writeMessage("event_push", batch)

Manager 事件接收:
  handleNode → case "event_push":
    → 解析 JSON 为 []ClusterEvent
      → EventCh channel 发送
        → SSE 实时推送到前端
        → 存储到环形缓冲区 (500 条)
        → 合并到拓扑数据
```

### 3.4 连接特征

| 特征 | 值 |
|------|-----|
| 连接方向 | Agent → Manager (主动) |
| 传输协议 | 自定义 TCP 帧 (非 HTTP/WS/gRPC) |
| 加密方式 | TLS 1.3 (MinVersion: VersionTLS13) |
| 保活机制 | 30s 心跳 + ACK |
| 重连策略 | 指数退避: 2s → 4s → 8s → ... → 5min (封顶)，最多 20 次 |
| Manager 行为 | 被动 Accept + ACK，不主动推送 |
| Agent 行为 | 主动连接 + 推送，单向数据流 |

---

## 4. 蜜标系统连接模式

### 4.1 蜜标文件服务

```
攻击者访问 Agent HTTP 蜜罐
  │ GET / (蜜罐主页)
  │ 响应 HTML 包含 hidden div:
  │   <a href="/bait/aws_credentials.txt">...</a>
  │   <a href="/bait/db_config.php">...</a>
  │   ...
  ▼
攻击者下载蜜标文件
  │ GET /bait/aws_credentials.txt
  ▼
Agent HTTP 蜜罐 handleBaitDelivery (server.go:395)
  │ baitGen.GetByPath("/bait/aws_credentials.txt")
  │ 返回伪造的 AWS 凭据文件内容
  │ baitTracker.Record(accessRecord) 本地记录
  ▼
访问事件通过集群通道上报:
  agent.PushEvent → event_push → Manager
```

### 4.2 蜜饵联动

文件: `internal/bait/linkage.go`

蜜标中的伪造凭据与蜜罐服务**仅在 Agent 本地 127.0.0.1 范围内联动**：
- SSH 蜜标 → 关联到本机 SSH 蜜罐 (:2222)
- MySQL 凭据 → 关联到本机 MySQL 蜜罐 (:3306)
- API Token → 关联到本机 HTTP 蜜罐 (:8081)

当攻击者使用蜜标凭据尝试登录蜜罐时，`CheckCredential` 进行凭据哈希匹配，确认该凭据来自蜜标，标记为"蜜标联动触发"。

---

## 5. 植入体反制数据回传

### 5.1 回传端点独占性

植入体 JS (截屏/文件扫描/网络探测) 的回传端点 `/api/countermeasure/exfil` **仅注册在 Manager API Server** 上，Agent HTTP 蜜罐**不注册此端点**。

```
植入体 JS 执行 (在攻击者浏览器中)
  │ 网络探测完成 → 回传结果
  ▼
POST /api/countermeasure/exfil (目标: Manager :8080)
  │ Manager handleCountermeasureExfil
  │ → ScoringEngine.RegisterScore (得分)
  │ → AuditTrail.RecordComplete (审计)
  │ → persistScreenCapture / persistFileScan (持久化)
```

**重要注意**: `traceability.NewEngine` 中植入体编排器 `OrchConfig.Endpoint` 默认值为 `http://localhost:8080`。在 Agent 节点部署时，需要将此地址配置为 Manager 的可达地址（而非 Agent 自身的 localhost）。

### 5.2 指纹采集双路径

指纹采集 (`/api/collect`) 存在**双路径设计**：

- **路径 A**: 浏览器 JS 通过 `new Image().src='/api/collect?d=...'` 相对路径 → 发往**注入 JS 的那个 Agent 的 HTTP 蜜罐端口**
- **路径 B**: 直接 HTTP 请求 Manager API → `/api/collect` → Manager 处理

路径 A 的指纹数据存储在 Agent 本地 SQLite，通过集群事件通道上报 Manager。

---

## 6. 完整反制流程时序 (Agent1 场景)

```
攻击者                 Agent1(蜜罐节点)          Manager(管理端)
  │                        │                       │
  │──HTTP GET /admin.php──▶│                       │
  │                        │──面包屑检测──────────▶│ (通过 event_push)
  │                        │──SelectPayload()      │
  │◀──HTML + 反制JS────────│                       │
  │                        │                       │
  │ (浏览器执行反制JS)      │                       │
  │──/api/collect─────────▶│ (Agent 本地处理)      │
  │                        │──上报指纹────────────▶│
  │                        │                       │
  │ (植入体: 截屏)          │                       │
  │──POST /api/            │                       │
  │   countermeasure/exfil─│──────────────────────▶│
  │                        │                       │──Score
  │                        │                       │──Audit
  │                        │                       │──Persist
  │                        │                       │
  │ (Agent1 断线)           │                       │
  │                        │──指数退避重连─────────▶│
  │                        │                       │
  │ (管理端派发升级)         │                       │
  │                        │◀──升级任务创建─────────│
  │                        │──Download(resume)─────│
  │                        │──Verify(SHA256)       │
  │                        │──Install→Restart      │
  │                        │──Progress notify─────▶│
```

---

## 7. 安全性分析

| 方面 | 评估 |
|------|------|
| 载荷隔离 | Agent 本地生成 JS，Manager 无法被攻击者通过 JS 注入反向攻击 |
| 连接方向 | 仅 Agent → Manager 单向，攻击者无法通过 Manager 端口反向连接 Agent |
| 反制回传 | Manager 独占 `/api/countermeasure/exfil`，Agent 不暴露此端点 |
| 蜜标本地化 | 蜜标文件本地服务，减少 Manager 带宽消耗 |
| 事件可靠性 | Agent 本地 SQLite + 集群通道双重保障，事件不丢失 |
| 断线恢复 | 指数退避自动重连 + 5s 批量缓冲 |
