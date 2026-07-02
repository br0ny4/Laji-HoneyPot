# Laji-HoneyPot 测试套件

> 版本: v0.11.1 | 更新时间: 2026-07-02

## 前置条件

- **管理端**: macOS (10.111.31.103) 已启动 honeypot-macos-arm64
  ```bash
  ./bin/honeypot-macos-arm64 --config config.yaml
  ```
- **Agent**: Windows 11 (10.111.29.4) 已部署并注册到集群
  ```powershell
  powershell -ExecutionPolicy Bypass -File deploy.ps1
  ```
- **网络**: 两台机器间 8080/8081/8443 端口互通 (Windows 防火墙已关闭)

## 脚本清单

| 脚本 | 用途 | 运行方式 |
|------|------|---------|
| `01_health_check.sh` | 管理端核心 API 健康检查、VulnDB、集群状态 | `bash 01_health_check.sh` |
| `02_payload_delivery.sh` | Payload 投递测试：7种UA × 9面包屑路径、Burp vs Chrome 大小对比 | `bash 02_payload_delivery.sh` |
| `03_countermeasure.sh` | 反制系统全链路：Screen/File/Net 外传 + 冷却 + 审计 + 拓扑 | `bash 03_countermeasure.sh` |
| `04_full_attack.sh` | 全量模拟攻击：端口扫描 + 协议级(MySQL/SSH/FTP/DNS) + 多面包屑 | `bash 04_full_attack.sh` |
| `05_cluster_verify.sh` | Agent 心跳验证、集群节点状态、陷阱端口探测 | `bash 05_cluster_verify.sh` |
| `06_traceability_test.sh` | **专项测试** — 溯源能力：15种UA识别、载荷链、VulnDB匹配、面包屑覆盖 | `bash 06_traceability_test.sh` |
| `07_countermeasure_test.sh` | **专项测试** — 反制效果：触发条件、冷却边界、异常输入、审计完整性 | `bash 07_countermeasure_test.sh` |
| `run_all.sh` | 一键运行全部 5 阶段测试 (01-05) | `bash run_all.sh` |

## 一键运行

```bash
cd deploy/test-scripts
chmod +x *.sh
./run_all.sh
```

## 专项测试 (T1/T2)

```bash
# T1: 溯源能力专项 (UA识别、载荷投递、VulnDB、面包屑覆盖)
bash 06_traceability_test.sh

# T2: 反制效果专项 (触发条件、冷却边界、异常输入、审计完整性)
bash 07_countermeasure_test.sh
```

## 问题跟踪

测试发现的问题已录入项目 [ISSUES.md](../../ISSUES.md)，按 P0/P1/P2/P3 分级管理。

## Windows Agent 部署

```powershell
# 拷贝 deploy/win-agent/ 到 Windows 后
powershell -ExecutionPolicy Bypass -File .\deploy.ps1
```
