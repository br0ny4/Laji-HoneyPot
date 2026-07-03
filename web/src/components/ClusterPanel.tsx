import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

// 集群节点状态（对应后端 cluster.NodeState）
interface NodeState {
  node_id: string;
  online: boolean;
  last_seen: string;
  connections: number;
  attacks: number;
  fingerprints: number;
  uptime_seconds: number;
}

interface ClusterNodesResponse {
  nodes: NodeState[];
  total: number;
  cluster_enabled: boolean;
}

// 格式化运行时间
function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

export default function ClusterPanel() {
  const [data, setData] = useState<ClusterNodesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // 周期性拉取节点状态 (每 10 秒)
  useEffect(() => {
    const fetchNodes = () => {
      apiFetch('/api/cluster/nodes')
        .then((r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.json();
        })
        .then((d: ClusterNodesResponse) => {
          setData(d);
          setLoading(false);
        })
        .catch((err) => {
          setError(`获取集群状态失败: ${err instanceof Error ? err.message : String(err)}`);
          setLoading(false);
        });
    };

    fetchNodes();
    const interval = setInterval(fetchNodes, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">集群管理 · 节点监控</h2>
        <span className="panel-controls">
          {data && (
            <>
              <span className={`stat-chip ${data.cluster_enabled ? 'severity-low' : ''}`}>
                {data.cluster_enabled ? '集群已启用' : '集群未启用'}
              </span>
              <span className="stat-chip" style={{ marginLeft: 8 }}>
                共 {data.total} 个节点
              </span>
            </>
          )}
        </span>
      </div>

      {error && (
        <div style={{ padding: '8px 16px', color: '#e74c3c', background: '#fdf0ef', borderRadius: 6, margin: '0 16px 12px' }}>
          {error}
        </div>
      )}

      {!data?.cluster_enabled && !loading && (
        <div className="empty-state" style={{ padding: 40, textAlign: 'center', color: '#5a6988' }}>
          <p style={{ fontSize: 16, marginBottom: 12 }}>集群模式未启用</p>
          <p style={{ fontSize: 13 }}>
            在 config.yaml 中设置 <code>cluster.enabled: true</code> 并重启服务以启用集群管理功能。
          </p>
          <p style={{ fontSize: 13, marginTop: 8 }}>
            启用后，远程蜜罐节点可通过 TLS 连接到本管理端，实现分布式部署。
          </p>
        </div>
      )}

      {loading && (
        <div style={{ padding: 24, textAlign: 'center', color: '#5a6988' }}>正在加载节点状态...</div>
      )}

      {data?.cluster_enabled && (
        <table className="data-table">
          <thead>
            <tr>
              <th>节点 ID</th>
              <th>状态</th>
              <th>最后心跳</th>
              <th>连接数</th>
              <th>攻击数</th>
              <th>指纹采集</th>
              <th>运行时间</th>
            </tr>
          </thead>
          <tbody>
            {data.nodes.map((node) => (
              <tr key={node.node_id}>
                <td className="mono" title={node.node_id}>
                  {node.node_id.length > 16 ? node.node_id.slice(0, 16) + '...' : node.node_id}
                </td>
                <td>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: node.online ? '#27ae60' : '#e74c3c',
                      marginRight: 6,
                    }}
                  />
                  <span style={{ color: node.online ? '#27ae60' : '#e74c3c', fontWeight: 600 }}>
                    {node.online ? '在线' : '离线'}
                  </span>
                </td>
                <td className="cell-time">
                  {node.last_seen ? new Date(node.last_seen).toLocaleTimeString() : '-'}
                </td>
                <td>{node.connections.toLocaleString()}</td>
                <td>{node.attacks.toLocaleString()}</td>
                <td>{node.fingerprints.toLocaleString()}</td>
                <td>{formatUptime(node.uptime_seconds)}</td>
              </tr>
            ))}
            {data.nodes.length === 0 && (
              <tr>
                <td colSpan={7} className="empty-hint">
                  暂无已注册节点 — 等待远程蜜罐节点连接
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {/* 部署指引 */}
      {(data?.cluster_enabled || true) && (
        <div style={{ margin: '16px', padding: '16px', background: '#1a2332', borderRadius: 8, border: '1px solid #2d3a4f' }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: 14, color: '#c8d6e5' }}>部署远程节点 (v0.17.1 双模式)</h3>
          
          <div style={{ marginBottom: 12 }}>
            <span style={{ color: '#f0c040', fontWeight: 600, fontSize: 13 }}>方式1: 一键拉取 (推荐) </span>
            <span style={{ color: '#8899aa', fontSize: 12 }}>— 切换到 </span>
            <span style={{ color: '#7ec8a0', fontWeight: 600, fontSize: 12, cursor: 'pointer' }}
                  onClick={() => { const tabs = document.querySelectorAll('.tab-label'); tabs.forEach(t => { if (t.textContent?.includes('Agent')) (t as HTMLElement).click(); }) }}>
              Agent部署
            </span>
            <span style={{ color: '#8899aa', fontSize: 12 }}> 页面，选择一键拉取模式获取命令</span>
          </div>

          <div style={{ marginBottom: 12 }}>
            <span style={{ color: '#f0c040', fontWeight: 600, fontSize: 13 }}>方式2: 手动部署 </span>
            <span style={{ color: '#8899aa', fontSize: 12 }}>— 下载部署包 + 本地编译 + 发送到目标主机</span>
          </div>

          <pre style={{
            background: '#0d1520',
            padding: 12,
            borderRadius: 4,
            fontSize: 12,
            color: '#7ec8a0',
            overflowX: 'auto',
            margin: 0,
          }}>
{`# 远程节点 config.yaml:
cluster:
  enabled: true
  role: "node"
  manager_addr: "<管理端IP>:8443"

# 启动蜜罐节点
./bin/honeypot

# 或使用 Agent 部署面板生成一键拉取/手动部署命令`}
          </pre>
        </div>
      )}
    </div>
  );
}
