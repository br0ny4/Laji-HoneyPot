import { useEffect, useState, useCallback } from 'react';
import { fetchVirtualTopology, VirtualTopologyData, VirtualSegment, VirtualHost, VirtualEdge } from '../api';

const ROLE_COLORS: Record<string, string> = {
  web: '#4CAF50',
  db: '#2196F3',
  dc: '#FF9800',
  app: '#9C27B0',
  jumpbox: '#607D8B',
  jenkins: '#E91E63',
  gitlab: '#FF5722',
  elastic: '#00BCD4',
  shadow: '#795548',
};

const ROLE_LABELS: Record<string, string> = {
  web: 'Web',
  db: 'DB',
  dc: '域控',
  app: '应用',
  jumpbox: '跳板',
  jenkins: 'Jenkins',
  gitlab: 'GitLab',
  elastic: 'ES',
  shadow: '影子',
};

function RoleBadge({ role }: { role: string }) {
  const color = ROLE_COLORS[role] || '#999';
  const label = ROLE_LABELS[role] || role;
  return (
    <span
      className="vt-role-badge"
      style={{ background: color }}
    >
      {label}
    </span>
  );
}

function HostCard({ host }: { host: VirtualHost }) {
  const hasGate = host.visible_after && host.visible_after.length > 0;
  return (
    <div className={`vt-host-card${host.is_shadow ? ' vt-shadow' : ''}`}>
      <div className="vt-host-header">
        <RoleBadge role={host.role} />
        <span className="vt-host-ip">{host.ip}</span>
        {host.is_shadow && <span className="vt-shadow-tag">影子</span>}
      </div>
      <div className="vt-host-body">
        <div className="vt-hostname">{host.hostname}</div>
        <div className="vt-os">{host.os}</div>
        {hasGate && (
          <div className="vt-gate-tokens">
            {host.visible_after.map(t => (
              <span key={t} className="vt-token">{t}</span>
            ))}
          </div>
        )}
      </div>
      {host.services.length > 0 && (
        <div className="vt-services">
          {host.services.map((svc, i) => (
            <div key={i} className="vt-service-item">
              <span className="vt-svc-port">{svc.port}</span>
              <span className="vt-svc-proto">{svc.protocol}</span>
              <span className="vt-svc-proc">{svc.process_name}</span>
              {svc.failure_mode && (
                <span className="vt-svc-failure" title={svc.failure_mode}>
                  {svc.failure_mode}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SegmentPanel({ segment }: { segment: VirtualSegment }) {
  return (
    <div className="vt-segment">
      <div className="vt-segment-header">
        <div className="vt-segment-title">
          <h3>{segment.id}</h3>
          <span className="vt-cidr">{segment.cidr}</span>
          <span className="vt-gw">gw: {segment.gateway}</span>
        </div>
        <span className="vt-host-count">{segment.host_count} 台主机</span>
      </div>
      {segment.description && (
        <div className="vt-segment-desc">{segment.description}</div>
      )}
      <div className="vt-hosts-grid">
        {segment.hosts.map(h => (
          <HostCard key={h.ip} host={h} />
        ))}
      </div>
    </div>
  );
}

function EdgesTable({ edges }: { edges: VirtualEdge[] }) {
  if (edges.length === 0) return null;
  return (
    <div className="vt-edges-section">
      <h3>网络连通关系</h3>
      <table className="vt-edges-table">
        <thead>
          <tr>
            <th>源</th>
            <th></th>
            <th>方式</th>
            <th></th>
            <th>目标</th>
          </tr>
        </thead>
        <tbody>
          {edges.map((e, i) => (
            <tr key={i}>
              <td className="vt-edge-from">{e.from}</td>
              <td className="vt-edge-arrow">→</td>
              <td className="vt-edge-via">{e.via.toUpperCase()}</td>
              <td className="vt-edge-arrow">→</td>
              <td className="vt-edge-to">{e.to}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function VirtualTopologyPanel() {
  const [data, setData] = useState<VirtualTopologyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const d = await fetchVirtualTopology();
      setData(d);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return <div className="vt-panel"><div className="vt-loading">加载拓扑数据...</div></div>;
  }
  if (error) {
    return (
      <div className="vt-panel">
        <div className="vt-error">
          <div>加载失败: {error}</div>
          <button onClick={load}>重试</button>
        </div>
      </div>
    );
  }
  if (!data || data.host_count === 0) {
    return (
      <div className="vt-panel">
        <div className="vt-empty">
          <div className="vt-empty-icon">🛡️</div>
          <h3>虚拟网络拓扑未配置</h3>
          <p>编辑 configs/topology.yaml 并重启服务以启用 SSH 高交互模式的虚拟网络拓扑功能。</p>
        </div>
      </div>
    );
  }

  return (
    <div className="vt-panel">
      <div className="vt-header">
        <h2>虚拟网络拓扑</h2>
        <span className="vt-summary">
          {data.segments.length} 网段 · {data.host_count} 台主机 · {data.edges.length} 条连接边
        </span>
      </div>
      <div className="vt-legend">
        {Object.entries(ROLE_LABELS).map(([role, label]) => (
          <span key={role} className="vt-legend-item">
            <span
              className="vt-legend-dot"
              style={{ background: ROLE_COLORS[role] || '#999' }}
            />
            {label}
          </span>
        ))}
      </div>
      {data.segments.map(seg => (
        <SegmentPanel key={seg.id} segment={seg} />
      ))}
      <EdgesTable edges={data.edges} />
    </div>
  );
}
