import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

interface Stats {
  active_services: number;
  today_conns: number;
  total_conns: number;
  attackers: number;
  counter_hits: number;
  fingerprint_cnt: number;
  by_service: Record<string, number>;
  by_tool: Record<string, number>;
}

interface Connection {
  id: number;
  timestamp: string;
  remote_ip: string;
  port: number;
  service: string;
  user_agent: string;
}

export default function DashboardPanel() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [conns, setConns] = useState<Connection[]>([]);

  useEffect(() => {
    apiFetch('/api/stats/detailed')
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});

    apiFetch('/api/connections?limit=10')
      .then((r) => r.json())
      .then((d) => setConns(d.connections || []))
      .catch(() => {});
  }, []);

  // SSE 实时更新（/api/events 已豁免认证，无需 api_key）
  useEffect(() => {
    const es = new EventSource('/api/events');
    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'stats') {
          apiFetch('/api/stats/detailed')
            .then((r) => r.json())
            .then(setStats)
            .catch(() => {});
          apiFetch('/api/connections?limit=10')
            .then((r) => r.json())
            .then((d) => setConns(d.connections || []))
            .catch(() => {});
        }
      } catch { /* ignore */ }
    };
    return () => es.close();
  }, []);

  if (!stats) {
    return <div className="loading">加载中...</div>;
  }

  return (
    <div className="dashboard-panel">
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.active_services}</div>
          <div className="stat-label">活跃服务</div>
        </div>
        <div className="stat-card accent-green">
          <div className="stat-value">{stats.today_conns}</div>
          <div className="stat-label">今日连接</div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-value">{stats.attackers}</div>
          <div className="stat-label">攻击者IP</div>
        </div>
        <div className="stat-card accent-blue">
          <div className="stat-value">{stats.counter_hits}</div>
          <div className="stat-label">面包屑触发</div>
        </div>
        <div className="stat-card accent-purple">
          <div className="stat-value">{stats.fingerprint_cnt}</div>
          <div className="stat-label">指纹采集</div>
        </div>
        <div className="stat-card accent-cyan">
          <div className="stat-value">{stats.total_conns}</div>
          <div className="stat-label">总连接数</div>
        </div>
      </div>

      <div className="panel-row">
        <div className="panel-half">
          <h3 className="section-title">服务分布</h3>
          <div className="service-bars">
            {Object.entries(stats.by_service || {}).map(([svc, cnt]) => (
              <div key={svc} className="service-bar-row">
                <span className="service-bar-label">{svc}</span>
                <div className="service-bar-track">
                  <div
                    className="service-bar-fill"
                    style={{
                      width: `${Math.min(100, (cnt / Math.max(...Object.values(stats.by_service), 1)) * 100)}%`,
                    }}
                  />
                </div>
                <span className="service-bar-count">{cnt}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel-half">
          <h3 className="section-title">攻击工具分布</h3>
          <div className="service-bars">
            {Object.entries(stats.by_tool || {}).length > 0 ? (
              Object.entries(stats.by_tool).map(([tool, cnt]) => (
                <div key={tool} className="service-bar-row">
                  <span className="service-bar-label">{tool}</span>
                  <div className="service-bar-track">
                    <div
                      className="service-bar-fill tool-fill"
                      style={{
                        width: `${Math.min(100, (cnt / Math.max(...Object.values(stats.by_tool), 1)) * 100)}%`,
                      }}
                    />
                  </div>
                  <span className="service-bar-count">{cnt}</span>
                </div>
              ))
            ) : (
              <div className="empty-hint">暂无工具检测数据</div>
            )}
          </div>
        </div>
      </div>

      <div>
        <h3 className="section-title">最近连接</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>IP</th>
              <th>服务</th>
              <th>端口</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody>
            {conns.map((c) => (
              <tr key={c.id}>
                <td className="cell-time">{new Date(c.timestamp).toLocaleString('zh-CN')}</td>
                <td className="mono">{c.remote_ip}</td>
                <td><span className="service-tag">{c.service}</span></td>
                <td>{c.port}</td>
                <td className="cell-ua" title={c.user_agent}>
                  {c.user_agent ? c.user_agent.slice(0, 40) + (c.user_agent.length > 40 ? '...' : '') : '-'}
                </td>
              </tr>
            ))}
            {conns.length === 0 && (
              <tr><td colSpan={5} className="empty-hint">暂无数据</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
