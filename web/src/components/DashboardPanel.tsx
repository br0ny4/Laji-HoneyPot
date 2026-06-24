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
  const [error, setError] = useState('');

  const fetchData = () => {
    apiFetch('/api/stats/detailed')
      .then((r) => {
        if (!r.ok) throw new Error(`API 返回 ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setStats(data as Stats);
        setError('');
      })
      .catch((err) => {
        console.error('[Dashboard] 获取统计失败:', err);
        setError(`无法连接到后端 API (${err.message})。请确认 honeypot 已启动且 API 端口 8080 可访问。`);
      });

    apiFetch('/api/connections?limit=10')
      .then((r) => {
        if (!r.ok) throw new Error(`API 返回 ${r.status}`);
        return r.json();
      })
      .then((d) => setConns(d.connections || []))
      .catch((err) => console.error('[Dashboard] 获取连接列表失败:', err));
  };

  useEffect(() => {
    fetchData();
  }, []);

  // SSE 实时更新
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource('/api/events');
      es.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'stats') {
            fetchData();
          }
        } catch { /* 忽略解析错误 */ }
      };
      es.onerror = () => {
        console.warn('[Dashboard] SSE 连接中断，将重连...');
      };
    } catch (err) {
      console.warn('[Dashboard] SSE 初始化失败:', err);
    }
    return () => {
      if (es) es.close();
    };
  }, []);

  // 错误状态
  if (error) {
    return (
      <div className="dashboard-panel">
        <div className="error-banner">
          <div className="error-icon">&#9888;</div>
          <div className="error-message">{error}</div>
          <button className="btn-refresh" onClick={fetchData}>重试</button>
        </div>
        <div className="error-hint">
          <h4>排查步骤：</h4>
          <ol>
            <li>确认后端已启动：<code>go run ./cmd/honeypot</code></li>
            <li>确认 API 监听地址为 <code>127.0.0.1:8080</code>（见 <code>config.yaml</code>）</li>
            <li>若使用 Vite 开发服务器，确认 proxy 配置指向 <code>http://127.0.0.1:8080</code></li>
            <li>生产环境请使用 <code>npm run build</code> 构建后由 Go 后端直接托管前端</li>
          </ol>
        </div>
      </div>
    );
  }

  if (!stats) {
    return <div className="loading">正在连接后端 API...</div>;
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
            {Object.keys(stats.by_service || {}).length === 0 && (
              <div className="empty-hint">暂无连接数据</div>
            )}
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
              <tr><td colSpan={5} className="empty-hint">暂无数据 — 等待攻击者连接</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
