import { useState, useEffect } from 'react';
import { apiFetch } from '../api';

interface SystemInfo {
  version: string;
  go_version: string;
  database: string;
  services: string;
  active_services: number;
  total_conns: number;
  fingerprint_cnt: number;
  attackers_today: number;
}

export default function OpsPanel() {
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    apiFetch('/api/system')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data: SystemInfo) => {
        if (!cancelled) {
          setSysInfo(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, []);

  const statusBadge = (val: number) =>
    val > 0 ? <span className="status-badge status-protected">{val}</span> : <span className="status-badge status-idle">0</span>;

  if (loading) {
    return <div className="ops-panel"><div className="loading">加载系统信息...</div></div>;
  }

  if (error) {
    return <div className="ops-panel"><div className="error">{error}</div></div>;
  }

  return (
    <div className="ops-panel">
      <h2 className="section-title">运维管理</h2>

      <div className="panel-row">
        <div className="panel-half">
          <h3 className="section-title">系统信息</h3>
          <table className="data-table">
            <tbody>
              <tr><td>版本</td><td>{sysInfo?.version || '-'}</td></tr>
              <tr><td>后端框架</td><td>{sysInfo?.go_version || '-'}</td></tr>
              <tr><td>数据库</td><td>{sysInfo?.database || '-'}</td></tr>
              <tr><td>蜜罐服务</td><td>{sysInfo?.services || '-'}</td></tr>
              <tr><td>活跃服务数</td><td>{statusBadge(sysInfo?.active_services ?? 0)}</td></tr>
              <tr><td>总连接数</td><td>{statusBadge(sysInfo?.total_conns ?? 0)}</td></tr>
              <tr><td>指纹采集数</td><td>{statusBadge(sysInfo?.fingerprint_cnt ?? 0)}</td></tr>
              <tr><td>今日攻击者</td><td>{statusBadge(sysInfo?.attackers_today ?? 0)}</td></tr>
            </tbody>
          </table>
        </div>

        <div className="panel-half">
          <h3 className="section-title">部署指南</h3>
          <div className="ops-instructions">
            <div className="ops-step">
              <span className="ops-step-num">1</span>
              <div>
                <strong>启动后端</strong>
                <code className="ops-code">go run ./cmd/honeypot</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">2</span>
              <div>
                <strong>启动前端</strong>
                <code className="ops-code">cd web && npm run dev</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">3</span>
              <div>
                <strong>访问管理端</strong>
                <code className="ops-code">http://localhost:3000</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">4</span>
              <div>
                <strong>构建生产版本</strong>
                <code className="ops-code">cd web && npm run build</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel-row">
        <div className="panel-half">
          <h3 className="section-title">性能指标</h3>
          <table className="data-table">
            <tbody>
              <tr><td>API 响应时间</td><td>&lt; 50ms</td></tr>
              <tr><td>拓扑图渲染</td><td>&lt; 500ms (含G6布局)</td></tr>
              <tr><td>SSE 推送延迟</td><td>&lt; 100ms</td></tr>
              <tr><td>速率限制</td><td>100 req/s (Token Bucket)</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
