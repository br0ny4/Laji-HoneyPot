import { useState, useEffect } from 'react';
import { apiFetch } from '../api';

interface BaitLinkage {
  id: string;
  token_id: string;
  bait_type: string;
  linkage_type: string;
  service_host: string;
  credential_key: string;
  seed_data: string;
  created_at: string;
  is_triggered: boolean;
  triggered_at: string;
  trigger_source: string;
}

interface LinkageStats {
  total: number;
  triggered: number;
  by_service: Record<string, number>;
  by_bait: Record<string, number>;
  trigger_rate: number;
}

const LINKAGE_LABELS: Record<string, string> = {
  ssh: 'SSH蜜罐', mysql: 'MySQL蜜罐', redis: 'Redis蜜罐',
  ftp: 'FTP蜜罐', rdp: 'RDP蜜罐', http: 'HTTP蜜罐',
  ldap: 'LDAP蜜罐', smb: 'SMB蜜罐',
};

const BAIT_LABELS: Record<string, string> = {
  aws_key: 'AWS凭证', db_creds: '数据库凭证', api_token: 'API令牌',
  ssh_key: 'SSH密钥', git_config: 'Git配置', wp_config: 'WP配置',
  env_file: '环境变量',
};

export default function BaitLinkagePanel() {
  const [linkages, setLinkages] = useState<BaitLinkage[]>([]);
  const [stats, setStats] = useState<LinkageStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchData = async () => {
    try {
      setLoading(true);
      const [lResp, sResp] = await Promise.all([
        apiFetch('/api/bait/linkages?limit=100'),
        apiFetch('/api/bait/linkages/stats'),
      ]);
      const lData = await lResp.json();
      const sData = await sResp.json();
      setLinkages(lData.linkages || []);
      setStats(sData);
      setError('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  if (loading) return <div className="panel"><div className="panel-body"><p>加载中...</p></div></div>;
  if (error) return <div className="panel"><div className="panel-body"><div className="alert alert-error">{error}</div></div></div>;

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>蜜饵联动</h2>
        <span className="panel-subtitle">蜜饵凭据 → 蜜罐服务联动关系，追踪攻击链路闭环</span>
      </div>
      <div className="panel-body">
        {stats && (
          <div className="stats-bar">
            <div className="stat-chip">
              <span className="stat-label">总联动数</span>
              <span className="stat-value">{stats.total}</span>
            </div>
            <div className="stat-chip">
              <span className="stat-label">已触发</span>
              <span className="stat-value" style={{color: stats.triggered > 0 ? '#ef4444' : '#22c55e'}}>{stats.triggered}</span>
            </div>
            <div className="stat-chip">
              <span className="stat-label">触发率</span>
              <span className="stat-value">{(stats.trigger_rate * 100).toFixed(1)}%</span>
            </div>
          </div>
        )}

        {stats?.by_service && Object.keys(stats.by_service).length > 0 && (
          <div className="distribution-bar">
            <h4>按服务分布</h4>
            <div className="tag-cloud">
              {Object.entries(stats.by_service).map(([k, v]) => (
                <span key={k} className="tag">{LINKAGE_LABELS[k] || k}: {v as number}</span>
              ))}
            </div>
          </div>
        )}

        <div style={{display:'flex', justifyContent:'flex-end', marginBottom: 12}}>
          <button className="btn btn-sm" onClick={fetchData}>刷新</button>
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th>蜜饵类型</th>
              <th>目标服务</th>
              <th>凭据</th>
              <th>服务地址</th>
              <th>触发状态</th>
              <th>触发时间</th>
            </tr>
          </thead>
          <tbody>
            {linkages.length === 0 ? (
              <tr><td colSpan={6} style={{textAlign:'center', padding: 40}}>暂无联动数据 — 需先生成蜜饵Token并注册联动关系</td></tr>
            ) : (
              linkages.map(l => (
                <tr key={l.id}>
                  <td>{BAIT_LABELS[l.bait_type] || l.bait_type}</td>
                  <td>{LINKAGE_LABELS[l.linkage_type] || l.linkage_type}</td>
                  <td><code>{l.credential_key}</code></td>
                  <td><code>{l.service_host}</code></td>
                  <td>
                    <span className={`status-dot ${l.is_triggered ? 'online' : 'offline'}`} />
                    {l.is_triggered ? '已触发' : '待命中'}
                  </td>
                  <td>{l.triggered_at ? new Date(l.triggered_at).toLocaleString() : '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
