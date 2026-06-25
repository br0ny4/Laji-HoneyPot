import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

interface CountermeasureEvent {
  id: number;
  timestamp: string;
  remote_ip: string;
  trigger_path: string;
  payload_type: string;
  payload_preview: string;
  user_agent: string;
  effective: boolean;
  related_attack_id: number;
  risk_level?: string;
}

const RISK_LEVEL_MAP: Record<string, { label: string; color: string }> = {
  critical: { label: '严重', color: '#ef4444' },
  high: { label: '高危', color: '#f97316' },
  medium: { label: '中危', color: '#eab308' },
  low: { label: '低危', color: '#22c55e' },
};

interface CMStats {
  total_deployed: number;
  total_effective: number;
  by_type: Record<string, number>;
  effect_rate: number;
}

const PAYLOAD_LABELS: Record<string, string> = {
  chrome_exploit: 'Chrome 专项',
  firefox: 'Firefox 专项',
  api_honeytoken: 'API蜜标',
  admin_honeytoken: '管理后台蜜标',
  springboot_honeytoken: 'SpringBoot蜜标',
  swagger_honeytoken: 'Swagger蜜标',
  source_honeytoken: '源码泄露蜜标',
  enhanced_fingerprint: '增强指纹',
  dns_rebinding: 'DNS重绑定',
  webrtc_internal_scan: 'WebRTC内网扫描',
  vpn_bait: 'VPN配置诱饵',
  heapdump_bait: 'Heapdump蜜标',
  behinder_decoy: '冰蝎反制',
  cs_xss: 'CS XSS反制',
};

export default function CountermeasurePanel() {
  const [cms, setCms] = useState<CountermeasureEvent[]>([]);
  const [stats, setStats] = useState<CMStats | null>(null);
  const [limit, setLimit] = useState(50);
  const [selected, setSelected] = useState<CountermeasureEvent | null>(null);

  const fetchData = () => {
    apiFetch(`/api/countermeasures?limit=${limit}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setCms(d.countermeasures || []))
      .catch((err) => console.error('[CountermeasurePanel] 获取反制日志失败:', err));
    apiFetch('/api/countermeasures/stats')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setStats(d))
      .catch((err) => console.error('[CountermeasurePanel] 获取反制统计失败:', err));
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [limit]);

  const typeLabel = (t: string) => PAYLOAD_LABELS[t] || t;
  const typeClass = (t: string) => {
    if (t.includes('exploit') || t.includes('_scan') || t.includes('xss')) return 'cm-type-danger';
    if (t.includes('honeytoken') || t.includes('bait')) return 'cm-type-bait';
    if (t.includes('fingerprint')) return 'cm-type-fingerprint';
    return 'cm-type-default';
  };

  const formatPreview = (s: string) => {
    if (s.length <= 80) return s;
    return s.slice(0, 80) + '...';
  };

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">反制日志</h2>
        <div className="panel-controls">
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value={20}>最近 20 条</option>
            <option value={50}>最近 50 条</option>
            <option value={200}>最近 200 条</option>
          </select>
          <button className="btn-refresh" onClick={fetchData}>刷新</button>
        </div>
      </div>

      {stats && (
        <div className="cm-stats-bar">
          <div className="cm-stat-item">
            <span className="cm-stat-value">{stats.total_deployed}</span>
            <span className="cm-stat-label">已部署</span>
          </div>
          <div className="cm-stat-item">
            <span className="cm-stat-value cm-effective">{stats.total_effective}</span>
            <span className="cm-stat-label">已奏效</span>
          </div>
          <div className="cm-stat-item">
            <span className="cm-stat-value cm-rate">{stats.effect_rate.toFixed(1)}%</span>
            <span className="cm-stat-label">有效率</span>
          </div>
          {Object.entries(stats.by_type || {}).slice(0, 5).map(([t, c]) => (
            <div className="cm-stat-item cm-stat-mini" key={t}>
              <span className="cm-stat-value">{c}</span>
              <span className="cm-stat-label">{typeLabel(t)}</span>
            </div>
          ))}
        </div>
      )}

      {selected && (
        <div className="attack-detail-modal" onClick={() => setSelected(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>反制详情</h3>
              <button className="btn-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">攻击者IP</span>
                <span className="detail-value mono">{selected.remote_ip}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">触发路径</span>
                <span className="detail-value mono">{selected.trigger_path}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">载荷类型</span>
                <span className={`cm-badge ${typeClass(selected.payload_type)}`}>{typeLabel(selected.payload_type)}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">风险等级</span>
                <span className="detail-value" style={{ color: RISK_LEVEL_MAP[selected.risk_level || 'low']?.color, fontWeight: 600 }}>
                  {RISK_LEVEL_MAP[selected.risk_level || 'low']?.label}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">时间</span>
                <span className="detail-value">{new Date(selected.timestamp).toLocaleString('zh-CN')}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">反制效果</span>
                <span className={`detail-value ${selected.effective ? 'cm-effective' : ''}`}>
                  {selected.effective ? '已奏效 (攻击者后续触发面包屑)' : '等待验证'}
                </span>
              </div>
              <div className="detail-section">
                <h4>User-Agent</h4>
                <p className="detail-text">{selected.user_agent || '(无)'}</p>
              </div>
              <div className="detail-section">
                <h4>载荷内容</h4>
                <pre className="detail-json" style={{ maxHeight: 400, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {selected.payload_preview}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: 60 }}>ID</th>
            <th style={{ width: 160 }}>时间</th>
            <th style={{ width: 130 }}>IP</th>
            <th style={{ width: 130 }}>载荷类型</th>
            <th style={{ width: 60 }}>风险</th>
            <th style={{ width: 160 }}>触发路径</th>
            <th>载荷摘要</th>
            <th style={{ width: 90 }}>效果</th>
            <th style={{ width: 60 }}>操作</th>
          </tr>
        </thead>
        <tbody>
          {cms.map((c) => (
            <tr key={c.id}>
              <td>{c.id}</td>
              <td className="cell-time">{new Date(c.timestamp).toLocaleString('zh-CN')}</td>
              <td className="mono">{c.remote_ip}</td>
              <td><span className={`cm-badge ${typeClass(c.payload_type)}`}>{typeLabel(c.payload_type)}</span></td>
              <td>
                <span style={{ color: RISK_LEVEL_MAP[c.risk_level || 'low']?.color, fontWeight: 600, fontSize: 12 }}>
                  {RISK_LEVEL_MAP[c.risk_level || 'low']?.label}
                </span>
              </td>
              <td className="mono cell-path">{c.trigger_path}</td>
              <td className="cell-ua">{formatPreview(c.payload_preview)}</td>
              <td>{c.effective ? <span className="cm-effective-badge">已奏效</span> : <span className="cm-pending-badge">待验证</span>}</td>
              <td><button className="btn-link" onClick={() => setSelected(c)}>详情</button></td>
            </tr>
          ))}
          {cms.length === 0 && (
            <tr><td colSpan={9} className="empty-hint">暂无反制记录 — 等待攻击者触发面包屑后自动部署</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
