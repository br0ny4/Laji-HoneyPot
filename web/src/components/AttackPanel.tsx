import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

interface AttackEvent {
  id: number;
  timestamp: string;
  remote_ip: string;
  path: string;
  tool_name: string;
  payload: string;
  risk_level?: string;
}

const RISK_LEVEL_MAP: Record<string, { label: string; color: string }> = {
  critical: { label: '严重', color: '#ef4444' },
  high: { label: '高危', color: '#f97316' },
  medium: { label: '中危', color: '#eab308' },
  low: { label: '低危', color: '#22c55e' },
};

export default function AttackPanel() {
  const [attacks, setAttacks] = useState<AttackEvent[]>([]);
  const [limit, setLimit] = useState(50);
  const [selected, setSelected] = useState<AttackEvent | null>(null);

  const fetchAttacks = () => {
    apiFetch(`/api/attacks?limit=${limit}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setAttacks(d.attacks || []))
      .catch((err) => console.error('[AttackPanel] 获取攻击事件失败:', err));
  };

  useEffect(() => {
    fetchAttacks();
  }, [limit]);

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">攻击事件管理</h2>
        <div className="panel-controls">
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value={20}>最近 20 条</option>
            <option value={50}>最近 50 条</option>
            <option value={200}>最近 200 条</option>
          </select>
          <button className="btn-refresh" onClick={fetchAttacks}>刷新</button>
        </div>
      </div>

      {selected && (
        <div className="attack-detail-modal" onClick={() => setSelected(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>攻击详情 #{selected.id}</h3>
              <button className="btn-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">时间</span>
                <span className="detail-value">{new Date(selected.timestamp).toLocaleString('zh-CN')}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">攻击IP</span>
                <span className="detail-value mono">{selected.remote_ip}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">风险等级</span>
                <span className="detail-value" style={{ color: RISK_LEVEL_MAP[selected.risk_level || 'low']?.color, fontWeight: 600 }}>
                  {RISK_LEVEL_MAP[selected.risk_level || 'low']?.label}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">触发路径</span>
                <span className="detail-value mono">{selected.path}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">检测工具</span>
                <span className={`service-tag ${selected.tool_name === 'unknown' ? 'tag-dim' : ''}`}>
                  {selected.tool_name}
                </span>
              </div>
              {selected.payload && (
                <div className="detail-section">
                  <h4>反制载荷</h4>
                  <pre className="detail-json">{selected.payload.slice(0, 500)}{selected.payload.length > 500 ? '...' : ''}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>时间</th>
            <th>攻击IP</th>
            <th style={{ width: 60 }}>风险</th>
            <th>路径</th>
            <th>检测工具</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {attacks.map((a) => (
            <tr key={a.id}>
              <td>{a.id}</td>
              <td className="cell-time">{new Date(a.timestamp).toLocaleString('zh-CN')}</td>
              <td className="mono">{a.remote_ip}</td>
              <td>
                <span style={{ color: RISK_LEVEL_MAP[a.risk_level || 'low']?.color, fontWeight: 600, fontSize: 12 }}>
                  {RISK_LEVEL_MAP[a.risk_level || 'low']?.label}
                </span>
              </td>
              <td className="mono">{a.path}</td>
              <td><span className={`service-tag ${a.tool_name === 'unknown' ? 'tag-dim' : ''}`}>{a.tool_name}</span></td>
              <td>
                <button className="btn-link" onClick={() => setSelected(a)}>详情</button>
              </td>
            </tr>
          ))}
          {attacks.length === 0 && (
            <tr><td colSpan={7} className="empty-hint">暂无攻击事件</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
