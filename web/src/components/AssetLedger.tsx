import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

interface AttackerSummary {
  remote_ip: string;
  first_seen: string;
  last_seen: string;
  attack_cnt: number;
  conn_cnt: number;
  services: string;
  breadcrumb_cnt: number;
  user_agents: string;
}

export default function AssetLedger() {
  const [attackers, setAttackers] = useState<AttackerSummary[]>([]);
  const [selected, setSelected] = useState<AttackerSummary | null>(null);

  useEffect(() => {
    apiFetch('/api/attackers?limit=100')
      .then((r) => r.json())
      .then((d) => setAttackers(d.attackers || []))
      .catch(() => {});
  }, []);

  const getRiskLevel = (a: AttackerSummary): string => {
    if (a.breadcrumb_cnt > 0) return '危险';
    if (a.conn_cnt >= 3) return '可疑';
    return '观察中';
  };

  const riskClass: Record<string, string> = {
    '危险': 'severity-high',
    '可疑': 'severity-medium',
    '观察中': 'severity-low',
  };

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">资产台账 · 攻击者画像</h2>
        <span className="panel-controls">
          <span className="stat-chip">共 {attackers.length} 个攻击IP</span>
        </span>
      </div>

      {selected && (
        <div className="attack-detail-modal" onClick={() => setSelected(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>攻击者画像: {selected.remote_ip}</h3>
              <button className="btn-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">IP 地址</span>
                <span className="detail-value mono">{selected.remote_ip}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">首次发现</span>
                <span className="detail-value">{selected.first_seen}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">最近活跃</span>
                <span className="detail-value">{selected.last_seen}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">连接次数</span>
                <span className="detail-value">{selected.conn_cnt}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">目标服务</span>
                <span className="detail-value">
                  {(selected.services || '').split(',').map((s) => (
                    <span key={s} className="service-tag" style={{ marginRight: 4 }}>{s}</span>
                  ))}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">面包屑触发</span>
                <span className="detail-value">{selected.breadcrumb_cnt} 次</span>
              </div>
              <div className="detail-section">
                <h4>User-Agent</h4>
                <p className="detail-text">{(selected.user_agents || '').replace(/,/g, ', ') || '(无)'}</p>
              </div>
              <div className="detail-section">
                <h4>风险评估</h4>
                <span className={`severity-badge ${riskClass[getRiskLevel(selected)]}`}>
                  {getRiskLevel(selected)}
                </span>
                {selected.breadcrumb_cnt > 0 && (
                  <p className="detail-text" style={{ marginTop: 8 }}>
                    该IP已触发面包屑诱饵，表明其正在主动探测敏感路径(如SpringBoot Actuator、Swagger文档、管理后台等)，具有较高攻击意图。
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>IP 地址</th>
            <th>首次发现</th>
            <th>连接数</th>
            <th>目标服务</th>
            <th>触饵次数</th>
            <th>风险等级</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {attackers.map((a) => (
            <tr key={a.remote_ip}>
              <td className="mono">{a.remote_ip}</td>
              <td className="cell-time">{a.first_seen.slice(0, 19)}</td>
              <td>{a.conn_cnt}</td>
              <td>
                {(a.services || '').split(',').slice(0, 3).map((s) => (
                  <span key={s} className="service-tag" style={{ marginRight: 2 }}>{s}</span>
                ))}
                {(a.services || '').split(',').length > 3 && '...'}
              </td>
              <td>{a.breadcrumb_cnt}</td>
              <td>
                <span className={`severity-badge ${riskClass[getRiskLevel(a)]}`}>
                  {getRiskLevel(a)}
                </span>
              </td>
              <td>
                <button className="btn-link" onClick={() => setSelected(a)}>详情</button>
              </td>
            </tr>
          ))}
          {attackers.length === 0 && (
            <tr><td colSpan={7} className="empty-hint">暂无攻击者数据 — 等待攻击事件发生</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
