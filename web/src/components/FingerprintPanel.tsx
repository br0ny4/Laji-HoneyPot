import { useEffect, useState } from 'react';
import { apiFetch } from '../api';

interface Fingerprint {
  id: number;
  timestamp: string;
  tracking_id: string;
  remote_ip: string;
  user_agent: string;
  raw_data: string;
}

export default function FingerprintPanel() {
  const [fps, setFps] = useState<Fingerprint[]>([]);
  const [limit, setLimit] = useState(50);
  const [selected, setSelected] = useState<Fingerprint | null>(null);

  const fetchFps = () => {
    apiFetch(`/api/fingerprints?limit=${limit}`)
      .then((r) => r.json())
      .then((d) => setFps(d.fingerprints || []))
      .catch(() => {});
  };

  useEffect(() => {
    fetchFps();
  }, [limit]);

  const parseFingerprintData = (raw: string) => {
    try {
      const d = JSON.parse(raw);
      const fields: string[] = [];
      if (d.canvas) fields.push('Canvas');
      if (d.gpu) fields.push(`GPU:${d.gpu}`);
      if (d.scr) fields.push(d.scr);
      if (d.tz) fields.push(d.tz);
      if (d.lang) fields.push(d.lang);
      if (d.ip) fields.push(`IP:${d.ip}`);
      if (d.bat) fields.push(`Bat:${d.bat}`);
      return fields.length > 0 ? fields.join(', ') : '基础指纹';
    } catch {
      return raw.slice(0, 80);
    }
  };

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">浏览器指纹 & 反制日志</h2>
        <div className="panel-controls">
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value={20}>最近 20 条</option>
            <option value={50}>最近 50 条</option>
            <option value={200}>最近 200 条</option>
          </select>
          <button className="btn-refresh" onClick={fetchFps}>刷新</button>
        </div>
      </div>

      {selected && (
        <div className="attack-detail-modal" onClick={() => setSelected(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>指纹详情</h3>
              <button className="btn-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">追踪ID</span>
                <span className="detail-value mono">{selected.tracking_id}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">远程IP</span>
                <span className="detail-value mono">{selected.remote_ip}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">时间</span>
                <span className="detail-value">{new Date(selected.timestamp).toLocaleString('zh-CN')}</span>
              </div>
              <div className="detail-section">
                <h4>User-Agent</h4>
                <p className="detail-text">{selected.user_agent || '(无)'}</p>
              </div>
              <div className="detail-section">
                <h4>完整指纹数据</h4>
                <pre className="detail-json">
                  {(() => {
                    try { return JSON.stringify(JSON.parse(selected.raw_data), null, 2); }
                    catch { return selected.raw_data; }
                  })()}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>时间</th>
            <th>追踪ID</th>
            <th>IP</th>
            <th>指纹摘要</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {fps.map((f) => (
            <tr key={f.id}>
              <td>{f.id}</td>
              <td className="cell-time">{new Date(f.timestamp).toLocaleString('zh-CN')}</td>
              <td className="mono">{f.tracking_id.slice(0, 12)}...</td>
              <td className="mono">{f.remote_ip}</td>
              <td className="cell-ua">{parseFingerprintData(f.raw_data)}</td>
              <td>
                <button className="btn-link" onClick={() => setSelected(f)}>详情</button>
              </td>
            </tr>
          ))}
          {fps.length === 0 && (
            <tr><td colSpan={6} className="empty-hint">暂无指纹数据 — 等待攻击者触发面包屑后自动采集</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
