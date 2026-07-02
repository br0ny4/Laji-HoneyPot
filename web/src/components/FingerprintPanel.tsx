import { useEffect, useState, useMemo } from 'react';
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
  const [limit, setLimit] = useState(100);
  const [selected, setSelected] = useState<Fingerprint | null>(null);
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<'time' | 'ip'>('time');
  const [viewMode, setViewMode] = useState<'list' | 'grouped'>('grouped');
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const fetchFps = () => {
    apiFetch(`/api/fingerprints?limit=${limit}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setFps(d.fingerprints || []))
      .catch((err) => console.error('[FingerprintPanel] 获取指纹失败:', err));
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

  const getUAInfo = (ua: string): { browser: string; os: string; icon: string } => {
    if (!ua) return { browser: '未知', os: '未知', icon: '?' };
    let browser = '未知';
    let os = '未知';
    let icon = '?';
    if (ua.includes('Chrome') && !ua.includes('Edg')) { browser = 'Chrome'; icon = 'C'; }
    else if (ua.includes('Firefox')) { browser = 'Firefox'; icon = 'F'; }
    else if (ua.includes('Edg')) { browser = 'Edge'; icon = 'E'; }
    else if (ua.includes('Safari') && !ua.includes('Chrome')) { browser = 'Safari'; icon = 'S'; }
    else if (ua.includes('python') || ua.includes('Python')) { browser = 'Python'; icon = 'P'; }
    else if (ua.includes('curl')) { browser = 'curl'; icon = 'c'; }
    else if (ua.includes('Burp')) { browser = 'Burp'; icon = 'B'; }
    else if (ua.includes('Nmap')) { browser = 'Nmap'; icon = 'N'; }
    if (ua.includes('Windows')) os = 'Win';
    else if (ua.includes('Mac')) os = 'Mac';
    else if (ua.includes('Linux') || ua.includes('X11')) os = 'Linux';
    else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
    else if (ua.includes('Android')) os = 'Android';
    return { browser, os, icon };
  };

  // 搜索过滤
  const filteredFps = useMemo(() => {
    if (!search) return fps;
    const q = search.toLowerCase();
    return fps.filter((f) =>
      f.remote_ip.includes(q) ||
      f.tracking_id.toLowerCase().includes(q) ||
      f.user_agent.toLowerCase().includes(q) ||
      parseFingerprintData(f.raw_data).toLowerCase().includes(q)
    );
  }, [fps, search]);

  // 排序
  const sortedFps = useMemo(() => {
    const sorted = [...filteredFps];
    if (sortField === 'time') {
      sorted.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } else {
      sorted.sort((a, b) => a.remote_ip.localeCompare(b.remote_ip) || new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }
    return sorted;
  }, [filteredFps, sortField]);

  // 按 IP 分组
  const groupedFps = useMemo(() => {
    const groups = new Map<string, Fingerprint[]>();
    for (const f of sortedFps) {
      const existing = groups.get(f.remote_ip) || [];
      existing.push(f);
      groups.set(f.remote_ip, existing);
    }
    return Array.from(groups.entries()).map(([ip, items]) => ({
      ip,
      count: items.length,
      latest: items[0].timestamp,
      items,
      expanded: expandedGroups.has(ip),
    }));
  }, [sortedFps, expandedGroups]);

  const toggleGroup = (ip: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  const expandAll = () => {
    setExpandedGroups(new Set(groupedFps.map((g) => g.ip)));
  };

  const collapseAll = () => {
    setExpandedGroups(new Set());
  };

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">浏览器指纹 & 反制日志</h2>
        <div className="panel-controls">
          <input
            type="text"
            className="search-input"
            placeholder="搜索 IP / UA / 追踪ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value={50}>最近 50 条</option>
            <option value={100}>最近 100 条</option>
            <option value={200}>最近 200 条</option>
          </select>
          <select value={sortField} onChange={(e) => setSortField(e.target.value as 'time' | 'ip')}>
            <option value="time">按时间排序</option>
            <option value="ip">按 IP 排序</option>
          </select>
          <select value={viewMode} onChange={(e) => setViewMode(e.target.value as 'list' | 'grouped')}>
            <option value="grouped">分组视图</option>
            <option value="list">列表视图</option>
          </select>
          <button className="btn-refresh" onClick={fetchFps}>刷新</button>
        </div>
      </div>

      {/* 指纹详情模态框 */}
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
                <h4>浏览器信息</h4>
                {(() => {
                  const info = getUAInfo(selected.user_agent);
                  return (
                    <div className="ua-badge-row">
                      <span className="ua-badge">{info.icon}</span>
                      <span>{info.browser} / {info.os}</span>
                    </div>
                  );
                })()}
                <p className="detail-text" style={{ marginTop: 8 }}>{selected.user_agent || '(无)'}</p>
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

      {/* 分组视图 */}
      {viewMode === 'grouped' && (
        <div className="fp-groups">
          <div className="fp-groups-toolbar">
            <span className="fp-count">共 {groupedFps.length} 个 IP, {sortedFps.length} 条记录</span>
            <div className="fp-groups-actions">
              <button className="btn-link" onClick={expandAll}>全部展开</button>
              <button className="btn-link" onClick={collapseAll}>全部折叠</button>
            </div>
          </div>
          {groupedFps.map((group) => (
            <div key={group.ip} className="fp-group-card">
              <div className="fp-group-header" onClick={() => toggleGroup(group.ip)}>
                <span className={`fp-expand-icon ${group.expanded ? 'expanded' : ''}`}>▶</span>
                <span className="fp-group-ip mono">{group.ip}</span>
                <span className="fp-group-count">{group.count} 条</span>
                <span className="fp-group-time">{new Date(group.latest).toLocaleString('zh-CN')}</span>
                <span className="fp-group-browsers">
                  {[...new Set(group.items.map((f) => getUAInfo(f.user_agent).icon))].slice(0, 5).map((icon, i) => (
                    <span key={i} className="fp-browser-icon">{icon}</span>
                  ))}
                </span>
              </div>
              {group.expanded && (
                <div className="fp-group-body">
                  {group.items.map((f) => (
                    <div key={f.id} className="fp-item-row" onClick={() => setSelected(f)}>
                      <span className="fp-item-id">{f.id}</span>
                      <span className="fp-item-time">{new Date(f.timestamp).toLocaleTimeString('zh-CN')}</span>
                      <span className="fp-item-tracking mono">{f.tracking_id.slice(0, 12)}...</span>
                      <span className="fp-item-ua">{parseFingerprintData(f.raw_data)}</span>
                      <span className="fp-item-browser">{getUAInfo(f.user_agent).icon}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* 列表视图 */}
      {viewMode === 'list' && (
        <table className="data-table fp-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>时间</th>
              <th>追踪ID</th>
              <th>IP</th>
              <th>浏览器</th>
              <th>指纹摘要</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {sortedFps.map((f) => {
              const info = getUAInfo(f.user_agent);
              return (
                <tr key={f.id}>
                  <td>{f.id}</td>
                  <td className="cell-time">{new Date(f.timestamp).toLocaleString('zh-CN')}</td>
                  <td className="mono fp-tracking-cell">{f.tracking_id.slice(0, 12)}...</td>
                  <td className="mono">{f.remote_ip}</td>
                  <td>
                    <span className="fp-browser-tag" title={f.user_agent}>{info.icon} {info.browser}</span>
                  </td>
                  <td className="cell-ua">{parseFingerprintData(f.raw_data)}</td>
                  <td>
                    <button className="btn-link" onClick={() => setSelected(f)}>详情</button>
                  </td>
                </tr>
              );
            })}
            {sortedFps.length === 0 && (
              <tr><td colSpan={7} className="empty-hint">
                {search ? '没有匹配的指纹记录' : '暂无指纹数据 — 等待攻击者触发面包屑后自动采集'}
              </td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
