import { useState, useEffect, useCallback } from 'react';
import { listEvidenceSummaries, getEvidenceByIP, type EvidenceSummary } from '../api';

const TOKEN_LABELS: Record<string, string> = {
  route_info: '路由信息',
  arp_cache: 'ARP缓存',
  subnet_scan: '子网扫描',
  db_probe: '数据库探测',
  http_probe: 'Web探测',
  domain_probe: '域渗透',
  lateral_probe: '横向移动',
  app_config: '配置窃取',
  app_log: '日志探测',
  service_enum: '服务枚举',
  pseudo_progress: '凭据搜索',
  priv_escalation: '提权尝试',
};

const RISK_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const INTENT_LABELS: Record<string, string> = {
  network_scan: '网络扫描',
  service_probe: '服务探测',
  http_probe: 'Web探测',
  db_probe: '数据库探测',
  evidence_search: '凭据窃取',
  domain_probe: '域渗透',
  lateral_movement: '横向移动',
  privilege_escalation: '提权',
  data_exfiltration: '数据外传',
  shell_command: '命令执行',
  unknown: '未知',
};

interface EvidenceDetail {
  id: number;
  timestamp: string;
  remote_ip: string;
  token: string;
  token_label: string;
  category: string;
  risk_level: string;
  input_preview: string;
  intent_category: string;
  intent_confidence: number;
}

export default function EvidencePanel() {
  const [summaries, setSummaries] = useState<EvidenceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [details, setDetails] = useState<EvidenceDetail[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchSummaries = useCallback(async () => {
    try {
      const data = await listEvidenceSummaries();
      setSummaries(data);
      setError('');
    } catch (e: any) {
      setError(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSummaries();
    const interval = setInterval(fetchSummaries, 15000);
    return () => clearInterval(interval);
  }, [fetchSummaries]);

  const handleSelectIP = async (ip: string) => {
    if (selectedIP === ip) {
      setSelectedIP(null);
      setDetails([]);
      return;
    }
    setSelectedIP(ip);
    setDetailLoading(true);
    try {
      const data = await getEvidenceByIP(ip);
      setDetails(data.events || []);
    } catch {
      setDetails([]);
    } finally {
      setDetailLoading(false);
    }
  };

  if (loading) {
    return <div className="panel-loading">加载证据数据中...</div>;
  }

  if (error) {
    return (
      <div className="panel-error">
        <p>{error}</p>
        <button className="btn btn-primary" onClick={fetchSummaries}>重试</button>
      </div>
    );
  }

  if (summaries.length === 0) {
    return (
      <div className="evidence-panel">
        <div className="panel-header">
          <h2>证据收集</h2>
          <span className="panel-subtitle">暂无攻击证据 — 等待攻击者触发面包屑或执行命令后自动收集</span>
        </div>
        <div className="empty-state">
          <p>📋 暂无证据收集数据</p>
          <p className="hint">攻击者触发蜜罐面包屑、执行探测命令时，系统将自动分析意图并收集证据</p>
        </div>
      </div>
    );
  }

  return (
    <div className="evidence-panel">
      <div className="panel-header">
        <h2>证据收集</h2>
        <span className="panel-subtitle">{summaries.length} 个攻击者 · 自动刷新</span>
      </div>

      <div className="evidence-layout">
        {/* 左侧：攻击者列表 */}
        <div className="evidence-attacker-list">
          <h3>攻击者一览</h3>
          {summaries.map((s) => (
            <div
              key={s.remote_ip}
              className={`evidence-attacker-card ${selectedIP === s.remote_ip ? 'selected' : ''}`}
              onClick={() => handleSelectIP(s.remote_ip)}
            >
              <div className="attacker-ip">{s.remote_ip}</div>
              <div className="attacker-stats">
                <span className="stat-badge">{s.total_evidence} 条证据</span>
                <span className="stat-time">{s.last_seen?.slice(0, 19).replace('T', ' ')}</span>
              </div>
              {s.top_categories.length > 0 && (
                <div className="attacker-cats">
                  {s.top_categories.map((c) => (
                    <span key={c.category} className="cat-tag">{c.category} ({c.count})</span>
                  ))}
                </div>
              )}
              {s.live_tokens.length > 0 && (
                <div className="live-tokens">
                  <span className="tokens-label">实时令牌:</span>
                  {s.live_tokens.map((t) => (
                    <span key={t} className="token-tag">{TOKEN_LABELS[t] || t}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* 右侧：证据详情 */}
        <div className="evidence-detail">
          {!selectedIP ? (
            <div className="detail-empty">← 选择一个攻击者查看证据详情</div>
          ) : detailLoading ? (
            <div className="detail-loading">加载详情中...</div>
          ) : (
            <>
              <h3>证据详情 — {selectedIP} ({details.length} 条记录)</h3>
              {details.length === 0 ? (
                <div className="empty-state small">该攻击者暂无证据记录</div>
              ) : (
                <div className="evidence-table-wrap">
                  <table className="evidence-table">
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>证据令牌</th>
                        <th>类别</th>
                        <th>风险</th>
                        <th>意图分类</th>
                        <th>输入预览</th>
                      </tr>
                    </thead>
                    <tbody>
                      {details.map((d) => (
                        <tr key={d.id}>
                          <td className="col-time">{d.timestamp?.slice(0, 19).replace('T', ' ')}</td>
                          <td><span className="token-badge">{d.token_label || d.token}</span></td>
                          <td>{d.category}</td>
                          <td>
                            <span
                              className="risk-badge"
                              style={{ backgroundColor: RISK_COLORS[d.risk_level] || '#999' }}
                            >
                              {d.risk_level}
                            </span>
                          </td>
                          <td>
                            {d.intent_category ? (
                              <span className="intent-badge">
                                {INTENT_LABELS[d.intent_category] || d.intent_category}
                                {d.intent_confidence > 0 && (
                                  <span className="confidence">{(d.intent_confidence * 100).toFixed(0)}%</span>
                                )}
                              </span>
                            ) : '-'}
                          </td>
                          <td className="col-input" title={d.input_preview}>
                            {d.input_preview?.length > 60
                              ? d.input_preview.slice(0, 60) + '...'
                              : d.input_preview || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
