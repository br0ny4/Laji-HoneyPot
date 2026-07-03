import { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import Skeleton from './Skeleton';

interface ProfileTag {
  category: string;
  name: string;
  name_cn: string;
  confidence: number;
  source: string;
  detail?: string;
}

interface TTPSignature {
  tactic: string;
  tactic_cn: string;
  technique_id: string;
  count: number;
}

interface FingerprintSummary {
  browser?: string;
  os?: string;
  gpu?: string;
  screen?: string;
  timezone?: string;
  inner_ip?: string;
  hardware_cpus?: number;
  device_memory?: number;
}

interface AttackerProfile {
  ip: string;
  first_seen: string;
  last_seen: string;
  total_connections: number;
  total_attacks: number;
  total_breadcrumbs: number;
  total_fingerprints: number;
  total_countermeasures: number;
  total_post_bodies: number;
  unique_services: string[];
  unique_paths: string[];
  port_scan_count: number;
  avg_req_per_minute: number;
  peak_hour: number;
  active_days: number;
  interaction_depth: number;
  tool_signatures: string[];
  ttp_signatures: TTPSignature[];
  fingerprint_summary?: FingerprintSummary;
  tags: ProfileTag[];
  skill_score: number;
  risk_score: number;
  threat_level: string;
}

interface ProfileStats {
  total_profiles: number;
  skill_dist: Record<string, number>;
  behavior_dist: Record<string, number>;
  motive_dist: Record<string, number>;
  tool_dist: Record<string, number>;
  threat_dist: Record<string, number>;
}

interface TagCategory {
  key: string;
  name: string;
}

const TAG_CATEGORY_LABELS: Record<string, string> = {
  skill: '技术水平',
  behavior: '行为特征',
  motive: '攻击目的',
  tool: '工具偏好',
};

const TAG_CATEGORY_COLORS: Record<string, string> = {
  skill: '#a855f7',
  behavior: '#f59e0b',
  motive: '#ef4444',
  tool: '#3b82f6',
};

const THREAT_LEVEL_MAP: Record<string, { label: string; color: string }> = {
  critical: { label: '严重', color: '#ef4444' },
  high: { label: '高危', color: '#f97316' },
  medium: { label: '中危', color: '#eab308' },
  low: { label: '低危', color: '#22c55e' },
};

export default function AttackerProfilePanel() {
  const [profiles, setProfiles] = useState<AttackerProfile[]>([]);
  const [stats, setStats] = useState<ProfileStats | null>(null);
  const [categories, setCategories] = useState<TagCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTag, setActiveTag] = useState('');
  const [selectedIP, setSelectedIP] = useState('');
  const [detailProfile, setDetailProfile] = useState<AttackerProfile | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    fetchProfiles();
    fetchStats();
    fetchCategories();
  }, [activeTag]);

  async function fetchProfiles() {
    setLoading(true);
    try {
      const params = activeTag ? `?tag=${activeTag}` : '';
      const res = await apiFetch(`/api/profiles${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setProfiles(data.profiles || []);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function fetchStats() {
    try {
      const res = await apiFetch('/api/profiles/stats');
      if (res.ok) setStats(await res.json());
    } catch {}
  }

  async function fetchCategories() {
    try {
      const res = await apiFetch('/api/profiles/tags');
      if (res.ok) {
        const data = await res.json();
        setCategories(data.categories || []);
      }
    } catch {}
  }

  async function fetchProfileDetail(ip: string) {
    setDetailLoading(true);
    try {
      const res = await apiFetch(`/api/profiles?ip=${encodeURIComponent(ip)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setDetailProfile(await res.json());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDetailLoading(false);
    }
  }

  function handleViewDetail(ip: string) {
    setSelectedIP(ip);
    fetchProfileDetail(ip);
  }

  function handleCloseDetail() {
    setSelectedIP('');
    setDetailProfile(null);
  }

  const tagsByCategory = (tags: ProfileTag[], cat: string) =>
    tags.filter((t) => t.category === cat);

  if (loading && profiles.length === 0) {
    return (
      <div>
        <div className="profile-stats-grid">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} variant="card" />
          ))}
        </div>
        <div className="panel-header">
          <h3 className="section-title" style={{ margin: 0 }}>攻击者画像</h3>
        </div>
        <div className="profile-list">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="profile-card" style={{ padding: 16 }}>
              <Skeleton variant="text" rows={3} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      {error && (
        <div className="panel-half" style={{ marginBottom: 12, borderColor: '#7f1d1d', color: '#fca5a5', fontSize: 13 }}>
          错误: {error}
          <button className="btn-refresh" style={{ marginLeft: 12 }} onClick={fetchProfiles}>重试</button>
        </div>
      )}

      {/* 标签统计大盘 */}
      {stats && (
        <div className="profile-stats-grid">
          <div className="profile-stats-card">
            <div className="ps-value">{stats.total_profiles}</div>
            <div className="ps-label">画像总数</div>
          </div>
          {Object.entries(stats.threat_dist).map(([k, v]) => (
            <div key={k} className="profile-stats-card" style={{ borderColor: THREAT_LEVEL_MAP[k]?.color + '40' }}>
              <div className="ps-value" style={{ color: THREAT_LEVEL_MAP[k]?.color }}>
                {v}
              </div>
              <div className="ps-label">{THREAT_LEVEL_MAP[k]?.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* 标签分类筛选 */}
      <div className="panel-header">
        <h3 className="section-title" style={{ margin: 0 }}>
          攻击者画像 {activeTag && <span style={{ color: '#64748b', fontSize: 13 }}>— 筛选: {TAG_CATEGORY_LABELS[activeTag] || activeTag}</span>}
        </h3>
        <div className="panel-controls">
          <div className="tag-filter-chips">
            <button
              className={`filter-chip ${activeTag === '' ? 'active' : ''}`}
              onClick={() => setActiveTag('')}
            >
              全部
            </button>
            {categories.map((cat) => (
              <button
                key={cat.key}
                className={`filter-chip ${activeTag === cat.key ? 'active' : ''}`}
                onClick={() => setActiveTag(cat.key)}
                style={activeTag === cat.key ? { borderColor: TAG_CATEGORY_COLORS[cat.key], color: TAG_CATEGORY_COLORS[cat.key] } : {}}
              >
                {cat.name}
              </button>
            ))}
          </div>
          <button className="btn-refresh" onClick={fetchProfiles} disabled={loading}>
            {loading ? '刷新中...' : '刷新'}
          </button>
        </div>
      </div>

      {/* 画像列表 */}
      <div className="profile-list">
        {profiles.length === 0 ? (
          <div className="empty-hint">暂无攻击者画像数据</div>
        ) : (
          profiles.map((p) => (
            <div
              key={p.ip}
              className={`profile-card ${selectedIP === p.ip ? 'selected' : ''}`}
              onClick={() => handleViewDetail(p.ip)}
            >
              <div className="pc-header">
                <div className="pc-ip-row">
                  <span className="pc-ip mono">{p.ip}</span>
                  <span className="pc-threat" style={{ background: THREAT_LEVEL_MAP[p.threat_level]?.color + '20', color: THREAT_LEVEL_MAP[p.threat_level]?.color }}>
                    {THREAT_LEVEL_MAP[p.threat_level]?.label}
                  </span>
                </div>
                <div className="pc-score">
                  <span title="技能评分">技能 {p.skill_score}</span>
                  <span className="pc-divider">|</span>
                  <span title="风险评分">风险 {p.risk_score}</span>
                </div>
              </div>

              {/* 标签区 */}
              <div className="pc-tags">
                {p.tags.map((t, i) => (
                  <span
                    key={i}
                    className="profile-tag"
                    style={{ background: TAG_CATEGORY_COLORS[t.category] + '20', color: TAG_CATEGORY_COLORS[t.category], borderColor: TAG_CATEGORY_COLORS[t.category] + '40' }}
                    title={`${t.name_cn} (${t.confidence}%)`}
                  >
                    {t.name_cn}
                  </span>
                ))}
              </div>

              {/* 基础指标 */}
              <div className="pc-metrics">
                <div className="pc-metric">
                  <span className="pc-metric-val">{p.total_connections}</span>
                  <span className="pc-metric-label">连接</span>
                </div>
                <div className="pc-metric">
                  <span className="pc-metric-val">{p.total_breadcrumbs}</span>
                  <span className="pc-metric-label">面包屑</span>
                </div>
                <div className="pc-metric">
                  <span className="pc-metric-val">{p.unique_services?.length || 0}</span>
                  <span className="pc-metric-label">服务</span>
                </div>
                <div className="pc-metric">
                  <span className="pc-metric-val">{p.active_days}d</span>
                  <span className="pc-metric-label">活跃</span>
                </div>
                <div className="pc-metric">
                  <span className="pc-metric-val">{p.port_scan_count}</span>
                  <span className="pc-metric-label">端口扫描</span>
                </div>
              </div>

              {/* TTP 简要 */}
              {p.ttp_signatures && p.ttp_signatures.length > 0 && (
                <div className="pc-ttps">
                  {p.ttp_signatures.slice(0, 4).map((ttp, i) => (
                    <span key={i} className="pc-ttp-chip" title={`${ttp.tactic_cn} — ${ttp.technique_id}`}>
                      {ttp.technique_id}
                    </span>
                  ))}
                  {p.ttp_signatures.length > 4 && (
                    <span className="pc-ttp-more">+{p.ttp_signatures.length - 4}</span>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* 详情侧栏 */}
      {(selectedIP && detailLoading) && (
        <div className="profile-detail-overlay">
          <div className="profile-detail-panel">
            <div className="loading" style={{ padding: 40 }}>加载画像详情...</div>
          </div>
        </div>
      )}
      {selectedIP && detailProfile && !detailLoading && (
        <div className="profile-detail-overlay" onClick={(e) => { if (e.target === e.currentTarget) handleCloseDetail(); }}>
          <div className="profile-detail-panel">
            <div className="detail-header">
              <div>
                <h3 className="mono">{detailProfile.ip}</h3>
                <span className="pc-threat" style={{ background: THREAT_LEVEL_MAP[detailProfile.threat_level]?.color + '20', color: THREAT_LEVEL_MAP[detailProfile.threat_level]?.color, marginTop: 4, display: 'inline-block' }}>
                  {THREAT_LEVEL_MAP[detailProfile.threat_level]?.label} — 技能{detailProfile.skill_score} / 风险{detailProfile.risk_score}
                </span>
              </div>
              <button className="btn-close" onClick={handleCloseDetail}>✕</button>
            </div>

            <div className="detail-body">
              {/* 基础信息 */}
              <div className="detail-section">
                <h4>基础信息</h4>
                <div className="detail-row"><span className="detail-label">首次发现</span><span className="detail-value">{detailProfile.first_seen}</span></div>
                <div className="detail-row"><span className="detail-label">最近活跃</span><span className="detail-value">{detailProfile.last_seen}</span></div>
                <div className="detail-row"><span className="detail-label">活跃天数</span><span className="detail-value">{detailProfile.active_days} 天</span></div>
                <div className="detail-row"><span className="detail-label">峰值时段</span><span className="detail-value">{detailProfile.peak_hour}:00 - {detailProfile.peak_hour + 1}:00</span></div>
                <div className="detail-row"><span className="detail-label">请求频率</span><span className="detail-value">{detailProfile.avg_req_per_minute.toFixed(1)} req/min</span></div>
                <div className="detail-row"><span className="detail-label">交互深度</span><span className="detail-value">{detailProfile.interaction_depth}%</span></div>
              </div>

              {/* 攻击统计 */}
              <div className="detail-section">
                <h4>攻击统计</h4>
                <div className="detail-row"><span className="detail-label">连接数</span><span className="detail-value">{detailProfile.total_connections}</span></div>
                <div className="detail-row"><span className="detail-label">面包屑触发</span><span className="detail-value">{detailProfile.total_breadcrumbs}</span></div>
                <div className="detail-row"><span className="detail-label">反制事件</span><span className="detail-value">{detailProfile.total_countermeasures}</span></div>
                <div className="detail-row"><span className="detail-label">端口扫描</span><span className="detail-value">{detailProfile.port_scan_count}</span></div>
                <div className="detail-row"><span className="detail-label">POST载荷</span><span className="detail-value">{detailProfile.total_post_bodies}</span></div>
                {detailProfile.unique_services && detailProfile.unique_services.length > 0 && (
                  <div className="detail-row">
                    <span className="detail-label">目标服务</span>
                    <span className="detail-value">
                      {detailProfile.unique_services.map((s) => (
                        <span key={s} className="service-tag" style={{ marginRight: 4 }}>{s}</span>
                      ))}
                    </span>
                  </div>
                )}
              </div>

              {/* 工具签名 */}
              {detailProfile.tool_signatures && detailProfile.tool_signatures.length > 0 && (
                <div className="detail-section">
                  <h4>工具特征</h4>
                  <div className="detail-value">
                    {detailProfile.tool_signatures.map((t) => (
                      <span key={t} className="profile-tag" style={{ background: '#3b82f620', color: '#3b82f6', border: '1px solid #3b82f640', marginRight: 6 }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 指纹信息 */}
              {detailProfile.fingerprint_summary && (
                <div className="detail-section">
                  <h4>设备指纹</h4>
                  {detailProfile.fingerprint_summary.browser && (
                    <div className="detail-row"><span className="detail-label">浏览器</span><span className="detail-value">{detailProfile.fingerprint_summary.browser}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.os && (
                    <div className="detail-row"><span className="detail-label">操作系统</span><span className="detail-value">{detailProfile.fingerprint_summary.os}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.gpu && (
                    <div className="detail-row"><span className="detail-label">GPU</span><span className="detail-value">{detailProfile.fingerprint_summary.gpu}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.screen && (
                    <div className="detail-row"><span className="detail-label">屏幕</span><span className="detail-value">{detailProfile.fingerprint_summary.screen}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.timezone && (
                    <div className="detail-row"><span className="detail-label">时区</span><span className="detail-value">{detailProfile.fingerprint_summary.timezone}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.inner_ip && (
                    <div className="detail-row"><span className="detail-label">内网IP</span><span className="detail-value mono">{detailProfile.fingerprint_summary.inner_ip}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.hardware_cpus != null && detailProfile.fingerprint_summary.hardware_cpus > 0 && (
                    <div className="detail-row"><span className="detail-label">CPU核数</span><span className="detail-value">{detailProfile.fingerprint_summary.hardware_cpus}</span></div>
                  )}
                  {detailProfile.fingerprint_summary.device_memory != null && detailProfile.fingerprint_summary.device_memory > 0 && (
                    <div className="detail-row"><span className="detail-label">设备内存</span><span className="detail-value">{detailProfile.fingerprint_summary.device_memory}GB</span></div>
                  )}
                </div>
              )}

              {/* 全量标签 */}
              <div className="detail-section">
                <h4>威胁标签 ({detailProfile.tags?.length || 0})</h4>
                {['skill', 'behavior', 'motive', 'tool'].map((cat) => {
                  const catTags = tagsByCategory(detailProfile.tags, cat);
                  if (catTags.length === 0) return null;
                  return (
                    <div key={cat} style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{TAG_CATEGORY_LABELS[cat]}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {catTags.map((t, i) => (
                          <span
                            key={i}
                            className="profile-tag"
                            style={{ background: TAG_CATEGORY_COLORS[t.category] + '20', color: TAG_CATEGORY_COLORS[t.category], border: `1px solid ${TAG_CATEGORY_COLORS[t.category]}40` }}
                            title={t.detail || `置信度 ${t.confidence}%`}
                          >
                            {t.name_cn}
                            <span style={{ marginLeft: 4, fontSize: 10, opacity: 0.7 }}>{t.confidence}%</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* TTP 技术图谱 */}
              {detailProfile.ttp_signatures && detailProfile.ttp_signatures.length > 0 && (
                <div className="detail-section">
                  <h4>TTPs 技术图谱</h4>
                  <div className="ttp-graph">
                    {detailProfile.ttp_signatures.map((ttp, i) => (
                      <div key={i} className="ttp-bar-row">
                        <span className="ttp-bar-tactic">{ttp.tactic_cn}</span>
                        <span className="ttp-bar-id mono">{ttp.technique_id}</span>
                        <div className="ttp-bar-track">
                          <div
                            className="ttp-bar-fill"
                            style={{ width: `${Math.min(ttp.count * 20, 100)}%` }}
                          />
                        </div>
                        <span className="ttp-bar-cnt">{ttp.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 访问路径 */}
              {detailProfile.unique_paths && detailProfile.unique_paths.length > 0 && (
                <div className="detail-section">
                  <h4>访问路径 ({detailProfile.unique_paths.length})</h4>
                  <div className="detail-json" style={{ maxHeight: 150 }}>
                    {detailProfile.unique_paths.slice(0, 20).join('\n')}
                    {detailProfile.unique_paths.length > 20 && `\n... 共 ${detailProfile.unique_paths.length} 条路径`}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
