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

// 资产扫描结果中单个服务信息
interface ServiceInfo {
  host: string;
  port: number;
  open: boolean;
  protocol: string;
  service: string;
  banner: string;
  scanned: string;
}

// 资产扫描结果汇总
interface ScanResult {
  total: number;
  open: number;
  services: ServiceInfo[];
  duration: string;
}

export default function AssetLedger() {
  const [attackers, setAttackers] = useState<AttackerSummary[]>([]);
  const [selected, setSelected] = useState<AttackerSummary | null>(null);
  // 资产扫描状态
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState('');

  useEffect(() => {
    apiFetch('/api/attackers?limit=100')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setAttackers(d.attackers || []))
      .catch((err) => console.error('[AssetLedger] 获取攻击者列表失败:', err));
  }, []);

  // 触发端口扫描
  const handleScan = async () => {
    setScanning(true);
    setScanError('');
    try {
      const r = await apiFetch('/api/assets/scan', { method: 'POST' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data: ScanResult = await r.json();
      setScanResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setScanError(`扫描失败: ${msg}`);
    } finally {
      setScanning(false);
    }
  };

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
          <button
            className="btn-scan"
            onClick={handleScan}
            disabled={scanning}
            style={{ marginLeft: 12 }}
          >
            {scanning ? '扫描中...' : '扫描端口'}
          </button>
        </span>
      </div>

      {/* 扫描错误提示 */}
      {scanError && (
        <div className="scan-error" style={{ padding: '8px 16px', color: '#e74c3c', background: '#fdf0ef', borderRadius: 6, margin: '0 16px 12px' }}>
          {scanError}
        </div>
      )}

      {/* 资产扫描结果 - 服务清单 */}
      {scanResult && (
        <div className="asset-inventory" style={{ margin: '0 16px 16px', border: '1px solid #2d3a4f', borderRadius: 8, overflow: 'hidden' }}>
          <div className="inventory-header" style={{ padding: '10px 16px', background: '#1a2332', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: 14, color: '#c8d6e5' }}>
              服务清单
              <span style={{ marginLeft: 8, fontSize: 12, color: '#5a6988' }}>
                共 {scanResult.total} 端口 · {scanResult.open} 开放 · 耗时 {scanResult.duration}
              </span>
            </h3>
            <button
              className="btn-link"
              onClick={() => setScanResult(null)}
              style={{ color: '#5a6988' }}
            >
              收起
            </button>
          </div>
          <table className="data-table" style={{ margin: 0 }}>
            <thead>
              <tr>
                <th>主机</th>
                <th>端口</th>
                <th>状态</th>
                <th>服务</th>
                <th>Banner</th>
                <th>扫描时间</th>
              </tr>
            </thead>
            <tbody>
              {scanResult.services
                .filter((s) => s.open) // 仅展示开放端口
                .map((svc, i) => (
                  <tr key={`${svc.host}:${svc.port}-${i}`}>
                    <td className="mono">{svc.host}</td>
                    <td className="mono">{svc.port}</td>
                    <td>
                      <span style={{ color: '#27ae60', fontWeight: 600 }}>开放</span>
                    </td>
                    <td>
                      {svc.service ? (
                        <span className="service-tag">{svc.service}</span>
                      ) : (
                        <span style={{ color: '#5a6988' }}>未知</span>
                      )}
                    </td>
                    <td className="mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={svc.banner}>
                      {svc.banner || '-'}
                    </td>
                    <td className="cell-time">{svc.scanned.slice(0, 19)}</td>
                  </tr>
                ))}
              {scanResult.services.filter((s) => s.open).length === 0 && (
                <tr>
                  <td colSpan={6} className="empty-hint">
                    {scanning ? '正在扫描...' : '未发现开放端口 — 本机可能已启用防火墙'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

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
