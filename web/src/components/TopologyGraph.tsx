import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { Graph } from '@antv/g6';
import { apiFetch } from '../api';

// ---------- 类型定义 ----------
interface TopoNode {
  id: string;
  label: string;
  type: string; // attacker, honeypot, asset
  ip: string;
  status?: string;
  data?: Record<string, unknown>;
}

interface TopoEdge {
  source: string;
  target: string;
  label: string;
  edgeType: string; // attack, countermeasure, internal
  tactic?: string;
  techniqueID?: string;
  data?: Record<string, unknown>;
}

interface AttackerStep {
  service: string;
  tactic: string;
  techniqueID: string;
  label: string;
  lastTime: string;
}

interface Countermeasure {
  toolName: string;
  path: string;
  tactic: string;
  techniqueID: string;
  timestamp: string;
}

interface AttackerChain {
  ip: string;
  attacks: AttackerStep[];
  counters: Countermeasure[];
}

interface TacticCover {
  tactic: string;
  tacticCN: string;
  techniqueID: string;
  count: number;
}

interface TopologyData {
  nodes: TopoNode[];
  edges: TopoEdge[];
  chains?: AttackerChain[];
  tacticCoverage?: TacticCover[];
}

interface DetailInfo {
  type: 'node' | 'edge';
  id: string;
  label: string;
  nodeType?: string;
  ip?: string;
  status?: string;
  edgeType?: string;
  tactic?: string;
  techniqueID?: string;
  data?: Record<string, unknown>;
}

// ---------- 常量 ----------
const NODE_COLORS: Record<string, { fill: string; stroke: string }> = {
  attacker: { fill: '#ef4444', stroke: '#dc2626' },
  honeypot: { fill: '#3b82f6', stroke: '#2563eb' },
  asset: { fill: '#22c55e', stroke: '#16a34a' },
};

const EDGE_STYLES: Record<string, { stroke: string; lineDash?: number[]; lineWidth: number }> = {
  attack: { stroke: '#ef4444', lineWidth: 2 },
  countermeasure: { stroke: '#06b6d4', lineDash: [6, 3], lineWidth: 3 },
  internal: { stroke: '#4b5563', lineDash: [4, 4], lineWidth: 1 },
};

const TACTIC_NAMES: Record<string, string> = {
  Reconnaissance: '侦察',
  'Initial Access': '初始访问',
  Execution: '执行',
  Persistence: '持久化',
  'Credential Access': '凭证访问',
  Discovery: '发现',
  'Lateral Movement': '横向移动',
  Collection: '采集',
  'Command and Control': '命令与控制',
  Exfiltration: '数据渗出',
  Impact: '影响',
};

const TACTIC_COLORS: Record<string, string> = {
  Reconnaissance: '#f59e0b',
  'Initial Access': '#ef4444',
  Execution: '#dc2626',
  Persistence: '#8b5cf6',
  'Credential Access': '#ec4899',
  Discovery: '#3b82f6',
  'Lateral Movement': '#06b6d4',
  Collection: '#10b981',
  'Command and Control': '#f97316',
};

const TYPE_LABELS: Record<string, string> = {
  attacker: '攻击源',
  honeypot: '蜜罐节点',
  asset: '核心资产',
};

// ---------- 组件 ----------
export default function TopologyGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);
  const [detail, setDetail] = useState<DetailInfo | null>(null);
  const [topoData, setTopoData] = useState<TopologyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedChains, setExpandedChains] = useState<Set<string>>(new Set());
  const [highlightPath, setHighlightPath] = useState<string | null>(null);

  const fetchTopology = useCallback(async () => {
    try {
      const res = await apiFetch('/api/topology');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: TopologyData = await res.json();
      setTopoData(data);
    } catch (err) {
      console.error('[TopologyGraph] 获取拓扑失败:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  // 构建 G6 图
  useEffect(() => {
    if (!containerRef.current || !topoData) return;
    if (graphRef.current) { graphRef.current.destroy(); graphRef.current = null; }

    const width = containerRef.current.clientWidth || 900;
    const height = 500;

    // 转换节点
    const g6Nodes = topoData.nodes.map((n) => {
      const colors = NODE_COLORS[n.type] || { fill: '#6b7280', stroke: '#4b5563' };
      const isAttacker = n.type === 'attacker';
      return {
        id: n.id,
        data: { ...n, label: n.label },
        style: {
          fill: colors.fill,
          stroke: colors.stroke,
          lineWidth: 2,
          radius: isAttacker ? 20 : 6,
          size: [Math.max(n.label.length * 10 + 20, 110), 32] as [number, number],
          labelText: n.label,
          labelFill: '#e2e8f0',
          labelFontSize: 11,
          labelFontFamily: "'SF Mono','Fira Code',monospace",
          labelPlacement: 'center' as const,
        },
      };
    });

    // 转换边
    const g6Edges = topoData.edges.map((e) => {
      const style = EDGE_STYLES[e.edgeType] || EDGE_STYLES.attack;
      return {
        source: e.source,
        target: e.target,
        data: { ...e },
        style: {
          stroke: e.edgeType === 'countermeasure' ? '#06b6d4' : style.stroke,
          lineWidth: style.lineWidth,
          lineDash: style.lineDash,
          targetArrow: true,
          labelText: e.label,
          labelFill: '#94a3b8',
          labelFontSize: 9,
          labelBackground: true,
          labelBackgroundFill: '#0f172a',
          labelBackgroundOpacity: 0.85,
        },
        state: {},
      };
    });

    const graph = new Graph({
      container: containerRef.current,
      width,
      height,
      data: { nodes: g6Nodes, edges: g6Edges },
      layout: {
        type: 'dagre',
        rankdir: 'TB',
        ranksep: 80,
        nodesep: 40,
      },
      behaviors: ['drag-canvas', 'zoom-canvas'],
      autoFit: 'view',
      animation: true,
      node: {
        style: { cursor: 'pointer' },
      },
      edge: {
        style: { cursor: 'pointer' },
      },
    });

    graph.render();

    // 节点点击
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    graph.on('node:click', (evt: any) => {
      const nodeId = evt.target?.id;
      const nodeData = topoData.nodes.find((n) => n.id === nodeId);
      if (nodeData) {
        setHighlightPath(null);
        setDetail({
          type: 'node',
          id: nodeData.id,
          label: nodeData.label,
          nodeType: nodeData.type,
          ip: nodeData.ip || '',
          status: nodeData.status,
          data: nodeData.data,
        });
      }
    });

    // 边点击 — 高亮溯源反制路径
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    graph.on('edge:click', (evt: any) => {
      const edgeId = evt.target?.id;
      const edgeData = topoData.edges.find(
        (e) => `${e.source}-${e.target}` === edgeId
      );
      if (edgeData) {
        if (edgeData.edgeType === 'countermeasure') {
          setHighlightPath(`${edgeData.source}-${edgeData.target}`);
        }
        setDetail({
          type: 'edge',
          id: `${edgeData.source} → ${edgeData.target}`,
          label: edgeData.label,
          edgeType: edgeData.edgeType,
          tactic: edgeData.tactic,
          techniqueID: edgeData.techniqueID,
          data: edgeData.data,
        });
      }
    });

    graph.on('canvas:click', () => {
      setDetail(null);
      setHighlightPath(null);
    });

    graphRef.current = graph;

    const handleResize = () => {
      if (containerRef.current && graphRef.current) {
        graphRef.current.setSize(containerRef.current.clientWidth, 500);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      if (graphRef.current) { graphRef.current.destroy(); graphRef.current = null; }
    };
  }, [topoData, highlightPath]);

  // 切换攻击链展开
  const toggleChain = (ip: string) => {
    setExpandedChains((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  };

  // 展开所有
  const expandAll = () => {
    if (!topoData?.chains) return;
    setExpandedChains(new Set(topoData.chains.map((c) => c.ip)));
  };

  const collapseAll = () => {
    setExpandedChains(new Set());
  };

  // 统计
  const stats = useMemo(() => {
    if (!topoData) return null;
    const attackEdges = topoData.edges.filter((e) => e.edgeType === 'attack').length;
    const cmEdges = topoData.edges.filter((e) => e.edgeType === 'countermeasure').length;
    const coveredTactics = topoData.tacticCoverage?.filter((t) => t.count > 0).length || 0;
    return { nodes: topoData.nodes.length, attackEdges, cmEdges, coveredTactics };
  }, [topoData]);

  // ---- ATT&CK 战术热量条 ----
  const renderTacticHeatmap = () => {
    if (!topoData?.tacticCoverage || topoData.tacticCoverage.length === 0) return null;
    return (
      <div className="tactic-heatmap">
        <div className="tactic-heatmap-label">ATT&CK 战术覆盖</div>
        <div className="tactic-heatmap-bar">
          {topoData.tacticCoverage.map((tc) => {
            const color = TACTIC_COLORS[tc.tactic] || '#6b7280';
            const active = tc.count > 0;
            return (
              <div
                key={tc.tactic}
                className={`tactic-cell ${active ? 'active' : ''}`}
                style={{
                  '--tactic-color': color,
                } as React.CSSProperties}
                title={`${tc.tacticCN}${tc.techniqueID ? ` (${tc.techniqueID})` : ''}: ${tc.count} 事件`}
              >
                <div className="tactic-dot" style={{ background: active ? color : '#374151' }} />
                <span className="tactic-name">{tc.tacticCN}</span>
                {active && tc.techniqueID && (
                  <span className="tactic-tid">{tc.techniqueID}</span>
                )}
                <span className="tactic-count">{tc.count}</span>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // ---- 攻击链路时间线 ----
  const renderAttackChains = () => {
    if (!topoData?.chains || topoData.chains.length === 0) return null;

    return (
      <div className="attack-chains">
        <div className="chains-header">
          <h3 className="chains-title">攻击链路时间线</h3>
          <div className="chains-actions">
            <button className="btn-chain-action" onClick={expandAll}>展开全部</button>
            <button className="btn-chain-action" onClick={collapseAll}>收起全部</button>
          </div>
        </div>

        {topoData.chains.map((chain) => {
          const isExpanded = expandedChains.has(chain.ip);
          const hasCounter = chain.counters && chain.counters.length > 0;
          return (
            <div key={chain.ip} className={`chain-group ${hasCounter ? 'has-counter' : ''}`}>
              <div className="chain-ip-row" onClick={() => toggleChain(chain.ip)}>
                <span className={`chain-expand-icon ${isExpanded ? 'expanded' : ''}`}>▶</span>
                <span className="chain-ip">{chain.ip}</span>
                <span className="chain-badges">
                  <span className="chain-badge badge-attack">{chain.attacks.length} 攻击</span>
                  {hasCounter && (
                    <span className="chain-badge badge-counter">{chain.counters.length} 反制</span>
                  )}
                </span>
              </div>

              {isExpanded && (
                <div className="chain-detail">
                  {/* 攻击步骤 */}
                  {chain.attacks.map((a, ai) => (
                    <div key={ai} className="chain-step attack-step">
                      <div className="step-connector" style={{ '--step-color': TACTIC_COLORS[a.tactic] || '#6b7280' } as React.CSSProperties} />
                      <div className="step-content">
                        <div className="step-header">
                          <span className="step-service">{a.service}</span>
                          <span className="step-tactic-label" style={{ background: TACTIC_COLORS[a.tactic] || '#374151' }}>
                            {TACTIC_NAMES[a.tactic] || a.tactic}
                          </span>
                          <span className="step-tid">{a.techniqueID}</span>
                        </div>
                        <div className="step-desc">{a.label}</div>
                        {a.lastTime && <div className="step-time">{a.lastTime}</div>}
                      </div>
                    </div>
                  ))}

                  {/* 溯源反制步骤 */}
                  {chain.counters && chain.counters.map((cm, ci) => (
                    <div key={`cm-${ci}`} className="chain-step counter-step">
                      <div className="step-connector counter-connector" />
                      <div className="step-content cm-content">
                        <div className="step-header">
                          <span className="step-service cm-icon">⚡ 溯源反制</span>
                          <span className="step-tactic-label" style={{ background: TACTIC_COLORS[cm.tactic] || '#06b6d4' }}>
                            {TACTIC_NAMES[cm.tactic] || cm.tactic}
                          </span>
                          <span className="step-tid">{cm.techniqueID}</span>
                        </div>
                        <div className="step-desc">
                          <span className="cm-tool">{cm.toolName}</span>
                          <span className="cm-path mono">{cm.path}</span>
                        </div>
                        <div className="step-time">{cm.timestamp}</div>
                      </div>
                    </div>
                  ))}

                  {chain.attacks.length === 0 && chain.counters.length === 0 && (
                    <div className="chain-empty">暂无攻击记录</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="topology-container">
      {/* 头部 */}
      <div className="topology-header">
        <h2 className="section-title">攻击路径 & 溯源反制拓扑</h2>
        <div className="topology-legend">
          <span className="legend-item"><span className="legend-dot attack-dot" />攻击路径</span>
          <span className="legend-item"><span className="legend-dot cm-dot" />溯源反制</span>
          <span className="legend-item"><span className="legend-dot internal-dot" />内部通路</span>
          {highlightPath && (
            <span className="legend-item legend-highlight">
              <span className="legend-pulse" />路径高亮中
            </span>
          )}
          <button className="btn-refresh" onClick={fetchTopology} disabled={loading}>
            {loading ? '加载中...' : '刷新'}
          </button>
        </div>
      </div>

      {/* ATT&CK 战术热量条 */}
      {renderTacticHeatmap()}

      {/* 拓扑图主体 */}
      <div className="topology-main">
        <div ref={containerRef} className="topology-graph" style={{ minHeight: 500 }} />

        {/* 详情侧边栏 */}
        {detail && (
          <div className="detail-sidebar">
            <div className="detail-header">
              <h3>{detail.type === 'node' ? '节点详情' : '路径详情'}</h3>
              <button className="btn-close" onClick={() => setDetail(null)}>✕</button>
            </div>

            <div className="detail-body">
              {detail.type === 'node' && (
                <>
                  <div className="detail-row">
                    <span className="detail-label">节点名称</span>
                    <span className="detail-value">{detail.label}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">类型</span>
                    <span className={`detail-badge badge-${detail.nodeType}`}>
                      {TYPE_LABELS[detail.nodeType || ''] || detail.nodeType}
                    </span>
                  </div>
                  {detail.ip && detail.ip !== '0.0.0.0' && (
                    <div className="detail-row">
                      <span className="detail-label">IP 地址</span>
                      <span className="detail-value mono">{detail.ip}</span>
                    </div>
                  )}
                  {detail.status && (
                    <div className="detail-row">
                      <span className="detail-label">状态</span>
                      <span className={`status-badge status-${detail.status}`}>
                        {detail.status === 'protected' ? '已防护' : detail.status}
                      </span>
                    </div>
                  )}
                  {detail.data && typeof detail.data === 'object' && (
                    <div className="detail-section">
                      <h4>附加信息</h4>
                      <pre className="detail-json">
                        {JSON.stringify(detail.data, null, 2)}
                      </pre>
                    </div>
                  )}
                </>
              )}

              {detail.type === 'edge' && (
                <>
                  <div className="detail-row">
                    <span className="detail-label">路径</span>
                    <span className="detail-value mono">{detail.id}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">操作</span>
                    <span className="detail-value">{detail.label}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">类型</span>
                    <span className={`detail-badge badge-edge-${detail.edgeType}`}>
                      {detail.edgeType === 'attack'
                        ? '攻击行为'
                        : detail.edgeType === 'countermeasure'
                          ? '溯源反制'
                          : detail.edgeType === 'internal'
                            ? '内部通路'
                            : detail.edgeType}
                    </span>
                  </div>
                  {detail.tactic && (
                    <>
                      <div className="detail-row">
                        <span className="detail-label">ATT&CK 战术</span>
                        <span className="detail-value" style={{ color: TACTIC_COLORS[detail.tactic] || '#94a3b8' }}>
                          {TACTIC_NAMES[detail.tactic] || detail.tactic}
                        </span>
                      </div>
                      {detail.techniqueID && (
                        <div className="detail-row">
                          <span className="detail-label">技术编号</span>
                          <span className="detail-value mono" style={{ color: '#f59e0b' }}>
                            {detail.techniqueID}
                          </span>
                        </div>
                      )}
                    </>
                  )}
                  {detail.data && typeof detail.data === 'object' && (
                    <div className="detail-section">
                      <h4>详细信息</h4>
                      <pre className="detail-json">
                        {JSON.stringify(detail.data, null, 2)}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* 攻击链路时间线 */}
      {renderAttackChains()}

      {/* 统计栏 */}
      {stats && (
        <div className="topology-stats-bar">
          <span>节点: {stats.nodes}</span>
          <span>攻击连边: {stats.attackEdges}</span>
          <span>反制连边: {stats.cmEdges}</span>
          <span>ATT&CK 战术覆盖: {stats.coveredTactics}/8</span>
        </div>
      )}
    </div>
  );
}
