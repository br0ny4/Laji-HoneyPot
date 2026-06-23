import { useEffect, useRef, useState, useCallback } from 'react';
import { Graph, type GraphOptions } from '@antv/g6';
import { apiFetch } from '../api';

interface TopoNode {
  id: string;
  label: string;
  type: string;
  ip: string;
  status?: string;
  data?: Record<string, unknown>;
}

interface TopoEdge {
  source: string;
  target: string;
  label: string;
  edgeType: string;
  data?: Record<string, unknown>;
}

interface TopologyData {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

interface DetailInfo {
  type: 'node' | 'edge';
  id: string;
  label: string;
  nodeType?: string;
  ip?: string;
  status?: string;
  edgeType?: string;
  data?: Record<string, unknown>;
}

const NODE_COLORS: Record<string, { fill: string; stroke: string }> = {
  attacker: { fill: '#ef4444', stroke: '#dc2626' },
  honeypot: { fill: '#3b82f6', stroke: '#2563eb' },
  asset: { fill: '#22c55e', stroke: '#16a34a' },
};

const EDGE_COLORS: Record<string, { stroke: string; lineDash?: number[] }> = {
  attack: { stroke: '#ef4444' },
  countermeasure: { stroke: '#3b82f6', lineDash: [5, 5] },
  internal: { stroke: '#6b7280', lineDash: [3, 3] },
};

export default function TopologyGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);
  const [detail, setDetail] = useState<DetailInfo | null>(null);
  const [topoData, setTopoData] = useState<TopologyData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchTopology = useCallback(async () => {
    try {
      const res = await apiFetch('/api/topology');
      const data: TopologyData = await res.json();
      setTopoData(data);
    } catch {
      // keep stale data
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  useEffect(() => {
    if (!containerRef.current || !topoData) return;

    if (graphRef.current) {
      graphRef.current.destroy();
    }

    const width = containerRef.current.clientWidth;
    const height = 600;

    // 转换节点
    const nodes = topoData.nodes.map((n) => {
      const colors = NODE_COLORS[n.type] || { fill: '#6b7280', stroke: '#4b5563' };
      return {
        id: n.id,
        data: {
          label: n.label,
          nodeType: n.type,
          ip: n.ip,
          status: n.status,
          topoData: n.data,
        },
        style: {
          fill: colors.fill,
          stroke: colors.stroke,
          lineWidth: 2,
          radius: n.type === 'attacker' ? 20 : 8,
          size: [Math.max(n.label.length * 10, 100), 36] as [number, number],
          labelFill: '#ffffff',
          labelFontSize: n.type === 'attacker' ? 10 : 12,
          labelFontFamily: 'monospace',
          labelText: n.label,
        },
        type: 'rect',
      };
    });

    // 转换边
    const edges = topoData.edges.map((e) => {
      const colors = EDGE_COLORS[e.edgeType] || { stroke: '#6b7280' };
      return {
        source: e.source,
        target: e.target,
        data: {
          label: e.label,
          edgeType: e.edgeType,
          edgeData: e.data,
        },
        style: {
          stroke: colors.stroke,
          lineWidth: e.edgeType === 'countermeasure' ? 2.5 : 1.5,
          lineDash: colors.lineDash,
          targetArrow: true,
          labelText: e.label,
          labelFill: '#94a3b8',
          labelFontSize: 10,
          labelBackground: true,
          labelBackgroundFill: '#0f172a',
        },
      };
    });

    const graph = new Graph({
      container: containerRef.current,
      width,
      height,
      data: { nodes, edges } as GraphOptions['data'],
      layout: {
        type: 'force',
        preventOverlap: true,
        nodeStrength: -200,
        edgeStrength: 0.3,
        linkDistance: 150,
      },
      behaviors: ['drag-canvas', 'zoom-canvas', 'drag-element'],
      autoFit: 'view',
      animation: true,
    });

    graph.render();

    // 节点点击 → 侧边栏
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    graph.on('node:click', (evt: any) => {
      const nodeId = evt.target?.id;
      const nodeData = topoData.nodes.find((n) => n.id === nodeId);
      if (nodeData) {
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

    // 边点击 → 侧边栏
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    graph.on('edge:click', (evt: any) => {
      const edgeId = evt.target?.id;
      const edgeData = topoData.edges.find(
        (e) => `${e.source}-${e.target}` === edgeId || e.source + '-' + e.target === edgeId
      );
      if (edgeData) {
        setDetail({
          type: 'edge',
          id: `${edgeData.source} → ${edgeData.target}`,
          label: edgeData.label,
          edgeType: edgeData.edgeType,
          data: edgeData.data,
        });
      }
    });

    // 点击画布空白 → 关闭侧边栏
    graph.on('canvas:click', () => {
      setDetail(null);
    });

    graphRef.current = graph;

    // 响应式 resize
    const handleResize = () => {
      if (containerRef.current && graphRef.current) {
        const w = containerRef.current.clientWidth;
        graphRef.current.setSize(w, 600);
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (graphRef.current) {
        graphRef.current.destroy();
        graphRef.current = null;
      }
    };
  }, [topoData]);

  const typeLabels: Record<string, string> = {
    attacker: '攻击源',
    honeypot: '蜜罐节点',
    asset: '核心资产',
  };

  return (
    <div className="topology-container">
      <div className="topology-header">
        <h2 className="section-title">攻击路径 & 溯源反制拓扑</h2>
        <div className="topology-legend">
          <span className="legend-item"><span className="legend-dot attack-dot" />攻击路径</span>
          <span className="legend-item"><span className="legend-dot cm-dot" />溯源反制</span>
          <span className="legend-item"><span className="legend-dot internal-dot" />内部通路</span>
          <button className="btn-refresh" onClick={fetchTopology} disabled={loading}>
            {loading ? '加载中...' : '刷新'}
          </button>
        </div>
      </div>

      <div className="topology-main">
        <div
          ref={containerRef}
          className="topology-graph"
          style={{ minHeight: 600 }}
        />

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
                      {typeLabels[detail.nodeType || ''] || detail.nodeType}
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

      {topoData && (
        <div className="topology-stats-bar">
          <span>节点: {topoData.nodes.length}</span>
          <span>攻击连边: {topoData.edges.filter(e => e.edgeType === 'attack').length}</span>
          <span>反制连边: {topoData.edges.filter(e => e.edgeType === 'countermeasure').length}</span>
        </div>
      )}
    </div>
  );
}
