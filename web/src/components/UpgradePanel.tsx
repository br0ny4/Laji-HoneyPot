import { useState, useEffect, useRef } from 'react';
import { listUpgradeJobs, createUpgradeJob, cancelUpgradeJob, UpgradeJob } from '../api';

interface UpgradePanelProps {
  nodes: Array<{ node_id: string; online: boolean }>;
  preselectedNode?: string;
}

const STATUS_LABELS: Record<string, string> = {
  pending: '待下载',
  downloading: '下载中',
  installing: '安装中',
  complete: '已完成',
  failed: '失败',
  rollback: '已回滚',
  cancelled: '已取消',
};

const STATUS_COLORS: Record<string, string> = {
  pending: '#f0c040',
  downloading: '#5dade2',
  installing: '#8e44ad',
  complete: '#27ae60',
  failed: '#e74c3c',
  rollback: '#e67e22',
  cancelled: '#7f8c8d',
};

export default function UpgradePanel({ nodes, preselectedNode }: UpgradePanelProps) {
  const [jobs, setJobs] = useState<UpgradeJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState('');
  const [targetVersion, setTargetVersion] = useState('0.19.0');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  const [toastMsg, setToastMsg] = useState('');

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const toast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 2500);
  };

  const fetchJobs = async () => {
    try {
      const data = await listUpgradeJobs();
      setJobs(data);
      setError('');
    } catch (e) {
      setError(`获取升级任务失败: ${e instanceof Error ? e.message : String(e)}`);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchJobs();
    pollRef.current = setInterval(fetchJobs, 8000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  // 当从集群管理跳转过来时，自动预选节点
  useEffect(() => {
    if (preselectedNode) {
      setSelectedNode(preselectedNode);
    }
  }, [preselectedNode]);

  const handleCreate = async () => {
    if (!selectedNode) {
      setCreateError('请选择目标节点');
      return;
    }
    if (!targetVersion.trim()) {
      setCreateError('请输入目标版本号');
      return;
    }
    setCreating(true);
    setCreateError('');
    try {
      await createUpgradeJob(selectedNode, targetVersion.trim());
      toast(`升级任务已创建: ${selectedNode} → ${targetVersion}`);
      setSelectedNode('');
      setTargetVersion('0.19.0');
      fetchJobs();
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : String(e));
    }
    setCreating(false);
  };

  const handleCancel = async (jobID: string) => {
    try {
      await cancelUpgradeJob(jobID);
      toast('升级任务已取消');
      fetchJobs();
    } catch (e) {
      toast(`取消失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const onlineNodes = nodes.filter(n => n.online);

  return (
    <div className="attack-panel">
      <div className="panel-header">
        <h2 className="section-title">Agent 升级管理</h2>
        <span className="panel-controls">
          <span className="stat-chip" style={{ marginLeft: 8 }}>
            {jobs.length} 个任务
          </span>
        </span>
      </div>

      {/* Toast */}
      {toastMsg && <div className="toast-notification toast-visible">{toastMsg}</div>}

      {/* 创建升级任务 */}
      <div style={{ padding: '16px', borderBottom: '1px solid #2d3a4f' }}>
        <h3 style={{ margin: '0 0 12px 0', fontSize: 14, color: '#c8d6e5' }}>创建升级任务</h3>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label style={{ fontSize: 12, color: '#8899aa' }}>目标节点</label>
            <select
              value={selectedNode}
              onChange={e => setSelectedNode(e.target.value)}
              style={{
                padding: '6px 12px',
                background: '#1a2332',
                color: '#c8d6e5',
                border: '1px solid #2d3a4f',
                borderRadius: 4,
                fontSize: 13,
              }}
            >
              <option value="">选择节点...</option>
              {onlineNodes.map(n => (
                <option key={n.node_id} value={n.node_id}>
                  {n.node_id.length > 20 ? n.node_id.slice(0, 20) + '...' : n.node_id}
                </option>
              ))}
              {onlineNodes.length === 0 && (
                <option disabled>暂无在线节点</option>
              )}
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label style={{ fontSize: 12, color: '#8899aa' }}>目标版本</label>
            <input
              type="text"
              value={targetVersion}
              onChange={e => setTargetVersion(e.target.value)}
              placeholder="0.19.0"
              style={{
                padding: '6px 12px',
                background: '#1a2332',
                color: '#c8d6e5',
                border: '1px solid #2d3a4f',
                borderRadius: 4,
                fontSize: 13,
                width: 120,
              }}
            />
          </div>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleCreate}
            disabled={creating || !selectedNode}
            style={{ height: 34 }}
          >
            {creating ? '创建中...' : '创建升级任务'}
          </button>
        </div>
        {createError && (
          <div style={{ color: '#e74c3c', fontSize: 12, marginTop: 8 }}>{createError}</div>
        )}
      </div>

      {/* 错误提示 */}
      {error && (
        <div style={{ padding: '8px 16px', color: '#e74c3c', background: '#fdf0ef', borderRadius: 6, margin: '0 16px 12px' }}>
          {error}
        </div>
      )}

      {/* 升级任务列表 */}
      {loading && (
        <div style={{ padding: 24, textAlign: 'center', color: '#5a6988' }}>正在加载升级任务...</div>
      )}

      {!loading && jobs.length === 0 && (
        <div className="empty-state" style={{ padding: 40, textAlign: 'center', color: '#5a6988' }}>
          <p style={{ fontSize: 16, marginBottom: 8 }}>暂无升级任务</p>
          <p style={{ fontSize: 13 }}>
            在上方选择一个在线节点和目标版本来创建升级任务
          </p>
        </div>
      )}

      {jobs.length > 0 && (
        <div style={{ padding: '0 16px 16px' }}>
          {jobs.map(job => {
            const isActive = ['pending', 'downloading', 'installing'].includes(job.status);
            const progressPct = Math.round(job.progress * 100);
            return (
              <div
                key={job.id}
                style={{
                  padding: 14,
                  marginBottom: 10,
                  background: '#1a2332',
                  border: '1px solid #2d3a4f',
                  borderRadius: 8,
                }}
              >
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div>
                    <span className="mono" style={{ fontSize: 12, marginRight: 8 }}>
                      {job.id.length > 12 ? job.id.slice(0, 12) + '..' : job.id}
                    </span>
                    <span style={{
                      color: STATUS_COLORS[job.status] || '#8899aa',
                      fontWeight: 600,
                      fontSize: 12,
                      padding: '1px 8px',
                      borderRadius: 3,
                      background: (STATUS_COLORS[job.status] || '#8899aa') + '20',
                    }}>
                      {STATUS_LABELS[job.status] || job.status}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: '#5a6988' }}>
                    {job.node_id} → v{job.version}
                  </div>
                </div>

                {/* Progress bar */}
                {isActive && (
                  <div className="progress-bar-wrap" style={{ marginBottom: 6 }}>
                    <div
                      className="progress-bar-fill"
                      style={{
                        width: `${progressPct}%`,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                )}
                {job.status === 'complete' && (
                  <div className="progress-bar-wrap" style={{ marginBottom: 6 }}>
                    <div className="progress-bar-fill" style={{ width: '100%', background: '#27ae60' }} />
                  </div>
                )}

                {/* Info row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 11, color: '#5a6988' }}>
                    {isActive ? `进度: ${progressPct}%` : ''}
                    {job.status === 'complete' && job.completed_at && `完成于: ${new Date(job.completed_at).toLocaleString()}`}
                    {job.status === 'failed' && job.error && `错误: ${job.error}`}
                    {job.status === 'rollback' && '已回滚到上一版本'}
                  </span>

                  {isActive && (
                    <button
                      className="btn btn-sm"
                      onClick={() => handleCancel(job.id)}
                      style={{
                        fontSize: 11,
                        padding: '3px 10px',
                        background: '#5a1a1a',
                        color: '#e74c3c',
                        border: '1px solid #7a2a2a',
                      }}
                    >
                      取消
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
