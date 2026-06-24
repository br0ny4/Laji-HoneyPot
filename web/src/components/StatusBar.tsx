import { useEffect, useState } from 'react';
import { emitLog, LogEntry, onLog } from '../api';

const MAX_LOGS = 50;

export default function StatusBar() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [expanded, setExpanded] = useState(false);
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [sseOk, setSseOk] = useState<boolean | null>(null);

  useEffect(() => {
    return onLog((entry) => {
      setLogs((prev) => [entry, ...prev].slice(0, MAX_LOGS));

      // 自动检测 API 连通性
      if (entry.msg.includes('/api/') || entry.msg.includes('API 连通性')) {
        if (entry.level === 'error') setApiOk(false);
        else if (entry.level === 'info') setApiOk(true);
      }
      // 检测 SSE 连通性
      if (entry.msg.includes('SSE')) {
        if (entry.level === 'error') setSseOk(false);
        else if (entry.level === 'info') setSseOk(true);
      }
    });
  }, []);

  // 初始连通性探测
  useEffect(() => {
    fetch('/healthz')
      .then(() => {
        setApiOk(true);
        emitLog('info', 'API 连通性检测通过 /healthz');
      })
      .catch(() => {
        setApiOk(false);
        emitLog('error', 'API 连通性检测失败 — 后端可能未启动');
      });
  }, []);

  // SSE 状态通过 window 事件接收（DashboardPanel 在 EventSource open/error 时触发）
  useEffect(() => {
    const onSseOpen = () => { setSseOk(true); emitLog('info', 'SSE 已连接'); };
    const onSseError = () => { setSseOk(false); emitLog('warn', 'SSE 连接中断，将在 3 秒后重连'); };
    window.addEventListener('sse-open', onSseOpen);
    window.addEventListener('sse-error', onSseError);
    return () => {
      window.removeEventListener('sse-open', onSseOpen);
      window.removeEventListener('sse-error', onSseError);
    };
  }, []);

  const errorCount = logs.filter((l) => l.level === 'error').length;
  const warnCount = logs.filter((l) => l.level === 'warn').length;
  const lastError = logs.find((l) => l.level === 'error');

  return (
    <div className="status-bar">
      <div className="status-bar-main" onClick={() => setExpanded(!expanded)}>
        <span className="status-dot" data-status={apiOk === true ? 'ok' : apiOk === false ? 'err' : 'unknown'} />
        <span className="status-label">API</span>

        <span className="status-dot" data-status={sseOk === true ? 'ok' : sseOk === false ? 'err' : 'unknown'} style={{ marginLeft: 12 }} />
        <span className="status-label">SSE</span>

        <span className="status-log-count">
          {errorCount > 0 && <span className="log-badge log-err">{errorCount}</span>}
          {warnCount > 0 && <span className="log-badge log-warn">{warnCount}</span>}
          <span className="log-badge log-info">{logs.length}</span>
        </span>

        <span className="status-toggle">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div className="status-log-panel">
          {lastError && (
            <div className="status-last-error">
              <strong>最近错误：</strong>
              <span>{lastError.msg}</span>
              <span className="log-time">{new Date(lastError.ts).toLocaleTimeString('zh-CN')}</span>
            </div>
          )}
          <div className="status-log-list">
            {logs.length === 0 ? (
              <div className="log-empty">暂无日志 — 等待 API 请求...</div>
            ) : (
              logs.slice(0, 30).map((l, i) => (
                <div key={i} className={`log-line log-${l.level}`}>
                  <span className="log-time">{new Date(l.ts).toLocaleTimeString('zh-CN')}</span>
                  <span className="log-level">{l.level.toUpperCase()}</span>
                  <span className="log-msg">{l.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
