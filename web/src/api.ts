// API 请求工具 — 管理端所有请求自动携带 X-API-Key 认证头
const API_KEY = 'hp-admin-2024';

// LogEntry 日志条目，用于前端状态栏展示
export interface LogEntry {
  ts: number;
  level: 'info' | 'warn' | 'error';
  msg: string;
}

type LogListener = (entry: LogEntry) => void;
const logListeners: LogListener[] = [];

/** 订阅全局日志流（React 组件使用） */
export function onLog(fn: LogListener) {
  logListeners.push(fn);
  return () => {
    const idx = logListeners.indexOf(fn);
    if (idx >= 0) logListeners.splice(idx, 1);
  };
}

/** 发射一条全局日志（供非组件代码直接调用） */
export function emitLog(level: LogEntry['level'], msg: string) {
  const entry: LogEntry = { ts: Date.now(), level, msg };
  for (const fn of logListeners) fn(entry);
}

// 管理端 fetch 封装，自动附加 X-API-Key 并记录请求日志
export async function apiFetch(url: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set('X-API-Key', API_KEY);
  const start = performance.now();
  try {
    const res = await fetch(url, { ...init, headers });
    const elapsed = Math.round(performance.now() - start);
    emitLog(res.ok ? 'info' : 'warn', `${init?.method || 'GET'} ${url} → ${res.status} (${elapsed}ms)`);
    return res;
  } catch (err: unknown) {
    const elapsed = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : String(err);
    emitLog('error', `${init?.method || 'GET'} ${url} 失败 (${elapsed}ms): ${msg}`);
    throw err;
  }
}

// SSE EventSource 不支持自定义 Header，通过查询参数传递 API Key
// 由于后端 apiKeyMiddleware 豁免了 /api/events，这里保留用于其他 SSE 场景
export function apiEventSource(url: string): EventSource {
  const sep = url.includes('?') ? '&' : '?';
  return new EventSource(`${url}${sep}api_key=${API_KEY}`);
}

export { API_KEY };
