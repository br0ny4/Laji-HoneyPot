// API 请求工具 — JWT 认证 + 自动令牌刷新
import { showToast } from './Toast';
let accessToken = '';
let refreshToken = '';

// 令牌存储键名
const TOKEN_KEY = 'hp_access_token';
const REFRESH_KEY = 'hp_refresh_token';

// 从 localStorage 恢复令牌
try {
  accessToken = localStorage.getItem(TOKEN_KEY) || '';
  refreshToken = localStorage.getItem(REFRESH_KEY) || '';
} catch { /* localStorage 不可用 */ }

/** 保存令牌到 localStorage */
function persistTokens(access: string, refresh: string) {
  accessToken = access;
  refreshToken = refresh;
  try {
    localStorage.setItem(TOKEN_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  } catch { /* ignore */ }
}

/** 清除令牌 */
export function clearTokens() {
  accessToken = '';
  refreshToken = '';
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  } catch { /* ignore */ }
}

/** 获取当前访问令牌 */
export function getAccessToken(): string {
  return accessToken;
}

/** 是否已登录 */
export function isLoggedIn(): boolean {
  return !!accessToken;
}

/** 检查令牌是否过期 */
function isTokenExpired(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return (payload.exp * 1000) < Date.now();
  } catch {
    return true;
  }
}

/** 自动刷新令牌 */
async function tryRefreshToken(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    persistTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

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

/** 发射一条全局日志 */
export function emitLog(level: LogEntry['level'], msg: string) {
  const entry: LogEntry = { ts: Date.now(), level, msg };
  for (const fn of logListeners) fn(entry);
}

// 防止并发刷新
let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

/** 管理端 fetch 封装，自动携带 JWT Bearer 令牌并处理刷新 */
export async function apiFetch(url: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);

  // 跳过认证端点
  const isAuthEndpoint = url.startsWith('/api/auth/');

  if (!isAuthEndpoint && accessToken) {
    // 令牌即将过期时主动刷新
    if (isTokenExpired(accessToken)) {
      if (!isRefreshing) {
        isRefreshing = true;
        refreshPromise = tryRefreshToken().finally(() => {
          isRefreshing = false;
          refreshPromise = null;
        });
      }
      if (refreshPromise) {
        await refreshPromise;
      }
    }
    if (accessToken) {
      headers.set('Authorization', `Bearer ${accessToken}`);
    }
  }

  const start = performance.now();
  try {
    const res = await fetch(url, { ...init, headers });
    const elapsed = Math.round(performance.now() - start);

    // 令牌过期，尝试刷新后重试一次
    if (res.status === 401 && !isAuthEndpoint && refreshToken) {
      const refreshed = await tryRefreshToken();
      if (refreshed) {
        const retryHeaders = new Headers(init?.headers);
        retryHeaders.set('Authorization', `Bearer ${accessToken}`);
        const retryRes = await fetch(url, { ...init, headers: retryHeaders });
        const retryElapsed = Math.round(performance.now() - start);
        emitLog(retryRes.ok ? 'info' : 'warn', `(retry) ${init?.method || 'GET'} ${url} → ${retryRes.status} (${retryElapsed}ms)`);
        return retryRes;
      }
      // 刷新失败，会话过期
      showToast('会话已过期，请重新登录', 3000);
      setTimeout(() => {
        clearTokens();
        window.location.reload();
      }, 1500);
    }

    emitLog(res.ok ? 'info' : 'warn', `${init?.method || 'GET'} ${url} → ${res.status} (${elapsed}ms)`);
    return res;
  } catch (err: unknown) {
    const elapsed = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : String(err);
    emitLog('error', `${init?.method || 'GET'} ${url} 失败 (${elapsed}ms): ${msg}`);
    throw err;
  }
}

/** 登录接口 */
export async function login(username: string, password: string): Promise<{ success: boolean; mustChangePassword?: boolean; error?: string }> {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { success: false, error: data.error || '登录失败' };
    }
    persistTokens(data.access_token, data.refresh_token);
    if (data.must_change_password) {
      emitLog('warn', '首次登录，请修改初始密码');
      return { success: true, mustChangePassword: true };
    }
    emitLog('info', `登录成功: ${username} (${data.expires_in}s 有效)`);
    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

/** 登出 */
export async function logout(): Promise<void> {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  } catch { /* ignore */ }
  clearTokens();
  emitLog('info', '已登出');
}

/** 修改自己的密码（支持首次登录强制改密） */
export async function changeOwnPassword(oldPassword: string, newPassword: string): Promise<{ success: boolean; error?: string }> {
  try {
    const res = await fetch('/api/auth/changepassword', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { success: false, error: data.error || '密码修改失败' };
    }
    emitLog('info', '密码修改成功');
    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}

/** SSE 已改用 JWT Authorization，但 EventSource 不支持自定义 Header，
 *  因此 /api/events 在后端豁免 JWT 认证 */
export function apiEventSource(url: string): EventSource {
  return new EventSource(url);
}

export { accessToken, refreshToken, persistTokens };

// ======================== Agent 升级管理 API ========================

export interface UpgradeJob {
  id: string;
  version: string;
  status: string;  // pending | downloading | installing | complete | failed | rollback
  node_id: string;
  package_url: string;
  package_hash: string;
  progress: number;  // 0.0 - 1.0
  created_at: string;
  completed_at?: string;
  error?: string;
}

/** 获取升级任务列表 */
export async function listUpgradeJobs(nodeID?: string): Promise<UpgradeJob[]> {
  const qs = nodeID ? `?node_id=${encodeURIComponent(nodeID)}` : '';
  const res = await apiFetch(`/api/upgrade/jobs${qs}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  return data.jobs || [];
}

/** 创建升级任务 */
export async function createUpgradeJob(nodeID: string, version: string): Promise<UpgradeJob> {
  const res = await apiFetch('/api/upgrade/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_id: nodeID, version }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

/** 取消升级任务 */
export async function cancelUpgradeJob(jobID: string): Promise<void> {
  const res = await apiFetch(`/api/upgrade/jobs/${encodeURIComponent(jobID)}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

/** 获取单个升级任务状态 */
export async function getUpgradeJob(jobID: string): Promise<UpgradeJob> {
  const res = await apiFetch(`/api/upgrade/jobs/${encodeURIComponent(jobID)}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ======================== Agent 守护进程控制 API ========================

export interface DaemonStatus {
  node_id: string;
  installed: boolean;
  status: string;  // running | stopped | not_installed
}

/** 获取 Agent 守护进程状态 */
export async function getAgentDaemonStatus(nodeID?: string): Promise<DaemonStatus> {
  const qs = nodeID ? `?node_id=${encodeURIComponent(nodeID)}` : '';
  const res = await apiFetch(`/api/agent/daemon/status${qs}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** 控制 Agent 守护进程 (start/stop/restart) */
export async function controlAgentDaemon(nodeID: string, action: 'start' | 'stop' | 'restart'): Promise<void> {
  const res = await apiFetch('/api/agent/daemon/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_id: nodeID, action }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
}
