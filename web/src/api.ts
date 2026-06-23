// API 请求工具 — 管理端所有请求自动携带 X-API-Key 认证头
const API_KEY = 'hp-admin-2024';

// 管理端 fetch 封装，自动附加 X-API-Key
export function apiFetch(url: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set('X-API-Key', API_KEY);
  return fetch(url, { ...init, headers });
}

// SSE EventSource 不支持自定义 Header，通过查询参数传递 API Key
// 由于后端 apiKeyMiddleware 豁免了 /api/events，这里保留用于其他 SSE 场景
export function apiEventSource(url: string): EventSource {
  const sep = url.includes('?') ? '&' : '?';
  return new EventSource(`${url}${sep}api_key=${API_KEY}`);
}

export { API_KEY };
