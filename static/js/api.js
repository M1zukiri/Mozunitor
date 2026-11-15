// 1.1.0 会话层：不再有 token URL / localStorage token。
// 登录或壳内 launch token 换 HttpOnly 会话；写请求带 CSRF 头。
// 401 必须原样交回调用方（poll 的 401 分支负责弹登录层）。

export const IS_LOOPBACK = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(location.hostname);

const SESSION = { scope: '', csrf: '', node: null, version: '', setup_done: false };

export function sessionInfo() { return SESSION; }

export function setSession(data) {
  Object.assign(SESSION, data || {});
  return SESSION;
}

function isSafe(method) {
  return ['GET', 'HEAD', 'OPTIONS'].includes(String(method || 'GET').toUpperCase());
}

/* 所有请求统一从这里走：带 Cookie；写请求自动补 CSRF 头。 */
export async function apiFetch(url, opt) {
  opt = opt || {};
  const method = String(opt.method || 'GET').toUpperCase();
  const headers = Object.assign({}, opt.headers || {});
  if (!isSafe(method) && SESSION.csrf) headers['X-Mozunitor-CSRF'] = SESSION.csrf;
  return fetch(url, Object.assign({ credentials: 'same-origin' }, opt, { method, headers }));
}

/* 兼容旧调用名：1.1.0 起不再有 token 头。 */
export function authHeaders() {
  return {};
}

/* 兼容旧调用名：验收脚本与 board/side 仍用 authFetch。 */
export async function authFetch(url, opt) {
  return apiFetch(url, opt);
}

async function readJSON(r) {
  try { return await r.json(); } catch (e) { return {}; }
}

/* 启动流程：带 launch 片段 → 壳会话；否则读 /api/session；都不是则交给登录层。 */
export async function bootstrap() {
  let launch = '';
  const m = (location.hash || '').match(/[#&]launch=([^&]+)/);
  if (m) {
    launch = decodeURIComponent(m[1]);
    try {
      history.replaceState(null, '', location.pathname + location.search);
    } catch (e) { /* 老浏览器不支持就算了 */ }
  }
  let status = null;
  try {
    const r = await fetch('/api/setup/status', { credentials: 'same-origin' });
    if (r.ok) status = await readJSON(r);
  } catch (e) { /* 非本地入口读不到，按需要登录处理 */ }
  const needsSetup = !!(status && status.needs_setup);

  if (launch) {
    const r = await apiFetch('/api/session/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: launch }),
    });
    if (r.ok) {
      setSession(await readJSON(r));
      return { needsSetup, session: SESSION, status, launch };
    }
  }
  const r = await apiFetch('/api/session');
  if (r.ok) {
    setSession(await readJSON(r));
    return { needsSetup, session: SESSION, status, launch };
  }
  return { needsSetup, session: null, status, launch };
}

export async function login(password) {
  const r = await apiFetch('/api/session/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  const d = await readJSON(r);
  if (!r.ok || !d.ok) return { ok: false, error: d.error || '口令不正确', status: r.status };
  setSession(d);
  return { ok: true, session: SESSION };
}

export async function completeSetup(password) {
  const r = await apiFetch('/api/setup/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  const d = await readJSON(r);
  if (!r.ok || !d.ok) return { ok: false, error: d.error || '初始化失败', status: r.status };
  setSession(d);
  return { ok: true, session: SESSION };
}

export async function logout() {
  await apiFetch('/api/session/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  Object.assign(SESSION, { scope: '', csrf: '' });
}

/* 验收脚本在页面里发请求用；不是业务入口。 */
window.__mozunitor = Object.assign(window.__mozunitor || {}, {
  authFetch, apiFetch, bootstrap, login, completeSetup, sessionInfo,
});
