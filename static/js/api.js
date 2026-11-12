// 网络与凭据：所有请求统一从这里走，token 存 localStorage 只用于首个 X-Mozunitor-Token，
// 服务端验证后改发 HttpOnly Cookie。

/* 当前页面是不是从本机访问的。非本机时日后再点 127.0.0.1 是打不开的，
   所以「打开」按钮要改指局域网入口（见 board.js）。 */
export const IS_LOOPBACK = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(location.hostname);

export function authToken() {
  try {
    return localStorage.getItem('mozunitor_token') || '';
  } catch (e) {
    return '';
  }
}

/* 带 ?token= 的链接（README 里的书签用法）必须能直接进。 */
export function tokenFromUrl() {
  try {
    return new URLSearchParams(location.search).get('token') || '';
  } catch (e) {
    return '';
  }
}

export function authHeaders() {
  const t = authToken() || tokenFromUrl();
  return t ? { 'X-Mozunitor-Token': t } : {};
}

/* 401 原样交回调用方判断：这里若顺手弹登录层或抛异常，poll 里那句
   `r.status === 401` 就永远执行不到 —— 曾经就是这么把登录层弄丢的。 */
export async function authFetch(url, opt) {
  opt = opt || {};
  opt.headers = Object.assign({}, opt.headers || {}, authHeaders());
  return fetch(url, opt);
}

/* 验收脚本在页面里发请求用；不是业务入口。 */
window.__mozunitor = Object.assign(window.__mozunitor || {}, { authFetch, authHeaders });
