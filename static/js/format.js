// 纯格式化函数：不碰 DOM、不读全局状态，所有渲染模块共用。

export const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export const fmtMB = (v) => v == null ? '—' : (v >= 1024 ? (v / 1024).toFixed(1) + ' GB' : v + ' MB');
export const fmtMs = (v) => v == null ? '—' : (v < 1 ? '<1' : Math.round(v)) + ' ms';
export const fmtPct = (v) => v == null ? '—' : (v < 0.05 ? '0' : v.toFixed(1)) + '%';
export const fmtBytes = (v) => v == null ? '—'
  : (v >= 1073741824 ? (v / 1073741824).toFixed(2) + ' GB' : Math.round(v / 1048576) + ' MB');
export const fmtNum = (v) => (v == null || v === '') ? '—' : Number(v).toLocaleString('en-US');

export function fmtDur(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}天${h}时`;
  if (h) return `${h}时${m}分`;
  return `${m}分`;
}

/* 模型卸载倒计时：expires_at 是绝对时间戳，按本地时钟算。 */
export function fmtLeft(iso) {
  if (!iso) return '—';
  const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (!isFinite(s)) return '—';
  if (s <= 0) return '即将卸载';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h) return `${h} 时 ${m} 分`;
  if (m) return `${m} 分 ${s % 60} 秒`;
  return `${s} 秒`;
}

/* ISO 时间戳的「多久以前」；与 fmtLeft 一样按本地时钟算，3 秒轮询的粒度足够。 */
export function agoIso(iso) {
  if (!iso) return '';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (!isFinite(s) || s < 0) return '';
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h} 小时前` : `${Math.floor(h / 24)} 天前`;
}
