// Mozunitor 设置页：按频率分组（常用 / 服务与分级 / 采集与保活）。
// 显示偏好与置顶存本设备 localStorage；面板配置走 /api/settings（命令字段仅回环可改）。
import { esc } from './format.js';
import { authFetch, authHeaders } from './api.js';
import { toast } from './modal.js';
import {
  DATA, TIERS, TIER_ORDER, CARD_FIELDS, pins, itemByKey, unpin,
  globalCardPrefs, setGlobalCardPref, resetGlobalCardPrefs,
  mobileHideOptional, setMobileHideOptional, machineBlocks, tierItems, tierStats,
} from './state.js';

const $ = (s) => document.querySelector(s);
let PANEL = null;

const INTERVALS = [
  ["probe_local_ms", "探测间隔"],
  ["sample_local_ms", "本机采样"],
  ["sample_remote_ms", "远端采样"],
  ["peer_poll_ms", "对端轮询"],
  ["keepalive_ms", "保活巡检"],
];

function cardPrefFields() {
  const defaults = (DATA && DATA.ui && DATA.ui.card) || {};
  const overrides = globalCardPrefs();
  return CARD_FIELDS.map((f) => {
    const on = Object.prototype.hasOwnProperty.call(overrides, f.id)
      ? !!overrides[f.id] : !!defaults[f.id];
    return `<label class="pref"><input type="checkbox" data-pref-card="${f.id}"${on ? ' checked' : ''}>`
      + ` ${f.label}</label>`;
  }).join('');
}

function pinnedRows() {
  const entries = [];
  for (const key of pins()) {
    const hit = itemByKey(key);
    entries.push(hit.it
      ? `<div class="pref-row"><span class="pref-name">${esc(hit.it.name)}</span>`
        + `<span class="pref-note">${esc(hit.node || '本机')}</span>`
        + `<button class="ghost" data-unpin="${esc(key)}">取消置顶</button></div>`
      : `<div class="pref-row"><span class="pref-name">${esc(key)}</span>`
        + `<span class="pref-note">当前不可用</span>`
        + `<button class="ghost" data-unpin="${esc(key)}">移除</button></div>`);
  }
  return entries.join('') || '<div class="empty">还没有置顶服务。卡片右上角的星标可切换。</div>';
}

function tierOverview() {
  const parts = [];
  for (const m of machineBlocks(DATA)) {
    const rows = [];
    for (const tier of TIER_ORDER) {
      const entries = tierItems(m, tier);
      if (!entries.length) continue;
      const st = tierStats(entries);
      const names = entries.slice().sort((a, b) => a.it.name.localeCompare(b.it.name, 'zh'))
        .map((e) => esc(e.it.name)).join('、');
      rows.push(`<div class="pref-row"><span class="badge tier-tag tier-${tier}">${TIERS[tier]}</span>`
        + `<span class="pref-name">${names}</span>`
        + `<span class="pref-note">${tier === 'optional' ? `${st.total} 项` : `${st.up}/${st.total} 在线`}</span></div>`);
    }
    parts.push(`<div class="pref-group"><div class="pref-group-head">${esc(m.name)}</div>`
      + (rows.join('') || '<div class="empty">无上报数据</div>') + '</div>');
  }
  return parts.join('');
}

function probeText(probe) {
  if (!probe) return '—';
  const kind = probe.kind || '';
  if (kind === 'tcp') return `tcp ${probe.host || '*'}:${probe.port || ''}`;
  if (kind === 'http') return `http ${probe.url || ''}`;
  if (kind === 'process') return `进程 ${probe.name || ''}`;
  if (kind === 'task') return `计划任务 ${probe.name || ''}`;
  return `${kind} ${probe.port || ''}`;
}

function serviceRows() {
  const rows = (PANEL && PANEL.services) || [];
  if (!rows.length) return '<div class="empty">设置快照还没载入</div>';
  const commands = !!(PANEL.editable && PANEL.editable.commands);
  return rows.map((svc) => {
    const tierOpts = TIER_ORDER.map((t) =>
      `<option value="${t}"${svc.tier === t ? ' selected' : ''}>${TIERS[t]}</option>`).join('');
    const cmd = commands ? `<details class="cmd-edit"><summary>命令</summary>`
      + `<label>探测</label><input class="wide" data-probe="${esc(svc.id)}" value="${esc(probeText(svc.probe))}" readonly>`
      + `<label>restart</label><textarea data-cmd="restart" data-id="${esc(svc.id)}">${esc(JSON.stringify(svc.restart || null, null, 2))}</textarea>`
      + `<label>stop</label><textarea data-cmd="stop" data-id="${esc(svc.id)}">${esc(JSON.stringify(svc.stop || null, null, 2))}</textarea>`
      + `<button class="ghost" data-save-commands="${esc(svc.id)}">保存命令</button></details>` : '';
    return `<div class="svc-setting"><div class="pref-row">`
      + `<span class="pref-name">${esc(svc.name)} <span class="pref-note">${esc(svc.group || '')}</span></span>`
      + `<span class="pref-note">${esc(probeText(svc.probe))}</span>`
      + `<select data-service-tier="${esc(svc.id)}">${tierOpts}</select>`
      + `<label class="pref"><input type="checkbox" data-service-keepalive="${esc(svc.id)}"${svc.keepalive ? ' checked' : ''}> 保活</label>`
      + `</div>${cmd}</div>`;
  }).join('');
}

function panelNumbers() {
  if (!PANEL) return '';
  const iv = PANEL.intervals || {};
  const ka = PANEL.keepalive || {};
  return `
    <h3 class="sec">采样间隔（毫秒）</h3>
    <div class="pref-list">${INTERVALS.map(([key, label]) =>
      `<label class="pref-row"><span class="pref-name">${label}</span>`
      + `<input type="number" min="500" max="3600000" step="500" data-interval="${key}" value="${esc(iv[key] ?? '')}">`
      + `</label>`).join('')}</div>
    <button type="button" data-save-panel="intervals">保存采样间隔</button>
    <h3 class="sec">保活策略</h3>
    <div class="pref-list">
      <label class="pref-row"><span class="pref-name">连续失败阈值</span>
        <input type="number" min="1" max="10" data-ka="down_streak" value="${esc(ka.down_streak ?? '')}"></label>
      <label class="pref-row"><span class="pref-name">失败上限</span>
        <input type="number" min="1" max="20" data-ka="max_fails" value="${esc(ka.max_fails ?? '')}"></label>
      <label class="pref-row"><span class="pref-name">退避阶梯（秒，逗号分隔）</span>
        <input type="text" data-ka="backoff" value="${esc((ka.backoff || []).join(','))}"></label>
    </div>
    <button type="button" data-save-panel="keepalive">保存保活策略</button>`;
}

export function renderSettings() {
  const body = $('#settings-body');
  if (!body || !DATA) return;
  body.innerHTML = `
    <section class="settings-sec">
      <h2>常用</h2>
      <h3 class="sec">卡片显示</h3>
      <div class="cardprefs">${cardPrefFields()}</div>
      <button class="ghost" type="button" data-card-reset-global="1">恢复默认字段</button>
      <h3 class="sec">移动端</h3>
      <label class="pref"><input type="checkbox" data-pref-mobile="1"${mobileHideOptional() ? ' checked' : ''}>
        手机上隐藏「按需」组</label>
      <h3 class="sec">置顶</h3>
      <div class="pref-list">${pinnedRows()}</div>
    </section>
    <section class="settings-sec">
      <h2>服务与分级</h2>
      <p class="hint">分级决定告警强度与分组：核心异常红色横幅并自动展开，常驻只给组头计数，按需不统计在线。</p>
      <div class="pref-list">${tierOverview()}</div>
      <h3 class="sec">服务清单</h3>
      <div class="pref-list">${serviceRows()}</div>
    </section>
    <section class="settings-sec">
      <h2>采集与保活</h2>
      ${panelNumbers() || (PANEL
        ? '<div class="empty">当前面板没有可改的采样设置</div>'
        : '<div class="empty">设置快照载入中…</div>')}
    </section>`;
}

export async function openSettings() {
  const box = $('#settings');
  if (!box) return;
  renderSettings();
  box.classList.remove('hidden');
  const close = $('#settings-close');
  if (close) close.focus();
  try {
    const r = await authFetch('/api/settings');
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    PANEL = d;
  } catch (e) {
    PANEL = null;
    toast(`设置快照读取失败：${e}`, 'bad');
  }
  renderSettings();
}

export async function reloadPanelSettings() {
  if (!settingsOpen()) return;
  try {
    const r = await authFetch('/api/settings');
    const d = await r.json().catch(() => ({}));
    if (r.ok) PANEL = d;
  } catch (e) { /* 保留旧快照 */ }
  renderSettings();
}

export function closeSettings() {
  const box = $('#settings');
  if (box) box.classList.add('hidden');
}

export function settingsOpen() {
  const box = $('#settings');
  return box ? !box.classList.contains('hidden') : false;
}

export async function savePanel(section, values) {
  try {
    const r = await authFetch('/api/settings', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ section, values }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    toast('设置已保存', 'ok');
    PANEL = d.settings || PANEL;
    renderSettings();
    return true;
  } catch (e) {
    toast(`保存失败：${e}`, 'bad');
    return false;
  }
}

export { setGlobalCardPref, resetGlobalCardPrefs, setMobileHideOptional, unpin };
