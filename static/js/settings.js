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
let SEC = null;
let SEC_ERR = '';

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

function fmtTs(ts) {
  const n = Number(ts);
  if (!n) return '—';
  return new Date(n * 1000).toLocaleString('zh-CN', { hour12: false });
}

function securitySection() {
  if (!SEC) {
    return `<div class="empty">安全状态读取失败${SEC_ERR ? '：' + esc(SEC_ERR) : ''}`
      + '（需要管理员口令登录；本机脚本可用本地 token）</div>';
  }
  const net = SEC.network || {};
  const fp = net.tls_fingerprint_pretty || '未生成（开启网络入口后生成）';
  const cidrs = (net.allowed_cidrs || []).join(', ');
  const nodes = (SEC.nodes || []).map((n) =>
    `<div class="pref-row"><span class="pref-name">${esc(n.name)} · ${esc(n.id)}</span>`
    + `<span class="pref-note">${esc(n.url || '')}</span>`
    + `<button class="ghost" data-revoke-node="${esc(n.id)}">解除</button></div>`).join('');
  const devices = (SEC.devices || []).map((d) =>
    `<div class="pref-row"><span class="pref-name">${esc(d.name)}</span>`
    + `<span class="pref-note">${d.revoked ? '已吊销' : esc(d.scope || '')}</span>`
    + (d.revoked ? '' : `<button class="ghost" data-revoke-device="${esc(d.id)}">吊销</button>`)
    + '</div>').join('');
  const sessions = (SEC.sessions || []).map((s) =>
    `<div class="pref-row"><span class="pref-name">${esc(s.listener)} · ${esc(s.scope)}`
    + ` …${esc(s.sid || '')}</span>`
    + `<span class="pref-note">${esc(s.ip || '')} · ${esc(fmtTs(s.last_seen))}</span></div>`)
    .join('');
  return `
    <h3 class="sec">网络入口（HTTPS）</h3>
    <p class="hint">默认只监听回环。开启后按 CIDR 白名单放行局域网/Tailnet；当前网络为「公用网络」时拒绝开启。</p>
    <div class="pref-list">
      <label class="pref-row"><span class="pref-name">启用网络入口</span>
        <input type="checkbox" data-net="enabled"${net.enabled ? ' checked' : ''}></label>
      <label class="pref-row"><span class="pref-name">模式</span>
        <select data-net="mode">
          <option value="lan"${net.mode === 'lan' ? ' selected' : ''}>局域网</option>
          <option value="tailnet"${net.mode === 'tailnet' ? ' selected' : ''}>Tailnet</option>
        </select></label>
      <label class="pref-row"><span class="pref-name">绑定地址（留空自动选择）</span>
        <input type="text" data-net="bind" value="${esc(net.bind || '')}" placeholder="192.168.1.10"></label>
      <label class="pref-row"><span class="pref-name">端口</span>
        <input type="number" min="1024" max="65535" data-net="port" value="${esc(net.port || 8443)}"></label>
      <label class="pref-row"><span class="pref-name">允许来源 CIDR（逗号分隔）</span>
        <input type="text" class="wide" data-net="cidrs" value="${esc(cidrs)}"></label>
    </div>
    <p class="hint">证书指纹 SHA256：<code>${esc(fp)}</code></p>
    <button type="button" data-save-network="1">保存网络设置</button>
    <button class="ghost" type="button" data-rotate-cert="1">轮换证书</button>
    <h3 class="sec">活动会话</h3>
    <div class="pref-list">${sessions || '<div class="empty">没有活动会话</div>'}</div>
    <h3 class="sec">管理员口令</h3>
    <div class="pref-list">
      <label class="pref-row"><span class="pref-name">原口令</span>
        <input type="password" data-pw="old" autocomplete="current-password"></label>
      <label class="pref-row"><span class="pref-name">新口令（至少 8 位）</span>
        <input type="password" data-pw="new" autocomplete="new-password"></label>
    </div>
    <button type="button" data-save-password="1">修改口令</button>
    <h3 class="sec">设备配对</h3>
    <p class="hint">先开启 HTTPS 网络入口。手机端填面板地址并输入配对码；开启 TLS 后证书指纹随配对信息一起出示。</p>
    <div class="pref-list">
      <div class="pref-row"><span class="pref-name">配对码</span>
        <span class="pref-note" id="pair-code">未生成</span></div>
    </div>
    <button type="button" data-start-pair="1">生成配对码</button>
    <h3 class="sec">已配对设备</h3>
    <div class="pref-list">${devices || '<div class="empty">还没有配对设备</div>'}</div>
    <h3 class="sec">节点互联</h3>
    <p class="hint">与另一台机器配对后，本机面板会主动拉取对端 /api/node；未配对节点一律 401。</p>
    <div class="pref-list">${nodes || '<div class="empty">还没有配对节点</div>'}</div>
    <div class="pref-list">
      <label class="pref-row"><span class="pref-name">对端地址</span>
        <input type="text" class="wide" data-node-url placeholder="https://192.168.1.20:8443/"></label>
      <label class="pref-row"><span class="pref-name">对端配对码</span>
        <input type="text" data-node-code placeholder="对端生成的配对码"></label>
    </div>
    <button type="button" data-pair-node="1">配对该节点</button>
    <button type="button" data-node-pair-start="1">生成我的节点配对码</button>
    <p class="hint" id="node-pair-code"></p>`;
}

function netValues(extra) {
  const q = (sel) => document.querySelector(sel);
  const payload = {
    enabled: !!(q('[data-net="enabled"]') || {}).checked,
    mode: ((q('[data-net="mode"]') || {}).value) || 'lan',
    bind: (((q('[data-net="bind"]') || {}).value) || '').trim(),
    port: Number(((q('[data-net="port"]') || {}).value) || 8443),
    allowed_cidrs: (((q('[data-net="cidrs"]') || {}).value) || '')
      .split(',').map((x) => x.trim()).filter(Boolean),
  };
  return Object.assign(payload, extra || {});
}

async function saveNetwork(payload) {
  try {
    const r = await authFetch('/api/security/network', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    SEC = Object.assign({}, SEC, { network: d.network || SEC.network });
    renderSettings();
    toast(payload.rotate_cert ? '证书已轮换，请重新配对手机端' : '网络设置已保存', 'ok');
  } catch (e) {
    toast(`网络设置保存失败：${e}`, 'bad');
  }
}

async function savePassword() {
  const q = (sel) => document.querySelector(sel);
  try {
    const r = await authFetch('/api/security/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        old: ((q('[data-pw="old"]') || {}).value) || '',
        new: ((q('[data-pw="new"]') || {}).value) || '',
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    toast('口令已修改，请重新登录', 'ok');
    setTimeout(() => location.reload(), 800);
  } catch (e) {
    toast(`修改口令失败：${e}`, 'bad');
  }
}

async function startPair() {
  try {
    const r = await authFetch('/api/pair/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    const el = document.querySelector('#pair-code');
    if (el) el.textContent = d.code + '（' + Math.round((d.expires_in || 300) / 60) + ' 分钟内有效）';
    toast('配对码已生成：' + d.code, 'ok');
  } catch (e) {
    toast(`生成配对码失败：${e}`, 'bad');
  }
}

async function revokeDevice(id) {
  try {
    const r = await authFetch('/api/devices/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    SEC = Object.assign({}, SEC, { devices: d.devices || [] });
    renderSettings();
    toast('设备已吊销', 'ok');
  } catch (e) {
    toast(`吊销失败：${e}`, 'bad');
  }
}

async function pairNode() {
  const q = (sel) => document.querySelector(sel);
  try {
    const r = await authFetch('/api/nodes/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: (((q('[data-node-url]') || {}).value) || '').trim(),
        code: (((q('[data-node-code]') || {}).value) || '').trim(),
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    SEC = Object.assign({}, SEC, { nodes: d.nodes || [] });
    renderSettings();
    toast('节点已配对', 'ok');
  } catch (e) {
    toast(`节点配对失败：${e}`, 'bad');
  }
}

async function nodePairStart() {
  try {
    const r = await authFetch('/api/nodes/pair/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    const el = document.querySelector('#node-pair-code');
    if (el) el.textContent = '配对码 ' + d.code + '（' + Math.round((d.expires_in || 300) / 60) + ' 分钟内有效）';
    toast('节点配对码已生成：' + d.code, 'ok');
  } catch (e) {
    toast(`生成节点配对码失败：${e}`, 'bad');
  }
}

async function revokeNode(id) {
  try {
    const r = await authFetch('/api/nodes/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    SEC = Object.assign({}, SEC, { nodes: d.nodes || [] });
    renderSettings();
    toast('节点已解除配对', 'ok');
  } catch (e) {
    toast(`解除配对失败：${e}`, 'bad');
  }
}

document.addEventListener('click', (e) => {
  if (e.target.closest('[data-save-network]')) { saveNetwork(netValues()); return; }
  if (e.target.closest('[data-rotate-cert]')) { saveNetwork(netValues({ rotate_cert: true })); return; }
  if (e.target.closest('[data-save-password]')) { savePassword(); return; }
  if (e.target.closest('[data-start-pair]')) { startPair(); return; }
  if (e.target.closest('[data-pair-node]')) { pairNode(); return; }
  if (e.target.closest('[data-node-pair-start]')) { nodePairStart(); return; }
  const rev = e.target.closest('[data-revoke-device]');
  if (rev) { revokeDevice(rev.dataset.revokeDevice); return; }
  const rn = e.target.closest('[data-revoke-node]');
  if (rn) revokeNode(rn.dataset.revokeNode);
});

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
    </section>
    <section class="settings-sec">
      <h2>安全</h2>
      ${securitySection()}
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
  SEC = null;
  SEC_ERR = '';
  try {
    const sr = await authFetch('/api/security');
    const sd = await sr.json().catch(() => ({}));
    if (sr.ok) SEC = sd;
    else SEC_ERR = sd.error || ('HTTP ' + sr.status);
  } catch (e) {
    SEC_ERR = String(e);
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
