// 详情侧边栏：指标头 → 操作区 → 下属 → 卡片显示 → 服务声明的面板 → 动作历史。
// 骨架只在选中项变化时重建；其余时候只刷新轻量部分，滚动位置与面板内容不会被轮询冲掉。
import { esc, fmtMB, fmtMs, fmtPct, fmtDur, agoIso } from './format.js';
import { authFetch, authHeaders, authToken, IS_LOOPBACK } from './api.js';
import {
  SEL, SEL_KEY, INFLIGHT, CARD_FIELDS, currentItem, childrenOf, effectiveCard,
  setSel, setSelKey, nextPaneSeq, findAnyItem,
} from './state.js';
import {
  renderSections, isPaneOp, isActionOp, opUrl, loadPane, tickCountdowns, opHiddenNote,
} from './ops.js';
import { askConfirm, toast } from './modal.js';
import { markSelected } from './board.js';

const $ = (s) => document.querySelector(s);
let PARAMS = null;      // { id, node, settings:[...], loadedAt }

const APPLY_LABEL = {
  hot: '热生效',
  restart: '重启服务后生效',
  reopen: '重开服务后生效',
  next_load: '下次加载生效',
  reload: '刷新页面后生效',
};

export function showSideResult(html, isErr) {
  const box = $('#side-result');
  if (!box) return;
  box.innerHTML = `<div class="${isErr ? 'mdl-err' : 'opresult'}">${html}</div>`;
}

/* 指标头：状态、探测、进程、内存、CPU、运行时长、依赖 —— 这些每个服务都有，故内建。 */
function sideMetrics(it) {
  const bits = [];
  const stateLabel = it.status === 'up' ? '正常' : it.status === 'down' ? '不可达' : '未知';
  const srcTag = it.status_src === 'peer' ? '对端自评' : '';
  bits.push(`<span class="sm">状态 <b>${stateLabel}</b>`
    + (srcTag ? ` · ${srcTag}` : '') + (it.detail ? ` · ${esc(it.detail)}` : '') + '</span>');
  if (it.reach) bits.push(`<span class="sm" title="${esc(it.reach.detail || '')}">本机探测 <b>${it.reach.ok ? '可达' : '不可达'}</b></span>`);
  if (it.latency_ms != null) bits.push(`<span class="sm">探测 <b>${fmtMs(it.latency_ms)}</b></span>`);
  if (it.pid != null) bits.push(`<span class="sm">PID <b>${it.pid}</b></span>`);
  if (it.proc_name) bits.push(`<span class="sm">进程 <b>${esc(it.proc_name)}</b></span>`);
  if (it.mem_mb != null) bits.push(`<span class="sm${it.mem_mb >= 800 ? ' hot' : ''}">内存 <b>${fmtMB(it.mem_mb)}</b></span>`);
  if (it.cpu_pct != null) bits.push(`<span class="sm${it.cpu_pct >= 50 ? ' hot' : ''}">CPU <b>${fmtPct(it.cpu_pct)}</b></span>`);
  if (it.uptime_s != null) bits.push(`<span class="sm">已运行 <b>${fmtDur(it.uptime_s)}</b></span>`);
  if (it.group) bits.push(`<span class="sm dim">分组 ${esc(it.group)} · ${esc(it.tier || '')}</span>`);
  let extra = '';
  if (it.role) extra += `<div class="noterow">${esc(it.role)}</div>`;
  if (it.flag) extra += `<div class="warnrow">${esc(it.flag)}</div>`;
  if (it.warn) extra += `<div class="warnrow">${esc(it.warn)}</div>`;
  if (it.status_note) extra += `<div class="warnrow">${esc(it.status_note)}</div>`;
  if (it.stop_warn) extra += `<div class="noterow">终止时：${esc(it.stop_warn)}</div>`;
  if (it.under) extra += `<div class="noterow">归属：`
    + `<b>${esc(it.under)}</b> 的下属 —— 不在概览上单占一行，从宿主详情进入</div>`;
  if (it.keepalive) {
    const k = it.keepalive;
    if (k.invalid) {
      extra += `<div class="warnrow">保活不可用：`
        + `${esc(k.invalid)}（该服务不会被自动拉起）</div>`;
    } else if (k.paused) {
      extra += `<div class="warnrow">保活已暂停：连续 ${esc(k.max_fails)} 次拉起失败`
        + (k.last_error ? `，最后一条「${esc(k.last_error)}」` : '')
        + '。修好后点「重启」即可恢复保活。</div>';
    } else {
      const kb = [];
      if (k.starts) kb.push(`已自动拉起 ${k.starts} 次`);
      if (k.last_ok_at) kb.push(`上次 ${agoIso(k.last_ok_at)}`);
      if (k.waiting_on) kb.push(`等待依赖 ${k.waiting_on}`);
      if (k.fails) kb.push(`本轮已失败 ${k.fails}/${k.max_fails}`);
      extra += `<div class="noterow">保活：`
        + `${esc(kb.join('，') || '已接入，尚未需要拉起')}</div>`;
    }
  }
  const deps = it.needs || [], sup = it.supports || [];
  if (deps.length || sup.length) {
    const parts = [];
    if (deps.length) {
      parts.push('<span class="lbl">依赖</span>' + deps.map((d) =>
        `<span class="dep${d.status === 'up' ? '' : ' bad'}">${esc(d.label)}${d.status === 'up' ? '' : ' 中断'}</span>`).join(''));
    }
    if (sup.length) {
      parts.push('<span class="lbl">被依赖</span>' + sup.map((d) =>
        `<span class="dep">${esc(d.label)}</span>`).join(''));
    }
    extra += `<div class="deprow${(it.deps_broken || []).length ? ' broken' : ''}">${parts.join('')}</div>`;
  }
  return `<div class="metrics smetrics">${bits.join('')}</div>${extra}`;
}

/* 操作区：link 开地址，run 与写类脚本执行。对端服务只出能转发的（where 声明），
   其余在下面列一行原因。 */
function sideOps(it) {
  const remote = !!SEL.node;
  const buttons = [];
  const hidden = [];
  if (!remote && it.fwd_port && !IS_LOOPBACK) {
    const host = location.hostname;
    const token = host.endsWith('.ts.net') ? '' : authToken();
    const url = `${location.protocol}//${host}:${it.fwd_port}/`
      + (token ? `?token=${encodeURIComponent(token)}` : '');
    buttons.push(`<button data-open="${esc(url)}" title="局域网入口 ${esc(host)}:${it.fwd_port}">局域网</button>`);
  }
  for (const op of (it.ops || [])) {
    if (remote && op.where !== 'peer') { hidden.push(op); continue; }
    if (!isActionOp(op)) continue;
    if (op.rowonly && op.kind !== 'link') continue;
    if (op.kind === 'link') {
      buttons.push(`<button data-url="${esc(op.url)}"${op.danger ? ' class="danger"' : ''}`
        + `>${esc(op.label || '打开')}</button>`);
      continue;
    }
    const key = `${SEL.node || ''}:${it.id}:${op.id}`;
    const busy = INFLIGHT.has(key);
    buttons.push(`<button${op.danger ? ' class="danger"' : ''} data-op="${esc(op.id)}"`
      + ` data-svc="${esc(it.id)}" data-action="1"${SEL.node ? ` data-node="${esc(SEL.node)}"` : ''}`
      + (busy ? ' disabled' : '')
      + ` title="${esc(op.note || op.label || '')}"`
      + `>${esc(busy ? '等待响应…' : (op.label || op.id))}</button>`);
  }
  if (it.stoppable && !it.keepalive) {
    buttons.push(`<button class="danger stop" data-stop="${esc(it.id)}" data-name="${esc(it.name)}"`
      + `${SEL.node ? ` data-node="${esc(SEL.node)}"` : ''}>终止</button>`);
  }
  let kaNote = '';
  if (it.keepalive && it.stoppable) {
    kaNote = '<div class="noterow">没有「终止」：该服务由面板保活，'
      + '停掉会被自动拉起；要干预请用「重启」</div>';
  }
  if (!remote && (!it.restart_kind || it.restart_kind === 'none') && it.restart_why) {
    kaNote += `<div class="noterow">不可重启：${esc(it.restart_why)}</div>`;
  }
  if (it.restart_kind && it.restart_kind !== 'none') {
    buttons.push(`<button class="danger" data-restart="${esc(it.id)}" data-name="${esc(it.name)}"`
      + `${SEL.node ? ` data-node="${esc(SEL.node)}"` : ''}>重启</button>`);
  }
  const why = hidden.map((op) => `<div class="noterow">`
    + `${esc(op.label || op.id)} 未显示：${esc(opHiddenNote(it, op))}</div>`).join('');
  return `<h3 class="sec">操作</h3><div class="sideops">${buttons.join('') || '<span class="empty">没有可用操作</span>'}</div>${kaNote}${why}`;
}

/* 宿主详情里的「下属」区。子条目没有自己的卡片，但仍然可以点开详情。 */
function sideChildren(it) {
  const kids = childrenOf(it.id, SEL.node);
  if (!kids.length) return '';
  const rows = kids.map((k) => {
    const up = k.status === 'up';
    const nAttr = SEL.node ? ` data-node="${esc(SEL.node)}"` : '';
    const state = up ? '正常' : (k.status === 'down' ? '不可达' : '未知');
    const srcTag = k.status_src === 'peer' ? '对端自评' : '';
    const reachTag = k.reach ? ` · 本机${k.reach.ok ? '可达' : '不可达'}` : '';
    return `<div class="childrow">`
      + `<span class="dot${up ? ' on' : ''}"></span>`
      + `<span class="cname">${esc(k.name)}</span>`
      + `<span class="cstate${(up && !k.degraded) ? '' : ' bad'}">${esc(state + srcTag)}`
      + (k.detail ? ` · ${esc(k.detail)}` : '') + esc(reachTag) + '</span>'
      + `<button class="ghost" data-side="${esc(k.id)}"${nAttr}>详情</button>`
      + '</div>';
  }).join('');
  return `<h3 class="sec">下属（${kids.length}）</h3>${rows}`;
}

/* 卡片显示：每服务独有的默认值由服务声明，这里按本设备偏好覆盖。 */
function sideCardPrefs(it, node) {
  const pref = effectiveCard(it, node);
  const boxes = CARD_FIELDS.map((f) =>
    `<label><input type="checkbox" data-card-field="${f.id}"`
    + `${pref[f.id] ? ' checked' : ''}> ${f.label}</label>`).join('');
  return `<h3 class="sec">卡片显示</h3><div class="cardprefs">${boxes}`
    + `<button class="ghost" type="button" data-card-reset="1">恢复默认</button></div>`;
}

/* 服务参数：声明在 services.json 的 settings 里，当前值由适配器读。 */
function paramInput(f) {
  const id = esc(f.id);
  const val = f.value == null ? '' : f.value;
  if (f.type === 'choice') {
    return `<select data-param="${id}">` + (f.choices || []).map((c) =>
      `<option value="${esc(c)}"${String(c) === String(val) ? ' selected' : ''}>${esc(c)}</option>`)
      .join('') + '</select>';
  }
  if (f.type === 'bool') {
    return `<input type="checkbox" data-param="${id}"${val ? ' checked' : ''}>`;
  }
  const type = f.type === 'int' || f.type === 'float' ? 'number' : 'text';
  const step = f.step != null ? ` step="${esc(f.step)}"` : '';
  const min = f.min != null ? ` min="${esc(f.min)}"` : '';
  const max = f.max != null ? ` max="${esc(f.max)}"` : '';
  return `<input type="${type}" data-param="${id}" value="${esc(val)}"${step}${min}${max}>`;
}

function renderParams() {
  const box = $('#side-params');
  if (!box) return;
  if (!PARAMS) { box.innerHTML = ''; return; }
  if (PARAMS.error) {
    box.innerHTML = `<h3 class="sec">参数</h3><div class="mdl-err">${esc(PARAMS.error)}</div>`;
    return;
  }
  const rows = (PARAMS.settings || []).map((f) => {
    if (f.error) {
      return `<div class="param-row"><span class="param-label">${esc(f.label || f.id)}</span>`
        + `<span class="param-err">${esc(f.error)}</span></div>`;
    }
    const apply = f.apply ? `<span class="param-apply">${esc(APPLY_LABEL[f.apply] || f.apply)}</span>` : '';
    const note = f.note ? `<div class="param-note">${esc(f.note)}</div>` : '';
    return `<div class="param-row"><label class="param-label">${esc(f.label || f.id)}</label>`
      + `<span class="param-control">${paramInput(f)}</span>${apply}</div>${note}`;
  }).join('');
  if (!rows) { box.innerHTML = ''; return; }
  box.innerHTML = `<h3 class="sec">参数</h3><div class="params">${rows}`
    + `<button type="button" data-save-params="1">保存参数</button></div>`;
}

async function loadServiceSettings(it, node) {
  if (!it || !(it.settings || []).length) { PARAMS = null; renderParams(); return; }
  PARAMS = { id: it.id, node: node || '', error: null, settings: [] };
  renderParams();
  try {
    const r = await authFetch(`/api/service-settings?id=${encodeURIComponent(it.id)}`
      + (node ? `&node=${encodeURIComponent(node)}` : ''));
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    PARAMS = { id: it.id, node: node || '', error: d.error || null,
               settings: d.settings || [], meta: d.meta || {} };
  } catch (e) {
    PARAMS = { id: it.id, node: node || '', error: `读取参数失败：${e}`, settings: [] };
  }
  renderParams();
}

async function saveParams(btn) {
  if (!PARAMS || PARAMS.error) return;
  const values = {};
  const changed = [];
  document.querySelectorAll('#side-params [data-param]').forEach((el) => {
    const f = (PARAMS.settings || []).find((x) => x.id === el.dataset.param);
    if (!f) return;
    let raw = el.type === 'checkbox' ? el.checked : el.value;
    if (f.type === 'int') raw = parseInt(raw, 10);
    if (f.type === 'float') raw = parseFloat(raw);
    if (String(raw) !== String(f.value == null ? '' : f.value)) {
      values[f.id] = raw;
      changed.push(`<b>${esc(f.label || f.id)}</b>：${esc(f.value == null ? '—' : f.value)} → ${esc(raw)}`);
    }
  });
  if (!Object.keys(values).length) { toast('没有改动', 'warn'); return; }
  const ok = await askConfirm({
    title: '保存服务参数？',
    message: '只写入下面列出的字段；写操作会记入动作历史。',
    code: 'SERVICE_SETTINGS',
    badge: '参数',
    detail: changed.join('；'),
    ok: '保存',
    danger: true,
  });
  if (!ok) return;
  btn.disabled = true;
  try {
    const r = await authFetch('/api/service-settings', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' },
        window.__mozunitor ? window.__mozunitor.authHeaders() : {}),
      body: JSON.stringify({ id: PARAMS.id, values, node: PARAMS.node || undefined }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok || !d.ok) throw new Error(d.error || ('HTTP ' + r.status));
    toast(`参数已保存${(d.notes || []).length ? '：' + d.notes.join('；') : ''}`, 'ok');
  } catch (e) {
    toast(`保存失败：${e}`, 'bad');
  } finally {
    btn.disabled = false;
    const it = currentItem();
    if (it) loadServiceSettings(it, SEL.node);
  }
}

/* 面板骨架：只读操作各成一节。lazy 的先给一个「展开」按钮，点了才取数。 */
function sidePanes(it) {
  const remote = !!SEL.node;
  const panes = (it.ops || []).filter((op) => isPaneOp(op) && !(remote && op.where !== 'peer'));
  if (!panes.length) return '<h3 class="sec">详情面板</h3><div class="empty">该服务未声明详情面板</div>';
  return panes.map((op) => {
    if (op.lazy) {
      return `<div class="pane" data-pane="${esc(op.id)}"><h3 class="sec">${esc(op.label || op.id)}</h3>`
        + `<button class="ghost" data-op="${esc(op.id)}" data-svc="${esc(it.id)}" data-lazy="1"`
        + `>展开</button></div>`;
    }
    return `<div class="pane" data-pane="${esc(op.id)}"><h3 class="sec">${esc(op.label || op.id)}</h3>`
      + `<div class="pane-body"><div class="empty">载入中…</div></div></div>`;
  }).join('');
}

function loadPanes(it) {
  const panes = (it.ops || []).filter((op) => isPaneOp(op) && !op.lazy
    && !(SEL.node && op.where !== 'peer'));
  for (const op of panes) {
    const box = document.querySelector(`#side-panes [data-pane="${op.id}"]`);
    if (box) loadPane(box, op);
  }
}

async function loadHistory(it) {
  const key = SEL_KEY;
  const box = $('#side-history');
  if (!box) return;
  try {
    const r = await authFetch(`/api/history?id=${encodeURIComponent(it.id)}&limit=20`);
    if (SEL_KEY !== key || !$('#side-history')) return;
    const d = await r.json();
    box.innerHTML = '<h3 class="sec">动作历史</h3>' + (d.error
      ? `<div class="mdl-err">${esc(d.error)}</div>`
      : `<div class="pane-body">${renderSections(d.sections)}</div>`);
  } catch (e) {
    if (SEL_KEY === key && $('#side-history')) {
      box.innerHTML = `<h3 class="sec">动作历史</h3><div class="mdl-err">读取失败：${esc(String(e))}</div>`;
    }
  }
}

export function renderSide() {
  const body = $('#side-body');
  if (!body) return;
  const it = currentItem();
  const empty = $('#side-empty');
  if (empty) empty.classList.toggle('hidden', !!it);
  if (!it) {
    $('#side-name').textContent = '服务详情';
    $('#side-sub').textContent = '从左侧选一个服务';
    body.innerHTML = '';
    body.classList.add('hidden');
    PARAMS = null;
    setSelKey('');
    return;
  }
  body.classList.remove('hidden');
  $('#side-name').textContent = it.name;
  $('#side-sub').textContent = it.id + (SEL.node ? ` · ${SEL.node}` : '');
  const key = `${SEL.node || ''}:${SEL.svc}`;
  if (key === SEL_KEY) {
    $('#side-metrics').innerHTML = sideMetrics(it);
    $('#side-ops').innerHTML = sideOps(it);
    const ch = $('#side-children');
    if (ch) ch.innerHTML = sideChildren(it);
    const cp = $('#side-card');
    if (cp) cp.innerHTML = sideCardPrefs(it, SEL.node);
    return;
  }
  setSelKey(key);
  body.innerHTML = `<div id="side-metrics">${sideMetrics(it)}</div>`
    + `<div id="side-ops">${sideOps(it)}</div>`
    + `<div id="side-params"></div>`
    + `<div id="side-children">${sideChildren(it)}</div>`
    + `<div id="side-card">${sideCardPrefs(it, SEL.node)}</div>`
    + '<div id="side-result"></div>'
    + `<div id="side-panes">${sidePanes(it)}</div>`
    + '<div id="side-history" class="pane"><h3 class="sec">动作历史</h3>'
    + '<div class="empty">载入中…</div></div>';
  loadHistory(it);
  loadPanes(it);
  loadServiceSettings(it, SEL.node);
}

export function sideOpen(svcId, nodeId) {
  setSel({ svc: svcId, node: nodeId || undefined });
  setSelKey('');                      // 强制重建面板
  renderSide();
  markSelected();
  const side = $('#side');
  if (side) side.classList.add('open');
  const body = $('#side-body');
  if (body) body.scrollTop = 0;
}

export function sideClose() {
  setSel(null);
  setSelKey('');
  nextPaneSeq();
  renderSide();
  markSelected();
  $('#side')?.classList.remove('open');
}

/* 任何针对某个服务的动作都先让侧边栏聚焦到它。 */
export function ensureSide(id, node) {
  if (SEL && SEL.svc === id && (SEL.node || undefined) === (node || undefined)) return;
  sideOpen(id, node);
}

/* 结果条：动作 / 脚本 / 面板共用。 */
export function showOpResult(it, op, d) {
  const verb = op.label || op.id;
  const spent = d.elapsed_s != null ? `${d.elapsed_s}s` : '';
  const head = (d.ok === false ? `${verb}未成功` : `${verb}完成`)
    + (spent ? `（${spent}）` : '');
  const steps = (d.steps || []).map((s) => `[${s.t}] ${s.msg}`).join('\n');
  showSideResult(`<b>${esc(head)}</b>` + (steps ? `<pre class="optext">${esc(steps)}</pre>` : ''),
    d.ok === false);
  if (d.sections) {
    showSideResult(`<b>${esc(head)}</b><div class="op-live">${renderSections(d.sections)}</div>`,
      d.ok === false);
    tickCountdowns();
  }
}

export { sideMetrics, sideOps, sidePanes, saveParams, loadServiceSettings };
