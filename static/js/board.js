// 机器 → 级别（core / normal / optional）→ 服务卡片。置顶区复用同一套卡片渲染。
import { esc, fmtMB, fmtMs, fmtPct, fmtDur, agoIso } from './format.js';
import {
  DATA, SEL, INFLIGHT, TIERS, TIER_ORDER, CARD_FIELDS,
  machineBlocks, tierItems, tierOf, tierStats, itemBad, itemByKey,
  pins, isPinned, pinKey, effectiveCard, collapseFor, mobileHideOptional, NARROW,
} from './state.js';
import { IS_LOOPBACK } from './api.js';

const $ = (s) => document.querySelector(s);

/* 保活状态的小标记。只在「有事」时出现 —— 正常运行时状态点已经说明了问题，
   再加一枚「保活正常」的徽章只会稀释卡片上的信息。上限取自后端，不写死 5。 */
function kaBadge(ka) {
  if (!ka) return '';
  if (ka.invalid) {
    return `<span class="badge badge--warning ka-badge" title="${esc(ka.invalid)}">保活不可用</span>`;
  }
  if (ka.paused) {
    return `<span class="badge badge--blocked ka-badge" title="${esc(ka.last_error || '连续拉起失败')}">保活已暂停</span>`;
  }
  if (ka.fails) {
    return `<span class="badge badge--warning ka-badge" title="${esc(ka.last_error || '')}">`
      + `保活 ${ka.fails}/${ka.max_fails}</span>`;
  }
  return '';
}

function pinButton(node, id) {
  const on = isPinned(node, id);
  return `<button class="pin" type="button" data-pin="${esc(pinKey(node, id))}"`
    + ` aria-pressed="${on ? 'true' : 'false'}" title="${on ? '取消置顶' : '置顶'}">`
    + `${on ? '★' : '☆'}</button>`;
}

function stateText(it, pref) {
  const srcTag = it.status_src === 'peer' ? '对端自评' : '';
  const narrow = !!(NARROW && NARROW.matches);
  const showDetail = pref.detail && it.detail && !(narrow && it.status === 'up');
  return [srcTag, showDetail ? it.detail : ''].filter(Boolean).join(' · ');
}

function metricBits(it) {
  const m = [];
  if (it.pid != null) m.push(`<span>PID <b>${it.pid}</b></span>`);
  if (it.proc_name) m.push(`<span>进程 <b>${esc(it.proc_name)}</b></span>`);
  if (it.mem_mb != null) m.push(`<span class="${it.mem_mb >= 800 ? 'hot' : ''}">内存 <b>${fmtMB(it.mem_mb)}</b></span>`);
  if (it.cpu_pct != null) m.push(`<span class="${it.cpu_pct >= 50 ? 'hot' : ''}">CPU <b>${fmtPct(it.cpu_pct)}</b></span>`);
  if (it.uptime_s != null) m.push(`<span>已运行 <b>${fmtDur(it.uptime_s)}</b></span>`);
  if (it.latency_ms != null) m.push(`<span>探测 <b>${fmtMs(it.latency_ms)}</b></span>`);
  if (it.reach) m.push(`<span title="${esc(it.reach.detail || '')}">本机 <b>${it.reach.ok ? '可达' : '不可达'}</b></span>`);
  for (const b of (it.badges || [])) {
    m.push(`<span class="${b.hot ? 'hot' : ''}">${esc(b.text)}</span>`);
  }
  return m.join('');
}

function depRow(it) {
  const deps = it.needs || [];
  const sup = it.supports || [];
  if (!deps.length && !sup.length) return '';
  const parts = [];
  if (deps.length) {
    parts.push('<span class="lbl">依赖</span>' + deps.map((d) =>
      `<span class="dep${d.status === 'up' ? '' : ' bad'}" title="${d.status === 'up' ? '可达' : '不可达'}">`
      + `${esc(d.label)}${d.status === 'up' ? '' : ' 中断'}</span>`).join(''));
  }
  if (sup.length) {
    parts.push('<span class="lbl">被依赖</span>' + sup.map((d) =>
      `<span class="dep">${esc(d.label)}</span>`).join(''));
  }
  return `<div class="deprow${(it.deps_broken || []).length ? ' broken' : ''}">${parts.join('')}</div>`;
}

function cardActions(it, node) {
  const remote = !!node;
  const key = remote ? `${node}:${it.id}` : it.id;
  const nAttr = remote ? ` data-node="${esc(node)}"` : '';
  const busy = INFLIGHT.has(key);
  const actions = [];
  if (it.stoppable && !it.keepalive) {
    actions.push(`<button class="danger stop" data-stop="${esc(it.id)}" data-name="${esc(it.name)}"${nAttr}`
      + (busy ? ' disabled' : '')
      + ` title="停掉该服务以释放内存；之后可用「重启」拉回">${busy ? '等待响应…' : '终止'}</button>`);
  }
  if (it.restart_kind && it.restart_kind !== 'none') {
    actions.push(`<button class="danger" data-restart="${esc(it.id)}" data-name="${esc(it.name)}"${nAttr}`
      + (busy ? ' disabled' : '')
      + `>${busy ? '等待响应…' : '重启'}</button>`);
  } else if (!remote) {
    actions.push(`<button disabled title="${esc(it.restart_why || '')}">不可重启</button>`);
  }
  actions.push(`<button data-side="${esc(it.id)}"${nAttr}>详情</button>`);
  return actions.join('');
}

export function renderCard(it, node, opt) {
  opt = opt || {};
  const pref = effectiveCard(it, node);
  const status = it.status === 'up' ? 'up' : it.status === 'down' ? 'down' : 'unknown';
  const tone = status === 'up' ? 'ok' : status === 'down' ? 'blocked' : 'info';
  const stateLabel = status === 'up' ? '正常' : status === 'down' ? '不可达' : '未知';
  const selected = SEL && SEL.svc === it.id && (SEL.node || '') === (node || '');
  const st = stateText(it, pref);
  const bits = pref.metrics ? metricBits(it) : '';
  const metrics = (st || bits) ? `<div class="metrics">`
    + (st ? `<span class="svc-state">${esc(st)}</span>` : '') + bits + '</div>' : '';
  const deps = (pref.deps || (it.deps_broken || []).length) ? depRow(it) : '';
  const note = (pref.note && it.access && it.access.note)
    ? `<div class="noterow">${esc(it.access.note)}</div>` : '';
  const warnBits = [];
  if (pref.warn && it.warn) warnBits.push(it.warn);
  if (pref.warn && it.status_note) warnBits.push(it.status_note);
  const warn = warnBits.length
    ? `<div class="warnrow">${esc(warnBits.join('；'))}</div>` : '';
  const flag = it.flag
    ? `<span class="badge badge--warning" title="${esc(it.flag)}">${esc(it.flag)}</span>` : '';
  const ka = (pref.keepalive !== false) ? kaBadge(it.keepalive) : '';
  const role = (pref.role && it.role)
    ? `<span class="svc-role" title="${esc(it.role)}">${esc(it.role)}</span>` : '';

  return `<article class="svc ${status}${it.flag ? ' norecovery' : ''}${selected ? ' selected' : ''}`
    + `${opt.pinned ? ' pinned' : ''}" data-sid="${esc(it.id)}" data-snode="${esc(node || '')}">`
    + `<div class="svc-body"><div class="svc-line">${pinButton(node, it.id)}`
    + `<span class="svc-name">${esc(it.name)}</span>`
    + `<span class="badge badge--${tone}">${stateLabel}</span>${ka}${flag}${role}</div>`
    + `${metrics}${deps}${note}${warn}</div>`
    + `<div class="actions">${cardActions(it, node)}</div></article>`;
}

/* 按需层：没在跑是常态，不套卡片那套状态/依赖结构，只留状态点、名称与按钮。 */
export function renderTile(it, node, opt) {
  opt = opt || {};
  const up = it.status === 'up';
  const busy = INFLIGHT.has(node ? `${node}:${it.id}` : it.id);
  const acts = [pinButton(node, it.id)];
  if (up && it.access && it.access.url) {
    acts.push(`<button data-open="${esc(it.access.url)}">打开</button>`);
  }
  if (busy) {
    acts.push('<button disabled>等待响应…</button>');
  } else if (!up) {
    acts.push(`<button data-launch="${esc(it.id)}" data-name="${esc(it.name)}">启动</button>`);
  } else if (it.stoppable && !it.keepalive) {
    acts.push(`<button class="danger stop" data-stop="${esc(it.id)}" data-name="${esc(it.name)}">停止</button>`);
  } else {
    acts.push('<button disabled title="关闭请直接关它的窗口">运行中</button>');
  }
  return `<div class="tile${up ? ' on' : ''}${opt.pinned ? ' pinned' : ''}"`
    + ` data-sid="${esc(it.id)}" data-snode="${esc(node || '')}">`
    + `<span class="dot"></span>`
    + `<span class="tile-name" title="${esc(it.role || '')}">${esc(it.name)}</span>`
    + `<span class="tile-acts">${acts.join('')}</span></div>`;
}

function renderItem(entry, opt) {
  return tierOf(entry.it) === 'optional'
    ? renderTile(entry.it, entry.node, opt)
    : renderCard(entry.it, entry.node, opt);
}

/* 状态排序：有问题的排前面；同档内按名称。 */
function sortEntries(entries) {
  return entries.slice().sort((a, b) =>
    (itemBad(b.it) - itemBad(a.it)) || String(a.it.name).localeCompare(String(b.it.name), 'zh'));
}

function tierHead(block, tier, stats, collapsed) {
  const title = TIERS[tier] || tier;
  let meta = '';
  let badge = '';
  if (tier === 'optional') {
    meta = `${stats.total} 项`;
  } else {
    meta = `${stats.up}/${stats.total}`;
    if (stats.issues) badge = ` <span class="badge badge--blocked">${stats.issues} 异常</span>`;
  }
  return `<div class="tier-head" role="button" tabindex="0" aria-expanded="${collapsed ? 'false' : 'true'}"`
    + ` data-toggle-tier="1" data-machine="${esc(block.id)}" data-tier="${tier}">`
    + `<span class="tier-caret" aria-hidden="true">${collapsed ? '▸' : '▾'}</span>`
    + `<h3 class="tier-title">${title}</h3><span class="tier-meta">${meta}</span>${badge}</div>`;
}

function renderTierGroup(block, tier, entries) {
  if (!entries.length) return '';
  if (tier === 'optional' && mobileHideOptional()
      && window.matchMedia('(max-width: 860px)').matches) return '';
  const stats = tierStats(entries);
  const collapsed = collapseFor(block.id, tier, tier !== 'optional' && stats.issues > 0);
  const body = sortEntries(entries).map((e) => renderItem(e)).join('');
  return `<section class="tier-group tier-${tier}" data-machine="${esc(block.id)}" data-tier="${tier}">`
    + `${tierHead(block, tier, stats, collapsed)}`
    + `<div class="tier-body"${collapsed ? ' hidden' : ''}>${body}</div></section>`;
}

function machineMeta(m) {
  const sm = m.summary || {};
  const sumTxt = sm.total != null ? `${sm.up || 0}/${sm.total} 在线` : '';
  const ageS = (!m.self && m.at) ? Math.max(0, Math.round(Date.now() / 1000 - m.at)) : null;
  if (m.self) return sumTxt;
  if (m.online) {
    return [sumTxt, m.latency_ms != null ? fmtMs(m.latency_ms) + ' 延迟' : '']
      .filter(Boolean).join(' · ')
      + (ageS != null && ageS > 20 ? ` · 快照 ${ageS}s 前` : '');
  }
  return '离线 · ' + (m.error || '不可达');
}

export function renderMachine(m) {
  const tiers = TIER_ORDER.map((t) => renderTierGroup(m, t, tierItems(m, t))).join('');
  const badge = m.self
    ? '<span class="badge badge--info">本机</span>'
    : (m.online ? '<span class="badge badge--ok">在线</span>'
      : '<span class="badge badge--blocked">离线</span>');
  return `<section class="machine${m.online ? '' : ' off'}" data-machine="${esc(m.id)}">`
    + `<div class="machine-head group-head">`
    + `<h2>${esc(m.name)}</h2>`
    + (m.id && String(m.id).toLowerCase() !== String(m.name).toLowerCase()
      ? `<span class="hint">${esc(m.id)}</span>` : '')
    + `<span class="gmeta">${esc(machineMeta(m))}</span>${badge}</div>`
    + `<div class="machine-tiers">${tiers || '<div class="empty">无上报数据</div>'}</div></section>`;
}

export function renderBoard(d) {
  const board = $('#board');
  if (!board) return;
  board.innerHTML = machineBlocks(d).map(renderMachine).join('')
    || '<div class="empty">无上报数据</div>';
  markSelected();
}

export function renderPinned(d) {
  const box = $('#pinned');
  const body = $('#pinned-body');
  if (!box || !body) return;
  const entries = [];
  for (const key of pins()) {
    const hit = itemByKey(key);
    if (hit.it) entries.push(hit);
  }
  box.classList.toggle('hidden', !entries.length);
  const count = $('#pinned-count');
  if (count) count.textContent = entries.length ? String(entries.length) : '';
  body.innerHTML = entries.map((e) => renderItem(e, { pinned: true })).join('');
  markSelected();
}

export function markSelected() {
  const want = SEL ? `${SEL.node || ''}:${SEL.svc}` : '';
  document.querySelectorAll('#board .svc, #pinned .svc, #board .tile, #pinned .tile').forEach((el) => {
    const key = `${el.dataset.snode || ''}:${el.dataset.sid || ''}`;
    el.classList.toggle('selected', !!want && key === want);
  });
}

export { CARD_FIELDS };
