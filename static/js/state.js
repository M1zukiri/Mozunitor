// 模块级状态、本设备偏好与派生数据。渲染模块只读这里；轮询与重绘由 app.js 调度。

export const POLL_MS = 3000;

/* 正在等待后端答复的服务。重启 / 终止是同步阻塞的（远端要等到端口真的起来才返回），
   而 3 秒轮询会重建整块面板 —— 只把按钮置灰会被下一次渲染冲掉，所以进行中的状态
   必须存在这里，由卡片渲染在每次重绘时重新施加。key 带节点前缀。 */
export const INFLIGHT = new Set();

export let DATA = null;
export let OFFLINE = false;
export let SEL = null;          // { svc, node } —— 当前选中的服务与所属节点
export let SEL_KEY = '';        // 已渲染的选中键；与上面不一致才重建面板
export let PANE_SEQ = 0;        // 面板请求序号，用于丢弃迟到响应

export const TIERS = { core: '核心', normal: '常驻', optional: '按需' };
export const TIER_ORDER = ['core', 'normal', 'optional'];
export const CARD_FIELDS = [
  { id: 'role', label: '角色说明' },
  { id: 'detail', label: '探测说明' },
  { id: 'metrics', label: '运行指标' },
  { id: 'deps', label: '依赖' },
  { id: 'note', label: '访问说明' },
  { id: 'warn', label: '警告' },
  { id: 'badges', label: '服务徽章' },
  { id: 'keepalive', label: '保活标记' },
];

export const NARROW = (() => {
  try {
    return window.matchMedia('(max-width: 560px)');
  } catch (e) {
    return null;
  }
})();

export function setData(d) { DATA = d; }
export function setOffline(v) { OFFLINE = v; }
export function setSel(v) { SEL = v; }
export function setSelKey(v) { SEL_KEY = v; }
export function nextPaneSeq() { return ++PANE_SEQ; }

// ---------------------------------------------------------------- 本设备偏好

const LS = {
  pins: 'mozunitor.pins',
  collapse: 'mozunitor.collapse',
  card: 'mozunitor.card',
  mobile: 'mozunitor.mobile_hide_optional',
};

function readPref(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (e) {
    return fallback;
  }
}

function writePref(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) { /* 隐私模式写不进就只在本次会话生效 */ }
}

export const pinKey = (node, id) => `${node || ''}:${id}`;

export function pins() {
  const v = readPref(LS.pins, []);
  return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
}

export function isPinned(node, id) { return pins().includes(pinKey(node, id)); }

export function togglePin(node, id) {
  const key = pinKey(node, id);
  const list = pins();
  const i = list.indexOf(key);
  if (i >= 0) list.splice(i, 1); else list.push(key);
  writePref(LS.pins, list);
  return list.includes(key);
}

export function unpin(key) {
  writePref(LS.pins, pins().filter((x) => x !== key));
}

/* 卡片字段：全局默认（后端 ui.card）→ 服务声明（item.card）→ 全局偏好 → 单服务偏好。 */
export function effectiveCard(it, node) {
  const base = Object.assign({},
    (DATA && DATA.ui && DATA.ui.card) || {}, (it && it.card) || {});
  const g = readPref(LS.card, {});
  const s = readPref(`${LS.card}.${node || ''}:${it.id}`, {});
  return Object.assign(base, g || {}, s || {});
}

export function globalCardPrefs() { return readPref(LS.card, {}); }
export function setGlobalCardPref(field, value) {
  const cur = globalCardPrefs();
  cur[field] = !!value;
  writePref(LS.card, cur);
}
export function resetGlobalCardPrefs() { writePref(LS.card, {}); }

export function serviceCardPrefs(node, id) {
  return readPref(`${LS.card}.${node || ''}:${id}`, {});
}
export function setServiceCardPref(node, id, field, value) {
  const cur = serviceCardPrefs(node, id);
  cur[field] = !!value;
  writePref(`${LS.card}.${node || ''}:${id}`, cur);
}
export function resetServiceCardPref(node, id) {
  try { localStorage.removeItem(`${LS.card}.${node || ''}:${id}`); } catch (e) { /* 忽略 */ }
}

export function collapseStored(machineId, tier) {
  const m = readPref(LS.collapse, {}) || {};
  const key = `${machineId}:${tier}`;
  return Object.prototype.hasOwnProperty.call(m, key) ? !!m[key] : undefined;
}

export function collapseFor(machineId, tier, hasIssues) {
  const stored = collapseStored(machineId, tier);
  if (stored !== undefined) return stored;
  return tier === 'core' ? !hasIssues : true;   // 核心有异常时自动展开
}

export function storeCollapse(machineId, tier, collapsed) {
  const m = readPref(LS.collapse, {}) || {};
  m[`${machineId}:${tier}`] = !!collapsed;
  writePref(LS.collapse, m);
}

export function mobileHideOptional() {
  const v = readPref(LS.mobile, null);
  if (v === null) return !!(DATA && DATA.ui && DATA.ui.mobile_hide_optional);
  return !!v;
}

export function setMobileHideOptional(v) { writePref(LS.mobile, !!v); }

// ---------------------------------------------------------------- 派生数据

export function tierOf(it) {
  if (!it) return 'normal';
  if (it.tier === 'core' || it.tier === 'normal' || it.tier === 'optional') return it.tier;
  const g = String(it.group || '');
  if (g === 'infra') return 'core';
  if (g === 'launchpad') return 'optional';
  return 'normal';
}

const isChild = (it) => !!(it && it.under);

/* 归属递归展开：若出现 A under B、B under C，A 也必须出现在 C 的下属里。
   只认直接子项的话，深度 ≥2 的条目会在界面上哪里都不出现。 */
export function childrenOf(svcId, nodeId) {
  const want = nodeId || '';
  const all = [];
  for (const m of machineList()) {
    for (const g of (m.groups || [])) {
      if ((g.srcNode || '') !== want) continue;
      for (const it of (g.items || [])) all.push(it);
    }
  }
  const out = [];
  const seen = new Set([svcId]);
  const walk = (parent) => {
    for (const it of all) {
      if (it.under !== parent || seen.has(it.id)) continue;
      seen.add(it.id);
      out.push(it);
      walk(it.id);
    }
  };
  walk(svcId);
  return out;
}

/* 机器层：本节点在最上，其余节点按名字依次排下。
   分组归属由 group.machine 声明（缺省=本节点）——不再靠组 id 猜机器。 */
export function machineBlocks(d) {
  const node = d.node || {};
  const selfId = node.id || 'self';
  const selfGroups = d.groups || [];
  const tagged = (mid) => selfGroups.filter((g) => g.machine === mid);

  const blocks = [{
    id: selfId, name: node.name || '本机', self: true, online: true,
    groups: selfGroups.filter((g) => !g.machine || g.machine === selfId),
    summary: d.summary, meta: d.local_meta,
  }];

  for (const pid of Object.keys(d.peers || {}).sort()) {
    const p = d.peers[pid] || {};
    const snap = p.snapshot || {};
    const pnode = snap.node || {};
    const mid = pnode.id || pid;
    blocks.push({
      id: mid, name: pnode.name || pid, self: false,
      online: !!p.online, latency_ms: p.latency_ms, error: p.error,
      at: p.snap_at || p.at,
      groups: [
        ...(snap.groups || []).map((g) => Object.assign({}, g, { srcNode: mid })),
        ...tagged(mid).map((g) => Object.assign({}, g, { srcNode: undefined })),
      ],
      summary: snap.summary || {}, meta: snap.meta,
    });
  }
  // 配置标了一台机器、但那台机器没出现在 peers 里：仍给它一个块，别静默吞掉那些分组
  for (const g of selfGroups) {
    if (g.machine && !blocks.some((b) => b.id === g.machine)) {
      blocks.push({
        id: g.machine, name: g.machine, self: false, online: false,
        error: '未在 peers 中发现该节点', groups: tagged(g.machine),
        summary: {}, meta: null,
      });
    }
  }
  return blocks;
}

export function machineList() {
  return DATA ? machineBlocks(DATA) : [];
}

export function findAnyItem(svcId, nodeId) {
  const want = nodeId || '';
  for (const m of machineList()) {
    for (const g of (m.groups || [])) {
      if ((g.srcNode || '') !== want) continue;
      const hit = (g.items || []).find((x) => x.id === svcId);
      if (hit) return hit;
    }
  }
  return null;
}

export function itemByKey(key) {
  const i = String(key || '').indexOf(':');
  const node = key.slice(0, i), id = key.slice(i + 1);
  return { node, id, it: findAnyItem(id, node) };
}

export function currentItem() {
  return SEL ? findAnyItem(SEL.svc, SEL.node) : null;
}

/* 本机自己声明的分组（d.groups）；对端快照在 d.peers 里，不算本机统计。 */
export function localItems(d, skipOptional) {
  const out = [];
  for (const g of ((d && d.groups) || [])) {
    for (const it of (g.items || [])) {
      if (isChild(it)) continue;
      if (skipOptional && tierOf(it) === 'optional') continue;
      out.push(it);
    }
  }
  return out;
}

export function keepaliveSummary(d) {
  const kaItems = localItems(d, true).filter((it) => it.keepalive);
  return {
    total: kaItems.length,
    paused: kaItems.filter((it) => it.keepalive.paused && !it.keepalive.invalid),
    invalid: kaItems.filter((it) => it.keepalive.invalid),
  };
}

/* 不可达服务的名字只用来拼一行摘要，不参与判断 —— 计数一律取后端 summary。 */
export function downNames(d, tier) {
  const names = [];
  for (const it of localItems(d, true)) {
    if (tier && tierOf(it) !== tier) continue;
    if (it.status === 'down') names.push(it.name);
  }
  return names;
}

export function peerStale(d) {
  const out = [];
  const now = Date.now() / 1000;
  for (const pid of Object.keys((d && d.peers) || {})) {
    const p = d.peers[pid] || {};
    if (!p.online) continue;
    const at = p.snap_at || p.at;
    if (!at) continue;
    const age = Math.round(now - at);
    if (age > 40) out.push(`${pid} ${age}s 前`);
  }
  return out;
}

/* 一台机器里某一档的全部条目（不含下属）。 */
export function tierItems(block, tier) {
  const out = [];
  for (const g of (block.groups || [])) {
    for (const it of (g.items || [])) {
      if (isChild(it)) continue;
      if (tierOf(it) !== tier) continue;
      out.push({ it, node: g.srcNode || '' });
    }
  }
  return out;
}

export function itemBad(it) {
  return (it.status !== 'up' || (it.deps_broken || []).length
    || (it.keepalive && (it.keepalive.paused || it.keepalive.invalid))) ? 1 : 0;
}

export function tierStats(entries) {
  let up = 0, issues = 0;
  for (const { it } of entries) {
    if (it.status === 'up') up += 1;
    if (itemBad(it)) issues += 1;
  }
  return { up, total: entries.length, issues };
}
