// 入口：轮询 /api/state，统一调度状态条、警告条、置顶区、分组卡片与详情右栏；
// 全局事件委托也在这里，模块之间不互相挂监听。
import { esc, fmtMs, fmtDur } from './js/format.js';
import {
  authFetch, IS_LOOPBACK, bootstrap, login as apiLogin, completeSetup,
} from './js/api.js';
import {
  askConfirm, bindConfirm, confirmOpen, settleConfirm,
  showGate, hideGate, gateMsg, clearGateMsg, toast,
  SETUP, setSetup,
} from './js/modal.js';
import {
  POLL_MS, NARROW, DATA, OFFLINE, SEL, INFLIGHT,
  setData, setOffline, currentItem,
  localItems, keepaliveSummary, downNames, peerStale, tierOf, itemBad,
  pins, togglePin, unpin, setGlobalCardPref, resetGlobalCardPrefs,
  mobileHideOptional, setMobileHideOptional, TIER_ORDER,
  storeCollapse, resetServiceCardPref, setServiceCardPref,
} from './js/state.js';
import {
  renderBoard, renderPinned, markSelected,
} from './js/board.js';
import {
  renderSide, sideOpen, sideClose, saveParams,
} from './js/side.js';
import { loadPane, renderSections, isPaneOp, tickCountdowns } from './js/ops.js';
import {
  openSettings, closeSettings, settingsOpen, renderSettings, savePanel,
} from './js/settings.js';
import {
  doStop, doRestart, doLaunch, runOp, openExternal,
} from './js/actions.js';

const $ = (s) => document.querySelector(s);
const coreIssues = (d) => localItems(d).filter((it) => tierOf(it) === 'core' && itemBad(it));
const normalIssues = (d) => localItems(d).filter((it) => tierOf(it) === 'normal' && itemBad(it));

/* ------------------------------------------------------------------ 顶栏 */

function renderStatus(d) {
  const node = (d && d.node) || {};
  const peers = Object.values((d && d.peers) || {});
  const online = peers.filter((p) => p.online).length;
  $('#status-node').textContent = node.name || '—';
  const core = coreIssues(d).length;
  const normal = normalIssues(d).length;
  const setStat = (id, text, tone) => {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.dataset.tone = tone || '';
  };
  setStat('#stat-core', `核心异常 ${core}`, core ? 'bad' : 'muted');
  setStat('#stat-normal', `常驻异常 ${normal}`, normal ? 'warn' : 'muted');
  setStat('#stat-peers', `对端 ${online}/${peers.length}`, peers.length && online < peers.length ? 'bad' : 'muted');
  const stamp = $('#stamp');
  if (stamp) stamp.textContent = ((d && d.server_time) || '').slice(11, 19) || '—';
  const bar = $('#statusbar');
  if (bar) bar.classList.toggle('offline', OFFLINE);
}

/* ------------------------------------------------------------------ KPI */

function renderKpis(d) {
  const box = $('#kpi-row');
  if (!box) return;
  const s = (d && d.summary) || {};
  const peers = Object.values((d && d.peers) || {});
  const online = peers.filter((p) => p.online).length;
  const ka = keepaliveSummary(d);
  const core = coreIssues(d).length;
  const normal = normalIssues(d).length;
  const kaIssues = ka.paused.length + ka.invalid.length;
  const tiles = [
    {
      label: '核心异常',
      value: `${core}<small>项</small>`,
      foot: core ? '<span class="badge badge--blocked">需处理</span>' : '<span class="badge badge--ok">正常</span>',
    },
    {
      label: '常驻异常',
      value: `${normal}<small>项</small>`,
      foot: normal ? '<span class="badge badge--warning">需处理</span>' : '<span class="badge badge--ok">正常</span>',
    },
    {
      label: '对端节点',
      value: peers.length ? `${online}<small>/${peers.length}</small>` : '—',
      foot: peers.length
        ? (peers.some((p) => p.online) ? '在线' : '全部离线')
          + (online < peers.length ? ' <span class="badge badge--blocked">离线</span>' : '')
        : '未配置对端',
    },
    {
      label: '保活干预',
      value: `${kaIssues}<small>项</small>`,
      foot: `${ka.total} 项受保活 `
        + (kaIssues ? '<span class="badge badge--blocked">需处理</span>'
          : '<span class="badge badge--ok">正常</span>'),
    },
  ];
  box.innerHTML = tiles.map((t) =>
    `<section class="kpi"><span class="kpi-label">${esc(t.label)}</span>`
    + `<span class="kpi-value">${t.value}</span>`
    + `<span class="kpi-foot">${t.foot}</span></section>`).join('');
}

/* ------------------------------------------------------------------ 警告条 */

/* 只放「整体状态」这一级：核心异常红色、常驻异常合并为琥珀一行、对端问题单列。
   服务级的细节留在卡片与详情里；最多两行，其余合并计数。 */
function renderWarnings(d) {
  const box = $('#warnings');
  if (!box) return;
  const rows = [];
  if (OFFLINE) {
    rows.push(['bad', 'BACKEND_DOWN', '后端不可达',
      '页面保留最后一次成功快照，判据可能已过期；控制按钮当前会失败。']);
  }
  const lm = d && d.local_meta;
  if (lm && lm.error) rows.push(['bad', 'COLLECT_LOCAL', '本机采集失败', String(lm.error)]);

  const local = localItems(d);
  const core = local.filter((it) => tierOf(it) === 'core');
  const normal = local.filter((it) => tierOf(it) === 'normal');
  const kaInv = core.filter((it) => it.keepalive && it.keepalive.invalid);
  const kaPaused = core.filter((it) => it.keepalive && it.keepalive.paused && !it.keepalive.invalid);
  const coreDown = core.filter((it) => it.status === 'down');
  const coreDeps = core.filter((it) => (it.deps_broken || []).length);
  if (kaInv.length) {
    rows.push(['bad', 'KEEPALIVE_INVALID', `核心保活不可用 ${kaInv.length} 项`,
      kaInv.map((it) => `${it.name}：${it.keepalive.invalid}`).join('；')]);
  }
  if (kaPaused.length) {
    rows.push(['bad', 'KEEPALIVE_PAUSED', `核心保活暂停 ${kaPaused.length} 项`,
      kaPaused.map((it) => `${it.name}${it.keepalive.last_error ? '：' + it.keepalive.last_error : ''}`)
        .join('；')]);
  }
  if (coreDown.length) {
    rows.push(['bad', 'CORE_DOWN', `核心服务不可达 ${coreDown.length} 项`,
      coreDown.slice(0, 4).map((it) => it.name).join(' / ')
      + (coreDown.length > 4 ? ' 等' : '')]);
  }
  if (coreDeps.length) {
    rows.push(['bad', 'CORE_DEP_BROKEN', `核心依赖中断 ${coreDeps.length} 处`,
      coreDeps.slice(0, 4).map((it) => it.name).join(' / ')
      + (coreDeps.length > 4 ? ' 等' : '')]);
  }
  const nDown = normal.filter((it) => it.status === 'down');
  const nDeps = normal.filter((it) => (it.deps_broken || []).length);
  const nPaused = normal.filter((it) => it.keepalive && (it.keepalive.paused || it.keepalive.invalid));
  if (nDown.length || nDeps.length || nPaused.length) {
    const bits = [];
    if (nDown.length) bits.push(`${nDown.length} 项不可达`);
    if (nDeps.length) bits.push(`${nDeps.length} 处依赖中断`);
    if (nPaused.length) bits.push(`${nPaused.length} 项保活暂停`);
    const names = nDown.slice(0, 4).map((it) => it.name).join(' / ');
    rows.push(['warn', 'NORMAL_ISSUES', `常驻异常 ${bits.join(' · ')}`,
      names + (nDown.length > 4 ? ' 等' : '')]);
  }
  const offlinePeers = Object.keys((d && d.peers) || {})
    .filter((k) => !(d.peers[k] || {}).online);
  if (offlinePeers.length) {
    rows.push(['bad', 'PEER_OFFLINE', `对端 ${offlinePeers.join(' / ')} 离线`,
      '该机器显示的是最后一次快照，判据可能已过期。']);
  }
  const stale = peerStale(d);
  if (stale.length) rows.push(['warn', 'PEER_STALE', '对端快照偏旧', stale.join(' / ')]);

  const shown = rows.slice(0, 2);
  if (rows.length > 2) {
    shown[1] = [shown[1][0], shown[1][1], shown[1][2],
      `${shown[1][3]}；另有 ${rows.length - 2} 项提示`];
  }
  box.innerHTML = shown.map(([tone, code, title, msg]) =>
    `<div class="warning${tone === 'warn' ? ' warning--advisory' : ''}">`
    + `<span class="warning-code">${esc(code)}</span>`
    + `<strong>${esc(title)}</strong><span>${esc(msg)}</span></div>`).join('');
}

/* ------------------------------------------------------------------ 渲染 */

function render(d) {
  setData(d);
  setOffline(false);
  renderStatus(d);
  renderKpis(d);
  renderWarnings(d);
  renderPinned(d);
  renderBoard(d);
  const count = $('#board-count');
  if (count) {
    const n = document.querySelectorAll('#board .svc, #board .tile').length;
    const machines = document.querySelectorAll('#board .machine').length;
    count.textContent = `${n} 项 · ${machines} 台`;
  }
  renderSide();
  // 声明了 refresh:"poll" 的面板随轮询局部刷新 —— 只换它的内层容器，侧边栏滚动位置不丢。
  if (SEL) {
    const it = currentItem();
    for (const op of ((it && it.ops) || [])) {
      if (op.refresh === 'poll' && isPaneOp(op)) {
        const box = document.querySelector(`#side-panes [data-pane="${op.id}"]`);
        if (box && box.querySelector('.op-live')) loadPane(box, op);
      }
    }
  }
}

/* 轮询失败时保留上一份快照（数据仍可读），但把「这是旧数据」说到明处。 */
function setOfflineView() {
  setOffline(true);
  const bar = $('#statusbar');
  if (bar) bar.classList.add('offline');
  renderWarnings(DATA);
  if (!DATA) {
    const board = $('#board');
    if (board) board.innerHTML = '<div class="empty">无法连接 Mozunitor 后端</div>';
    document.querySelectorAll('#kpi-row .kpi-foot').forEach((el) => { el.textContent = '无数据'; });
  }
}

/* ------------------------------------------------------------------ 主循环 */

async function poll() {
  try {
    const r = await authFetch('/api/state', { cache: 'no-store' });
    if (r.status === 401) {
      if (!NEEDS_SETUP) showLoginGate('会话已过期，请重新登录');
      return;
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    // 本机免凭据，轮询会成功 —— 但首次设置层不能被它顺手关掉，二者是竞态
    if (!SETUP) hideGate();
    render(await r.json());
  } catch (e) {
    setOfflineView();
  }
}

/* ------------------------------------------------------------------ 登录 / 初始化 */

let NEEDS_SETUP = false;
let LAUNCH_PROOF = '';       // 壳内 launch token：初始化时可当一次性凭据

function gateError(msg) {
  const el = $('#gate-err');
  if (el) el.textContent = msg || '';
}

function showSetupGate(launch) {
  NEEDS_SETUP = true;
  LAUNCH_PROOF = launch || '';
  setSetup(true);
  $('#gate-title').textContent = '首次初始化';
  $('#gate-desc').textContent = '设置管理员口令（至少 8 位）。'
    + (LAUNCH_PROOF ? '' : ' setup code 见前台启动日志或壳日志。');
  $('#gate-user-field').classList.toggle('hidden', !!LAUNCH_PROOF);
  $('#gate-user').placeholder = 'setup code';
  $('#gate-user').value = '';
  $('#gate-pass').placeholder = '管理员口令（至少 8 位）';
  $('#gate-go').textContent = '初始化';
  $('#gate-later').classList.add('hidden');
  $('#gate-hint').textContent = '口令不会明文落盘；初始化后本窗口自动登录。';
  showGate();
}

function showLoginGate(msg) {
  NEEDS_SETUP = false;
  setSetup(false);
  $('#gate-title').textContent = '需要登录';
  $('#gate-desc').textContent = '输入管理员口令。1.1.0 起回环访问同样需要登录。';
  $('#gate-user-field').classList.add('hidden');
  $('#gate-pass').placeholder = '管理员口令';
  $('#gate-go').textContent = '登录';
  $('#gate-later').classList.add('hidden');
  $('#gate-hint').textContent = '登录后 Cookie 保持 30 天；在设置页可注销当前会话。';
  gateMsg(msg || '');
  showGate();
}

async function submitGate() {
  const pass = $('#gate-pass').value || '';
  const proof = LAUNCH_PROOF || ($('#gate-user').value || '').trim();
  gateError('');
  if (NEEDS_SETUP) {
    if (!pass) return gateError('请设置管理员口令');
    const r = await completeSetup(pass, proof);
    if (!r.ok) return gateError(r.error);
    NEEDS_SETUP = false;
    setSetup(false);
    hideGate();
    poll();
    return;
  }
  if (!pass) return gateError('请输入口令');
  const r = await apiLogin(pass);
  if (!r.ok) return gateError(r.error);
  $('#gate-pass').value = '';
  hideGate();
  poll();
}

async function initAuth() {
  try {
    const boot = await bootstrap();
    if (boot.needsSetup) { showSetupGate(boot.launch); return; }
    if (boot.session) { hideGate(); poll(); return; }
    showLoginGate('登录后即可查看面板');
  } catch (e) {
    showLoginGate('无法连接后端：' + e);
  }
}

/* ------------------------------------------------------------------ 事件 */

function onTierToggle(el) {
  const group = el.closest('.tier-group');
  const body = group && group.querySelector('.tier-body');
  if (!body) return;
  const next = !body.hidden;
  body.hidden = next;
  el.setAttribute('aria-expanded', next ? 'false' : 'true');
  const caret = el.querySelector('.tier-caret');
  if (caret) caret.textContent = next ? '▸' : '▾';
  storeCollapse(el.dataset.machine, el.dataset.tier, next);
}

function repaintCards() {
  renderBoard(DATA);
  renderPinned(DATA);
}

function bindEvents() {
  document.addEventListener('click', (e) => {
    const tierBtn = e.target.closest('[data-toggle-tier]');
    if (tierBtn) return onTierToggle(tierBtn);

    const pinBtn = e.target.closest('[data-pin]');
    if (pinBtn) {
      togglePin(...(function () {
        const key = pinBtn.dataset.pin;
        const i = key.indexOf(':');
        return [key.slice(0, i), key.slice(i + 1)];
      })());
      repaintCards();
      if (settingsOpen()) renderSettingsPage();
      return;
    }

    const sideBtn = e.target.closest('[data-side]');
    if (sideBtn) return sideOpen(sideBtn.dataset.side, sideBtn.dataset.node);
    const saveP = e.target.closest('[data-save-params]');
    if (saveP) return saveParams(saveP);
    const urlBtn = e.target.closest('[data-url]');
    if (urlBtn) return openExternal(urlBtn.dataset.url);
    if (e.target.closest('#side-close')) return sideClose();

    const opBtn = e.target.closest('[data-op]');
    if (opBtn) {
      let args = null;
      if (opBtn.dataset.args) {
        try { args = JSON.parse(opBtn.dataset.args); } catch (err) { args = null; }
      }
      if (opBtn.dataset.runcell) return runOp(opBtn.dataset.op, opBtn, args);
      if (opBtn.dataset.action) return runOp(opBtn.dataset.op, opBtn, args);
      if (opBtn.dataset.lazy) {
        const box = opBtn.closest('[data-pane]');
        const it = currentItem();
        const op = it && (it.ops || []).find((x) => x.id === opBtn.dataset.op);
        if (box && op) {
          box.innerHTML = `<h3 class="sec">${esc(op.label || op.id)}</h3>`
            + '<div class="pane-body"><div class="empty">载入中…</div></div>';
          loadPane(box, op);
        }
        return;
      }
      return;
    }
    const openBtn = e.target.closest('[data-open]');
    if (openBtn) return openExternal(openBtn.dataset.open);
    const lpBtn = e.target.closest('[data-launch]');
    if (lpBtn) return doLaunch(lpBtn.dataset.launch, lpBtn.dataset.name, lpBtn);
    const stopBtn = e.target.closest('[data-stop]');
    if (stopBtn) return doStop(stopBtn.dataset.stop, stopBtn.dataset.name, stopBtn);
    const rsBtn = e.target.closest('[data-restart]');
    if (rsBtn) return doRestart(rsBtn.dataset.restart, rsBtn.dataset.name, rsBtn);

    if (e.target.closest('#open-settings')) return openSettings();
    if (e.target.closest('#settings-close')) return closeSettings();
    if (e.target.id === 'settings') return closeSettings();
    const un = e.target.closest('[data-unpin]');
    if (un) { unpin(un.dataset.unpin); renderPinned(DATA); renderBoard(DATA); renderSettingsPage(); return; }
    if (e.target.closest('[data-card-reset-global]')) {
      resetGlobalCardPrefs();
      repaintCards();
      renderSettingsPage();
      return;
    }
    if (e.target.closest('[data-card-reset]')) {
      if (SEL) {
        resetServiceCardPref(SEL.node, SEL.svc);
        renderSide();
        repaintCards();
      }
      return;
    }

    const saveSet = e.target.closest('[data-save-panel]');
    if (saveSet) {
      const section = saveSet.dataset.savePanel;
      const values = {};
      if (section === 'intervals') {
        document.querySelectorAll('[data-interval]').forEach((el) => {
          values[el.dataset.interval] = Number(el.value);
        });
      } else if (section === 'keepalive') {
        document.querySelectorAll('[data-ka]').forEach((el) => {
          if (el.dataset.ka === 'backoff') {
            values.backoff = el.value.split(',').map((x) => Number(x.trim())).filter((x) => x > 0);
          } else {
            values[el.dataset.ka] = Number(el.value);
          }
        });
      }
      savePanel(section, values).then((ok) => { if (ok) poll(); });
      return;
    }

    const saveCmd = e.target.closest('[data-save-commands]');
    if (saveCmd) {
      const box = saveCmd.closest('.cmd-edit');
      const sid = saveCmd.dataset.saveCommands;
      try {
        const restart = JSON.parse((box.querySelector('[data-cmd="restart"]') || {}).value || 'null');
        const stop = JSON.parse((box.querySelector('[data-cmd="stop"]') || {}).value || 'null');
        savePanel('commands', { id: sid, restart, stop }).then((ok) => { if (ok) poll(); });
      } catch (err) {
        toast(`命令不是合法 JSON：${err}`, 'bad');
      }
    }
  });

  document.addEventListener('change', (e) => {
    const cf = e.target.closest('[data-card-field]');
    if (cf && SEL) {
      setServiceCardPref(SEL.node, SEL.svc, cf.dataset.cardField, cf.checked);
      repaintCards();
      renderSide();
      return;
    }
    const pc = e.target.closest('[data-pref-card]');
    if (pc) {
      setGlobalCardPref(pc.dataset.prefCard, pc.checked);
      repaintCards();
      return;
    }
    if (e.target.closest('[data-pref-mobile]')) {
      setMobileHideOptional(e.target.checked);
      renderBoard(DATA);
      return;
    }
    const tierSel = e.target.closest('[data-service-tier]');
    if (tierSel) {
      savePanel('service', { id: tierSel.dataset.serviceTier, patch: { tier: tierSel.value } })
        .then((ok) => { if (ok) poll(); });
      return;
    }
    const kaBox = e.target.closest('[data-service-keepalive]');
    if (kaBox) {
      savePanel('service', { id: kaBox.dataset.serviceKeepalive, patch: { keepalive: kaBox.checked } })
        .then((ok) => { if (ok) poll(); });
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (confirmOpen()) { settleConfirm(false); return; }
    if (settingsOpen()) { closeSettings(); return; }
    if ($('#side')?.classList.contains('open')) sideClose();
  });

  $('#refresh')?.addEventListener('click', poll);
  $('#side-close')?.addEventListener('click', sideClose);

  const form = $('#gate-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      submitGate();
    });
    const later = $('#gate-later');
    if (later) later.addEventListener('click', () => { setSetup(false); hideGate(); });
  }

  // 跨过窄屏断点时状态行的取舍会变，立即重绘一次，不必等下一轮 3 秒
  if (NARROW) {
    const onNarrowChange = () => { if (DATA) renderBoard(DATA); };
    if (NARROW.addEventListener) NARROW.addEventListener('change', onNarrowChange);
    else if (NARROW.addListener) NARROW.addListener(onNarrowChange);
  }
}

/* 设置页被偏好变更触发重绘。 */
function renderSettingsPage() { renderSettings(); }

bindConfirm();
bindEvents();
setInterval(tickCountdowns, 1000);
initAuth();
setInterval(poll, POLL_MS);
