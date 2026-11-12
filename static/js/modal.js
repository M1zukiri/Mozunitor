// 确认层、登录层与 toast。所有遮罩类 UI 的通用出口，不碰业务状态。

const $ = (s) => document.querySelector(s);

let CONFIRM_RESOLVE = null;   // 非空即确认层开着

/* 破坏性动作的确认层：后果（stop_warn / 重启影响）写在同一块里。 */
export function askConfirm(opt) {
  opt = opt || {};
  const box = $('#confirm');
  if (!box) return Promise.resolve(false);
  $('#confirm-title').textContent = opt.title || '确认操作';
  $('#confirm-msg').textContent = opt.message || '';
  $('#confirm-code').textContent = opt.code || 'ACTION';
  $('#confirm-detail').textContent = opt.detail || '';
  $('#confirm-rule').style.display = opt.detail ? '' : 'none';
  $('#confirm-badge').textContent = opt.badge || '后果';
  const yes = $('#confirm-yes');
  yes.textContent = opt.ok || '确认';
  yes.classList.toggle('btn-danger', opt.danger !== false);
  box.hidden = false;
  return new Promise((resolve) => {
    CONFIRM_RESOLVE = (value) => {
      box.hidden = true;
      CONFIRM_RESOLVE = null;
      resolve(value);
    };
    yes.focus();
  });
}

export function settleConfirm(value) {
  if (CONFIRM_RESOLVE) CONFIRM_RESOLVE(value);
}

export function confirmOpen() { return !!CONFIRM_RESOLVE; }

export function bindConfirm() {
  const box = $('#confirm');
  if (!box) return;
  $('#confirm-yes').addEventListener('click', () => settleConfirm(true));
  $('#confirm-no').addEventListener('click', () => settleConfirm(false));
  $('#confirm-x').addEventListener('click', () => settleConfirm(false));
  box.addEventListener('click', (e) => { if (e.target === box) settleConfirm(false); });
}

let toastTimer = null;

export function toast(msg, tone) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.dataset.tone = tone || 'ok';
  el.dataset.show = 'true';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.dataset.show = 'false'; }, 2600);
}

/* 登录与首次设置共用同一张卡片；SETUP 为真时提交的是「改凭据」，否则是「登录」。 */
export let SETUP = false;
export function setSetup(v) { SETUP = !!v; }

export function showGate(msg) {
  const gate = $('#gate');
  if (!gate) return;
  gate.classList.remove('hidden');
  if (msg) clearGateMsg();
  gateMsg(msg);
}

export function hideGate() {
  const gate = $('#gate');
  if (gate) gate.classList.add('hidden');
}

/* 用户提交 token 得到的提示，不该被紧随其后的轮询 401 覆盖掉 —— 只在空位时落笔。 */
export function gateMsg(msg) {
  const err = $('#gate-err');
  if (err && !err.textContent) err.textContent = msg || '';
}

export function clearGateMsg() {
  const err = $('#gate-err');
  if (err) err.textContent = '';
}
