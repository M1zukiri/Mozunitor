// 服务动作：终止 / 重启 / 启动 / 服务声明的 run 操作。确认层与结果条在这里串起来。
import { esc } from './format.js';
import { authFetch, authHeaders } from './api.js';
import { askConfirm } from './modal.js';
import { SEL, INFLIGHT, findAnyItem } from './state.js';
import { ensureSide, renderSide, showSideResult, showOpResult } from './side.js';
import { opUrl } from './ops.js';

function resultHtml(head, d) {
  const body = (d.steps || []).map((s) => `[${s.t}] ${s.msg}`).join('\n');
  return `<b>${esc(head)}</b>` + (body ? `<pre class="optext">${esc(body)}</pre>` : '');
}

/* 动词由动作名推出，而不是「不是 stop 就当成重启」—— 那会把模型动作报成「重启完成」。 */
function actionVerb(d) {
  const a = String((d || {}).action || '');
  if (a === 'stop') return '终止';
  if (a === 'restart') return '重启';
  return a || '操作';
}

export function showActionResult(name, d, verb) {
  verb = verb || actionVerb(d);
  const freed = d.freed_mb ? `，释放约 ${d.freed_mb} MB` : '';
  const head = (d.ok ? `${verb}完成` : `${verb}未成功`) + `（${d.elapsed_s}s${freed}）`;
  showSideResult(resultHtml(head, d), !d.ok);
}

export async function doStop(id, name, btn) {
  const node = btn.dataset.node || '';
  ensureSide(id, node || undefined);
  const key = node ? `${node}:${id}` : id;
  const it = findAnyItem(id, node);
  const ok = await askConfirm({
    title: `终止「${name}」？`,
    message: '服务会被停掉、内存随之释放，之后可用「重启」重新拉起。',
    code: 'STOP_SERVICE',
    badge: '终止',
    detail: (it && it.stop_warn) || '',
    ok: '确认终止',
    danger: true,
  });
  if (!ok) return;

  btn.disabled = true;
  INFLIGHT.add(key);
  try {
    const r = await authFetch('/api/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(node ? { id, node } : { id })
    });
    showActionResult(name, await r.json());
  } catch (e) {
    showSideResult(`${name} · 请求失败：${e}`, true);
  } finally {
    INFLIGHT.delete(key);
    renderSide();
  }
}

export async function doRestart(id, name, btn) {
  const node = btn.dataset.node || '';
  ensureSide(id, node || undefined);
  const key = node ? `${node}:${id}` : id;
  const card = btn.closest('.svc');
  const warnEl = card && card.querySelector('.warnrow');
  const ok = await askConfirm({
    title: `重启「${name}」？`,
    message: '面板会先停掉当前进程，再按服务声明的启动链拉起，并等到端口或进程就绪才返回。',
    code: 'RESTART_SERVICE',
    badge: '重启',
    detail: warnEl ? warnEl.textContent.trim() : '',
    ok: '确认重启',
    danger: true,
  });
  if (!ok) return;

  btn.disabled = true;
  INFLIGHT.add(key);
  // 不在这里重绘：重绘会把按钮换成新节点，手指若还按在原来的位置上，
  // pointerup 就落不到同一个元素上；下一次 3 秒轮询会按 INFLIGHT 把它置灰。
  try {
    const r = await authFetch('/api/restart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(node ? { id, node } : { id })
    });
    showActionResult(name, await r.json());
  } catch (e) {
    showSideResult(`${name} · 请求失败：${e}`, true);
  } finally {
    INFLIGHT.delete(key);
    renderSide();
  }
}

/* 启动复用 /api/restart 那条「停 → 起 → 等端口/进程」的链：未运行时「停」是空操作，
   起来之后才返回。启动无破坏性，故不弹确认框。 */
export async function doLaunch(id, name, btn) {
  ensureSide(id);
  btn.disabled = true;
  INFLIGHT.add(id);
  try {
    const r = await authFetch('/api/restart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    showActionResult(name, await r.json(), '启动');
  } catch (e) {
    showSideResult(`${name} · 请求失败：${e}`, true);
  } finally {
    INFLIGHT.delete(id);
    renderSide();
  }
}

function findOp(svcId, opId, nodeId) {
  const it = findAnyItem(svcId, nodeId);
  return { it, op: it ? ((it.ops || []).find((o) => o.id === opId) || null) : null };
}

/* 从面板里的表格行或操作区触发。服务与节点取自当前选中项。 */
export async function runOp(opId, btn, args) {
  if (!SEL) return;
  const { it, op } = findOp(SEL.svc, opId, SEL.node);
  if (!it || !op) return;
  const body = Object.assign({}, args || {});
  const form = document.querySelector('#side-ops');
  if (form && op.fields) {
    form.querySelectorAll('[data-field]').forEach((el) => { body[el.dataset.field] = el.value; });
  }
  const key = `${SEL.node || ''}:${it.id}:${opId}`;
  INFLIGHT.add(key);
  if (btn) btn.disabled = true;
  renderSide();
  try {
    const r = await authFetch(opUrl(SEL.svc, opId), {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify(body),
    });
    const d = await r.json();
    showOpResult(it, op, d);
  } catch (e) {
    showSideResult(`请求失败：${e}`, true);
  } finally {
    INFLIGHT.delete(key);
    if (btn) btn.disabled = false;
    renderSide();
  }
}

/* 应用壳里开应用内新窗口；壳不在时与改造前一致。 */
export function openExternal(url) {
  if (!url) return;
  const api = window.pywebview && window.pywebview.api;
  if (api && api.open_child) { api.open_child(url); return; }
  window.open(url, '_blank', 'noopener');
}
