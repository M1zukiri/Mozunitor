// 服务声明的操作面：四种节类型 + 表格单元格 + 表单 + 面板取数。
// 前端不认识任何服务 id：只按 kind 分发，服务取自当前选中项。
import { esc } from './format.js';
import { authFetch, authHeaders } from './api.js';
import { SEL, SEL_KEY } from './state.js';

const $ = (s) => document.querySelector(s);

export const opUrl = (svcId, opId) => `/api/op?id=${encodeURIComponent(svcId)}`
  + `&op=${encodeURIComponent(opId)}`;

/* 操作面按用途分成两半：只读的成面板，其余进操作区。
   script 类按它声明的 level 判 —— 会改状态的脚本属于操作区，不是面板。 */
export const isPaneOp = (op) => op.kind === 'view'
  || (op.kind === 'script' && op.level !== 'write');
export const isActionOp = (op) => !isPaneOp(op);

/* 表格单元格：字符串直接渲染；{t,...} 是带装饰的文本；{btn,...} 是内嵌的动作按钮。 */
export function renderCell(c) {
  if (c == null) return '<td></td>';
  if (typeof c === 'string') return `<td>${esc(c)}</td>`;
  if (c.btn) {
    return `<td class="act"><button${c.danger ? ' class="danger"' : ''}`
      + ` data-op="${esc(c.op)}" data-runcell="1"`
      + (c.data ? ` data-args="${esc(JSON.stringify(c.data))}"` : '')
      + `>${esc(c.btn)}</button></td>`;
  }
  const cls = [c.hot ? 'hot' : '', c.dim ? 'dim' : ''].filter(Boolean).join(' ');
  const cd = c.countdown ? ` data-exp="${esc(c.countdown)}"` : '';
  return `<td${cls ? ` class="${cls}"` : ''}><span class="cd"${cd}>${esc(c.t == null ? '—' : c.t)}</span></td>`;
}

/* 四种节类型覆盖全部形状：分节标题落成节的 title，徽章行落成 notes，
   错误条与空态是兜底 —— 数据缺失时给可见反馈，不静默什么都不发生。 */
export function renderSections(secs) {
  const out = [];
  for (const s of (secs || [])) {
    const title = s.title ? `<h3 class="sec">${esc(s.title)}</h3>` : '';
    if (s.kind === 'kv') {
      const rows = (s.rows || []).map((r) => `<tr><th>${esc(r.label)}</th>`
        + `<td>${esc(r.value == null ? '—' : r.value)}</td></tr>`).join('');
      out.push(title + `<table class="kv">${rows}</table>`);
    } else if (s.kind === 'table') {
      const head = (s.cols || []).map((c) => `<th>${esc(c)}</th>`).join('');
      const body = (s.rows || []).map(
        (r) => `<tr>${(r.cells || []).map(renderCell).join('')}</tr>`).join('');
      out.push(title + `<div class="tw"><table class="mdl"><thead><tr>${head}</tr></thead>`
        + `<tbody>${body}</tbody></table></div>`);
    } else if (s.kind === 'notes') {
      out.push((s.items || []).map((n) => `<div class="${n.level === 'warn' ? 'warnrow' : 'noterow'}">`
        + `${esc(n.text)}</div>`).join(''));
    } else if (s.kind === 'text') {
      out.push(title + `<pre class="optext${s.mono === false ? ' prose' : ''}">${esc(s.text || '')}</pre>`);
    }
  }
  return out.join('') || '<div class="empty">无内容</div>';
}

export function opForm(op) {
  const fields = (op.fields || []).filter((f) => !f.from);
  if (!fields.length) return '<div class="empty">该操作没有需要填写的参数</div>';
  return '<div class="opform">' + fields.map((f) => {
    const label = esc(f.label || f.name);
    if (f.choices) {
      return `<label>${label}<select data-field="${esc(f.name)}">`
        + f.choices.map((c) => `<option value="${esc(c)}"`
          + (String(c) === String(f.default) ? ' selected' : '') + `>${esc(c)}</option>`).join('')
        + `</select></label>`;
    }
    return `<label>${label}<input data-field="${esc(f.name)}" type="text"`
      + ` value="${esc(f.default == null ? '' : f.default)}"></label>`;
  }).join('') + '</div>';
}

/* 取一个面板的内容。迟到响应靠 SEL_KEY 比对丢弃 —— A 还在取数就切到 B 时，
   A 的结果不能落到 B 的面板上。 */
export async function loadPane(box, op) {
  const key = SEL_KEY;
  if (!SEL) return;
  const body = box.querySelector('.pane-body') || box;
  try {
    const r = op.kind === 'script'
      ? await authFetch(opUrl(SEL.svc, op.id), {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
          body: JSON.stringify({}),
        })
      : await authFetch(opUrl(SEL.svc, op.id));
    if (SEL_KEY !== key) return;
    const d = await r.json();
    if (SEL_KEY !== key) return;
    if (op.kind === 'script' && d.sections) {
      body.innerHTML = `<div class="op-live">${renderSections(d.sections)}</div>`;
      tickCountdowns();
      return;
    }
    body.innerHTML = d.error
      ? `<div class="mdl-err">${esc(d.error)}</div>`
      : `<div class="op-live">${renderSections(d.sections)}</div>`;
    tickCountdowns();
  } catch (e) {
    if (SEL_KEY !== key) return;
    body.innerHTML = `<div class="mdl-err">读取失败：${esc(String(e))}</div>`;
  }
}

/* 每秒刷新带 data-exp 的倒计时单元格。 */
export function tickCountdowns() {
  document.querySelectorAll('#side-body .cd[data-exp]').forEach((el) => {
    const left = Math.round((new Date(el.dataset.exp).getTime() - Date.now()) / 1000);
    if (Number.isNaN(left)) return;
    el.textContent = left <= 0 ? '已到期'
      : (left < 3600 ? `${Math.floor(left / 60)}m${String(left % 60).padStart(2, '0')}s`
        : `${Math.floor(left / 3600)}h${String(Math.floor(left % 3600 / 60)).padStart(2, '0')}m`);
  });
}

/* 未在对端显示的操作，原因写清楚 —— 用户不该只看到按钮少了却不知道为什么。 */
export function opHiddenNote(it, op) {
  if (op.link || op.kind === 'link') return '地址指向对端自己的回环入口，本机点不开';
  if (op.kind === 'script') return '脚本在本机执行，需在本机面板上跑';
  if (op.kind === 'run') return '动作在对端执行，目前只转发终止与重启';
  return '读的是对端本机的配置与文件，需在对端面板查看';
}
