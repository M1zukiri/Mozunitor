// 主题：theme.css 是 industrial-pixel-ui 原样副本，themes.css 按 data-theme 重映射 token。
// 选择只存在本设备（localStorage），与置顶、卡片显示一致。

export const THEMES = [
  {
    id: 'cyan', label: '工业浅青', src: '默认 · 浅青纸面 + 琥珀选中',
    chips: ['#0b0e0f', '#a9d5cf', '#d9a441', '#c2e3de'],
  },
  {
    id: 'navy', label: '海军蓝', src: '海军蓝·五色（第 3 组）',
    chips: ['#001f50', '#c9e4e3', '#83b7bd', '#005da1'],
  },
  {
    id: 'night', label: '暗夜色', src: '暗夜色·五色（第 1 组）',
    chips: ['#4a444b', '#e3d7d0', '#cec3a3', '#a15525'],
  },
  {
    id: 'mono', label: '极简灰', src: '无色彩系三锚 · 纯灰',
    chips: ['#4a444b', '#e7e6e3', '#bfbeb9', '#acacab'],
  },
];

const KEY = 'mozunitor.theme';

function validTheme(id) {
  return THEMES.some((t) => t.id === id) ? id : 'cyan';
}

export function currentTheme() {
  try {
    return validTheme(localStorage.getItem(KEY));
  } catch (e) {
    return 'cyan';
  }
}

export function applyTheme(id) {
  const want = validTheme(id);
  if (want === 'cyan') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = want;
  return want;
}

export function setTheme(id) {
  const want = applyTheme(id);
  try {
    localStorage.setItem(KEY, want);
  } catch (e) { /* 隐私模式写不进就只在本次会话生效 */ }
  return want;
}
