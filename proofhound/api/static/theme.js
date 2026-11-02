// 控制台换肤（UI 增量）：四套预设主题，侧栏底部切换。
//
// 纪律（与 M5b 控制台同源）：
// - 零外部资源、零构建链：本文件与 app.css 都是本地 /static 资产；
// - **零浏览器存储**——不写 localStorage / sessionStorage / cookie。选择只经 URL 查询串
//   `?theme=<id>` 保留（history.replaceState），刷新与书签能回到同一套皮肤；
// - 文案一律 textContent 落地，不用 HTML 字符串注入；
// - 主题 id 必须与 app.css 的 `[data-theme="..."]` 选择器**一一对应**：
//   tests/test_console_theme.py 会核对，漏一个就会红。

const THEMES = [
  { id: 'dark', label: '深色', hint: '默认深色（GitHub Dark 风格）' },
  { id: 'light', label: '浅色', hint: '白底浅色（强光环境）' },
  { id: 'ocean', label: '暗夜蓝', hint: '深海蓝底 + 青色强调' },
  { id: 'paper', label: '纸墨', hint: '暖白纸面 + 墨绿强调' },
];

const DEFAULT_THEME = THEMES[0].id;
const THEME_QUERY_KEY = 'theme';

function knownTheme(id) {
  return THEMES.some((theme) => theme.id === id) ? id : null;
}

function readThemeFromUrl() {
  try {
    const value = new URLSearchParams(location.search).get(THEME_QUERY_KEY);
    return knownTheme(value) || DEFAULT_THEME;
  } catch (err) {
    return DEFAULT_THEME; // 异常 URL：回落默认，不影响其余功能
  }
}

function writeThemeToUrl(id) {
  try {
    const url = new URL(location.href);
    url.searchParams.set(THEME_QUERY_KEY, id);
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  } catch (err) {
    /* 改不了地址栏也不影响换肤本身（只是刷新后退回默认） */
  }
}

function applyTheme(id, { persist = true } = {}) {
  const theme = knownTheme(id) || DEFAULT_THEME;
  document.documentElement.dataset.theme = theme;
  document.querySelectorAll('.theme-option').forEach((button) => {
    const active = button.dataset.themeId === theme;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', active ? 'true' : 'false');
  });
  if (persist) writeThemeToUrl(theme);
}

function renderPicker() {
  const host = document.getElementById('theme-picker');
  if (!host) return;
  const options = document.createElement('div');
  options.className = 'theme-options';
  for (const theme of THEMES) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'theme-option';
    button.dataset.themeId = theme.id;
    button.title = theme.hint;
    button.setAttribute('aria-pressed', 'false');
    const swatch = document.createElement('span');
    swatch.className = 'theme-swatch';
    const label = document.createElement('span');
    label.textContent = theme.label;
    button.append(swatch, label);
    button.addEventListener('click', () => applyTheme(theme.id));
    options.appendChild(button);
  }
  host.appendChild(options);
}

const initialTheme = readThemeFromUrl();
applyTheme(initialTheme, { persist: false }); // 首屏先上色，避免闪一下默认主题
renderPicker();
applyTheme(initialTheme, { persist: false }); // 按钮建好后再同步一次选中态
