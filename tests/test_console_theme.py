"""控制台换肤（UI 增量）的静态守护：主题表 ↔ CSS 选择器 ↔ 零存储纪律。

## 为什么用静态检查

控制台是**零构建链**的手写 SPA（无 npm / 无打包器 / 无 Node 依赖），pytest 里没有
可执行 JS 的运行时。所以这里钉住的是"能静态核对、且一改就最容易漂"的三件事：

1. **主题表单一真相源**：`theme.js` 的 `THEMES` 与 `app.css` 的 `[data-theme="…"]`
   选择器**一一对应**——加一个主题却忘了写 CSS，界面会静默退回默认色；
2. **零浏览器存储**：主题偏好只经 URL 查询串 `?theme=` 保留（`history.replaceState`），
   不写 `localStorage` / `sessionStorage` / cookie——这是 M5b "零 Web 存储"纪律的延续
   （凭据与页面数据都不落浏览器存储，主题这种无害偏好也不开这个口子）；
3. **零外部资源 / 无 HTML 注入**：主题按钮的文案用 `textContent` 落地（与既有纪律一致），
   静态资产不引入任何外域 URL。

浏览器里的真实行为（切换、URL 记忆、刷新保持、未知主题回落）由人工实跑核对：
`http://127.0.0.1:<port>/?theme=light` 等四套主题逐屏截图 + 断言，产物在
`shots/proofhound_ui/themes/`（不进仓库）。
"""

from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "proofhound" / "api" / "static"
INDEX = STATIC / "index.html"
CSS = STATIC / "app.css"
JS = STATIC / "theme.js"
APP_JS = STATIC / "app.js"

#: 四套预设（与需求一致：先预设几个主题）。
EXPECTED_IDS = ("dark", "light", "ocean", "paper")

#: 每套主题都必须自己定义的基色（缺一个就会串色到上一套）。
CORE_VARS = ("--bg", "--panel", "--panel-alt", "--border", "--text", "--muted", "--accent")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """去掉整行注释（本仓库的注释里会**说明**"不用 localStorage"，那不是使用）。"""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


def _themes_block() -> str:
    text = _read(JS)
    match = re.search(r"const THEMES = \[(.*?)\n\];", text, re.S)
    assert match is not None, "theme.js 里找不到 THEMES 表"
    return match.group(1)


def _theme_ids_from_js() -> tuple[str, ...]:
    return tuple(re.findall(r"id:\s*'([a-z0-9-]+)'", _themes_block()))


def _theme_ids_from_css() -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r'\[data-theme="([a-z0-9-]+)"\]', _read(CSS))))


def _css_theme_blocks() -> dict[str, str]:
    blocks: dict[str, str] = {}
    for match in re.finditer(
        r'(:root,\s*\[data-theme="([a-z0-9-]+)"\]|\[data-theme="([a-z0-9-]+)"\])\s*\{(.*?)\}',
        _read(CSS),
        re.S,
    ):
        theme = match.group(2) or match.group(3)
        blocks[theme] = match.group(4)
    return blocks


# --------------------------------------------------------------- 主题表一致性


def test_theme_assets_exist_and_are_local():
    for path in (INDEX, CSS, JS):
        assert path.is_file(), path
    index = _read(INDEX)
    assert "/static/theme.js" in index
    assert "/static/app.css" in index


def test_theme_ids_match_css_selectors():
    from_js = _theme_ids_from_js()
    assert from_js == EXPECTED_IDS, from_js
    assert set(from_js) == set(_theme_ids_from_css())


def test_every_theme_defines_core_vars():
    blocks = _css_theme_blocks()
    assert set(blocks) == set(EXPECTED_IDS)
    for theme_id, block in blocks.items():
        for name in CORE_VARS:
            assert re.search(rf"{name}\s*:", block), f"{theme_id} 缺 {name}"


def test_default_theme_is_the_first_preset():
    text = _read(JS)
    assert "const DEFAULT_THEME = THEMES[0].id;" in text
    assert _theme_ids_from_js()[0] == "dark"


def test_theme_swatches_cover_every_preset():
    css = _read(CSS)
    for theme_id in EXPECTED_IDS:
        assert f'.theme-option[data-theme-id="{theme_id}"] .theme-swatch' in css


def test_theme_id_never_reaches_dom_as_html():
    """主题按钮用 createElement + textContent 落地（禁 innerHTML 注入）。"""
    text = _read(JS)
    assert "innerHTML" not in text
    assert "textContent" in text
    assert "createElement('button')" in text


# --------------------------------------------------------------- 零存储 / 零外链


def test_theme_preference_uses_url_not_browser_storage():
    text = _code_only(_read(JS))
    for forbidden in ("localStorage", "sessionStorage", "indexedDB", "document.cookie"):
        assert forbidden not in text, f"theme.js 不得使用 {forbidden}"
    assert "URLSearchParams" in text
    assert "history.replaceState" in text
    assert "THEME_QUERY_KEY = 'theme'" in text


def test_no_browser_storage_anywhere_in_static_assets():
    for path in (INDEX, CSS, JS, APP_JS):
        text = _code_only(_read(path))
        for forbidden in ("localStorage", "sessionStorage", "indexedDB"):
            assert forbidden not in text, f"{path.name} 出现了 {forbidden}"


def test_static_assets_reference_no_external_urls():
    patterns = (
        r'(?:src|href)\s*=\s*["\']https?://',
        r'url\(\s*["\']?https?://',
        r"@import",
    )
    for path in (INDEX, CSS, JS):
        text = _read(path)
        for pattern in patterns:
            assert re.search(pattern, text) is None, f"{path.name} 命中 {pattern}"


# --------------------------------------------------------------- 侧栏挂载点


def test_picker_is_mounted_in_sidebar_with_a11y_label():
    index = _read(INDEX)
    assert 'id="theme-picker"' in index
    assert 'aria-label="界面主题"' in index
    assert 'class="theme-title"' in index
    # 侧栏在 <aside id="sidenav"> 内、脚本先 theme 后 app（首屏不闪默认色）
    assert index.index('id="theme-picker"') > index.index('id="sidenav"')
    assert index.index("/static/theme.js") < index.index("/static/app.js")


def test_picker_selects_only_one_theme_at_a_time():
    text = _read(JS)
    assert "classList.toggle('active', active)" in text
    assert "setAttribute('aria-pressed'" in text
