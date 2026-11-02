"""控制台「运行进度 + 暂停/继续」的静态守护（零构建链，pytest 里没有 JS 运行时）。

## 钉住什么

1. **状态机有 paused**：前端的状态文案必须覆盖后端新增的 ``paused``（漏了列表与
   状态条会显示英文 ``paused``）；
2. **动作按钮是状态化的**：``启动`` 只应出现在 ``created`` 分支，运行中给 ``暂停``、
   暂停后给 ``继续``——这正是"点了启动按钮还能一直按"那个缺陷的静态防线；
3. **可视化面板存在且只用 CSS**：阶段条 / 进度条 / 环形图（`conic-gradient`），
   零外部图表库、零 innerHTML；
4. **暂停不是"立即冻结"**：前端文案写明"阶段边界生效"，避免 UI 承诺做不到的语义。

浏览器实跑（启动→暂停→继续→完成）由 Playwright 手工核对，截图在
``shots/proofhound_ui/pause/``（不进仓库）。
"""

from __future__ import annotations

from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "proofhound" / "api" / "static"
APP_JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "app.css").read_text(encoding="utf-8")


def test_state_label_covers_paused():
    assert "paused: '已暂停'" in APP_JS
    assert ".badge.state-paused" in CSS


def test_start_button_only_in_created_branch():
    # 启动按钮出现在 created 分支内，且不会无条件渲染
    assert "if (detail.state === 'created')" in APP_JS
    assert "'primary', '启动'" in APP_JS
    assert "RUNNING_STATES.has(detail.state)" in APP_JS
    assert "state === 'paused'" in APP_JS
    assert "'primary', '继续'" in APP_JS


def test_start_race_is_guarded():
    """POST /run 返回后线程尚未切到 scanning 的毫秒窗口：running 为真就显示「启动中…」。"""
    assert "'启动中…'" in APP_JS
    assert "if (detail.running)" in APP_JS


def test_pause_and_resume_endpoints_are_wired():
    assert "/pause`" in APP_JS or "/${path}`" in APP_JS
    assert "post('pause', pauseBtn)" in APP_JS
    assert "post('resume', resumeBtn)" in APP_JS
    # 受理后按钮变成"暂停中…"（不是再发一次请求）
    assert "'暂停中…'" in APP_JS


def test_progress_panel_shows_phase_boundary_semantics():
    assert "阶段边界生效" in APP_JS
    assert "执行线程挂起中" in APP_JS
    assert "PHASES" in APP_JS and APP_JS.count("{ state: '") >= 5


def test_progress_visualisation_is_pure_css():
    for cls in (".phases", ".phase-track", ".progress", ".donut", ".run-legend"):
        assert cls in CSS, cls
    assert "conic-gradient" in APP_JS
    assert "innerHTML" not in APP_JS


def test_running_and_paused_have_distinct_visuals():
    assert ".progress.running .bar" in CSS
    assert ".progress.paused .bar" in CSS
    assert ".phase.paused .phase-track" in CSS
    assert "phasePulse" in CSS


def test_progress_panel_is_rendered_in_detail_view():
    assert "progressPanel" in APP_JS
    assert "updateProgress(detail)" in APP_JS
    assert "renderProgress(detail, counts)" in APP_JS
