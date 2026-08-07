"""模板渲染（M4，§5.7）：docxtpl + Jinja2（StrictUndefined）。

- 数据与表现分离：渲染器只读 :func:`~proofhound.report.data.build_context`
  产出的结构化 context（纯 dict），不读 Finding 库、不碰证据原文；
- 失败语义清晰：模板缺失/非文件 → :class:`RenderError` 指明路径；模板
  变量未定义（StrictUndefined）/语法错误 → :class:`RenderError` 带出
  Jinja 原始信息，不静默空渲染；
- 渲染确定性：narrative 固定后同一 context + 同一模板 → 产出 docx 的
  ``word/document.xml`` 内容一致（docx zip 字节级时间戳不保证，见
  AGENTS.md 已知限制）。
"""

from __future__ import annotations

from pathlib import Path

import jinja2
from docxtpl import DocxTemplate


class RenderError(RuntimeError):
    """模板渲染失败：模板缺失、变量未定义或语法错误。"""


def render_docx(
    context: dict, template_path: str | Path, out_path: str | Path
) -> Path:
    """用 docx 模板渲染报告，返回输出路径。

    ``context`` 必须是结构化 dict（契约见 AGENTS.md 模板变量清单）；
    未定义变量在 StrictUndefined 下抛 :class:`RenderError`。
    """
    template_path = Path(template_path)
    if not template_path.is_file():
        raise RenderError(f"报告模板不存在: {template_path}")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    try:
        tpl = DocxTemplate(str(template_path))
    except Exception as exc:
        raise RenderError(f"报告模板无法打开: {template_path}（{exc}）") from exc
    try:
        # autoescape=True：替换值做 XML 转义——finding/叙述文本中的 & < >
        # 原样保留；不转义会被 docx 的 recover 解析静默吞掉（&X 伪实体）
        tpl.render(context, env, autoescape=True)
    except jinja2.UndefinedError as exc:
        raise RenderError(
            f"模板变量未定义: {exc}（模板 {template_path}）"
        ) from exc
    except jinja2.TemplateError as exc:
        raise RenderError(
            f"模板语法错误: {exc}（模板 {template_path}）"
        ) from exc
    tpl.save(str(out_path))
    return out_path
