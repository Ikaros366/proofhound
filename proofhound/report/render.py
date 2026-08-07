"""模板渲染（M4，§5.7）：docxtpl + Jinja2（StrictUndefined）。

- 数据与表现分离：渲染器只读 :func:`~proofhound.report.data.build_context`
  产出的结构化 context（纯 dict），不读 Finding 库、不碰证据原文；
- 失败语义清晰：模板缺失/非文件 → :class:`RenderError` 指明路径；模板
  变量未定义（StrictUndefined）/语法错误 → :class:`RenderError` 带出
  Jinja 原始信息，不静默空渲染；
- M4.5：注册 ``cn_date`` 过滤器（ISO 时间戳 → 「2026年8月7日」，空值 →
  空串，非 ISO 原样返回）；``{{r }}`` 富文本适配——docxtpl 会把 ``{{r }}``
  的值原样插到 run 之外，纯字符串会整个丢失（docxtpl 0.20.2 实测），必须
  是 :class:`docxtpl.RichText`。渲染前扫描模板中的 ``{{r }}`` 标签，把
  context 里对应键（点路径末段）的字符串值自动包装成 RichText（自带
  ``__html__``，autoescape 下安全、内部转义 ``& < >``、``\\n`` 换行），
  数据层 context 仍保持纯 JSON；
- 渲染确定性：narrative 固定后同一 context + 同一模板 → 产出 docx 的
  ``word/document.xml`` 内容一致（docx zip 字节级时间戳不保证，见
  AGENTS.md 已知限制）。
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime
from pathlib import Path

import jinja2
from docxtpl import DocxTemplate, RichText


class RenderError(RuntimeError):
    """模板渲染失败：模板缺失、变量未定义或语法错误。"""


#: 模板中的 {{r <点路径>}} 富文本标签（去 XML 标签后匹配）
_RICHTEXT_TAG = re.compile(r"\{\{r\s+([A-Za-z_][\w.]*)")
_XML_TAG = re.compile(r"<[^>]+>")


def _cn_date(value: object) -> str:
    """``cn_date`` 过滤器：ISO 时间 → 「2026年8月7日」（不补零）。

    空值（None/空白串）→ 空串；非 ISO 串原样返回（不静默吞、不炸渲染，
    用户手填的「2026年8月」类值也能透传）。
    """
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    return f"{parsed.year}年{parsed.month}月{parsed.day}日"


def _richtext_keys(template_path: Path) -> set[str]:
    """扫描模板各 word/*.xml 的 ``{{r <点路径>}}`` 标签，取末段属性名集合。

    原始 XML 里标签可能被拆进多个 run（Word 随时拆 run），先去 XML 标签
    再匹配（与 docxtpl patch_xml 的拼标签逻辑同效）。
    """
    keys: set[str] = set()
    with zipfile.ZipFile(template_path) as zf:
        for name in zf.namelist():
            if not (name.startswith("word/") and name.endswith(".xml")):
                continue
            text = _XML_TAG.sub("", zf.read(name).decode("utf-8", errors="ignore"))
            for expr in _RICHTEXT_TAG.findall(text):
                keys.add(expr.rsplit(".", 1)[-1])
    return keys


def _wrap_richtext(value: object, keys: set[str]) -> object:
    """深遍历 context（不改原对象），把 ``{{r }}`` 目标键的字符串值包成
    :class:`docxtpl.RichText`；其余值原样保留。"""
    if isinstance(value, dict):
        return {
            key: (
                RichText(item)
                if key in keys and isinstance(item, str)
                else _wrap_richtext(item, keys)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_wrap_richtext(item, keys) for item in value]
    return value


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
    env.filters["cn_date"] = _cn_date
    try:
        tpl = DocxTemplate(str(template_path))
    except Exception as exc:
        raise RenderError(f"报告模板无法打开: {template_path}（{exc}）") from exc
    richtext_keys = _richtext_keys(template_path)
    if richtext_keys:  # {{r }} 目标值必须是 RichText（纯字符串会被丢弃）
        context = _wrap_richtext(context, richtext_keys)
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
