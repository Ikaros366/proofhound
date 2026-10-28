"""图形验证码 OCR（M21-a）：可选依赖 ``ddddocr``，**懒导入**。

- 没装 ``ddddocr`` 时抛 :class:`OcrUnavailableError`，由编排层转
  ``blocked``（不静默降级成"验证码错误"——那会把 OCR 缺依赖误读成"有防护"）；
- 引擎单例缓存（初始化约 1s，别每次重来）；
- 识别结果只保留字母数字（验证码常见形如 ``j8f6``），空串由调用方当失败处理。
"""

from __future__ import annotations

_ENGINE = None


class OcrUnavailableError(RuntimeError):
    """``ddddocr`` 未安装（可选依赖）。"""


def available() -> bool:
    try:
        import ddddocr  # noqa: F401
    except ImportError:
        return False
    return True


def _engine():
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    try:
        import ddddocr
    except ImportError as exc:  # pragma: no cover - 依赖缺失路径
        raise OcrUnavailableError(
            "ddddocr 未安装（pip install ddddocr；图形验证码识别需要它）"
        ) from exc
    _ENGINE = ddddocr.DdddOcr(show_ad=False)
    return _ENGINE


def solve(image: bytes) -> str:
    """识别一张验证码图片，返回字母数字串（失败返回空串）。"""
    if not image:
        return ""
    text = _engine().classification(image)
    return "".join(ch for ch in str(text) if ch.isalnum())


__all__ = ["OcrUnavailableError", "available", "solve"]
