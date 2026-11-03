"""M24-a：从爬行产出的 JS 里找接口 → 未授权访问确认（手工 CLI）。

## 定位与边界（详版见 README §「从爬行产出的 JS 找接口」与 design.md §7.28）

- **只补发现侧**：从既有 katana JSONL 的 ``response.body`` 里**重新**抽 JS 接口
  路径——限制 53 已记录 ``-jc`` 的抽取是**部分的**（模板串、``fetch("/x")`` 经常
  抽不到），故不能把"katana 没抽到"读作"不存在"；
- **判定链零改动**：三态仍由 :func:`proofhound.verify.unauth_control.judge_unauth`
  给出；本包**不注册** ``vuln_type``、不改 ``VULN_REGISTRY`` / ``GATE_MATRIX`` /
  状态机 / 证据门；
- **零 LLM**：抽取、匹配、重放、判定全是确定性代码；
- **一个人工入口**：本里程碑只交付 ``python -m proofhound.jsimport``，把
  ``js-endpoint`` 接成 ``unauth-exposure`` 的新生产者留到 M24-b（数据支持后另议）。

## 模块分工

| 模块 | 职责 |
|---|---|
| :mod:`~proofhound.jsimport.crawl` | katana JSONL → ``CrawlRecord`` / ``JsDocument``（``Source`` 抽象） |
| :mod:`~proofhound.jsimport.extract` | JS 正文 → 路径模板 + 锚点 + 去重 |
| :mod:`~proofhound.jsimport.match` | 模板 × 观测 URL → A/B/C 分级 + URL 合成 |
| :mod:`~proofhound.jsimport.probe` | 会话自检 + 认证基线 + 匿名对照 + 判定 + 证据落盘 |
| :mod:`~proofhound.jsimport.__main__` | CLI（退出码 0/1/2） |
"""

from __future__ import annotations

from proofhound.jsimport.crawl import (
    CrawlBundle,
    CrawlRecord,
    JsDocument,
    KatanaJsonlSource,
    load_crawl,
    load_katana_jsonl,
    parse_katana_text,
)
from proofhound.jsimport.extract import (
    EndpointAnchor,
    EndpointTemplate,
    extract_endpoints,
)
from proofhound.jsimport.match import Candidate, ObservedIndex, classify, synthesize_url

__all__ = [
    "Candidate",
    "CrawlBundle",
    "CrawlRecord",
    "EndpointAnchor",
    "EndpointTemplate",
    "ImportConfig",
    "ImportReport",
    "JsDocument",
    "KatanaJsonlSource",
    "ObservedIndex",
    "classify",
    "extract_endpoints",
    "load_crawl",
    "load_katana_jsonl",
    "parse_katana_text",
    "run_jsimport",
    "synthesize_url",
]

def __getattr__(name: str):
    """PEP 562：重的 CLI 入口按需导入（M33）。

    ``probe`` 会把 ``verify`` → ``core`` → ``skills`` 一整串拉起来，而
    :mod:`proofhound.tools.parsers.katana_jsonl` 在编排器导入链的**早期**就要用
    本包的 ``extract``（M33：把 JS 接口接成生产候选）。probe 随包导入会让这条轻
    路径连带整棵应用树，导入顺序稍变即成环（实测
    ``ModuleNotFoundError: proofhound.skills.registry``）。

    故 ``ImportConfig`` / ``ImportReport`` / ``run_jsimport`` 三个名字改为惰性
    ——``from proofhound.jsimport import run_jsimport`` 照旧可用，只是推迟到真用。
    """
    if name in ("ImportConfig", "ImportReport", "run_jsimport"):
        from proofhound.jsimport import probe

        return getattr(probe, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
