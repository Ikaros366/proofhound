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
from proofhound.jsimport.probe import ImportConfig, ImportReport, run_jsimport

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
