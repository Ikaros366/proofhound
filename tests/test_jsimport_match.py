"""M24-a 匹配层：模板 × 观测 URL → A/B/C 分级 + 合成 URL。

锁四件事：

1. **过滤只是收敛**：公开/非数据接口与状态变更词表各自有明确原因码，且
   **状态变更词优先**（命中即根本不进探测循环，交接单 §4.6）；
2. **A 类用观测实例原样重放**（参数不猜），其余同模板实例只记
   ``additional_instances``；
3. **B 类合成**：路径参数与 query 值都填种子，键保持首次出现顺序；
4. **同 URL 只探一次**：后到的模板记 ``duplicate_url`` 进清单，既不重复发请求，
   也不静默丢掉（否则 §9 的 /api/orders/1001 会被确认两次）。
"""

from __future__ import annotations

from proofhound.jsimport.crawl import CrawlRecord
from proofhound.jsimport.extract import EndpointAnchor, EndpointTemplate
from proofhound.jsimport.match import (
    GRADE_INVENTORY,
    GRADE_OBSERVED,
    GRADE_SYNTHESIZED,
    ObservedIndex,
    classify,
    exclusion_reason,
    synthesize_url,
    template_regex,
)

ORIGIN = "http://127.0.0.1:8000"


def _endpoint(path_template: str, query_keys: tuple[str, ...] = ()) -> EndpointTemplate:
    return EndpointTemplate(
        js_sha256="a" * 64,
        js_url=f"{ORIGIN}/static/app.js",
        origin=ORIGIN,
        path_template=path_template,
        query_keys=query_keys,
        anchor=EndpointAnchor(offset=0, line=1, literal=path_template),
    )


def _record(url: str, *, status: int = 200, order: int = 1) -> CrawlRecord:
    return CrawlRecord(
        order=order,
        source="katana.stdout.log",
        lineno=order,
        url=url,
        method="GET",
        status=status,
        content_type="application/json",
        body="{}",
        body_sha256="b" * 64,
    )


def _index(*records: CrawlRecord) -> ObservedIndex:
    return ObservedIndex.build(records)


# --------------------------------------------------------------- 候选过滤


def test_public_endpoints_are_excluded_by_name_not_by_guessing():
    assert exclusion_reason(_endpoint("/api/config")) == "excluded_segment:config"
    assert exclusion_reason(_endpoint("/api/health")) == "excluded_segment:health"
    assert exclusion_reason(_endpoint("/api/status")) == "excluded_segment:status"
    assert exclusion_reason(_endpoint("/api/metrics")) == "excluded_segment:metrics"


def test_mutating_segments_win_over_everything_else():
    """状态变更词优先：``/api/logout`` 既是排除词也是变更词 ⇒ 必须记变更。"""
    assert exclusion_reason(_endpoint("/api/logout")) == "mutating_segment:logout"
    assert exclusion_reason(_endpoint("/api/orders/delete")) == "mutating_segment:delete"
    assert exclusion_reason(_endpoint("/api/x/transfer")) == "mutating_segment:transfer"


def test_mutating_query_key_is_also_skipped():
    assert exclusion_reason(_endpoint("/api/orders", ("delete",))) == "mutating_query:delete"


def test_non_data_path_is_filtered():
    assert exclusion_reason(_endpoint("/foo/bar")) == "not_data_endpoint"


def test_data_clues_keep_the_candidate():
    assert exclusion_reason(_endpoint("/api/anything")) is None  # 前缀
    assert exclusion_reason(_endpoint("/v2/anything")) is None  # 版本前缀
    assert exclusion_reason(_endpoint("/graphql")) is None
    assert exclusion_reason(_endpoint("/admin/panel")) is None  # 段名线索
    assert exclusion_reason(_endpoint("/thing/{param}")) is None  # 路径参数
    assert exclusion_reason(_endpoint("/thing", ("id",))) is None  # 查询键


def test_classify_marks_filtered_as_inventory_with_reason():
    candidates = classify([_endpoint("/api/config")], _index())
    assert len(candidates) == 1
    assert candidates[0].grade == GRADE_INVENTORY
    assert candidates[0].probe_url is None
    assert candidates[0].reason == "excluded_segment:config"


# --------------------------------------------------------------- A 类：观测实例


def test_observed_instance_is_replayed_verbatim():
    endpoint = _endpoint("/api/orders/{param}")
    observed = _record(f"{ORIGIN}/api/orders/1001")
    candidate = classify([endpoint], _index(observed))[0]
    assert candidate.grade == GRADE_OBSERVED
    assert candidate.probe_url == observed.url  # 参数不猜：用观测到的原 URL
    assert candidate.observed_ref == observed.evidence_ref
    assert candidate.synthetic is False


def test_additional_instances_keep_only_the_first_for_replay():
    endpoint = _endpoint("/api/orders/{param}")
    first = _record(f"{ORIGIN}/api/orders/1001", order=1)
    second = _record(f"{ORIGIN}/api/orders/2002", order=2)
    candidate = classify([endpoint], _index(first, second))[0]
    assert candidate.probe_url == first.url
    assert candidate.additional_instances == (second.url,)


def test_non_2xx_observation_does_not_make_an_observed_candidate():
    """观测索引只收 2xx：404 的实例不算 A 类（交接单 §5.3）。"""
    endpoint = _endpoint("/api/orders/{param}")
    candidate = classify(
        [endpoint], _index(_record(f"{ORIGIN}/api/orders/1001", status=404))
    )[0]
    assert candidate.grade == GRADE_SYNTHESIZED
    assert candidate.synthetic is True


# --------------------------------------------------------------- B 类：合成


def test_synthesized_url_fills_path_param_and_query_keys_in_order():
    endpoint = _endpoint("/api/report/{param}", ("report_id", "format"))
    url = synthesize_url(endpoint)
    assert url == f"{ORIGIN}/api/report/1?report_id=1&format=1"


def test_synthesized_url_honours_custom_seed():
    endpoint = _endpoint("/api/orders/{param}", ("page",))
    assert synthesize_url(endpoint, "42") == f"{ORIGIN}/api/orders/42?page=42"


def test_synthesized_candidate_is_flagged_as_synthetic():
    candidate = classify([_endpoint("/api/profile")], _index())[0]
    assert candidate.grade == GRADE_SYNTHESIZED
    assert candidate.synthetic is True
    assert candidate.probe_url == f"{ORIGIN}/api/profile"
    assert candidate.reason == "synthesized_instance"


# --------------------------------------------------------------- 同 URL 只探一次


def test_second_template_on_same_url_is_collapsed_but_keeps_its_grade():
    """同 URL 只探一次：后到的模板**等级仍是 A**，只是 ``collapsed`` 进清单。"""
    literal = _endpoint("/api/orders/1001")
    templated = _endpoint("/api/orders/{param}")
    observed = _record(f"{ORIGIN}/api/orders/1001")
    candidates = classify([literal, templated], _index(observed))
    assert candidates[0].grade == GRADE_OBSERVED
    assert candidates[0].probe_url == observed.url
    assert candidates[1].grade == GRADE_OBSERVED  # 仍是 A 类，不是"被过滤"
    assert candidates[1].collapsed is True
    assert candidates[1].reason == "duplicate_url"
    assert candidates[1].duplicate_of == "/api/orders/1001"


def test_same_path_with_different_query_keys_is_not_a_duplicate():
    observed_a = _record(f"{ORIGIN}/api/orders?a=1", order=1)
    observed_b = _record(f"{ORIGIN}/api/orders?b=1", order=2)
    candidates = classify(
        [_endpoint("/api/orders", ("a",)), _endpoint("/api/orders", ("b",))],
        _index(observed_a, observed_b),
    )
    assert [item.grade for item in candidates] == [GRADE_OBSERVED, GRADE_OBSERVED]
    assert candidates[0].probe_url != candidates[1].probe_url


# --------------------------------------------------------------- 模板正则


def test_template_regex_is_segment_bound():
    pattern = template_regex("/api/orders/{param}")
    assert pattern.fullmatch("/api/orders/1001")
    assert not pattern.fullmatch("/api/orders/1001/items")  # 段数不同
    assert not pattern.fullmatch("/api/orders/")  # 空段
    assert not pattern.fullmatch("/api/user/1001")  # 字面段不同


def test_template_regex_supports_param_inside_segment():
    pattern = template_regex("/api/orders/{param}.json")
    assert pattern.fullmatch("/api/orders/1001.json")
    assert not pattern.fullmatch("/api/orders/1001.xml")
