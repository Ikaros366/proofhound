"""M24-a CLI：``python -m proofhound.jsimport`` 的退出码与端到端接线。

这里跑的是 **真实 stdlib HTTP**（conftest 的 ``http_server``）+ **真实 urllib**，
不是罐头 fetch——CLI 这一层要证明的是"参数 → 引擎 → 证据 → 退出码"整条链通着，
而不是再测一遍引擎。

退出码口径（交接单 §6）：0 = 至少 1 条 confirmed；1 = 无 confirmed；
2 = 入口错误 / 无会话 / 会话失效 / scope 全拒。
"""

from __future__ import annotations

import json
from pathlib import Path

from proofhound.jsimport.__main__ import build_parser, main

COOKIE = "s3cr3t-cookie-value"
APP_JS = 'fetch("/api/orders/1001");\nfetch("/api/config");\n'


def _prepare(
    tmp_path: Path, served: Path, base_url: str, *, with_session: bool = True
) -> tuple[Path, Path]:
    """落一个 SPA 静态站点 + 一份 katana JSONL + 一份 scope。"""
    (served / "static").mkdir(parents=True, exist_ok=True)
    (served / "api" / "orders").mkdir(parents=True, exist_ok=True)
    (served / "static" / "app.js").write_text(APP_JS, encoding="utf-8")
    order_json = json.dumps({"id": 1001, "owner": "alice", "total": 42})
    (served / "api" / "orders" / "1001").write_text(order_json, encoding="utf-8")

    records = [
        {
            "timestamp": "2026-10-28T00:00:00Z",
            "request": {"method": "GET", "endpoint": f"{base_url}/", "raw": "GET / HTTP/1.1\r\n\r\n"},
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body": "<html>spa</html>",
            },
        },
        {
            "timestamp": "2026-10-28T00:00:01Z",
            "request": {
                "method": "GET",
                "endpoint": f"{base_url}/static/app.js",
                "raw": "GET /static/app.js HTTP/1.1\r\n\r\n",
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/javascript; charset=utf-8"},
                "body": APP_JS,
            },
        },
        {
            "timestamp": "2026-10-28T00:00:02Z",
            "request": {
                "method": "GET",
                "endpoint": f"{base_url}/api/orders/1001",
                "raw": "GET /api/orders/1001 HTTP/1.1\r\n\r\n",
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": order_json,
            },
        },
    ]
    jsonl = tmp_path / "katana.stdout.log"
    jsonl.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in records) + "\n",
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    lines = ["networks: [127.0.0.0/8]", "ports: []"]
    if with_session:
        lines += ["session:", "  cookies:", f"    sid: {COOKIE}"]
    scope.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return jsonl, scope


def test_cli_confirms_real_anonymous_equivalence(tmp_path, http_server):
    base_url, served, _handler = http_server
    jsonl, scope = _prepare(tmp_path, served, base_url)
    out = tmp_path / "out"

    code = main(
        ["--katana-jsonl", str(jsonl), "--scope", str(scope), "--out", str(out), "--qps", "0"]
    )

    assert code == 0
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["confirmed"] == 1
    assert summary["confirmed"][0]["url"] == f"{base_url}/api/orders/1001"
    assert summary["confirmed"][0]["judgment"]["byte_identical"] is True
    assert summary["counts"]["inventory"] >= 1  # /api/config 进清单
    assert COOKIE not in (out / "summary.json").read_text(encoding="utf-8")


def test_cli_without_session_exits_2(tmp_path, http_server):
    base_url, served, _handler = http_server
    jsonl, scope = _prepare(tmp_path, served, base_url, with_session=False)
    out = tmp_path / "out"

    code = main(
        ["--katana-jsonl", str(jsonl), "--scope", str(scope), "--out", str(out), "--qps", "0"]
    )

    assert code == 2
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["confirmed"] == 0
    assert summary["session"]["configured"] is False


def test_cli_missing_inputs_exit_2(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks: [127.0.0.0/8]\n", encoding="utf-8")
    assert main(["--katana-jsonl", str(tmp_path / "nope.jsonl"), "--scope", str(scope)]) == 2
    jsonl = tmp_path / "katana.stdout.log"
    jsonl.write_text("", encoding="utf-8")
    assert main(["--katana-jsonl", str(jsonl), "--scope", str(tmp_path / "nope.yaml")]) == 2


def test_cli_bad_scope_file_exits_2(tmp_path):
    jsonl = tmp_path / "katana.stdout.log"
    jsonl.write_text("", encoding="utf-8")
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks: not-a-list\n", encoding="utf-8")
    assert main(["--katana-jsonl", str(jsonl), "--scope", str(scope)]) == 2


def test_cli_parser_defaults_match_the_documented_limits():
    args = build_parser().parse_args(["--katana-jsonl", "a.jsonl", "--scope", "s.yaml"])
    assert args.max_js == 50
    assert args.max_probes == 100
    assert args.qps == 2.0
    assert args.param_seed == "1"
    assert args.fetch_missing is False
