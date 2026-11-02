"""CLI：``python -m proofhound.xxeprobe``——XXE 的手工先验（M25-a）。

```bash
python -m proofhound.xxeprobe \\
  --url https://target/soap/endpoint \\
  --scope scopes/lab.yaml \\
  --content-type application/xml \\
  [--body-template file.xml] [--allow-file /path] [--out evidence/xxe/<ts>] \\
  [--callback-host 10.0.0.5] [--callback-wait 3] [--timeout 10]
```

退出码（交接单 §6）：

- ``0``：至少 1 条 **confirmed**（内容通道或回调通道）；
- ``1``：没有 confirmed（rejected / blocked / 没有任何判定）；
- ``2``：**结构性失败**——入口错误 / 无 scope / URL 越界 / listener 不可用 /
  模板里的 ``file://`` 目标不在白名单且未 ``--allow-file`` / 模板派生不出对照。
  这不是"测过且安全"。

## 一次运行做什么（顺序即纪律）

```
out 目录 + audit.jsonl
   → check_scope（越界即 2，零请求）
   → 起 CallbackListener（不可用即 2）+ 两个互不相同的 token（probe / control）
   → 选 canary / 裁决模板里的 file:// 目标（默认拒绝）+ 派生 4 个探针体
   → 爆发前统一核「实体膨胀」红线（任何一条不合格即整体不发）
   → 4 个探针：baseline(带 control URL) → file(alive+canary) → file-negative → callback
      每个发请求前再 check_scope 一次
   → 等回调宽限窗口 → 收 token 命中 / control 命中 / ignored
   → judge（零 LLM）→ 证据落盘 → 退出码
```

## 证据（交接单 §8）

``probe_<n>.json``（模板名/URL/状态码/是否命中签名/阴性对照结果/sha256）、
``response_<n>.txt``（截断 ≤256KB 且脱敏，**0600**）、``judgment.json``（三态 +
两条通道的事实 + 全部否定项）、``summary.json``（**不含时间戳与输出路径** ⇒
连跑两次逐字节一致）、``summary.md``、``audit.jsonl``。

脱敏两个口子：``SessionConfig.secret_values()``（Cookie/请求头）与**回调 token**
（只以 ``sha256:<hex8>`` 形态出现）。响应正文可能含目标文件内容（``root:x:0:0``
一行）⇒ 证据文件 0600，且**不进 summary 正文、不进任何 prompt**。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import redact_bytes, secret_marker
from proofhound.verify import xxe
from proofhound.verify.http_body import BodyResponse, post, tls_context_for
from proofhound.verify.ssrf import (
    CallbackListener,
    SsrfListenerError,
    callback_url,
    resolve_callback_bind,
    resolve_callback_host,
    resolve_callback_port,
)

#: 缺省证据目录的父目录（与其余 demo/工具一致；``evidence/`` 不入库）。
DEFAULT_OUT_PARENT = Path("evidence") / "xxe"

#: 模板只读白名单外路径时的占位 canary（内容通道零覆盖，只能靠回调确认）。
UNAVAILABLE_CANARY = xxe.Canary(label="unavailable", url="", path="", signature="")

#: summary.json 里保留的稳定性事实（**剔除** listener 端口等随运行变化的值）。
_SUMMARY_FACT_KEYS = (
    "baseline_canary_hit",
    "file_canary_hit",
    "negative_canary_hit",
    "alive_replaced",
    "alive_literal_echoed",
    "alive_evidence_sound",
    "callback_hit",
    "callback_control_hit",
    "listener_unavailable",
    "all_probes_answered",
    "errored_probes",
    "unanswered_probes",
    "canary_available",
    "requested_probes",
)


class XxeProbeError(RuntimeError):
    """结构性失败（CLI 返回退出码 2，不是"测过且安全"）。"""


@dataclass
class ProbeConfig:
    """一次手工先验的全部输入与上限（CLI 只是它的解析器）。"""

    url: str
    scope: Scope
    out_dir: Path
    content_type: str = xxe.DEFAULT_CONTENT_TYPE
    body_template: Path | None = None
    allow_files: tuple[str, ...] = ()
    callback_host: str | None = None
    callback_wait: float = xxe.CALLBACK_WAIT_SECONDS
    timeout: float = xxe.DEFAULT_TIMEOUT
    max_bytes: int = xxe.MAX_RESPONSE_BYTES


@dataclass
class ProbeReport:
    """一次运行的结果（CLI 只负责打印与返回退出码）。"""

    judgment: xxe.XxeJudgment
    out_dir: Path
    summary: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return 0 if self.judgment.confirmed else 1

    def render_lines(self) -> list[str]:
        j = self.judgment
        target = self.summary.get("target", {})
        canary = self.summary.get("canary", {})
        channels = " + ".join(j.channels) if j.channels else "-"
        lines = [
            f"[+] XXE 手工先验（M25-a）  {target.get('url', '')}",
            f"    Content-Type: {target.get('content_type', '')}",
            (
                f"    canary: {canary.get('path', '')}（签名只在 0600 证据里）"
                if canary.get("available", True)
                else "    canary: （本次模板只读白名单外路径，内容通道零覆盖）"
            ),
            "    探针: "
            + "  ".join(
                f"{p['probe']}={p.get('status')}" for p in self.summary.get("probes", [])
            ),
            f"    结论: {j.verdict.upper()}"
            + (f"（{channels} 通道）" if j.channels else ""),
        ]
        lines.extend(f"      - {reason}" for reason in j.reasons)
        lines.append(f"    证据: {self.out_dir}")
        return lines


# --------------------------------------------------------------- 小工具


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha8(value: str) -> str:
    """脱敏标记：``sha256:<hex8>``（与 ``compliance/session.py`` 同一形态）。"""
    return secret_marker(value)


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - 非 POSIX 文件系统
        pass


def _write_private(path: Path, data: bytes) -> None:
    """写文件并收紧到 0600（响应正文可能含目标文件内容）。"""
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - 非 POSIX 文件系统
        pass


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _secrets(scope: Scope) -> list[str]:
    return scope.session.secret_values() if scope.session else []


def _redactions(secrets: list[str], *tokens: str) -> list[str]:
    """脱敏清单 = 会话秘密 + 回调 token（token 只以 sha8 形态留在证据里）。"""
    values = list(secrets)
    values.extend(token for token in tokens if token)
    return [item for item in values if item]


def _canary_from_scan(scan: xxe.FileTargetScan) -> xxe.Canary | None:
    """模板里第一个**白名单**目标对应的 canary（没有则 None）。"""
    if not scan.allowed:
        return None
    return xxe.require_whitelisted(scan.allowed[0])


def _summarize_hits(records, token: str) -> list[dict]:
    """回调记录 → 去敏摘要（**只留 token 的 sha256 前 8 位**）。"""
    return [
        {
            "token_sha8": _sha8(token),
            "path": record.path,
            "source_ip": record.source_ip,
            "user_agent": record.user_agent,
            "at": record.at,
        }
        for record in records
    ]


# --------------------------------------------------------------- 主体


def _template_plan(
    template_text: str, callback_url_value: str
) -> tuple[xxe.ProbeSpec, ...]:
    """由操作员模板派生 4 步（顺序与自动通道一致）。"""
    derived = xxe.derive_template_probes(
        template_text, callback_url=callback_url_value
    )
    return (
        xxe.ProbeSpec(xxe.PROBE_BASELINE, xxe.ROLE_BASELINE, derived.baseline),
        xxe.ProbeSpec(xxe.PROBE_FILE, xxe.ROLE_FILE, derived.file),
        xxe.ProbeSpec(xxe.PROBE_NEGATIVE, xxe.ROLE_NEGATIVE, derived.negative),
        xxe.ProbeSpec(xxe.PROBE_CALLBACK, xxe.ROLE_CALLBACK, derived.callback),
    )


def _write_probe_evidence(
    out_dir: Path,
    index: int,
    spec: xxe.ProbeSpec,
    config: ProbeConfig,
    response: BodyResponse,
    observation: xxe.ProbeObservation,
    *,
    canary: xxe.Canary,
    redactions: list[str],
) -> dict:
    """落一份 ``probe_<n>.json`` + ``response_<n>.txt``（0600），返回**不含正文**的行。"""
    row = {
        "probe": spec.name,
        "role": spec.role,
        "index": index,
        "url": config.url,
        "content_type": config.content_type,
        "status": response.status,
        "error": response.error,
        "bytes": len(response.body),
        "truncated": response.truncated,
        "body_sha256": sha256(response.body).hexdigest() if response.body else "",
        "request_sha256": spec.sha256,
        "answered": observation.answered,
        "alive_seen": observation.alive_seen,
        "alive_literal_echoed": observation.alive_literal_echoed,
        "canary_hit": observation.canary_seen(canary.signature),
    }
    _write_private(out_dir / f"probe_{index}.json", _json_bytes(row))
    _write_private(
        out_dir / f"response_{index}.txt", redact_bytes(response.body, redactions)
    )
    return row


def _read_template(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise XxeProbeError(f"body 模板不可读：{exc}") from None
    if not text.strip():
        raise XxeProbeError("body 模板是空的")
    return text


def _resolve_template(
    config: ProbeConfig, audit: AuditLog
) -> tuple[str | None, xxe.Canary, bool, bool]:
    """裁决模板：白名单 → canary → 阳性对照是否可靠。

    返回 ``(template_text, canary, canary_available, alive_evidence_sound)``；
    模板为空时返回 ``(None, default_canary(), True, True)``。派生本身只做**可派生性
    校验**（真正要发的 4 个 body 在拿到真实回调地址后才构造——占位地址不能发出去）。
    """
    if config.body_template is None:
        canary = xxe.default_canary()
        return None, canary, True, True

    text = _read_template(Path(config.body_template))
    scan = xxe.scan_file_targets(text, allow=config.allow_files)
    audit.record(
        "xxe_template_scan",
        file_urls=list(scan.urls),
        allowed=list(scan.allowed),
        rejected=list(scan.rejected),
        overrides=list(scan.overrides),
    )
    if not scan.ok:
        audit.record("xxe_file_rejected", rejected=list(scan.rejected))
        raise XxeProbeError(
            "模板里的 file:// 目标不在 canary 白名单："
            + ", ".join(scan.rejected)
            + "（如确需读取，显式 --allow-file <path>）"
        )
    for url in scan.overrides:
        audit.record("xxe_file_override", path=url)
    if not scan.urls:
        audit.record("xxe_template_without_file_url")

    found = _canary_from_scan(scan)
    canary = found or UNAVAILABLE_CANARY
    canary_available = found is not None
    # 裸 alive 字样（非字符引用）⇒ "响应里有 alive" 可由原样回显解释
    alive_evidence_sound = xxe.ALIVE_MARKER not in text
    try:
        xxe.derive_template_probes(text, callback_url="http://127.0.0.1:1/placeholder")
    except xxe.XxeError as exc:
        audit.record("xxe_template_invalid", error=str(exc))
        raise XxeProbeError(str(exc)) from None
    return text, canary, canary_available, alive_evidence_sound


def run_xxeprobe(config: ProbeConfig) -> ProbeReport:
    """跑一次手工先验（判定零 LLM），返回 :class:`ProbeReport`。

    结构性失败抛 :class:`XxeProbeError`（审计已落盘）。
    """
    out_dir = Path(config.out_dir)
    _mkdir_private(out_dir)
    audit = AuditLog(out_dir / "audit.jsonl")
    secrets = _secrets(config.scope)
    audit.record(
        "xxe_started",
        url=config.url,
        content_type=config.content_type,
        body_template=str(config.body_template) if config.body_template else None,
        allow_files=list(config.allow_files),
    )

    # 1) 红线 5：发请求前必过 scope（越界 ⇒ 零请求 + 退出码 2）
    decision = check_scope(config.scope, [config.url])
    if not decision.allowed:
        audit.record("xxe_scope_rejected", url=config.url, violations=decision.violations)
        raise XxeProbeError(
            f"URL 不在 scope 授权范围内：{'; '.join(decision.violations)}（零请求）"
        )

    # 2) listener（不可用 ⇒ 结构性失败，不是"测过且安全"）
    listener: CallbackListener | None = None
    try:
        host = config.callback_host or resolve_callback_host()
        bind = resolve_callback_bind(host)
        port = resolve_callback_port()
        listener = CallbackListener(host=bind, port=port).start()
    except (SsrfListenerError, OSError) as exc:
        audit.record("xxe_listener_failed", error=str(exc))
        raise XxeProbeError(f"回调 listener 不可用：{exc}") from None

    try:
        probe_token = xxe.new_xxe_token()
        control_token = xxe.new_xxe_token()
        listener.register(probe_token)
        listener.register(control_token)
        target_port = listener.port
        probe_callback_url = callback_url(host, target_port, probe_token)
        control_callback_url = callback_url(host, target_port, control_token)
        audit.record(
            "xxe_listener_started",
            bind=f"{bind}:{target_port}",
            advertised=f"{host}:{target_port}",
            probe_token_sha8=_sha8(probe_token),
            control_token_sha8=_sha8(control_token),
        )

        # 3) 模板裁决 / canary
        template_text, canary, canary_available, alive_sound = _resolve_template(
            config, audit
        )

        # 4) 探针计划（模板派生体在拿到真实回调地址后才构造）
        if template_text is not None:
            plan = _template_plan(template_text, probe_callback_url)
        else:
            plan = xxe.probe_plan(
                canary=canary,
                callback_url=probe_callback_url,
                control_url=control_callback_url,
            )

        # 5) 爆发前的统一红线：实体膨胀（任何一条不合格 ⇒ 整体不发）
        for spec in plan:
            reasons = xxe.entity_amplification_reasons(spec.body)
            if reasons:
                audit.record("xxe_body_rejected", probe=spec.name, reasons=list(reasons))
                raise XxeProbeError(
                    f"拒绝发送 {spec.name}：{'；'.join(reasons)}"
                    "（实体膨胀是 DoS，不是本类型）"
                )

        # 6) 4 个探针（每请求前再 check_scope）
        redactions = _redactions(secrets, probe_token, control_token)
        observations: dict[str, xxe.ProbeObservation] = {}
        rows: list[dict] = []
        for index, spec in enumerate(plan, start=1):
            per_request = check_scope(config.scope, [config.url])
            if not per_request.allowed:
                audit.record(
                    "xxe_scope_rejected",
                    url=config.url,
                    violations=per_request.violations,
                )
                raise XxeProbeError("URL 在探测期间失去 scope 授权（已停止，零后续请求）")
            response = post(
                config.url,
                spec.body,
                content_type=config.content_type,
                session=config.scope.session,
                timeout=config.timeout,
                max_bytes=config.max_bytes,
                # M30：scope 显式声明 insecure 才放宽（缺省严格校验）
                ssl_context=tls_context_for(config.scope),
            )
            observation = xxe.ProbeObservation(
                name=spec.name,
                status=response.status,
                error=response.error,
                body=response.body,
                url=config.url,
            )
            observations[spec.role] = observation
            row = _write_probe_evidence(
                out_dir,
                index,
                spec,
                config,
                response,
                observation,
                canary=canary,
                redactions=redactions,
            )
            rows.append(row)
            audit.record(
                "xxe_probe_attempt",
                template=spec.name,
                status=response.status,
                error=response.error,
                bytes=len(response.body),
                answered=observation.answered,
                canary_hit=row["canary_hit"],
                alive_seen=observation.alive_seen,
                request_sha256=spec.sha256,
            )

        # 7) 回调宽限窗口（目标可能异步取数）
        _wait_for_callbacks(listener, probe_token, config.callback_wait)
        probe_hits = list(listener.hits(probe_token))
        control_hits = list(listener.hits(control_token))
        ignored = list(listener.ignored)
        for record in probe_hits:
            audit.record(
                "xxe_callback_received",
                token_sha8=_sha8(record.token),
                path=record.path,
                source_ip=record.source_ip,
            )
        for record in ignored:
            audit.record("xxe_callback_ignored", path=record.path, reason=record.reason)

        # 8) 判定（零 LLM）
        judgment = xxe.judge(
            canary=canary,
            baseline=observations[xxe.ROLE_BASELINE],
            file_probe=observations[xxe.ROLE_FILE],
            negative=observations[xxe.ROLE_NEGATIVE],
            callback=observations[xxe.ROLE_CALLBACK],
            callback_hit=bool(probe_hits),
            control_hit=bool(control_hits),
            listener_error=False,
            callback_host_port=f"{host}:{target_port}",
            alive_evidence_sound=alive_sound,
            canary_available=canary_available,
        )
        audit.record(
            "xxe_judged",
            verdict=judgment.verdict,
            channels=list(judgment.channels),
            canary_available=canary_available,
            callback_hit=bool(probe_hits),
            callback_control_hit=bool(control_hits),
        )

        # 9) 证据落盘
        judgment_payload = {
            **judgment.to_dict(),
            "probes": rows,
            "callbacks": {
                "probe_hits": _summarize_hits(probe_hits, probe_token),
                "control_hits": _summarize_hits(control_hits, control_token),
                "ignored": [
                    {"path": record.path, "reason": record.reason} for record in ignored
                ],
            },
            "canary_available": canary_available,
            "body_template": str(config.body_template) if config.body_template else None,
        }
        _write_private(out_dir / "judgment.json", _json_bytes(judgment_payload))

        summary = _build_summary(config, judgment, rows, canary, canary_available)
        _write_private(out_dir / "summary.json", _json_bytes(summary))
        (out_dir / "summary.md").write_text(
            _render_summary_md(summary, judgment, out_dir), encoding="utf-8"
        )
        audit.record(
            "xxe_completed",
            verdict=judgment.verdict,
            channels=list(judgment.channels),
            requests=len(rows),
        )
        return ProbeReport(judgment=judgment, out_dir=out_dir, summary=summary)
    finally:
        listener.close()


def _wait_for_callbacks(listener: CallbackListener, token: str, seconds: float) -> None:
    """轮询等待回调（命中即返回；最多 ``seconds`` 秒）。"""
    deadline = time.monotonic() + max(0.0, float(seconds))
    while time.monotonic() < deadline:
        if listener.has_hit(token):
            return
        time.sleep(0.05)


def _build_summary(
    config: ProbeConfig,
    judgment: xxe.XxeJudgment,
    rows: list[dict],
    canary: xxe.Canary,
    canary_available: bool,
) -> dict:
    """``summary.json``：**不含时间戳、输出路径、端口** ⇒ 连跑两次逐字节一致。"""
    facts = judgment.facts
    return {
        "tool": "proofhound.xxeprobe",
        "milestone": "M25-a",
        "target": {"url": config.url, "content_type": config.content_type},
        "canary": {
            "label": canary.label,
            "path": canary.path,
            "signature": canary.signature,
            "available": canary_available,
        },
        "probes": [
            {
                "probe": row["probe"],
                "role": row["role"],
                "status": row["status"],
                "error": row["error"],
                "answered": row["answered"],
                "canary_hit": row["canary_hit"],
                "alive_seen": row["alive_seen"],
            }
            for row in rows
        ],
        "judgment": {
            "verdict": judgment.verdict,
            "channels": list(judgment.channels),
            "reasons": list(judgment.reasons),
        },
        "facts": {key: facts[key] for key in _SUMMARY_FACT_KEYS if key in facts},
        "counts": {
            "requests": len(rows),
            "confirmed_channels": len(judgment.channels),
        },
    }


def _render_summary_md(summary: dict, judgment: xxe.XxeJudgment, out_dir: Path) -> str:
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# XXE 手工先验（M25-a）",
        "",
        f"- 生成时间：{generated_at}",
        f"- 目标：`POST {summary['target']['url']}`（{summary['target']['content_type']}）",
        f"- 证据目录：`{out_dir}`",
    ]
    canary = summary["canary"]
    if canary["available"]:
        lines.append(
            f"- canary：`{canary['path']}`（签名形态只写入 0600 证据文件）"
        )
    else:
        lines.append("- canary：本次模板只读白名单外路径 ⇒ 内容通道零覆盖")
    lines.extend(
        [
            "",
            "## 探针",
            "",
            "| # | 模板 | 状态码 | 已响应 | canary 命中 | alive 展开 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for index, probe in enumerate(summary["probes"], start=1):
        lines.append(
            f"| {index} | {probe['probe']} | {probe['status']} | "
            f"{'是' if probe['answered'] else '否'} | "
            f"{'是' if probe['canary_hit'] else '否'} | "
            f"{'是' if probe['alive_seen'] else '否'} |"
        )
    channels = " + ".join(judgment.channels) if judgment.channels else "（无）"
    lines.extend(
        ["", "## 结论", "", f"**{judgment.verdict.upper()}**（通道：{channels}）", ""]
    )
    lines.extend(f"- {reason}" for reason in judgment.reasons)
    lines.extend(
        [
            "",
            "## 纪律",
            "",
            "- 判定链零 LLM；`response_*.txt` 为 0600 且已脱敏（会话秘密 + 回调 token）。",
            "- 未命中只说明「该端点当前不解析外部实体 / 不接受这段 XML」，",
            "  **不等于**「没有 XXE 风险」。",
            "- 本工具只读两个写死的 canary 文件，不是任意文件读取器。",
            "",
        ]
    )
    return "\n".join(lines)


# --------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proofhound.xxeprobe",
        description=(
            "对单个端点做 XXE 确定性判定：内容通道（canary 文件签名 + 基线与阴性对照）"
            " + 回调通道（listener 收到唯一 token）"
        ),
    )
    parser.add_argument(
        "--url", required=True, help="目标端点（完整 URL，必须是 POST 入口）"
    )
    parser.add_argument("--scope", required=True, help="scope 授权文件（YAML）")
    parser.add_argument(
        "--content-type",
        default=xxe.DEFAULT_CONTENT_TYPE,
        help=f"请求体类型（缺省 {xxe.DEFAULT_CONTENT_TYPE}）",
    )
    parser.add_argument(
        "--body-template",
        default=None,
        help="操作员自带的 XML body 模板（作为 file 探针；其余探针由它派生）",
    )
    parser.add_argument(
        "--allow-file",
        action="append",
        default=[],
        metavar="PATH",
        help="显式放行模板里的一个白名单外 file:// 目标（可重复；记 xxe_file_override）",
    )
    parser.add_argument(
        "--out",
        default=None,
        help=f"证据输出目录（缺省 {DEFAULT_OUT_PARENT}/<UTC 时间戳>）",
    )
    parser.add_argument(
        "--callback-host",
        default=None,
        help=(
            "告知目标的回调地址（缺省读 PROOFHOUND_SSRF_CALLBACK_HOST；"
            "绑定地址仍由 PROOFHOUND_SSRF_CALLBACK_BIND 决定）"
        ),
    )
    parser.add_argument(
        "--callback-wait",
        type=float,
        default=xxe.CALLBACK_WAIT_SECONDS,
        help=f"回调宽限窗口秒数（缺省 {xxe.CALLBACK_WAIT_SECONDS}）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=xxe.DEFAULT_TIMEOUT,
        help=f"单请求超时秒数（缺省 {xxe.DEFAULT_TIMEOUT}）",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    scope_path = Path(args.scope)
    if not scope_path.is_file():
        print(f"[!] 找不到 scope 文件: {scope_path}", file=sys.stderr)
        return 2
    try:
        scope = Scope.from_file(scope_path)
    except Exception as exc:  # noqa: BLE001 - 入口错误统一报
        print(f"[!] scope 文件无法加载: {exc}", file=sys.stderr)
        return 2
    if args.body_template is not None and not Path(args.body_template).is_file():
        print(f"[!] 找不到 body 模板: {args.body_template}", file=sys.stderr)
        return 2

    out_dir = Path(args.out) if args.out else DEFAULT_OUT_PARENT / _timestamp()
    config = ProbeConfig(
        url=args.url,
        scope=scope,
        out_dir=out_dir,
        content_type=args.content_type,
        body_template=Path(args.body_template) if args.body_template else None,
        allow_files=tuple(args.allow_file or ()),
        callback_host=args.callback_host,
        callback_wait=max(0.0, args.callback_wait),
        timeout=max(0.1, args.timeout),
    )
    try:
        report = run_xxeprobe(config)
    except XxeProbeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    for line in report.render_lines():
        print(line)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
