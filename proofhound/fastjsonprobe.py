"""CLI：``python -m proofhound.fastjsonprobe``——不安全反序列化（fastjson 系）的手工先验。

```bash
python -m proofhound.fastjsonprobe \\
  --url https://target/Taxi/login.htm \\
  --scope scopes/lab.yaml \\
  [--field json] [--encoding b64] [--content-type application/x-www-form-urlencoded] \\
  [--json-template captured.json] [--json-key logname] \\
  [--tcp-port 0] [--dns-provider dnslog.cn] [--out evidence/fastjson/<ts>] \\
  [--timeout 10] [--dns-wait 20]
```

退出码（交接单 §6）：

- ``0``：至少 1 条 **confirmed**（观察点收到带唯一 token 的回调）；
- ``1``：没有 confirmed（rejected / blocked）；
- ``2``：**结构性失败**——入口错误 / 无 scope / URL 越界 / **所有**观察通道都不可用 /
  模板非法 / 命中禁用项（``$ref``、超大 body）。**这不是"测过且安全"**。

## 一次运行做什么（顺序即纪律）

```
out 目录 + audit.jsonl
  → check_scope（越界即 2，零请求）
  → 起观察点：TCP（缺省）/ DNSLog provider（opt-in）；都不可用即 2
  → 每个 gadget 分配**独立** token（DNS 用 qname、TCP 用独占端口）
  → baseline（主编码）
  → parse-control（主编码；静默才补试另两种 base64 变体）
  → gadget 族（优先级顺序，命中即停，每请求前再 check_scope）
  → gadget-control（**独立 token/端口**、同形态、无 @type）
  → 复测（仅命中时；也是独立 token/端口）
  → 等观察窗口 → 归因（token/端口）→ judge（零 LLM）→ 证据落盘
```

## 为什么对照与复测要独立 token

若对照与探针共用一个 token/端口，"基线或对照触发的迟到连接"与"实体触发的连接"在
观察点里同形，无法区分（M25-a 踩过同样的坑）。故对照/复测各自新分配一套回调落点，
形态（哪个 gadget、什么 URL 形状）与探针一致，**唯一变量是有没有 ``@type``**。

## 证据（交接单 §8）

``probe_<n>.json``（变体/编码/状态码/是否命中/对照结果/sha256）、
``request_<n>.json``（模板名 + 编码后 sha256 + 解码后 JSON，token 只留 sha8）、
``response_<n>.txt``（截断 ≤256KB 且脱敏，**0600**）、``observations.json``、
``judgment.json``、``summary.json``（**不含时间戳/输出路径/端口/token**，连跑两次逐字节
一致）、``summary.md``、``audit.jsonl``。

脱敏两个口子：``SessionConfig.secret_values()`` 与**观察 token**（只以 ``sha256:<hex8>``
形态出现）。token 原文不进任何证据文件、不进 summary、不进 prompt。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope, check_scope
from proofhound.compliance.session import redact_bytes as _session_redact_bytes
from proofhound.compliance.session import secret_marker
from proofhound.verify import fastjson as fj
from proofhound.verify import observe
from proofhound.verify.http_body import MAX_RESPONSE_BYTES, BodyResponse, post
from proofhound.verify.ssrf import resolve_callback_bind, resolve_callback_host

#: 缺省证据目录的父目录（``evidence/`` 不入库）。
DEFAULT_OUT_PARENT = Path("evidence") / "fastjson"

#: TCP 命中后的短宽限（连接通常与请求同步到达；异步目标给 1s）。
TCP_HIT_GRACE = 1.0

#: summary.json 里保留的**稳定事实**（剔除时间戳/输出路径/端口/token）。
_SUMMARY_FACT_KEYS = (
    "parse_control",
    "parse_control_holds",
    "echo_suspect",
    "baseline_refusal",
    "control_hit",
    "all_gadgets_refused",
    "unavailable_channels",
    "ignored_observations",
)

#: 证据脱敏：**任何** token 形态都替换成 sha8（不依赖调用方是否登记过它）。
_TOKEN_IN_TEXT = re.compile(r"(?i)phfj_?([0-9a-f]{32})")
_TOKEN_IN_BYTES = re.compile(rb"(?i)phfj_?([0-9a-f]{32})")


class FastjsonProbeError(RuntimeError):
    """结构性失败（CLI 返回退出码 2，不是"测过且安全"）。"""


@dataclass
class ProbeConfig:
    """一次手工先验的全部输入与上限（CLI 只是它的解析器）。"""

    url: str
    scope: Scope
    out_dir: Path
    field: str = fj.DEFAULT_FIELD
    encoding: str = fj.ENCODING_B64
    content_type: str | None = None
    json_key: str | None = None
    json_template: Path | None = None
    callback_host: str | None = None
    tcp_port: int | None = None
    dns_provider: str | None = None
    dns_api: str | None = None
    dns_wait: float = 20.0
    tcp_wait: float = 2.0
    timeout: float = 10.0
    max_bytes: int = MAX_RESPONSE_BYTES


@dataclass
class ProbeReport:
    """一次运行的结果（CLI 只负责打印与返回退出码）。"""

    judgment: fj.Judgment
    out_dir: Path
    summary: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return 0 if self.judgment.confirmed else 1

    def render_lines(self) -> list[str]:
        judgment = self.judgment
        target = self.summary.get("target", {})
        channels = " + ".join(judgment.channels) if judgment.channels else "-"
        lines = [
            f"[+] 不安全反序列化（fastjson 系）手工先验（M26-a）  {target.get('url', '')}",
            f"    编码: {target.get('encoding', '')}（字段 {target.get('field', '')}）",
            "    探针: "
            + "  ".join(
                f"{item['probe']}={item.get('status')}"
                for item in self.summary.get("probes", [])
            ),
            f"    结论: {judgment.verdict.upper()}"
            + (f"（通道：{channels}）" if judgment.channels else ""),
        ]
        lines.extend(f"      - {reason}" for reason in judgment.reasons)
        lines.append(f"    证据: {self.out_dir}")
        return lines


# --------------------------------------------------------------- 小工具


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - 非 POSIX 文件系统
        pass


def _write_private(path: Path, data: bytes) -> None:
    """写文件并收紧到 0600（响应正文可能含目标内部信息）。"""
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass


def _json_bytes(payload: dict) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _secrets(scope: Scope) -> list[str]:
    return scope.session.secret_values() if scope.session else []


def _error_kind(error: str | None) -> str:
    """错误只留类型（原文常带端口/路径，进 summary 会让两次运行不一致）。"""
    if not error:
        return ""
    return error.split(":", 1)[0].strip()


def redact_tokens_text(text: str) -> str:
    """把文本里任何 token 形态替换成 ``sha256:<hex8>``。"""
    return _TOKEN_IN_TEXT.sub(
        lambda match: secret_marker("phfj_" + match.group(1).lower()), text
    )


def redact_tokens_bytes(data: bytes) -> bytes:
    """字节级 token 脱敏（响应里可能回显 LDAP URL / 主机名）。"""
    return _TOKEN_IN_BYTES.sub(
        lambda match: secret_marker("phfj_" + match.group(1).decode().lower()).encode(
            "utf-8"
        ),
        data,
    )


def redact_text(text: str, secrets: list[str]) -> str:
    """完整脱敏：会话秘密（精确子串）+ 任何 token。"""
    return redact_tokens_text(_replace_secrets(text, secrets))


def redact_body(data: bytes, secrets: list[str]) -> bytes:
    """字节级完整脱敏：会话秘密 + 任何 token。"""
    return redact_tokens_bytes(_session_redact_bytes(data, secrets))


def _replace_secrets(text: str, secrets: list[str]) -> str:
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            text = text.replace(secret, secret_marker(secret))
    return text


# --------------------------------------------------------------- 观察点装配


def _build_provider(
    config: ProbeConfig,
) -> tuple["observe.DnsLogProvider | None", str]:
    """按 CLI/env 造 DNSLog provider；未配置返回 (None, "")，配错返回 (None, 原因)。"""
    env = dict(os.environ)
    if config.dns_provider:
        if config.dns_provider.strip().lower() in ("none", "off", "-"):
            env.pop(observe.ENV_DNS_PROVIDER, None)
        else:
            env[observe.ENV_DNS_PROVIDER] = config.dns_provider
    if config.dns_api:
        env[observe.ENV_DNS_API] = config.dns_api
    try:
        return observe.provider_from_env(env), ""
    except observe.ObserverError as exc:
        return None, str(exc)


def _advertised_host(config: ProbeConfig) -> str:
    return config.callback_host or resolve_callback_host()


def _build_observer(
    config: ProbeConfig, advertised: str
) -> tuple[observe.TcpObserver | None, str]:
    try:
        bind = resolve_callback_bind(advertised)
        base_port = (
            config.tcp_port if config.tcp_port is not None else _default_tcp_port()
        )
        observer = observe.TcpObserver(host=bind, base_port=base_port).start()
    except (observe.ObserverError, OSError, RuntimeError) as exc:
        return None, str(exc)
    return observer, ""


def _default_tcp_port() -> int:
    """TCP 端口基址：复用 SSRF 的 ``PROOFHOUND_SSRF_CALLBACK_PORT``（缺省 0 = 临时端口）。

    **注意**：本工具为每个 TCP 探针**独占**一个端口，故该值只当**基址**用
    （base、base+1、……），不是"唯一端口"。远程靶需要可预期的端口区间时设它。
    """
    from proofhound.verify.ssrf import resolve_callback_port

    try:
        return resolve_callback_port()
    except RuntimeError:
        return 0


def _allocate_callbacks(
    config: ProbeConfig,
    observer: observe.TcpObserver | None,
    provider: "observe.DnsLogProvider | None",
    audit: AuditLog,
) -> tuple[
    dict[str, fj.CallbackPlan],
    dict[str, observe.DnsAllocation],
    bool,
    str,
    str,
]:
    """为每个可用 gadget 分配**独立**回调落点。

    返回 ``(回调表, DNS 分配表, tcp_ok, tcp 不可用原因, dns 不可用原因)``。任一通道
    分配失败即整条通道降级（已分配的回调一并撤销，避免"一半通道"造成的假覆盖）——
    两条通道的原因**分开返回**，否则 DNS 的错会被记到 TCP 头上。
    """
    callbacks: dict[str, fj.CallbackPlan] = {}
    allocations: dict[str, observe.DnsAllocation] = {}
    dns_ok = provider is not None
    tcp_ok = observer is not None
    tcp_reason = ""
    dns_reason = ""

    def _drop_channel(channel: str) -> None:
        for name in [key for key, plan in callbacks.items() if plan.channel == channel]:
            plan = callbacks.pop(name)
            allocations.pop(observe.canonical_token(plan.token) or "", None)

    for gadget in fj.GADGETS:
        token = observe.new_token()
        if gadget.channel == fj.CHANNEL_DNS:
            if not dns_ok or provider is None:
                continue
            try:
                allocation = provider.allocate(token)
            except observe.ObserverError as exc:
                dns_ok = False
                dns_reason = dns_reason or str(exc)
                _drop_channel(fj.CHANNEL_DNS)
                audit.record(
                    "fastjson_observer_unavailable", channel="dns", reason=str(exc)
                )
                continue
            callbacks[gadget.name] = fj.CallbackPlan(
                token=token, channel=gadget.channel, qname=allocation.qname
            )
            allocations[observe.canonical_token(token) or token] = allocation
        else:
            if not tcp_ok or observer is None:
                continue
            try:
                probe = observer.allocate(
                    token,
                    kind="jdbc" if gadget.channel == fj.CHANNEL_TCP_JDBC else "ldap",
                )
            except observe.ObserverError as exc:
                tcp_ok = False
                tcp_reason = tcp_reason or str(exc)
                _drop_channel(fj.CHANNEL_TCP_LDAP)
                _drop_channel(fj.CHANNEL_TCP_JDBC)
                audit.record(
                    "fastjson_observer_unavailable", channel="tcp", reason=str(exc)
                )
                continue
            callbacks[gadget.name] = fj.CallbackPlan(
                token=token,
                channel=gadget.channel,
                host=_advertised_host(config),
                port=probe.port,
            )
    return callbacks, allocations, tcp_ok, tcp_reason, dns_reason


# --------------------------------------------------------------- 发送与归因


@dataclass
class _Attempt:
    """一次已发出的请求（响应字节原样留着，判定只看字节）。"""

    index: int
    spec: fj.ProbeSpec
    encoding: str
    body: bytes
    response: BodyResponse
    hit: bool = False


def _hit_for(
    spec: fj.ProbeSpec,
    observer: observe.TcpObserver | None,
    provider: "observe.DnsLogProvider | None",
) -> bool:
    """快速命中判定：TCP 看端口有没有连接；DNS 看一眼 provider 记录。"""
    if spec.channel == fj.CHANNEL_DNS:
        if provider is None or not spec.token:
            return False
        try:
            return any(item.token for item in provider.poll(spec.token))
        except observe.ObserverError:
            return False
    if observer is None or not spec.port:
        return False
    deadline = time.monotonic() + TCP_HIT_GRACE
    while True:
        if any(item.port == spec.port for item in observer.records()):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _send_spec(
    config: ProbeConfig,
    spec: fj.ProbeSpec,
    *,
    encoding: str,
    index: int,
    audit: AuditLog,
    secrets: list[str],
    out_dir: Path,
) -> _Attempt:
    """发一个探针：安全闸 → check_scope → POST → 证据落盘（不含判定）。"""
    reasons = fj.safety_reasons(spec.json_text)
    if reasons:
        audit.record("fastjson_body_rejected", probe=spec.name, reasons=list(reasons))
        raise FastjsonProbeError(
            f"拒绝发送 {spec.name}：{'；'.join(reasons)}（$ref/膨胀是 DoS，不是本类型）"
        )
    decision = check_scope(config.scope, [config.url])
    if not decision.allowed:
        audit.record(
            "fastjson_scope_rejected", url=config.url, violations=decision.violations
        )
        raise FastjsonProbeError(
            f"URL 不在 scope 授权范围内：{'; '.join(decision.violations)}（零请求）"
        )
    body = fj.encode_body(spec.json_text, encoding=encoding, field=config.field)
    content_type = config.content_type or fj.content_type_for(encoding)
    response = post(
        config.url,
        body,
        content_type=content_type,
        session=config.scope.session,
        timeout=config.timeout,
        max_bytes=config.max_bytes,
    )
    request_sha = sha256(body).hexdigest()
    audit.record(
        "fastjson_probe_attempt",
        variant=spec.name,
        gadget=spec.gadget,
        encoding=encoding,
        status=response.status,
        error=response.error,
        bytes=len(response.body),
        request_sha256=request_sha,
    )
    _write_private(
        out_dir / f"request_{index}.json",
        _json_bytes(
            {
                "index": index,
                "probe": spec.name,
                "encoding": encoding,
                "field": config.field,
                "request_sha256": request_sha,
                "json": redact_text(spec.json_text, secrets),
            }
        ),
    )
    _write_private(out_dir / f"response_{index}.txt", redact_body(response.body, secrets))
    return _Attempt(
        index=index,
        spec=spec,
        encoding=encoding,
        body=body,
        response=response,
    )


def _write_probe_row(out_dir: Path, attempt: _Attempt, *, marker: str) -> dict:
    """``probe_<n>.json``：一行结构化事实（**不含正文**）。"""
    spec = attempt.spec
    response = attempt.response
    body = response.body
    row = {
        "index": attempt.index,
        "probe": spec.name,
        "role": spec.role,
        "gadget": spec.gadget,
        "channel": spec.channel,
        "encoding": attempt.encoding,
        "status": response.status,
        "error": response.error,
        "answered": response.ok,
        "bytes": len(body),
        "truncated": response.truncated,
        "body_sha256": sha256(body).hexdigest() if body else "",
        "request_sha256": sha256(attempt.body).hexdigest(),
        "refused": fj.is_refusal(body),
        "echo_suspect": fj.parse_control_state(body, marker) == "echo_suspect",
        "hit": attempt.hit,
    }
    _write_private(out_dir / f"probe_{attempt.index}.json", _json_bytes(row))
    return row


def _attribute(
    attempts: list[_Attempt], observations: list[observe.Observation]
) -> tuple[dict[str, tuple[observe.Observation, ...]], tuple[observe.Observation, ...]]:
    """观察记录 → 探针名（DNS 按 token、TCP 按独占端口）。"""
    by_port = {item.spec.port: item.spec.name for item in attempts if item.spec.port}
    by_token = {
        observe.canonical_token(item.spec.token or ""): item.spec.name
        for item in attempts
        if item.spec.token
    }
    attributed: dict[str, list[observe.Observation]] = {}
    unmatched: list[observe.Observation] = []
    for observation in observations:
        name = None
        if observation.channel == fj.CHANNEL_DNS:
            name = by_token.get(observe.canonical_token(observation.token or ""))
        else:
            name = by_port.get(observation.port) if observation.port else None
            if name is None:
                name = by_token.get(observe.canonical_token(observation.token or ""))
        if name is None:
            unmatched.append(observation)
        else:
            attributed.setdefault(name, []).append(observation)
    return (
        {name: tuple(items) for name, items in attributed.items()},
        tuple(unmatched),
    )


def _collect_observations(
    config: ProbeConfig,
    attempts: list[_Attempt],
    observer: observe.TcpObserver | None,
    provider: "observe.DnsLogProvider | None",
    allocations: dict[str, observe.DnsAllocation],
    audit: AuditLog,
) -> list[observe.Observation]:
    """收 TCP 记录 + DNS provider 窗口轮询（只为**已发出**的探针等）。"""
    if observer is not None:
        observe.wait_for_tcp(observer, config.tcp_wait)
    records: list[observe.Observation] = list(observer.records()) if observer else []
    sent_tokens = {
        observe.canonical_token(item.spec.token or "")
        for item in attempts
        if item.spec.channel == fj.CHANNEL_DNS
    }
    pending = {
        token: allocation
        for token, allocation in allocations.items()
        if token in sent_tokens
    }
    if provider is not None and pending:
        try:
            records.extend(observe.collect_dns(provider, pending, wait=config.dns_wait))
        except observe.ObserverError as exc:
            audit.record("fastjson_observer_unavailable", channel="dns", reason=str(exc))
    return records


# --------------------------------------------------------------- 主体


def run_fastjsonprobe(config: ProbeConfig) -> ProbeReport:
    """跑一次手工先验（判定零 LLM），返回 :class:`ProbeReport`。

    结构性失败抛 :class:`FastjsonProbeError`（审计已落盘）。
    """
    out_dir = Path(config.out_dir)
    _mkdir_private(out_dir)
    audit = AuditLog(out_dir / "audit.jsonl")
    secrets = _secrets(config.scope)
    marker = fj.new_control_marker()

    audit.record(
        "fastjson_started",
        url=config.url,
        encoding=config.encoding,
        field=config.field,
        json_key=config.json_key,
        json_template=str(config.json_template) if config.json_template else None,
    )

    # 1) 红线 5：发请求前必过 scope（越界 ⇒ 零请求 + 退出码 2）
    decision = check_scope(config.scope, [config.url])
    if not decision.allowed:
        audit.record(
            "fastjson_scope_rejected", url=config.url, violations=decision.violations
        )
        raise FastjsonProbeError(
            f"URL 不在 scope 授权范围内：{'; '.join(decision.violations)}（零请求）"
        )

    # 2) 模板（结构性错误在发请求前就报）
    template_obj: dict | None = None
    json_key = config.json_key or fj.DEFAULT_JSON_KEY
    if config.json_template is not None:
        try:
            template_text = Path(config.json_template).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise FastjsonProbeError(f"JSON 模板不可读：{exc}") from None
        template_obj = fj.parse_json_template(template_text)
        json_key = fj.choose_injection_key(template_obj, config.json_key)
        audit.record("fastjson_template_loaded", json_key=json_key)

    # 3) 观察点（TCP 缺省开；DNS provider opt-in）
    try:
        observed_host = _advertised_host(config)
    except RuntimeError as exc:
        raise FastjsonProbeError(f"回调地址配置非法：{exc}") from None
    observer, tcp_reason = _build_observer(config, observed_host)
    provider, dns_reason = _build_provider(config)
    if observer is None:
        audit.record("fastjson_observer_unavailable", channel="tcp", reason=tcp_reason)
    if provider is None and dns_reason:
        audit.record("fastjson_observer_unavailable", channel="dns", reason=dns_reason)

    (
        callbacks,
        allocations,
        tcp_ok,
        tcp_allocate_reason,
        dns_allocate_reason,
    ) = _allocate_callbacks(config, observer, provider, audit)
    tcp_reason = tcp_reason or tcp_allocate_reason
    dns_reason = dns_reason or dns_allocate_reason
    if not callbacks:
        if observer is not None:
            observer.stop()
        raise FastjsonProbeError(
            "观察点全部不可用（TCP：%s；DNS：%s）——无法建立任何通道，未发出请求"
            % (tcp_reason or "无", dns_reason or "未配置")
        )

    audit.record(
        "fastjson_observer_started",
        tcp=tcp_ok,
        dns=provider is not None and bool(allocations),
        gadgets=sorted(callbacks),
    )

    attempts: list[_Attempt] = []
    try:
        # 4) 计划（baseline → parse-control → gadget 族）
        plan = fj.build_plan(
            callbacks, marker=marker, template=template_obj, json_key=json_key
        )
        baseline_spec, control_spec = plan[0], plan[1]
        gadget_specs = list(plan[2:])

        index = 0
        attempts.append(
            _send_spec(
                config,
                baseline_spec,
                encoding=config.encoding,
                index=index,
                audit=audit,
                secrets=secrets,
                out_dir=out_dir,
            )
        )
        index += 1

        # 5) 阳性对照 + 编码协商（静默才补试另两种 base64 变体）
        control_attempt = _send_spec(
            config,
            control_spec,
            encoding=config.encoding,
            index=index,
            audit=audit,
            secrets=secrets,
            out_dir=out_dir,
        )
        attempts.append(control_attempt)
        index += 1
        attempted_encodings = [config.encoding]
        while True:
            state = fj.parse_control_state(control_attempt.response.body, marker)
            if state in ("held", "echo_suspect"):
                break
            if len(attempted_encodings) >= 3:
                break
            if len(attempts) >= fj.MAX_REQUESTS_PER_ENTRY - 2:
                break
            candidates = [
                item
                for item in fj.alternate_encodings(config.encoding)
                if item not in attempted_encodings
            ]
            if not candidates:
                break
            attempted_encodings.append(candidates[0])
            control_attempt = _send_spec(
                config,
                control_spec,
                encoding=candidates[0],
                index=index,
                audit=audit,
                secrets=secrets,
                out_dir=out_dir,
            )
            attempts.append(control_attempt)
            index += 1
        active_encoding = control_attempt.encoding
        control_state = fj.parse_control_state(control_attempt.response.body, marker)
        audit.record(
            "fastjson_encoding_negotiated",
            attempted=attempted_encodings,
            active=active_encoding,
            parse_control=control_state,
        )

        # 6) gadget 族：只在阳性对照成立后发；命中即停；每请求前再 check_scope
        hit_gadget: str | None = None
        if control_state == "held":
            reserve = 2  # 给"阴性对照 + 复测"各留一个坑位
            for spec in gadget_specs:
                if len(attempts) + 1 + reserve > fj.MAX_REQUESTS_PER_ENTRY:
                    audit.record("fastjson_budget_exhausted", variant=spec.name)
                    break
                attempt = _send_spec(
                    config,
                    spec,
                    encoding=active_encoding,
                    index=index,
                    audit=audit,
                    secrets=secrets,
                    out_dir=out_dir,
                )
                attempts.append(attempt)
                index += 1
                attempt.hit = _hit_for(spec, observer, provider)
                if attempt.hit:
                    hit_gadget = spec.gadget
                    break

        # 7) 阴性对照（与命中的 gadget 同形态；没命中就对照第一个 gadget）
        reference = hit_gadget or (gadget_specs[0].gadget if gadget_specs else None)
        if reference is not None and len(attempts) + 1 <= fj.MAX_REQUESTS_PER_ENTRY:
            control_plan = _fresh_callback(
                config, reference, observer, provider, audit, allocations
            )
            if control_plan is not None:
                negative = fj.control_spec(
                    reference, control_plan, template=template_obj, json_key=json_key
                )
                attempt = _send_spec(
                    config,
                    negative,
                    encoding=active_encoding,
                    index=index,
                    audit=audit,
                    secrets=secrets,
                    out_dir=out_dir,
                )
                attempts.append(attempt)
                index += 1
                attempt.hit = _hit_for(negative, observer, provider)
                if attempt.hit:
                    audit.record("fastjson_control_observed", gadget=reference)

        # 8) 复测（仅命中时；独立回调落点）
        if hit_gadget is not None and len(attempts) + 1 <= fj.MAX_REQUESTS_PER_ENTRY:
            retest_plan = _fresh_callback(
                config, hit_gadget, observer, provider, audit, allocations
            )
            if retest_plan is not None:
                retest = fj.retest_spec(
                    hit_gadget, retest_plan, template=template_obj, json_key=json_key
                )
                attempt = _send_spec(
                    config,
                    retest,
                    encoding=active_encoding,
                    index=index,
                    audit=audit,
                    secrets=secrets,
                    out_dir=out_dir,
                )
                attempts.append(attempt)
                index += 1
                attempt.hit = _hit_for(retest, observer, provider)
                audit.record("fastjson_retest", gadget=hit_gadget, hit=attempt.hit)

        # 9) 等观察窗口并归因
        observations = _collect_observations(
            config, attempts, observer, provider, allocations, audit
        )
        attributed, unmatched = _attribute(attempts, observations)
        for name, items in attributed.items():
            for observation in items:
                audit.record(
                    "fastjson_observation",
                    channel=observation.channel,
                    token_sha8=observe.token_sha8(observation.token),
                    source=observation.source,
                    probe=name,
                )
        for observation in unmatched:
            audit.record(
                "fastjson_observation_ignored",
                channel=observation.channel,
                token_sha8=observe.token_sha8(observation.token),
                source=observation.source,
                reason="unattributed",
            )

        # 10) 判定（零 LLM）
        results = [
            fj.ProbeResult(
                name=attempt.spec.name,
                role=attempt.spec.role,
                gadget=attempt.spec.gadget,
                channel=attempt.spec.channel,
                status=attempt.response.status,
                error=attempt.response.error,
                body=attempt.response.body,
                json_text=attempt.spec.json_text,
            )
            for attempt in attempts
        ]
        channel_states = {
            "tcp": (tcp_ok, tcp_reason),
            "dns": (provider is not None and bool(allocations), dns_reason),
        }
        judgment = fj.judge(
            results=results,
            attributed=attributed,
            unmatched=unmatched,
            channel_states=channel_states,
            marker=marker,
        )
        audit.record(
            "fastjson_judged",
            verdict=judgment.verdict,
            channels=list(judgment.channels),
            requests=len(attempts),
        )

        # 11) 证据落盘（响应已逐条写过；这里写汇总）
        rows = []
        for attempt in attempts:
            attempt.hit = bool(attributed.get(attempt.spec.name))
            rows.append(_write_probe_row(out_dir, attempt, marker=marker))
        _write_observations(out_dir, observations, attributed, unmatched)
        _write_private(
            out_dir / "judgment.json",
            _json_bytes(
                {
                    **judgment.to_dict(),
                    "probes": rows,
                    "channels": {
                        name: {"available": ok, "reason": reason}
                        for name, (ok, reason) in channel_states.items()
                    },
                    "observations": {
                        "dns": [
                            item.to_dict()
                            for item in observations
                            if item.channel == fj.CHANNEL_DNS
                        ],
                        "tcp": [
                            item.to_dict()
                            for item in observations
                            if item.channel != fj.CHANNEL_DNS
                        ],
                    },
                }
            ),
        )
        summary = _build_summary(config, judgment, rows, active_encoding)
        _write_private(out_dir / "summary.json", _json_bytes(summary))
        (out_dir / "summary.md").write_text(
            _render_summary_md(summary, judgment, out_dir), encoding="utf-8"
        )
        audit.record(
            "fastjson_completed",
            verdict=judgment.verdict,
            channels=list(judgment.channels),
            requests=len(attempts),
        )
        return ProbeReport(judgment=judgment, out_dir=out_dir, summary=summary)
    finally:
        if observer is not None:
            observer.stop()
        if provider is not None:
            provider.close()


def _fresh_callback(
    config: ProbeConfig,
    gadget: str,
    observer: observe.TcpObserver | None,
    provider: "observe.DnsLogProvider | None",
    audit: AuditLog,
    allocations: dict[str, observe.DnsAllocation],
) -> fj.CallbackPlan | None:
    """对照/复测用**全新的**回调落点（独立 token/端口 ⇒ 归因不串线）。

    DNS 分配会登记进 ``allocations``——收观察记录时要知道"这些 token 也要等"。
    """
    spec = fj.get_gadget(gadget)
    token = observe.new_token()
    if spec.channel == fj.CHANNEL_DNS:
        if provider is None:
            return None
        try:
            allocation = provider.allocate(token)
        except observe.ObserverError as exc:
            audit.record("fastjson_observer_unavailable", channel="dns", reason=str(exc))
            return None
        allocations[observe.canonical_token(token) or token] = allocation
        return fj.CallbackPlan(token=token, channel=spec.channel, qname=allocation.qname)
    if observer is None:
        return None
    try:
        probe = observer.allocate(
            token, kind="jdbc" if spec.channel == fj.CHANNEL_TCP_JDBC else "ldap"
        )
    except observe.ObserverError as exc:
        audit.record("fastjson_observer_unavailable", channel="tcp", reason=str(exc))
        return None
    return fj.CallbackPlan(
        token=token, channel=spec.channel, host=_advertised_host(config), port=probe.port
    )


def _write_observations(
    out_dir: Path,
    observations: list[observe.Observation],
    attributed: dict[str, tuple[observe.Observation, ...]],
    unmatched: tuple[observe.Observation, ...],
) -> None:
    owner: dict[int, str] = {}
    for name, items in attributed.items():
        for item in items:
            owner[id(item)] = name
    payload = {
        "observations": [
            {
                **item.to_dict(),
                "probe": owner.get(id(item), ""),
                "attributed": id(item) in owner,
            }
            for item in observations
        ],
        "ignored": [item.to_dict() for item in unmatched],
        "counts": {
            "total": len(observations),
            "attributed": len(observations) - len(unmatched),
            "ignored": len(unmatched),
        },
    }
    _write_private(out_dir / "observations.json", _json_bytes(payload))


def _build_summary(
    config: ProbeConfig,
    judgment: fj.Judgment,
    rows: list[dict],
    active_encoding: str,
) -> dict:
    """``summary.json``：**不含时间戳、输出路径、端口与 token** ⇒ 连跑两次逐字节一致。"""
    facts = judgment.facts
    return {
        "tool": "proofhound.fastjsonprobe",
        "milestone": "M26-a",
        "target": {
            "url": config.url,
            "content_type": config.content_type or fj.content_type_for(active_encoding),
            "encoding": active_encoding,
            "field": config.field,
        },
        "probes": [
            {
                "probe": row["probe"],
                "role": row["role"],
                "channel": row["channel"],
                "status": row["status"],
                "error_kind": _error_kind(row["error"]),
                "answered": row["answered"],
                "refused": row["refused"],
                "hit": row["hit"],
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
            "gadgets": len([row for row in rows if row["role"] == fj.ROLE_GADGET]),
        },
    }


def _render_summary_md(summary: dict, judgment: fj.Judgment, out_dir: Path) -> str:
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# 不安全反序列化（fastjson 系）手工先验（M26-a）",
        "",
        f"- 生成时间：{generated_at}",
        f"- 目标：`POST {summary['target']['url']}`（{summary['target']['content_type']}）",
        f"- 编码：`{summary['target']['encoding']}`（表单字段 `{summary['target']['field']}`）",
        f"- 证据目录：`{out_dir}`",
        "",
        "## 探针",
        "",
        "| # | 探针 | 角色 | 通道 | 状态码 | 已响应 | 拒绝语义 | 命中 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for index, probe in enumerate(summary["probes"], start=1):
        lines.append(
            f"| {index} | {probe['probe']} | {probe['role']} | {probe['channel'] or '-'} | "
            f"{probe['status']} | {'是' if probe['answered'] else '否'} | "
            f"{'是' if probe['refused'] else '否'} | {'是' if probe['hit'] else '否'} |"
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
            "- 判定链零 LLM；证据来自观察点（DNS 记录全等 / TCP 端口+源 IP），",
            "  **响应里出现域名、路径、`@type` 字样都不是证据**。",
            "- 观察点只观察、不投递：TCP 回包是写死的常量，绝不返回类字节/referral。",
            "- 未命中只说明「该入口当前对**这组** payload 不成立」——版本、开关、黑名单、",
            "  出站策略四者任一都能造成同样的沉默，**不等于**不存在反序列化风险。",
            "- `response_*.txt` 是 0600 且已脱敏（会话秘密 + 观察 token）。",
            "",
        ]
    )
    return "\n".join(lines)


# --------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proofhound.fastjsonprobe",
        description=(
            "对单个入口做 fastjson 系反序列化的确定性判定："
            "观察点收到带唯一 token 的 DNS 查询 / TCP 连接才算 confirmed"
        ),
    )
    parser.add_argument("--url", required=True, help="目标入口（完整 URL，须是 POST 入口）")
    parser.add_argument("--scope", required=True, help="scope 授权文件（YAML）")
    parser.add_argument(
        "--field", default=fj.DEFAULT_FIELD, help=f"表单字段名（缺省 {fj.DEFAULT_FIELD}）"
    )
    parser.add_argument(
        "--encoding",
        default=fj.ENCODING_B64,
        choices=list(fj.ENCODINGS),
        help="主编码（另两种 base64 变体只在对照静默时补试）",
    )
    parser.add_argument(
        "--content-type",
        default=None,
        help="覆盖请求体类型（缺省由编码决定：表单 / application/json）",
    )
    parser.add_argument(
        "--json-key",
        default=None,
        help=(
            f"把 @type 嵌进哪个业务字段（缺省 {fj.DEFAULT_JSON_KEY}；"
            "有模板时自动选第一个可注入字段）"
        ),
    )
    parser.add_argument(
        "--json-template",
        default=None,
        help="操作员抓到的真实 JSON body（嵌套 @type 的输入来源；其余字段原样保留）",
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
        "--tcp-port",
        type=int,
        default=None,
        help=(
            "TCP 观察端口**基址**（缺省读 PROOFHOUND_SSRF_CALLBACK_PORT，0 = 临时端口）；"
            "每个 TCP 探针独占 base+i"
        ),
    )
    parser.add_argument(
        "--dns-provider",
        default=None,
        choices=[*observe.KNOWN_PROVIDERS, "none"],
        help="DNSLog provider（缺省读 PROOFHOUND_DNSLOG_PROVIDER；none = 显式关闭）",
    )
    parser.add_argument(
        "--dns-api",
        default=None,
        help="provider API 基地址（stub / 自建时用；缺省读 PROOFHOUND_DNSLOG_API）",
    )
    parser.add_argument(
        "--out",
        default=None,
        help=f"证据输出目录（缺省 {DEFAULT_OUT_PARENT}/<UTC 时间戳>）",
    )
    parser.add_argument(
        "--dns-wait",
        type=float,
        default=20.0,
        help="DNS 轮询窗口秒数（provider 记录常有秒级~十几秒延迟）",
    )
    parser.add_argument(
        "--tcp-wait",
        type=float,
        default=2.0,
        help="TCP 观察宽限秒数（连接通常与请求同步到达）",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="单请求超时秒数（缺省 10）"
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
    if args.json_template is not None and not Path(args.json_template).is_file():
        print(f"[!] 找不到 JSON 模板: {args.json_template}", file=sys.stderr)
        return 2

    out_dir = Path(args.out) if args.out else DEFAULT_OUT_PARENT / _timestamp()
    config = ProbeConfig(
        url=args.url,
        scope=scope,
        out_dir=out_dir,
        field=args.field,
        encoding=args.encoding,
        content_type=args.content_type,
        json_key=args.json_key,
        json_template=Path(args.json_template) if args.json_template else None,
        callback_host=args.callback_host,
        tcp_port=args.tcp_port,
        dns_provider=args.dns_provider,
        dns_api=args.dns_api,
        dns_wait=max(0.0, args.dns_wait),
        tcp_wait=max(0.0, args.tcp_wait),
        timeout=max(0.1, args.timeout),
    )
    try:
        report = run_fastjsonprobe(config)
    except FastjsonProbeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    for line in report.render_lines():
        print(line)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
