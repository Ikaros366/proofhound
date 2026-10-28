"""CLI：对一条抓到的登录请求做「简单重放暴破」判定（M21-a）。

输入是 Burp / Yakit 复制出来的**原始请求**；输出是证据 JSON + 三态结论。

```bash
python -m proofhound.loginprobe \
    --request login.txt --scope scopes/lab.yaml \
    --user admin --captcha-field code \
    --out evidence/loginprobe
```

退出码：0 = confirmed，1 = rejected，2 = blocked / 入口错误。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proofhound.compliance.scope import Scope, check_scope
from proofhound.verify.login_probe import (
    ProbeConfig,
    ProbeError,
    run_image_probe,
    run_sms_probe,
)
from proofhound.verify.raw_request import (
    RawRequestError,
    field_names,
    parse_raw_request,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proofhound.loginprobe",
        description="登录重放暴破探测（原始请求 → 验证码复用/固定码 → 三态判定）",
    )
    parser.add_argument("--request", required=True, help="原始 HTTP 请求文件（Burp/Yakit 复制）")
    parser.add_argument("--scope", required=True, help="scope 授权文件（YAML），越界直接拒绝")
    parser.add_argument("--user", required=True, help="要打的用户名（测试账号）")
    parser.add_argument("--out", default="evidence/loginprobe", help="证据输出目录")
    parser.add_argument("--user-field", default="username")
    parser.add_argument("--pass-field", default="password")
    parser.add_argument("--captcha-field", default="captcha", help="图形验证码字段；空串=无验证码")
    parser.add_argument("--captcha-image", default=None, help="验证码图片 URL（缺省从登录页自动找）")
    parser.add_argument("--login-page", default=None, help="登录页 URL（缺省用请求 URL 的 GET）")
    parser.add_argument("--attempts", type=int, default=25, help="重放次数（缺省 25，上限 50）")
    parser.add_argument("--scheme", default="https", choices=["http", "https"])
    parser.add_argument("--sms", action="store_true", help="短信验证码分支（只试固定测试码）")
    parser.add_argument("--phone-field", default=None)
    parser.add_argument("--sms-code-field", default=None)
    parser.add_argument("--test-phone", default="18888888888")
    parser.add_argument("--captcha-error-regex", default=None, help="可选：验证码错误文案正则")
    parser.add_argument("--credential-error-regex", default=None, help="可选：凭证错误文案正则")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--list-fields", action="store_true", help="只打印请求里的表单字段并退出")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.request)
    if not path.is_file():
        print(f"[!] 找不到请求文件: {path}", file=sys.stderr)
        return 2
    try:
        request = parse_raw_request(path.read_text(encoding="utf-8"), scheme=args.scheme)
    except RawRequestError as exc:
        print(f"[!] 原始请求解析失败: {exc}", file=sys.stderr)
        return 2

    if args.list_fields:
        print("表单字段:", ", ".join(field_names(request)) or "（无 body）")
        return 0

    try:
        scope = Scope.from_file(args.scope)
    except Exception as exc:  # noqa: BLE001 - 入口错误统一报
        print(f"[!] scope 文件无法加载: {exc}", file=sys.stderr)
        return 2
    decision = check_scope(scope, [request.url])
    if not decision.allowed:
        print(f"[!] 目标未获授权: {decision.violations}", file=sys.stderr)
        return 2

    config = ProbeConfig(
        request=request,
        user=args.user,
        user_field=args.user_field,
        pass_field=args.pass_field,
        captcha_field=args.captcha_field or None,
        captcha_image=args.captcha_image,
        login_page=args.login_page,
        attempts=max(1, min(args.attempts, 50)),
        timeout=args.timeout,
        sms=args.sms,
        phone_field=args.phone_field,
        sms_code_field=args.sms_code_field,
        test_phone=args.test_phone,
        captcha_error_regex=args.captcha_error_regex,
        credential_error_regex=args.credential_error_regex,
    )
    try:
        report = run_sms_probe(config) if args.sms else run_image_probe(config)
    except ProbeError as exc:
        print(f"[!] 探测失败: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    evidence = out / "probe.json"
    evidence.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[*] 模式={report.mode} 目标={report.target}")
    print(f"[*] 结论={report.verdict}")
    for reason in report.reasons:
        print(f"    - {reason}")
    print(f"[*] 证据: {evidence}（{len(report.attempts)} 条尝试）")
    return {"confirmed": 0, "rejected": 1, "blocked": 2}.get(report.verdict, 2)


if __name__ == "__main__":
    raise SystemExit(main())
