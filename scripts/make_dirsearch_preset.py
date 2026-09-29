#!/usr/bin/env python3
"""生成 dirsearch 的**离线预置**到 tools.d/dirsearch/（M16-b）。

用途
----
manifest 的两条配方是 ① ``local``（``./tools.d/dirsearch``）→ ② ``pip``（带闭包）。
本脚本把 ① 那条**离线零下载**的预置目录造出来：wrapper + ``lib/``（本体 + 全依赖
闭包）。造好后安装器在 ``check`` 阶段就能直接探到它，整个运行期不再联网。

为什么要有这个脚本
------------------
``.gitignore`` 把 ``tools.d/*`` 整片排除（属**运行时状态**，与 httpx/katana/sqlmap
三个预置目录同待遇）——24MB 的 Python 依赖闭包**不进公开仓库**。所以离线预置是
"一条命令生成一次、之后永久离线"，而不是随仓库分发。

与 installer 的关系
------------------
默认走 manifest 的 **pip 配方 + 闭包**（同一份钉版哈希，同一套 ``--require-hashes``
纪律）取发行件；因此本脚本**不自己写哈希**——哈希的唯一真相源是
``proofhound/tools/manifests/dirsearch.yaml``。``--wheels DIR`` 可指向已有的
wheelhouse 目录以完全离线重建。

跨平台说明（坑）
----------------
沙箱镜像是 ``python:3.12-alpine``（musllinux），而宿主通常是 glibc：直接
``pip install --target`` **找不到** musllinux wheel（``sys_tags()`` 里没有
musllinux）。故这里也传 ``--platform musllinux_1_2_x86_64 --only-binary=:all:``
交叉选择平台——与 ``installer._install_pip_with_closure`` 的取值保持一致。

用法
----
    .venv/bin/python scripts/make_dirsearch_preset.py            # 走 PyPI 取件
    .venv/bin/python scripts/make_dirsearch_preset.py --wheels DIR   # 离线重建
    .venv/bin/python scripts/make_dirsearch_preset.py --tools-d tools.d
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofhound.tools.manifest import load_manifest  # noqa: E402

MANIFEST = REPO / "proofhound" / "tools" / "manifests" / "dirsearch.yaml"

#: 沙箱镜像 python:3.12-alpine ⇒ musllinux（见模块 docstring 的跨平台说明）
PLATFORM = "musllinux_1_2_x86_64"
PY_VERSION = "3.12"
ABI = "cp312"

#: 白名单文件源（与 installer._PIP_FILE_HOSTS 同源）
PIP_FILE_HOSTS = ("files.pythonhosted.org",)

WRAPPER = """#!/bin/sh
# dirsearch 离线预置 wrapper（由 scripts/make_dirsearch_preset.py 生成）
#
# 三件事：
#   1. PYTHONPATH 指向随目录一起走的依赖闭包（lib/），不依赖宿主机装了什么；
#   2. 直跑 console script 而不 exec 它——其 shebang 指向**构建机**的
#      .venv/bin/python，容器里没有那个解释器（必须由本 wrapper 指定 python3）；
#   3. 把容器内 /tmp 的报告 cat 回 stdout：沙箱 rootfs 只读、/tmp 是 tmpfs
#      **随容器销毁**，不 cat 则报告蒸发，红线 3 的证据就拿不到。
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$HERE/lib${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
rc=0
python3 "$HERE/lib/bin/dirsearch" "$@" || rc=$?
if [ -f /tmp/ds_report.json ]; then cat /tmp/ds_report.json; fi
exit "$rc"
"""


def _download(url: str, dest: Path, attempts: int = 3) -> None:
    """流式下载 + 重试（大 wheel 偶发 ContentTooShort 已实测遇到过一次）。"""
    last: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=180) as resp, \
                    open(dest, "wb") as fh:
                shutil.copyfileobj(resp, fh, length=1 << 16)
            return
        except Exception as exc:  # 网络类错误一律重试
            last = exc
            print(f"      [重试 {i}/{attempts}] {type(exc).__name__}: {exc}")
    raise SystemExit(f"[错误] 下载失败（{attempts} 次）: {url} :: {last}")


def fetch_wheel(package: str, sha256: str, dest_dir: Path) -> Path:
    """按 sha256 从 PyPI 取发行件 wheel（哈希即身份），落到 dest_dir。"""
    name, _, version = package.partition("==")
    meta_url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(meta_url, timeout=60) as resp:
        meta = json.load(resp)
    wanted = sha256.lower()
    for item in meta.get("urls") or []:
        if (item.get("digests") or {}).get("sha256", "").lower() != wanted:
            continue
        filename = item.get("filename") or ""
        if not filename.endswith(".whl"):
            continue
        from urllib.parse import urlparse

        host = (urlparse(item["url"]).hostname or "").lower()
        if host not in PIP_FILE_HOSTS:
            raise SystemExit(f"[错误] 下载源不在白名单内: {host}")
        dest = dest_dir / filename
        if not dest.exists() or hashlib.sha256(dest.read_bytes()).hexdigest() != wanted:
            _download(item["url"], dest)
        got = hashlib.sha256(dest.read_bytes()).hexdigest()
        if got.lower() != wanted:
            raise SystemExit(f"[错误] SHA256 校验失败（{package}）: {got} != {wanted}")
        return dest
    raise SystemExit(f"[错误] PyPI 上找不到 sha256={sha256} 的 wheel（{package}）")


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 dirsearch 离线预置（M16-b）")
    ap.add_argument("--tools-d", default=str(REPO / "tools.d"),
                    help="tools.d 目录（默认仓库根下的 tools.d）")
    ap.add_argument("--wheels", default=None,
                    help="已有的 wheelhouse 目录（提供则完全离线重建）")
    ap.add_argument("--keep-wheels", action="store_true",
                    help="保留临时 wheelhouse 到 --wheels-cache 便于复用")
    args = ap.parse_args()

    manifest = load_manifest(MANIFEST)
    pip_recipe = next(r for r in manifest.install if r.type == "pip")
    if pip_recipe.closure is None:
        raise SystemExit("[错误] manifest 的 pip 配方没有 closure（本脚本需要它）")

    targets = [(pip_recipe.package, pip_recipe.sha256)]
    targets += [(e.package, e.sha256) for e in pip_recipe.closure]
    print(f"[*] manifest {manifest.name}=={manifest.version}："
          f"本体 1 + 闭包 {len(pip_recipe.closure)} = {len(targets)} 个发行件")

    tools_dir = Path(args.tools_d)
    tool_dir = tools_dir / manifest.name
    lib_dir = tool_dir / "lib"

    tmp_ctx = None
    if args.wheels:
        wheelhouse = Path(args.wheels)
        if not wheelhouse.is_dir():
            raise SystemExit(f"[错误] --wheels 目录不存在: {wheelhouse}")
        print(f"[*] 使用已有 wheelhouse: {wheelhouse}")
    else:
        tmp_ctx = tempfile.TemporaryDirectory()
        wheelhouse = Path(tmp_ctx.name)
        print(f"[*] 取件到临时 wheelhouse: {wheelhouse}")

    try:
        missing = []
        for package, sha in targets:
            hit = [p for p in wheelhouse.glob("*.whl")
                   if hashlib.sha256(p.read_bytes()).hexdigest() == sha.lower()]
            if hit:
                print(f"    [已有] {package:<28} {hit[0].name}")
                continue
            if args.wheels:
                missing.append(package)
                print(f"    [缺失] {package}")
                continue
            p = fetch_wheel(package, sha, wheelhouse)
            print(f"    [取回] {package:<28} {p.name}")
        if missing:
            raise SystemExit(f"[错误] wheelhouse 缺少 {len(missing)} 个发行件: {missing}")

        print(f"\n[*] 交叉平台安装（{PLATFORM}，宿主不匹配也照装）...")
        if lib_dir.exists():
            shutil.rmtree(lib_dir)
        lib_dir.mkdir(parents=True)
        specs = [p for p, _ in targets]
        cmd = [
            sys.executable, "-m", "pip", "install",
            "--no-index", f"--find-links={wheelhouse}",
            "--target", str(lib_dir),
            "--platform", PLATFORM,
            "--python-version", PY_VERSION,
            "--implementation", "cp",
            "--abi", ABI,
            "--only-binary=:all:",
            "--no-deps",
            "--upgrade",
            *specs,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout[-3000:])
            print(proc.stderr[-3000:], file=sys.stderr)
            raise SystemExit(f"[错误] pip 安装失败（rc={proc.returncode}）")
        print("    ✅ 安装完成")

        # 清掉宿主侧 import 产生的 __pycache__/*.pyc（不该进预置目录）
        removed = 0
        for pyc in lib_dir.rglob("*.pyc"):
            pyc.unlink()
            removed += 1
        for cache in [d for d in lib_dir.rglob("__pycache__") if d.is_dir()]:
            shutil.rmtree(cache, ignore_errors=True)
        if removed:
            print(f"    [清理] 移除 {removed} 个 .pyc")

        wrapper = tool_dir / manifest.name
        wrapper.write_text(WRAPPER, encoding="utf-8")
        wrapper.chmod(0o755)

        n_files = sum(1 for p in tool_dir.rglob("*") if p.is_file())
        size_mb = sum(p.stat().st_size for p in tool_dir.rglob("*")
                      if p.is_file()) / 1048576
        print(f"\n✅ 离线预置已生成: {tool_dir}")
        print(f"   文件数={n_files}  体积={size_mb:.1f} MiB")
        dicc = lib_dir / "dirsearch" / "db" / "dicc.txt"
        if dicc.is_file():
            words = len([l for l in dicc.read_text().splitlines() if l.strip()])
            print(f"   自带字典 {dicc.relative_to(tool_dir)}："
                  f"{dicc.stat().st_size} bytes / {words} 词")
            print(f"   sha256(dicc.txt) = {hashlib.sha256(dicc.read_bytes()).hexdigest()}")
        print("\n下一步：把内置字典挂到容器 /opt/tools/dicc.txt（或显式传 wordlist），"
              "构造器默认即用 /opt/tools/dicc.txt。")
    finally:
        if tmp_ctx is not None and not args.keep_wheels:
            tmp_ctx.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
