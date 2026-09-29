"""发布卫生守护测试（M13）：依赖锁与 CI 配置不得腐化。

钉住四件事（都不需要 Docker / 网络，故进无标记的默认门）：

① `requirements.txt`（完整锁）覆盖 `pyproject.toml` 的全部直接依赖，且钉住的版本
   满足 pyproject 的声明区间——两处版本漂移是 M13 之前真实发生过的事
   （uvicorn 0.52.1→0.54.0、playwright 1.62.0→1.63.0），故用测试钉死；
② 锁内不得出现可编辑安装 / VCS / 本地路径引用——否则"可复现安装"是假的；
③ CI workflow 存在、可解析，且单元门用的正是文档声明的测试选择式；
④ CI 的 Python 版本落在 `requires-python` 内（防止一边升 requires-python、
   一边 CI 还在旧解释器上跑）。
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "requirements.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: 文档（README / AGENTS.md）声明的默认门测试选择式，逐字一致
UNIT_SELECTION = 'python -m pytest -m "not docker and not browser" -q'

_LOCK_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[^\s;=]+$")


def _normalize(name: str) -> str:
    """PEP 503 规范化：小写，并把 [-_.] 归并为 '-'。"""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_lock() -> dict[str, str]:
    locked: dict[str, str] = {}
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert _LOCK_LINE.match(line), f"锁行必须是 name==version 形式：{line!r}"
        name, version = line.split("==", 1)
        locked[_normalize(name)] = version
    assert locked, "锁文件为空"
    return locked


def _project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def _direct_requirements() -> list[Requirement]:
    project = _project()
    specs = [*project["dependencies"], *project["optional-dependencies"]["dev"]]
    return [Requirement(spec) for spec in specs]


def _job_runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


# ---- ① 锁与 pyproject 不漂移 ----


def test_lock_covers_every_direct_dependency():
    locked = _parse_lock()
    missing = [
        req.name for req in _direct_requirements() if _normalize(req.name) not in locked
    ]
    assert not missing, f"锁里缺少直接依赖：{missing}"


def test_locked_versions_satisfy_pyproject_specifiers():
    locked = _parse_lock()
    violations = []
    for req in _direct_requirements():
        pinned = locked.get(_normalize(req.name))
        if pinned is None:
            continue  # 上一条测试负责报告缺失
        if req.specifier and Version(pinned) not in req.specifier:
            violations.append(f"{req.name}=={pinned} 不满足 {req.specifier}")
    assert not violations, f"锁与 pyproject 声明冲突：{violations}"


# ---- ② 锁必须是可复现的纯版本钉 ----


def test_lock_has_no_editable_vcs_or_local_references():
    body = LOCK.read_text(encoding="utf-8")
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert not line.startswith("-e"), f"锁内不得有可编辑安装：{line!r}"
        assert "git+" not in line, f"锁内不得有 VCS 引用：{line!r}"
        assert "file:" not in line and " @ " not in line, f"锁内不得有路径引用：{line!r}"


# ---- ③④ CI 配置 ----


def test_ci_workflow_exists_and_is_wellformed():
    assert WORKFLOW.is_file(), "缺 .github/workflows/ci.yml"
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert {"unit", "integration"} <= set(data["jobs"])


def test_ci_jobs_install_from_the_lock():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job_name in ("unit", "integration"):
        runs = _job_runs(data["jobs"][job_name])
        assert "pip install -r requirements.txt" in runs, (
            f"{job_name} job 必须从锁定文件安装（否则可复现性无从谈起）"
        )
        assert "--no-deps" in runs, (
            f"{job_name} job 装完锁后应以 --no-deps 安装本项目，避免解析器二次求解"
        )


def test_ci_unit_gate_uses_documented_selection():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert UNIT_SELECTION in _job_runs(data["jobs"]["unit"])


def test_ci_integration_gate_installs_browser_and_images():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    runs = _job_runs(data["jobs"]["integration"])
    assert "playwright install" in runs, "browser 标记用例需要 Chromium 二进制"
    assert "docker pull" in runs, "docker 标记用例需要预拉沙箱与靶场镜像"
    assert "python -m pytest -q" in runs, "integration 门应跑全量"


def test_ci_python_version_satisfies_requires_python():
    requires = SpecifierSet(_project()["requires-python"])
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    versions = set()
    for job in data["jobs"].values():
        for step in job["steps"]:
            with_block = step.get("with") or {}
            if "python-version" in with_block:
                versions.add(str(with_block["python-version"]))

    assert versions, "CI 未声明 python-version"
    for version in versions:
        assert Version(version) in requires, (
            f"CI 的 Python {version} 不满足 requires-python {requires}"
        )
