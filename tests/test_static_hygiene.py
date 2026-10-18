"""静态卫生守护：生产代码里不得有「只存不读」的局部变量（F841 的最小替代）。

## 为什么有这条（M19-d）

本轮审计在**1310 个测试全绿**的仓库里查出两处真实的死值，而它们都不是无害的：

- `core/orchestrator.py::_verify_cmdi` 的 `dns_value`——DNS 非命中变体的**注入值**
  算完即丢 ⇒ 整道防线从未把载荷投给目标；
- 同文件同函数的 `asset_origin`——同源自检改用别的方式后残留的副本。

两者都属于 `ruff` 的 `F841`（local variable assigned but never used）。本仓库此前
**没有任何静态检查**（`pyproject.toml` 无 ruff/flake8/mypy 配置，CI 只有 pytest），
所以这类缺陷唯一的发现方式就是人工通读。

## 为什么是手写 AST 而不是 ruff

`ruff` 在本机无法安装（PyPI 不可达），而 M13 的纪律是"先本地跑绿再进矩阵"——
把一个本地验证不了的依赖写进 `pyproject` + `requirements.txt` 锁 + CI，只能靠
CI 试错，不可接受。故这里用 stdlib `ast` 覆盖**唯一咬到过人的那一类**；
将来装得上 ruff 时，把本文件替换成 `ruff check --select F` 并保留同样的意图声明。

## 判定规则（保守，宁漏勿滥）

对 `proofhound/**/*.py` 的每个函数作用域：局部名若**只出现在 Store/Del 上下文**、
从未被 Load，即为嫌疑。以下一律**不报**（避免噪声）：
- 形参（`ast.arg`）；
- `_` 开头（惯例上的占位名）；
- 声明了 `nonlocal` / `global` 的名字（闭包赋值，`nonlocal errored` 就是这种）；
- comprehension / lambda 内的同名遮蔽（统一按"该名字在该函数里被读过"处理）。
"""

from __future__ import annotations

import ast
from pathlib import Path

PRODUCTION = Path(__file__).resolve().parent.parent / "proofhound"


class _ScopeScan(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stores: dict[str, int] = {}
        self.loads: set[str] = set()
        self.declared: set[str] = set()  # nonlocal / global

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.stores[node.id] = self.stores.get(node.id, 0) + 1
        else:
            self.loads.add(node.id)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        self.loads.add(node.arg)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.declared.update(node.names)

    def visit_Global(self, node: ast.Global) -> None:
        self.declared.update(node.names)


def _unused_locals(func: ast.AST) -> list[str]:
    scan = _ScopeScan()
    for stmt in func.body:  # 只扫本函数体；嵌套函数各自独立成项
        scan.visit(stmt)
    return sorted(
        name
        for name in scan.stores
        if name not in scan.loads and name not in scan.declared and not name.startswith("_")
    )


def _iter_functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def test_no_unused_local_variables_in_production_code():
    """生产代码不得有只存不读的局部变量（F841 类缺陷的最小守护）。"""
    offenders: list[str] = []
    for path in sorted(PRODUCTION.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for func in _iter_functions(tree):
            for name in _unused_locals(func):
                rel = path.relative_to(PRODUCTION.parent)
                offenders.append(f"{rel}:{func.lineno} {func.name}(): '{name}'")
    assert not offenders, (
        "以下局部变量只被赋值、从未被读取——历史上这类缺陷曾让一道防线整体失效"
        "（`dns_value` 算完即丢）与留下误导性副本（`asset_origin`）：\n  "
        + "\n  ".join(offenders)
    )


def test_guard_itself_detects_a_known_bad_shape():
    """自检：守护必须真的能抓住 `dns_value` 那种形态（否则它是空跑）。"""
    tree = ast.parse(
        "def f(xs):\n"
        "    kept, dropped = split(xs)\n"
        "    return kept\n"
    )
    func = next(_iter_functions(tree))
    assert _unused_locals(func) == ["dropped"]

    # 闭包赋值（nonlocal）不得误报——ssrf/cmdi 的 run_probe 就是这种形态
    tree = ast.parse(
        "def outer():\n"
        "    errored = False\n"
        "    def inner():\n"
        "        nonlocal errored\n"
        "        errored = True\n"
        "    inner()\n"
        "    return errored\n"
    )
    flagged = [n for f in _iter_functions(tree) for n in _unused_locals(f)]
    assert flagged == [], flagged
