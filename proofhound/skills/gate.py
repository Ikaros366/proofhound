"""Skill 导入安全闸（§5.1，必须实现）：对 skill 目录内脚本做静态检查。

扫描 ``*.py``（ast 解析）与 ``*.sh``/``*.bash``（正则），识别危险调用：
网络外联、文件删除、权限提升、动态执行。输出风险清单（RiskReport）供
用户确认流程使用；含高危项的 skill 由 registry 默认禁用，显式确认后才可
启用；``risk_level: L2`` 的 skill 恒标记为每次执行需人工确认（标记层面，
确认交互流程属编排器，M2 后续切片）。

本检查是**提示性**的：降低误报不是目标，漏报方向靠沙箱（只读挂载、
网络出口白名单、配额）兜底。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

CATEGORY_NETWORK = "network"  # 网络外联
CATEGORY_DELETE = "file_delete"  # 文件删除
CATEGORY_PRIVILEGE = "privilege"  # 权限提升
CATEGORY_EXEC = "dynamic_exec"  # 动态执行（信息级）
CATEGORY_PARSE = "parse_error"  # 脚本无法解析（无法审计即风险）

SEVERITY_HIGH = "high"
SEVERITY_INFO = "info"

# Python：危险属性调用（模块.方法），按 (根模块, 属性名) 匹配
_PY_CALL_RULES: list[tuple[str, str, str, str, str]] = [
    # (rule_id, 根模块, 属性, category, 说明)
    ("PY-NET-SOCKET", "socket", "socket", CATEGORY_NETWORK, "socket 原始网络访问"),
    ("PY-NET-URLLIB", "urllib.request", "urlopen", CATEGORY_NETWORK, "urllib 网络外联"),
    ("PY-NET-URLLIB", "urllib.request", "urlretrieve", CATEGORY_NETWORK, "urllib 网络外联"),
    ("PY-DEL-OS", "os", "remove", CATEGORY_DELETE, "os.remove 删除文件"),
    ("PY-DEL-OS", "os", "unlink", CATEGORY_DELETE, "os.unlink 删除文件"),
    ("PY-DEL-OS", "os", "rmdir", CATEGORY_DELETE, "os.rmdir 删除目录"),
    ("PY-DEL-SHUTIL", "shutil", "rmtree", CATEGORY_DELETE, "shutil.rmtree 递归删除"),
    ("PY-PRIV-OS", "os", "setuid", CATEGORY_PRIVILEGE, "os.setuid 权限提升"),
    ("PY-PRIV-OS", "os", "seteuid", CATEGORY_PRIVILEGE, "os.seteuid 权限提升"),
    ("PY-PRIV-OS", "os", "setgid", CATEGORY_PRIVILEGE, "os.setgid 权限提升"),
    ("PY-EXEC-OS", "os", "system", CATEGORY_EXEC, "os.system 执行 shell"),
    ("PY-EXEC-SUBPROCESS", "subprocess", "run", CATEGORY_EXEC, "subprocess 执行外部命令"),
    ("PY-EXEC-SUBPROCESS", "subprocess", "Popen", CATEGORY_EXEC, "subprocess 执行外部命令"),
    ("PY-EXEC-SUBPROCESS", "subprocess", "call", CATEGORY_EXEC, "subprocess 执行外部命令"),
]

# Python：危险导入（模块名前缀匹配）
_PY_IMPORT_RULES: list[tuple[str, str, str, str]] = [
    # (rule_id, 模块前缀, category, 说明)
    ("PY-NET-IMPORT", "socket", CATEGORY_NETWORK, "导入 socket"),
    ("PY-NET-IMPORT", "urllib.request", CATEGORY_NETWORK, "导入 urllib.request"),
    ("PY-NET-IMPORT", "http.client", CATEGORY_NETWORK, "导入 http.client"),
    ("PY-NET-IMPORT", "requests", CATEGORY_NETWORK, "导入 requests"),
    ("PY-NET-IMPORT", "httpx", CATEGORY_NETWORK, "导入 httpx"),
    ("PY-EXEC-IMPORT", "subprocess", CATEGORY_EXEC, "导入 subprocess"),
]

# Python：危险内建函数
_PY_BUILTIN_RULES: list[tuple[str, str, str, str]] = [
    ("PY-EXEC-EVAL", "eval", CATEGORY_EXEC, "eval 动态执行"),
    ("PY-EXEC-EXEC", "exec", CATEGORY_EXEC, "exec 动态执行"),
]

# Shell：危险命令（整行正则）
_SH_RULES: list[tuple[str, re.Pattern, str, str]] = [
    ("SH-NET", re.compile(r"\b(curl|wget|nc|ncat|telnet)\b"), CATEGORY_NETWORK, "网络外联命令"),
    ("SH-DEL", re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|-[a-zA-Z]*f[a-zA-Z]*r)\b"), CATEGORY_DELETE, "rm -r/-rf 递归删除"),
    ("SH-PRIV", re.compile(r"\b(sudo|setcap|doas)\b|\bsu\s+-"), CATEGORY_PRIVILEGE, "权限提升命令"),
    ("SH-PRIV-CHMOD", re.compile(r"\bchmod\s+(-R\s+)?[0-7]*[0-7]7[67]\b|\bchmod\s+(-R\s+)?777\b"), CATEGORY_PRIVILEGE, "chmod 放权"),
    ("SH-EXEC", re.compile(r"\b(eval|bash\s+-c|sh\s+-c)\b"), CATEGORY_EXEC, "动态执行"),
]

_SCRIPT_SUFFIXES_PY = {".py"}
_SCRIPT_SUFFIXES_SH = {".sh", ".bash"}


@dataclass(frozen=True)
class RiskFinding:
    """一条静态检查命中项。"""

    rule_id: str
    category: str
    severity: str
    file: str
    line: int
    detail: str


@dataclass
class RiskReport:
    """一个 skill 目录的风险清单。"""

    skill_dir: str
    findings: list[RiskFinding] = field(default_factory=list)

    @property
    def has_high(self) -> bool:
        return any(f.severity == SEVERITY_HIGH for f in self.findings)


def scan_skill(skill_dir: str | Path) -> RiskReport:
    """静态扫描 skill 目录内全部脚本，输出风险清单。"""
    skill_dir = Path(skill_dir)
    report = RiskReport(skill_dir=str(skill_dir))
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        rel = str(path.relative_to(skill_dir))
        if suffix in _SCRIPT_SUFFIXES_PY:
            report.findings.extend(_scan_python(path, rel))
        elif suffix in _SCRIPT_SUFFIXES_SH:
            report.findings.extend(_scan_shell(path, rel))
    return report


def _scan_python(path: Path, rel: str) -> list[RiskFinding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        return [
            RiskFinding(
                "PY-PARSE-ERROR", CATEGORY_PARSE, SEVERITY_HIGH, rel, 0,
                f"Python 解析失败（无法审计即风险）: {exc}",
            )
        ]
    findings: list[RiskFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                findings.extend(_match_import(alias.name, rel, node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module:
            findings.extend(_match_import(node.module, rel, node.lineno))
        elif isinstance(node, ast.Call):
            findings.extend(_match_call(node, rel))
    return findings


def _match_import(module: str, rel: str, lineno: int) -> list[RiskFinding]:
    return [
        RiskFinding(rule_id, category, _severity_of(category), rel, lineno,
                    f"{detail}: {module}")
        for rule_id, prefix, category, detail in _PY_IMPORT_RULES
        if module == prefix or module.startswith(prefix + ".")
    ]


def _match_call(node: ast.Call, rel: str) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    func = node.func
    if isinstance(func, ast.Name):
        for rule_id, name, category, detail in _PY_BUILTIN_RULES:
            if func.id == name:
                findings.append(
                    RiskFinding(rule_id, category, _severity_of(category),
                                rel, node.lineno, detail)
                )
    elif isinstance(func, ast.Attribute):
        dotted = _dotted_name(func)
        if dotted:
            for rule_id, root, attr, category, detail in _PY_CALL_RULES:
                if dotted == f"{root}.{attr}" or dotted.endswith(f".{root}.{attr}"):
                    findings.append(
                        RiskFinding(rule_id, category, _severity_of(category),
                                    rel, node.lineno, f"{detail}: {dotted}()")
                    )
    return findings


def _dotted_name(node: ast.expr) -> str | None:
    """把 Attribute/Name 链还原为点分路径，如 urllib.request.urlopen。"""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _scan_shell(path: Path, rel: str) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        return [
            RiskFinding(
                "SH-PARSE-ERROR", CATEGORY_PARSE, SEVERITY_HIGH, rel, 0,
                f"Shell 脚本编码异常（无法审计即风险）: {exc}",
            )
        ]
    for lineno, line in enumerate(lines, start=1):
        code = line.split("#", 1)[0]  # 粗略去注释
        for rule_id, pattern, category, detail in _SH_RULES:
            if pattern.search(code):
                findings.append(
                    RiskFinding(rule_id, category, _severity_of(category),
                                rel, lineno, f"{detail}: {line.strip()!r}")
                )
    return findings


def _severity_of(category: str) -> str:
    return SEVERITY_INFO if category == CATEGORY_EXEC else SEVERITY_HIGH
