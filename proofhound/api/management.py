"""管理面服务层（M6a，§5.9.2）：Scope 文件的管理 CRUD。

> **M9d 移除 Skill 管理面**：本系统不开放用户自写 skill（skill 库全部内置、
> 随仓库交付），故 zip 上传 / SKILL.md 编辑 / 删除 / copy-on-edit / 符号链接
> 本地化这一整套端点失去使用场景，与「导入安全闸」一并删除。skill 现在只随
> 仓库发布，改内置 skill 就是改仓库文件（走正常代码评审）。

- **只读写配置与文本**：零命令构造、零沙箱、零 LLM 调用（红线自查）；
- 写操作 confine：``scopes/`` 内，resolve 后强制校验；
- 校验 **all-or-nothing**：全部校验通过前零写入；写入走临时文件 +
  os.replace，拒绝即零残留；
- 审计：``scope_created``/``scope_updated``（含新旧 sha256）/
  ``scope_deleted`` 写 workspace 级 ``management.jsonl``
  （append-only，与 engagement 审计同级纪律）。
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from pathlib import Path

import yaml

from proofhound.api.runner import (
    ApiError,
    InvalidStateError,
    NotFoundError,
)
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope

#: scope 文件名白名单
SCOPE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\.ya?ml$")
#: scope 允许的顶层键（session 凭据只走创建任务 cookie 入口，不进管理面——
#: 防止凭据经 scope 文件落盘并被 GET 全文端点回显）
SCOPE_ALLOWED_KEYS = frozenset({"domains", "networks", "ports"})


class ValidationFailedError(ApiError):
    """管理面校验失败：message 携带完整校验明细（控制台原样展示）。"""

    status_code = 422
    error_code = "validation_failed"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def validate_scope_text(text: str) -> dict:
    """校验 scope YAML 全文，返回规范化 dict；任何非法抛 ValidationFailedError。

    规则：YAML 可解析且为映射；键集合 ⊆ {domains, networks, ports}（session
    显式拒绝、未知键拒绝——授权书不容忍静默吞 typo）；networks 逐条
    CIDR（ipaddress 校验）；ports 逐条 1-65535 整数；最后过一遍
    Scope.model_validate 与运行时模型锁步。
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationFailedError(f"scope YAML 解析失败: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValidationFailedError(
            "scope 文件必须是 YAML 映射（允许键: domains/networks/ports）"
        )
    unknown = sorted(set(data) - SCOPE_ALLOWED_KEYS)
    if unknown:
        note = (
            "（session 凭据只走创建任务的 cookie 入口，不进 scope 管理面）"
            if "session" in unknown
            else ""
        )
        raise ValidationFailedError(f"scope 含不允许的键 {unknown}{note}")
    domains = data.get("domains") or []
    if not isinstance(domains, list) or any(
        not isinstance(d, str) or not d.strip() for d in domains
    ):
        raise ValidationFailedError("domains 必须是非空字符串列表")
    networks = data.get("networks") or []
    if not isinstance(networks, list):
        raise ValidationFailedError("networks 必须是 CIDR 字符串列表")
    for item in networks:
        if not isinstance(item, str):
            raise ValidationFailedError(f"networks 含非字符串条目: {item!r}")
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValidationFailedError(f"networks 含非法 CIDR: {item!r}（{exc}）") from exc
    ports = data.get("ports") or []
    if not isinstance(ports, list):
        raise ValidationFailedError("ports 必须是 1-65535 整数列表")
    for item in ports:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ValidationFailedError(
                f"ports 含非法端口: {item!r}（须 1-65535 整数）"
            )
    Scope.model_validate({"domains": domains, "networks": networks, "ports": ports})
    return {"domains": domains, "networks": networks, "ports": ports}


class ManagementService:
    """workspace 级管理面：scope 文件 CRUD（server.py 的薄壳后端）。"""

    def __init__(self, manager):
        self.workspace_root = manager.workspace_root  # 已 resolve
        self.scopes_dir = manager.scopes_dir
        self.tools_dir = manager.workspace_root / "tools.d"
        self.audit: AuditLog = manager.management_audit

    # ==================== scope 管理 ====================

    def _scope_path(self, name: str) -> Path:
        """文件名白名单 + resolve 后必须在 scopes/ 内（双保险，fail-closed）。"""
        if not SCOPE_NAME_RE.match(name):
            raise ValidationFailedError(
                f"scope 文件名非法（须匹配 {SCOPE_NAME_RE.pattern}）: {name!r}"
            )
        candidate = (self.scopes_dir / name).resolve()
        if not candidate.is_relative_to(self.scopes_dir.resolve()):
            raise ValidationFailedError(f"scope 路径越出 scopes/: {name!r}")
        return candidate

    def list_scopes(self) -> list[dict]:
        items: list[dict] = []
        if not self.scopes_dir.is_dir():
            return items
        for path in sorted(self.scopes_dir.iterdir()):
            if not path.is_file() or not SCOPE_NAME_RE.match(path.name):
                continue
            sha = _sha256_file(path)
            try:
                data = validate_scope_text(path.read_text(encoding="utf-8"))
            except ValidationFailedError as exc:
                # 盘上损坏文件不拖垮列表：标红展示
                items.append(
                    {
                        "name": path.name,
                        "valid": False,
                        "sha256": sha,
                        "error": str(exc),
                    }
                )
                continue
            items.append({"name": path.name, "valid": True, "sha256": sha, **data})
        return items

    def get_scope(self, name: str) -> dict:
        path = self._scope_path(name)
        if not path.is_file():
            raise NotFoundError(f"scope 不存在: {name}")
        return {
            "name": name,
            "sha256": _sha256_file(path),
            "content": path.read_text(encoding="utf-8"),
        }

    def create_scope(self, name: str, content: str) -> dict:
        path = self._scope_path(name)
        validate_scope_text(content)  # 校验先于任何写
        if path.exists():
            raise InvalidStateError(f"scope 已存在（编辑请用 PUT）: {name}")
        self.scopes_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        sha = _sha256_file(path)
        self.audit.record("scope_created", name=name, sha256=sha)
        return {"name": name, "sha256": sha}

    def update_scope(self, name: str, content: str) -> dict:
        path = self._scope_path(name)
        if not path.is_file():
            raise NotFoundError(f"scope 不存在: {name}")
        validate_scope_text(content)
        old_sha = _sha256_file(path)
        tmp_file = path.with_name(path.name + ".tmp")
        tmp_file.write_text(content, encoding="utf-8")
        os.replace(tmp_file, path)
        new_sha = _sha256_file(path)
        self.audit.record(
            "scope_updated", name=name, old_sha256=old_sha, new_sha256=new_sha
        )
        return {"name": name, "sha256": new_sha}

    def delete_scope(self, name: str) -> dict:
        path = self._scope_path(name)
        if not path.is_file():
            raise NotFoundError(f"scope 不存在: {name}")
        sha = _sha256_file(path)
        path.unlink()
        self.audit.record("scope_deleted", name=name, sha256=sha)
        return {"deleted": name}


__all__ = [
    "ManagementService",
    "SCOPE_NAME_RE",
    "ValidationFailedError",
    "validate_scope_text",
]
