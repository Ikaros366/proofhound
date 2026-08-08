"""管理面服务层（M6a，§5.9.2）：Skill 与 Scope 文件的管理 CRUD。

- **只读写配置与文本**：零命令构造、零沙箱、零 LLM 调用（红线自查）；
- 写操作 confine：``skills/`` 与 ``scopes/`` 内，resolve 后强制校验；
  演示 workspace 的 ``skills`` 常是指向仓库的符号链接——写端点先把符号
  链接本地化（``_ensure_real_skills_dir``：顶层链接替换为真目录 + 逐
  skill 符号链接），内置 skill 编辑走 **copy-on-edit**（复制实体到
  workspace 再改），绝不顺着符号链接写仓库文件；
- **内置判定**：skill 目录 resolve 后落在 workspace 之外（符号链接逃出）
  → 内置，经 API 只读（DELETE 直接 409，PUT 走 copy-on-edit）；
  ``--workspace .``（workspace 即仓库）时无内外之分，skill 一律按用户
  skill 处理；copy-on-edit 后该 skill 转为 workspace 实体（builtin=false，
  可再编辑/删除，删除即从 registry 消失、仓库内置不再透出）；
- 校验 **all-or-nothing**：全部校验通过前零写入；写入走临时目录/临时
  文件 + rename/os.replace，拒绝即零残留；
- 审计：``skill_imported``/``skill_updated``（含新旧 sha256）/
  ``skill_deleted`` 与 ``scope_created``/``scope_updated``（含新旧
  sha256）/``scope_deleted`` 写 workspace 级 ``management.jsonl``
  （append-only，与 engagement 审计同级纪律）；
- registry 热重载：列表/读取按请求新建 ``SkillRegistry`` 重新 discover；
  engagement 运行时 registry 本就逐次 run 新建（runner.py
  default_phases_factory）——新 skill 无需重启即可被创建任务使用。
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import yaml

from proofhound.api.runner import (
    ApiError,
    InvalidStateError,
    NotFoundError,
)
from proofhound.compliance.audit import AuditLog
from proofhound.compliance.scope import Scope
from proofhound.skills.manifest import SkillManifestError, parse_skill_md
from proofhound.skills.registry import SkillRegistry
from proofhound.tools.build import known_tools

#: skill 上传 zip 大小上限（压缩态）
SKILL_ZIP_MAX_BYTES = 1 * 1024 * 1024
#: zip 解压总量上限（防 zip 炸弹：1 MiB 压缩包的放大兜底）
SKILL_ZIP_EXTRACT_MAX_BYTES = 8 * 1024 * 1024
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
    """workspace 级管理面：skill 库与 scope 文件 CRUD（server.py 的薄壳后端）。"""

    def __init__(self, manager):
        self.workspace_root = manager.workspace_root  # 已 resolve
        self.skills_dir = manager.skills_dir
        self.scopes_dir = manager.scopes_dir
        self.tools_dir = manager.workspace_root / "tools.d"
        self.audit: AuditLog = manager.management_audit

    # ==================== skill 管理 ====================

    def _registry(self) -> SkillRegistry:
        """按请求重解析（热重载）；audit=None：registered 事件不进管理日志。"""
        return SkillRegistry(self.skills_dir).discover()

    def _is_builtin(self, skill_path: Path) -> bool:
        """内置 = resolve 后落在 workspace 之外（符号链接逃出到仓库）。"""
        return not skill_path.resolve().is_relative_to(self.workspace_root)

    def _ensure_real_skills_dir(self) -> None:
        """把符号链接形态的 skills/ 本地化为真目录（写端点前置）。

        顶层符号链接 → 替换为真目录 + 逐 skill 符号链接（内置内容仍可读，
        但任何写入不再顺顶层链接落进仓库）；不存在则创建；真目录 no-op。
        """
        if self.skills_dir.is_symlink():
            target = self.skills_dir.resolve()
            entries = sorted(target.iterdir())
            self.skills_dir.unlink()  # 只删符号链接本身，不触碰目标
            self.skills_dir.mkdir()
            for entry in entries:
                (self.skills_dir / entry.name).symlink_to(entry)
        elif not self.skills_dir.exists():
            self.skills_dir.mkdir(parents=True)

    def _skill_summary(self, skill) -> dict:
        manifest = skill.manifest
        return {
            "name": manifest.name,
            "description": manifest.description,
            "version": manifest.version,
            "risk_level": manifest.risk_level,
            "required_tools": list(manifest.required_tools),
            "missing_tools": [
                t
                for t in manifest.required_tools
                if not (self.tools_dir / t).is_dir()
            ],
            "unknown_tools": [
                t for t in manifest.required_tools if t not in known_tools()
            ],
            "inputs": list(manifest.inputs),
            "outputs": list(manifest.outputs),
            "enabled": skill.enabled,
            "builtin": self._is_builtin(skill.path),
            "sha256": _sha256_file(skill.path / "SKILL.md"),
        }

    def list_skills(self) -> list[dict]:
        registry = self._registry()
        return [
            self._skill_summary(registry.get(item["name"]))
            for item in registry.list()
        ]

    def get_skill(self, name: str) -> dict:
        skill = self._registry().get(name)
        if skill is None:
            raise NotFoundError(f"skill 不存在: {name}")
        summary = self._skill_summary(skill)
        return {
            "name": summary["name"],
            "builtin": summary["builtin"],
            "sha256": summary["sha256"],
            "content": (skill.path / "SKILL.md").read_text(encoding="utf-8"),
        }

    def _validate_skill_md(self, candidate: Path, expect_name: str | None) -> None:
        """全量校验 SKILL.md：frontmatter schema + required_tools ⊆ 构造器注册表
        +（可选）manifest name 与目录名一致。非法抛 ValidationFailedError。"""
        try:
            manifest, _ = parse_skill_md(candidate)
        except (SkillManifestError, OSError) as exc:
            raise ValidationFailedError(f"SKILL.md 校验失败: {exc}") from exc
        unknown = [t for t in manifest.required_tools if t not in known_tools()]
        if unknown:
            raise ValidationFailedError(
                f"required_tools 含未知工具（无命令构造器，注册表: {known_tools()}）: "
                f"{unknown}"
            )
        if expect_name is not None and manifest.name != expect_name:
            raise ValidationFailedError(
                f"manifest name 与目录名不一致: {manifest.name!r} != {expect_name!r}"
            )

    def import_skill_zip(self, body: bytes) -> dict:
        """zip 上传（all-or-nothing）：单顶层目录 + 必含 SKILL.md + 防穿越。"""
        if len(body) > SKILL_ZIP_MAX_BYTES:
            raise ValidationFailedError(
                f"zip 超过大小上限（{len(body)} > {SKILL_ZIP_MAX_BYTES} 字节）"
            )
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
        except zipfile.BadZipFile as exc:
            raise ValidationFailedError(f"非法 zip 文件: {exc}") from exc

        tops: set[str] = set()
        files: list[tuple[PurePosixPath, zipfile.ZipInfo]] = []
        total_size = 0
        for info in zf.infolist():
            name = info.filename
            if "\\" in name:
                raise ValidationFailedError(f"zip 条目含反斜杠（拒绝）: {name!r}")
            rel = PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValidationFailedError(f"zip 条目路径穿越（拒绝）: {name!r}")
            if not rel.parts:
                continue
            tops.add(rel.parts[0])
            if info.is_dir():
                continue
            if len(rel.parts) < 2:
                raise ValidationFailedError(f"zip 根目录不允许直接放文件: {name!r}")
            total_size += info.file_size
            if total_size > SKILL_ZIP_EXTRACT_MAX_BYTES:
                raise ValidationFailedError(
                    f"zip 解压总量超过上限（{SKILL_ZIP_EXTRACT_MAX_BYTES} 字节）"
                )
            files.append((rel, info))
        if len(tops) != 1:
            raise ValidationFailedError(
                f"zip 必须恰好一个顶层目录（实际 {len(tops)} 个）"
            )
        top = next(iter(tops))
        if PurePosixPath(top) / "SKILL.md" not in [rel for rel, _ in files]:
            raise ValidationFailedError(f"zip 缺少 {top}/SKILL.md")

        self._ensure_real_skills_dir()
        staging = Path(tempfile.mkdtemp(prefix=".tmp-upload-", dir=self.skills_dir))
        try:
            for rel, info in files:
                dest = staging.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
            self._validate_skill_md(staging / top / "SKILL.md", expect_name=top)
            dest_dir = self.skills_dir / top
            if dest_dir.exists() or dest_dir.is_symlink():
                raise InvalidStateError(
                    f"skill 已存在（编辑请用 PUT）: {top}"
                )
            (staging / top).rename(dest_dir)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        sha = _sha256_file(dest_dir / "SKILL.md")
        self.audit.record("skill_imported", name=top, sha256=sha, files=len(files))
        return {"name": top, "sha256": sha}

    def update_skill(self, name: str, content: str) -> dict:
        """编辑 SKILL.md 全文（保存即校验）；内置 skill 走 copy-on-edit。"""
        skill = self._registry().get(name)
        if skill is None:
            raise NotFoundError(f"skill 不存在: {name}")
        self._ensure_real_skills_dir()
        # 校验先于任何写（all-or-nothing）
        staging = Path(tempfile.mkdtemp(prefix=".tmp-validate-", dir=self.skills_dir))
        try:
            candidate = staging / "SKILL.md"
            candidate.write_text(content, encoding="utf-8")
            self._validate_skill_md(candidate, expect_name=name)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

        builtin = self._is_builtin(skill.path)
        old_sha = _sha256_file(skill.path / "SKILL.md")
        new_sha = _sha256_bytes(content.encode("utf-8"))
        if builtin:
            # copy-on-edit：复制实体到 workspace skills/ 再改，仓库文件零触碰
            src = skill.path.resolve()
            staging = Path(
                tempfile.mkdtemp(prefix=".tmp-edit-", dir=self.skills_dir)
            )
            try:
                copy = staging / name
                shutil.copytree(src, copy)
                (copy / "SKILL.md").write_text(content, encoding="utf-8")
                link = self.skills_dir / name
                link.unlink()  # 只删符号链接本身
                copy.rename(self.skills_dir / name)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        else:
            target = skill.path / "SKILL.md"
            tmp_file = skill.path / ".SKILL.md.tmp"
            tmp_file.write_text(content, encoding="utf-8")
            os.replace(tmp_file, target)
        self.audit.record(
            "skill_updated",
            name=name,
            old_sha256=old_sha,
            new_sha256=new_sha,
            copied_from_builtin=builtin,
        )
        return {"name": name, "sha256": new_sha, "copied_from_builtin": builtin}

    def delete_skill(self, name: str) -> dict:
        """删除用户 skill；内置 skill 直接 409。"""
        skill = self._registry().get(name)
        if skill is None:
            raise NotFoundError(f"skill 不存在: {name}")
        if self._is_builtin(skill.path):
            raise InvalidStateError(
                f"内置 skill 经 API 只读，禁止删除: {name}（编辑将创建 workspace 副本）"
            )
        sha = _sha256_file(skill.path / "SKILL.md")
        if skill.path.is_symlink():
            # 双保险：不落内置判定的边角（workspace 内手工符号链接）也不顺着删
            raise InvalidStateError(f"skill 目录为符号链接，拒绝删除: {name}")
        shutil.rmtree(skill.path)
        self.audit.record("skill_deleted", name=name, sha256=sha)
        return {"deleted": name}

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
    "SKILL_ZIP_EXTRACT_MAX_BYTES",
    "SKILL_ZIP_MAX_BYTES",
    "ValidationFailedError",
    "validate_scope_text",
]
