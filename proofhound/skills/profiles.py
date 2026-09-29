"""内置 skill 的风险画像常量表（M9d：单一真相源）。

## 为什么需要它

在 M9d 之前，「某条内置 skill 是 L2 还是 L1、是否只读」这件事有**两个真相源**：
`skills/<name>/SKILL.md` 的 frontmatter，以及各种 Python 里写死的同名事实。两者
必须一致，但**没有任何机制保证**——改一处忘一处就会静默不一致，而这类不一致
恰好落在安全语义上（闸门裁定、是否需人工确认）。

M9d 起：**本表是运行时唯一真相源**，闸门只读这里；`SKILL.md` 的 frontmatter 降级为
人类可读文档。`tests/test_skill_profiles.py` 断言两者对内置 skill 逐条一致——文档
可以读，但**不能与代码矛盾**（不一致即测试失败，而不是静默生效）。

## 为什么常量表而不是每个函数自带

这是 M9c③ 的既有取舍的收敛：风险等级与是否只读是**策略声明**，不是实现细节；
把它们并到一张表里，才能一眼看出"哪些动作会被自动执行、哪些要问人"。
"""

from __future__ import annotations

from typing import NamedTuple


class SkillProfile(NamedTuple):
    """单条内置 skill 的风险画像（闸门输入）。"""

    risk_level: str  # L0 被动 / L1 主动扫描 / L2 利用验证
    mutating: bool  # 是否改变目标状态（M9c③：只读验证可自动，写操作留人工）
    note: str = ""  # 判据说明（为什么是这个等级/是否只读）


#: 内置 skill → 风险画像。**新增内置 skill 必须在此登记**（未登记即 KeyError，
#: fail-closed：不会静默按最宽松处理）。
SKILL_PROFILES: dict[str, SkillProfile] = {
    "web-scan": SkillProfile(
        risk_level="L1",
        mutating=True,
        note="主动扫描：向目标发起真实 HTTP 请求，不改状态但会留下访问痕迹",
    ),
    "recon-crawl": SkillProfile(
        risk_level="L1",
        mutating=True,
        note="爬行：向目标发起大量真实请求（katana 恒在 -cos 排除状态变更类端点）",
    ),
    "verify-sqli": SkillProfile(
        risk_level="L2",
        mutating=False,
        note="只读验证：sqlmap 固定 --batch，构造器硬禁 risk>2 的 OR 型注入与任何写操作",
    ),
    "verify-xss": SkillProfile(
        risk_level="L2",
        mutating=False,
        note="只读验证：浏览器仅加载 payload 页面做 canary 探测，不提交状态变更",
    ),
    "verify-idor": SkillProfile(
        risk_level="L2",
        mutating=False,
        note="只读验证：双会话各发一次 GET 做属性对比，无写操作",
    ),
    "verify-ssrf": SkillProfile(
        risk_level="L2",
        mutating=False,
        note=(
            "只读验证：只发只读 GET 探测（替换一个 query 参数取值），不提交表单、"
            "不改目标状态；确认靠宿主 listener 收到回调（带外二值事实）"
        ),
    ),
}


class UnknownSkillProfileError(KeyError):
    """查询未登记的内置 skill 风险画像（fail-closed）。"""


def profile_for(skill_name: str) -> SkillProfile:
    """取内置 skill 的风险画像；未登记即抛（fail-closed，绝不返回默认值）。"""
    try:
        return SKILL_PROFILES[skill_name]
    except KeyError:
        raise UnknownSkillProfileError(
            f"内置 skill {skill_name!r} 未在 proofhound/skills/profiles.py 登记风险画像；"
            "新增内置 skill 必须在此显式声明 risk_level 与 mutating"
        ) from None


__all__ = [
    "SKILL_PROFILES",
    "SkillProfile",
    "UnknownSkillProfileError",
    "profile_for",
]