"""叙述事实守卫（M6c，§5.7）：叙述对 Finding 状态的表述必须与真实状态一致。

纯确定性代码（正则/词表/计数比对），**零 LLM 参与判断**；本模块只返回
违规描述列表，不抛异常——由 narrative.py 包装为 NarrativeError 走原
"全量拒收零写入 + M6a 修复重试一次"语义。

三道守卫（语料 = overview/remediation 章节 + 各 finding 段落 + reasons_cn）：

1. **F-ID 存在性**：叙述引用的 ``F-YYYY-NNNN`` 必须真实存在（幻觉防护）；
2. **状态词共现**：每个 F-ID 取所在句（句号/分号/换行切分）做状态词共现
   检查——句中出现某类状态词而实际状态不符即违规；无状态词的中性列举
   放行。**否定前缀豁免**：状态词紧邻前缀为否定词（未/不/无/非/未能/
   无法/没有）时该次出现不计入共现（"未确认注入"不是确认表述）；
3. **计数断言**："确认 N 个 / N 个被确认 / 共确认 N" 中的 N 须等于真实
   Confirmed 桶数（误报计数同理对 Rejected 桶）；N 支持阿拉伯数字与
   中文数字一~十；同一命中按 span 去重，否定前缀豁免同样适用。

启发式边界（已知限制）：同句混排多个状态类别会被拒（由 prompt 措辞纪律
+ 修复重试兜底）；计数冷门变体（如"确认为 3"）宁漏勿滥。
"""

from __future__ import annotations

import re

from proofhound.findings.finding import FindingState

#: 叙述中引用的 Finding ID（与 finding._ID_PATTERN 同形，去行锚——出现即引用）
FID_PATTERN = re.compile(r"F-\d{4}-\d{4,}")

#: 句子切分符（句号/分号/换行）
_SENTENCE_SPLIT = re.compile(r"[。；;\n]+")

#: 状态词表：类别名 →（词元组，允许的真实状态集合）；英文词大小写不敏感
STATE_WORDS: tuple[tuple[str, tuple[str, ...], frozenset[FindingState]], ...] = (
    ("确认类", ("确认", "证实", "confirm"), frozenset({FindingState.CONFIRMED})),
    ("误报类", ("误报", "排除", "rejected"), frozenset({FindingState.REJECTED})),
    (
        "假设类",
        ("假设", "待验证", "hypothesis"),
        frozenset({FindingState.SIGNAL, FindingState.HYPOTHESIS}),
    ),
    (
        "有效验证类",
        ("有效验证", "行为复现", "reproduced"),
        frozenset({FindingState.REPRODUCED}),
    ),
)

#: 否定前缀：紧邻这些前缀的状态词出现不计入共现/计数（长前缀优先匹配）
NEGATION_PREFIXES: tuple[str, ...] = ("未能", "无法", "没有", "未", "不", "无", "非")

#: 计数断言的中文数字（一~十单字，规格如此；复合数词不展开）
_CN_NUMERAL: dict[str, int] = {
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}

_NUM = r"([0-9]+|[一二三四五六七八九十])"
_UNIT = r"[个条项]"
#: 动词与数字之间允许的插入（了/的、英文对照小括号，如 确认（confirmed）1 项）
_PAD = r"(?:（[^）]{0,12}）)?\s*(?:了|的)?\s*"

#: 确认计数形态：共确认 N / 确认（了|的|（…））N 个（条|项）/ N 个（条|项）…被确认
_CONFIRM_COUNT_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(rf"共\s*确认\s*(?:了)?\s*{_NUM}"),
    re.compile(rf"确认{_PAD}{_NUM}\s*{_UNIT}"),
    re.compile(rf"{_NUM}\s*{_UNIT}[^。；，,]{{0,8}}?被\s*确认"),
)

#: 误报计数形态：共排除/共判定（为）误报 N（个）/ 误报 N 个（条|项）/ N 个（条|项）…误报
_REJECT_COUNT_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(rf"共\s*(?:排除|判定(?:为)?误报)\s*{_NUM}\s*{_UNIT}?"),
    re.compile(rf"误报(?:（[^）]{{0,12}}）)?\s*{_NUM}\s*{_UNIT}"),
    re.compile(rf"{_NUM}\s*{_UNIT}[^。；，,]{{0,8}}?误报"),
)

#: 计数形态中的状态动词（用于否定前缀定位）
_COUNT_VERBS: tuple[str, ...] = ("确认", "误报", "排除")

_SNIPPET_MAX = 80


def _is_negated(text: str, pos: int) -> bool:
    """``text[:pos]`` 是否以否定前缀结尾（即 pos 处的词被否定修饰）。"""
    head = text[:pos]
    return any(head.endswith(prefix) for prefix in NEGATION_PREFIXES)


def _word_hit(sentence: str, word: str) -> bool:
    """句中存在该词的非否定出现（英文大小写不敏感）。"""
    return any(
        not _is_negated(sentence, match.start())
        for match in re.finditer(re.escape(word), sentence, re.IGNORECASE)
    )


def _sentences(text: str) -> list[str]:
    """按句号/分号/换行切句（丢弃空句）。"""
    return [piece for piece in _SENTENCE_SPLIT.split(text) if piece.strip()]


def _parse_num(token: str) -> int:
    return int(token) if token.isdigit() else _CN_NUMERAL[token]


def _check_counts(
    text: str,
    patterns: tuple[re.Pattern, ...],
    *,
    expected: int,
    label: str,
) -> list[str]:
    """计数断言：每种形态命中独立比对，按 span 去重，否定前缀豁免。"""
    violations: list[str] = []
    seen_spans: set[tuple[int, int]] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            span = match.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)
            phrase = match.group(0)
            # 否定判定定位到动词（确认/误报/排除）；形态以动词开头即检查匹配起点
            verb_offsets = [phrase.find(verb) for verb in _COUNT_VERBS]
            verb_offsets = [offset for offset in verb_offsets if offset >= 0]
            verb_pos = match.start() + (min(verb_offsets) if verb_offsets else 0)
            if _is_negated(text, verb_pos):
                continue
            claimed = _parse_num(match.group(1))
            if claimed != expected:
                violations.append(
                    f"计数断言：「{phrase}」声称 {claimed}，真实 {label} 桶 = {expected}"
                )
    return violations


def check_narrative_facts(
    texts: list[str],
    states: dict[str, FindingState],
    *,
    confirmed_count: int,
    rejected_count: int,
) -> list[str]:
    """对叙述文本跑三道事实守卫，返回违规描述列表（空 = 通过）。

    ``texts``：叙述语料（章节段落、finding 段落、reasons_cn 归因）；
    ``states``：全部 findings 的 id → 真实状态；计数断言给出真实桶数。
    """
    violations: list[str] = []
    for text in texts:
        for sentence in _sentences(text):
            for fid in FID_PATTERN.findall(sentence):
                state = states.get(fid)
                if state is None:
                    violations.append(
                        f"幻觉引用：{fid} 不存在于 findings"
                        f"（句「{sentence[:_SNIPPET_MAX]}」）"
                    )
                    continue
                for label, words, allowed in STATE_WORDS:
                    if state in allowed:
                        continue
                    hit = next(
                        (word for word in words if _word_hit(sentence, word)), None
                    )
                    if hit is not None:
                        violations.append(
                            f"{fid}：句「{sentence[:_SNIPPET_MAX]}」含{label}词"
                            f"「{hit}」，声称与实际状态 {state.value} 不一致"
                        )
        violations.extend(
            _check_counts(
                text, _CONFIRM_COUNT_PATTERNS, expected=confirmed_count, label="Confirmed"
            )
        )
        violations.extend(
            _check_counts(
                text, _REJECT_COUNT_PATTERNS, expected=rejected_count, label="Rejected"
            )
        )
    return violations
