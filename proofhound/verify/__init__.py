"""verify 模块：L4 验证层（M3b 起）。

M3b：证据门（gate.py，§5.4.2 最低验收标准矩阵）+ Verifier Agent
（verifier.py，§5.4.4 对抗校验，T2 档）。M6b：CVSS v3.1 计算器
（cvss.py，LLM 只产向量、分数由代码确定性计算）。baseline 完整档案、
误报库（§5.4.3/§5.4.5）属后续切片。
"""

from proofhound.verify.cvss import (
    CVSSVectorError,
    base_score,
    parse_vector,
    severity_for_score,
)
from proofhound.verify.gate import (
    BEHAVIORAL_EVIDENCE_KIND,
    GATE_MATRIX,
    GateRequirement,
    GateResult,
    check,
)
from proofhound.verify.verifier import Verifier, VerifierError

__all__ = [
    "BEHAVIORAL_EVIDENCE_KIND",
    "CVSSVectorError",
    "GATE_MATRIX",
    "GateRequirement",
    "GateResult",
    "Verifier",
    "VerifierError",
    "base_score",
    "check",
    "parse_vector",
    "severity_for_score",
]
