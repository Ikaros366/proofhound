"""verify 模块：L4 验证层（M3b 起）。

M3b：证据门（gate.py，§5.4.2 最低验收标准矩阵）+ Verifier Agent
（verifier.py，§5.4.4 对抗校验，T2 档）。baseline 完整档案、误报库
（§5.4.3/§5.4.5）属后续切片。
"""

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
    "GATE_MATRIX",
    "GateRequirement",
    "GateResult",
    "Verifier",
    "VerifierError",
    "check",
]
