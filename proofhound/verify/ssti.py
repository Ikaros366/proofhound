"""SSTI（服务端模板注入）的**差分求值**判据（M22，§7.25）。

## 这个模块要回答的**二值事实**

「服务端把这个参数当**模板**求值了」——判据不是"页面里出现了报错/特殊字符"，
而是**两个不同的乘法表达式都算出了正确乘积**，且基线响应里没有这两个数字。
这条事实与模板引擎的类型无关（Jinja2 / Twig / Django / EL / FreeMarker / ERB /
EJS 都成立），也与身份无关（故 `VULN_REGISTRY` 里 `requires_session=False`）。

## 三道对照（缺一不可）

1. **基线**：``finding.asset`` 原样响应不含探针乘积 —— 没有它就是"数字巧合"，
   不是求值；
2. **两个乘积**：同一语法下换操作数，**两个**乘积都要出现 —— 只中一个说明不了
   求值（可能是静态文本、也可能是取值被拼接）；
3. **畸形模板对照**：少一个右括号的探针**不得**算出乘积 —— 它挡的正是
   「strip 掉非数字后照样算乘法」这类端点：三个探针全中，但**判不了**
   （只能 blocked），因为"少一个括号也能算"证明不了"是模板引擎算的"。

## 与其它类型的关系

判据形态是「同一 URL 换取值，看两处响应里的确定性产物」，与 sqli 的布尔/时间
差分**同构但不同源**：SSTI 的产物是**模板引擎算出来的值**，不需要错误回显、
不需要时间差异、不需要数据库。故 method（:data:`SSTI_CONFIRMED_METHOD`）与
具名证据标签（:data:`SSTI_EVALUATION_EVIDENCE_KIND`）都与其余六类**互不染指**
（``tests/test_ssrf.py`` / ``tests/test_cmdi.py`` 的全矩阵断言）。

## 本模块的边界（诚实记录）

- 只看**响应里有没有乘积**：不做模板指纹识别、不产可用 RCE 载荷、不读文件、
  不反弹 shell —— 探针固定、无副作用、只 GET；
- **不覆盖盲注**（求值结果不回显到响应里的 SSTI）——那需要另外的带外观测手段；
- 乘积匹配用**数字边界**（前后不得紧邻数字），否则 ``136481`` 会假命中；
  被截断到只剩部分数字时匹配不上（宁漏勿滥的保守方向）。

## 落点进度

M22-a（第一步，只放开候选）落了**两个常量**：登记表
（``verify/gate.py::VULN_REGISTRY``）在登记时就要求 method 名与证据标签名，
故常量必须先于登记存在，不能等到第二步。差分求值的纯函数
（``match_products`` / ``judge`` / ``summary_for_verifier``）由 M22-b 补齐。
"""

from __future__ import annotations

#: 唯一认可确认手段（``verification.method`` 白名单成员）。
#: 与其余六类互不染指（全矩阵断言见 ``tests/test_ssrf.py`` / ``tests/test_cmdi.py``）。
SSTI_CONFIRMED_METHOD = "template-eval-confirmed"

#: 具名行为类证据标签（``evidence_kinds``）。刻意**不用**笼统的 ``behavioral``：
#: 让"这条 Confirmed 靠的是模板求值产物"在证据层可分辨（同 ``unauth-exposure`` 的
#: ``unauth-response-equivalence`` 先例）。铁律 2 只要求"存在任一非 status-code
#: 标签"，具名标签同样满足。
SSTI_EVALUATION_EVIDENCE_KIND = "template-evaluation"

__all__ = [
    "SSTI_CONFIRMED_METHOD",
    "SSTI_EVALUATION_EVIDENCE_KIND",
]
