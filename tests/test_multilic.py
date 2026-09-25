"""多许可证候选（OR）判定的轻量自测（无测试框架依赖）：python -m tests.test_multilic

覆盖：
* 原生 manifest 的 ``license`` 与 CycloneDX 并列条目均可识别为候选；
* 含 AND / 括号 / 未知标识的表达式仍按未知处理；
* 祖先与依赖各有候选时，对候选组合逐一调用兼容矩阵：
  全部冲突 -> 硬冲突；全部兼容 -> 通过（无条目）；其余 -> 需人工确认；
* 冲突/告警条目携带各组合判定与原最短路径；
* 单许可证结果与原有语义完全一致。
"""

from __future__ import annotations

from app import analyzer, licenses


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _manifest(ancestor_license, dep_license):
    return {
        "name": "t",
        "packages": [
            {"name": "app", "version": "1", "license": ancestor_license,
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": dep_license},
        ],
    }


def _find(result, ancestor="app@1", node="lib@1"):
    hits = [c for c in result["conflicts"] if c["ancestor"] == ancestor and c["node"] == node]
    return hits[0] if hits else None


# --- 表达式解析 ---------------------------------------------------------------


def test_parse_or_candidates() -> None:
    cases = licenses.parse_or_candidates
    _check(
        "MIT OR GPL-2.0 -> 2 candidates",
        [c["token"] for c in cases("MIT OR GPL-2.0")] == ["MIT", "GPL-2.0"],
    )
    _check(
        "case-insensitive or / aliases normalized",
        [c["token"] for c in cases("mit or Apache 2.0")] == ["MIT", "Apache-2.0"],
        str(cases("mit or Apache 2.0")),
    )
    _check("single license -> None", cases("MIT") is None)
    _check("AND expression -> None", cases("MIT AND GPL-2.0") is None)
    _check("parenthesized expression -> None", cases("(MIT OR GPL-2.0)") is None)
    _check("unknown operand -> None", cases("MIT OR OFL-1.1") is None)
    _check("dangling OR -> None", cases("MIT OR") is None)
    _check("empty -> None", cases("") is None and cases(None) is None)
    _check(
        "duplicates deduped in order",
        [c["token"] for c in cases("MIT OR Apache-2.0 OR mit")] == ["MIT", "Apache-2.0"],
        str(cases("MIT OR Apache-2.0 OR mit")),
    )


def test_or_token_is_order_independent() -> None:
    # 规范 token（指纹/对比用）按标识排序，与 OR 顺序无关；展示保留原文顺序
    a = licenses.license_info("MIT OR GPL-2.0")
    b = licenses.license_info("GPL-2.0 OR MIT")
    _check("canonical token order-independent", a["token"] == b["token"] == "GPL-2.0 OR MIT")
    _check(
        "display keeps original order",
        a["display"] == "MIT OR GPL-2.0" and b["display"] == "GPL-2.0 OR MIT",
    )
    _check(
        "combination list keeps original order",
        [c["token"] for c in a["license_candidates"]] == ["MIT", "GPL-2.0"]
        and [c["token"] for c in b["license_candidates"]] == ["GPL-2.0", "MIT"],
    )


# --- 全部冲突 -> 硬冲突 --------------------------------------------------------


def test_all_combinations_conflict_is_error() -> None:
    # GPL-2.0 / GPL-3.0 作为祖先候选，依赖 Apache-2.0 / MPL-2.0：
    # GPL-2.0->Apache-2.0 conflict, GPL-2.0->MPL-2.0 conflict,
    # GPL-3.0->Apache-2.0 ok(!), GPL-3.0->MPL-2.0 ok -> 混合，应为告警。
    # 这里构造真正“全部冲突”的组合：祖先 {GPL-2.0} 固定冲突 Apache-2.0，
    # 祖先 {GPL-2.0, AGPL-3.0} 对依赖 {Apache-2.0}：
    # GPL-2.0->Apache conflict；AGPL-3.0->Apache ok => 仍混合。
    # 选取：祖先 {GPL-2.0, LGPL-2.1} 对依赖 {MPL-2.0, GPL-3.0}：
    # GPL-2.0->MPL conflict, GPL-2.0->GPL-3.0 conflict,
    # LGPL-2.1->MPL conflict, LGPL-2.1->GPL-3.0 conflict => 全部冲突。
    result = analyzer.analyze_manifest(
        _manifest("GPL-2.0 OR LGPL-2.1", "MPL-2.0 OR GPL-3.0")
    )
    conflict = _find(result)
    _check("all-conflict produces entry", conflict is not None, str(result["conflicts"]))
    _check("all-conflict severity error", conflict["severity"] == "error", conflict["reason"])
    _check("multi_license flag set", conflict.get("multi_license") is True)
    _check("4 combinations evaluated", len(conflict["combinations"]) == 4,
           str(conflict["combinations"]))
    _check(
        "every combination is conflict",
        all(cmb["status"] == licenses.CONFLICT for cmb in conflict["combinations"]),
    )
    _check(
        "candidate token lists recorded",
        conflict["ancestor_license_candidates"] == ["GPL-2.0", "LGPL-2.1"]
        and conflict["node_license_candidates"] == ["MPL-2.0", "GPL-3.0"],
        str(conflict),
    )
    _check(
        "each combination carries original shortest path",
        all(cmb["path"] == ["app@1", "lib@1"] and cmb["distance"] == 1
            for cmb in conflict["combinations"]),
        str(conflict["combinations"]),
    )
    _check("summary counts 1 hard conflict", result["summary"]["conflicts"] == 1)


# --- 全部兼容 -> 通过（无条目） -------------------------------------------------


def test_all_combinations_ok_is_clean() -> None:
    # 祖先 MIT/Apache-2.0（宽松），依赖 MIT/ISC/BSD-3-Clause：全部 ok，
    # 唯一需注意 MIT->? 专有才告警，这里没有专有。
    result = analyzer.analyze_manifest(
        _manifest("MIT OR Apache-2.0", "ISC OR BSD-3-Clause")
    )
    _check("no conflict entry", _find(result) is None, str(result["conflicts"]))
    _check("status clean", result["status"] == "clean", result["status"])
    app_node = next(n for n in result["nodes"] if n["id"] == "app@1")
    _check(
        "ancestor node marked multi-license",
        app_node["license_category"] == "multi-license"
        # 规范 token 与 OR 顺序无关（按标识排序）
        and app_node["license"] == "Apache-2.0 OR MIT"
        and app_node["license_display"] == "MIT OR Apache-2.0",
        str(app_node),
    )


# --- 混合 -> 需人工确认 ---------------------------------------------------------


def test_mixed_combinations_is_warning() -> None:
    # 祖先 GPL-2.0 OR GPL-3.0，依赖 Apache-2.0：
    # GPL-2.0->Apache conflict；GPL-3.0->Apache ok => 混合 -> 告警。
    result = analyzer.analyze_manifest(_manifest("GPL-2.0 OR GPL-3.0", "Apache-2.0"))
    conflict = _find(result)
    _check("mixed produces entry", conflict is not None)
    _check("mixed severity warning", conflict["severity"] == "warning", conflict["reason"])
    statuses = {cmb["status"] for cmb in conflict["combinations"]}
    _check(
        "combination statuses include conflict and ok",
        statuses == {licenses.CONFLICT, licenses.OK},
        str(statuses),
    )
    by_pair = {(cmb["ancestor_token"], cmb["node_token"]): cmb["status"]
               for cmb in conflict["combinations"]}
    _check(
        "matrix reused per combination",
        by_pair[("GPL-2.0", "Apache-2.0")] == licenses.CONFLICT
        and by_pair[("GPL-3.0", "Apache-2.0")] == licenses.OK,
        str(by_pair),
    )
    _check(
        "reason enumerates counts",
        "2 种组合" in conflict["reason"] and "1 种兼容" in conflict["reason"]
        and "1 种冲突" in conflict["reason"],
        conflict["reason"],
    )
    _check("summary counts warning, not conflict",
           result["summary"]["conflicts"] == 0
           and result["summary"]["license_warnings"] == 1)
    _check("overall status warning", result["status"] == "warning", result["status"])


def test_mixed_with_matrix_warning_is_warning() -> None:
    # 祖先单许可证 MIT，依赖 MIT OR Proprietary：
    # MIT->MIT ok；MIT->Proprietary warning => 聚合 warning（需人工确认）。
    result = analyzer.analyze_manifest(_manifest("MIT", "MIT OR Proprietary"))
    conflict = _find(result)
    _check("single-side candidates still evaluated", conflict is not None)
    _check("aggregates to warning", conflict["severity"] == "warning", conflict["reason"])
    _check("2 combinations", len(conflict["combinations"]) == 2)


# --- 未知表达式仍按未知处理 ------------------------------------------------------


def test_unknown_expressions_stay_unknown() -> None:
    for expression in ("MIT AND GPL-2.0", "(MIT OR GPL-2.0)", "MIT OR OFL-1.1",
                       "Apache-2.0 WITH LLVM-exception"):
        result = analyzer.analyze_manifest(_manifest("MIT", expression))
        node = next(n for n in result["nodes"] if n["id"] == "lib@1")
        _check("%r unknown" % expression, node["license_known"] is False
               and node["license_candidates"] is None, str(node))
        conflict = _find(result)
        _check("%r yields unknown warning" % expression,
               conflict is not None and conflict["severity"] == "warning",
               str(conflict))
        _check("%r not treated as multi" % expression,
               conflict is not None and not conflict.get("multi_license"))


# --- CycloneDX 并列条目 + 传递路径 ----------------------------------------------


def test_cyclonedx_parallel_and_transitive_path() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "a", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "GPL-2.0"}}, {"license": {"id": "GPL-3.0"}}]},
            {"bom-ref": "m", "name": "mid", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"bom-ref": "l", "name": "leaf", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [
            {"ref": "a", "dependsOn": ["m"]},
            {"ref": "m", "dependsOn": ["l"]},
        ],
    }
    result = analyzer.analyze_manifest(bom)
    app = next(n for n in result["nodes"] if n["id"] == "app@1")
    _check(
        "cyclonedx parallel ids are candidates",
        [c["token"] for c in app["license_candidates"]] == ["GPL-2.0", "GPL-3.0"],
        str(app),
    )
    # app -> leaf（经 mid，2 跳）：GPL-2.0->Apache conflict / GPL-3.0->Apache ok
    conflict = _find(result, ancestor="app@1", node="leaf@1")
    _check("transitive multi entry exists", conflict is not None, str(result["conflicts"]))
    _check("transitive severity warning", conflict["severity"] == "warning")
    _check(
        "combinations carry the original shortest path via mid",
        all(cmb["path"] == ["app@1", "mid@1", "leaf@1"] and cmb["distance"] == 2
            for cmb in conflict["combinations"]),
        str(conflict["combinations"]),
    )
    _check(
        "top-level path remains shortest",
        conflict["path"] == ["app@1", "mid@1", "leaf@1"] and conflict["distance"] == 2,
        str(conflict["path"]),
    )


# --- 单许可证语义保持 ------------------------------------------------------------


def test_single_license_unchanged() -> None:
    # GPL-2.0 父 -> Apache-2.0 依赖：硬冲突，单许可证条目不带多候选字段
    result = analyzer.analyze_manifest(_manifest("GPL-2.0", "Apache-2.0"))
    conflict = _find(result)
    _check("single hard conflict", conflict["severity"] == "error")
    _check("single entry has no multi_license flag", not conflict.get("multi_license"))
    _check("single entry has no combinations key", "combinations" not in conflict)
    _check(
        "node license_candidates is None for single license",
        all(n.get("license_candidates") is None for n in result["nodes"]),
    )


def main() -> None:
    test_parse_or_candidates()
    test_or_token_is_order_independent()
    test_all_combinations_conflict_is_error()
    test_all_combinations_ok_is_clean()
    test_mixed_combinations_is_warning()
    test_mixed_with_matrix_warning_is_warning()
    test_unknown_expressions_stay_unknown()
    test_cyclonedx_parallel_and_transitive_path()
    test_single_license_unchanged()
    print("\nall tests passed.")


if __name__ == "__main__":
    main()
