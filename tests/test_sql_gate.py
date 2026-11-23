"""Comprehensive unit and adversarial red-team test suite for `lab-verify` (Issues #1..#22)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify import (  # noqa: E402
    LAYERS,
    SCHEMA,
    BatchGateEvaluator,
    QueryResult,
    VerifyVerdict,
    build_counterexample_dbs,
    build_db,
    cells_equal,
    check_parse,
    check_read_only,
    check_schema,
    column_in_range,
    expected_columns,
    gate,
    introspect_sqlite_schema,
    max_rows_bound,
    no_join_fanout,
    no_nulls,
    non_empty,
    open_readonly_db,
    run,
    unique_column,
    validate_candidates_schema,
    verify,
    verify_lean,
    verify_protocol,
    verify_sql,
)


@pytest.fixture(scope="module")
def db():
    con = build_db()
    yield con
    con.close()


@pytest.fixture(scope="module")
def ce_dbs():
    cons = build_counterexample_dbs()
    yield cons
    for c in cons:
        c.close()


# ---- Issue #1: Multi-row ORDER BY enforcement vs unordered multiset ----
def test_issue_1_order_by_enforced_when_present_in_gold(db):
    gold_sql = "SELECT id, yield_pct FROM experiments WHERE status = 'done' ORDER BY yield_pct DESC, id ASC"
    gold_res = run(db, gold_sql)
    assert gold_res.ordered is True

    # Matching descending order passes
    layer_ok, _ = gate(db, gold_sql, gold_res)
    assert layer_ok is None

    # Inverted ascending order (same multiset, wrong row order, no LIMIT 1) MUST fail Layer 4!
    inv_sql = "SELECT id, yield_pct FROM experiments WHERE status = 'done' ORDER BY yield_pct ASC, id ASC"
    layer_bad, reason = gate(db, inv_sql, gold_res)
    assert layer_bad == 3
    assert "row order mismatch" in reason

    # Unordered gold allows candidate with ORDER BY (multiset match)
    unord_gold = run(db, "SELECT operator, COUNT(*) FROM experiments GROUP BY operator")
    assert unord_gold.ordered is False
    layer_u, _ = gate(
        db,
        "SELECT operator, COUNT(id) AS n FROM experiments GROUP BY operator ORDER BY n DESC",
        unord_gold,
    )
    assert layer_u is None


# ---- Issue #2: Common Table Expressions (WITH cte AS (...)) ----
def test_issue_2_valid_and_invalid_ctes(db):
    gold_res = run(db, "SELECT COUNT(*) FROM experiments WHERE status = 'done'")
    cte_sql = (
        "WITH done_exps AS (SELECT * FROM experiments WHERE status = 'done') "
        "SELECT COUNT(*) FROM done_exps"
    )
    layer, reason = gate(db, cte_sql, gold_res)
    assert layer is None, reason

    # Explicit CTE column list
    cte_cols_sql = (
        "WITH summary(op_name, cnt) AS ("
        "  SELECT operator, COUNT(*) FROM experiments GROUP BY operator"
        ") SELECT op_name, cnt FROM summary"
    )
    g2 = run(db, "SELECT operator, COUNT(*) FROM experiments GROUP BY operator")
    assert gate(db, cte_cols_sql, g2) == (None, "match")

    # CTE column alias arity mismatch fails Layer 3
    bad_cte = "WITH s(a, b, c) AS (SELECT id, operator FROM experiments) SELECT a FROM s"
    l_bad, r_bad = gate(db, bad_cte, None)
    assert l_bad == 2 and "column count mismatch" in r_bad


# ---- Issue #3: Self-aliased unknown column bypass ----
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT bogus AS bogus FROM experiments",
        "SELECT scientist AS scientist FROM experiments",
        "SELECT COUNT(*) AS scientist FROM experiments WHERE scientist = 'Kim'",
        "SELECT 1 AS x FROM experiments WHERE x = 1",
    ],
)
def test_issue_3_self_aliased_unknown_columns_blocked_at_layer_3(db, sql):
    layer, reason = gate(db, sql, None)
    assert layer == 2
    assert "unknown column" in reason


# ---- Issue #4: Lexical scoping across subqueries & ambiguous JOIN columns ----
def test_issue_4_subquery_scope_isolation_and_ambiguous_join_columns(db):
    # Out-of-scope column `well` exists in `samples` subquery, NOT in outer `experiments`
    leak_sql = "SELECT well FROM experiments WHERE id IN (SELECT experiment_id FROM samples)"
    layer1, reason1 = gate(db, leak_sql, None)
    assert layer1 == 2
    assert "unknown column well in experiments" in reason1

    # Ambiguous `id` across joined `experiments` and `samples`
    ambig_sql = "SELECT id FROM experiments JOIN samples ON experiments.id = samples.experiment_id"
    layer2, reason2 = gate(db, ambig_sql, None)
    assert layer2 == 2
    assert "ambiguous column id" in reason2

    # Correlated EXISTS subquery referencing outer alias `e.id` is valid
    corr_sql = "SELECT e.id FROM experiments e WHERE EXISTS (SELECT 1 FROM samples s WHERE s.experiment_id = e.id)"
    layer3, reason3 = gate(db, corr_sql, None)
    assert layer3 is None, reason3

    # JOIN ... USING (id) disambiguates `id`
    using_sql = "SELECT id FROM experiments JOIN instruments USING (id)"
    layer4, reason4 = gate(db, using_sql, None)
    assert layer4 is None, reason4


# ---- Issue #5: Case-insensitive table, column, and alias resolution ----
def test_issue_5_mixed_case_identifiers_pass_all_layers(db):
    gold = run(db, "SELECT COUNT(*) FROM experiments WHERE status = 'done'")
    mixed_sql = "SELECT COUNT(E.ID) FROM Experiments AS E WHERE E.Status = 'done'"
    assert gate(db, mixed_sql, gold) == (None, "match")


# ---- Issue #6: Qualified star `SELECT e.*` vs `SELECT z.*` ----
def test_issue_6_qualified_star_projection(db):
    ok_layer, ok_reason = gate(db, "SELECT e.* FROM experiments e WHERE e.status = 'done'", None)
    assert ok_layer is None, ok_reason

    bad_layer, bad_reason = gate(db, "SELECT z.* FROM experiments e", None)
    assert bad_layer == 2
    assert "unknown table alias z" in bad_reason


# ---- Issue #7: Progress handler timeout, row cap, authorizer & DoS functions ----
@pytest.mark.parametrize(
    "dos_sql",
    [
        "SELECT randomblob(1000000000)",
        "SELECT zeroblob(1000000000)",
        "SELECT load_extension('evil.so')",
        "SELECT writefile('/tmp/pwn', 'x')",
        "SELECT fts3_tokenizer('simple')",
    ],
)
def test_issue_7_dangerous_and_dos_functions_blocked(db, dos_sql):
    layer, reason = gate(db, dos_sql, None)
    assert layer == 1
    assert "forbidden function" in reason


def test_issue_7_runaway_cartesian_and_recursive_cte_aborted_by_progress_handler(db):
    # Infinite/huge recursive CTE exceeds VM step budget and aborts cleanly in milliseconds
    runaway_cte = (
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 10000000) "
        "SELECT SUM(x) FROM cnt"
    )
    layer, reason = gate(db, runaway_cte, None, max_vm_steps=5_000, timeout_s=0.5)
    assert layer == 3
    assert "execution limit" in reason

    # Row cap check
    many_rows = (
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 50) "
        "SELECT x FROM cnt"
    )
    l_cap, r_cap = gate(db, many_rows, None, max_rows=10)
    assert l_cap == 3 and "max_rows cap" in r_cap

    # Direct SQLite authorizer blocks bypass even if someone calls `db.execute` directly!
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("PRAGMA writable_schema = ON")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("SELECT * FROM sqlite_master")


# ---- Issue #8: Empty, whitespace, semicolon, and comment-only inputs fail Layer 1 ----
@pytest.mark.parametrize("empty_sql", ["", "   \t\n  ", ";", ";;;", "-- TODO comment", "/* block comment */"])
def test_issue_8_empty_and_comment_inputs_fail_layer_1_parse(db, empty_sql):
    layer, reason = gate(db, empty_sql, None)
    assert layer == 0
    assert "empty SQL input" in reason


# ---- Issue #9: System catalog tables and attached DB qualifiers blocked ----
@pytest.mark.parametrize(
    "sys_sql",
    [
        "SELECT * FROM sqlite_master",
        "SELECT * FROM sqlite_schema",
        "SELECT * FROM sqlite_temp_master",
        "SELECT * FROM temp.experiments",
        "SELECT * FROM aux.experiments",
    ],
)
def test_issue_9_system_tables_and_db_qualifiers_blocked(db, sys_sql):
    layer, reason = gate(db, sys_sql, None)
    assert layer == 2
    assert "forbidden" in reason


# ---- Issue #10: Counterexample perturbation DBs & row content mismatch diagnostics ----
def test_issue_10_counterexample_catches_coincidental_queries_and_checks_arity(db, ce_dbs):
    # qid 9 gold = ('PCR',) on primary DB; `WHERE id = 1` ALSO returns ('PCR',) on primary DB!
    gold_q9 = "SELECT protocol FROM experiments ORDER BY yield_pct DESC LIMIT 1"
    gold_res_q9 = run(db, gold_q9)
    coincidental_q9 = "SELECT protocol FROM experiments WHERE id = 1"
    layer_c9, reason_c9 = gate(
        db,
        coincidental_q9,
        gold_res_q9,
        gold_sql=gold_q9,
        counterexample_cons=ce_dbs,
    )
    assert layer_c9 == 3
    assert "counterexample db" in reason_c9

    # qid 3 gold = (5,) on primary DB; `COUNT(*) WHERE protocol = 'PCR'` ALSO returns (5,)!
    gold_q3 = "SELECT COUNT(DISTINCT reagent) FROM samples"
    gold_res_q3 = run(db, gold_q3)
    coincidental_q3 = "SELECT COUNT(*) FROM experiments WHERE protocol = 'PCR'"
    layer_c3, reason_c3 = gate(
        db,
        coincidental_q3,
        gold_res_q3,
        gold_sql=gold_q3,
        counterexample_cons=ce_dbs,
    )
    assert layer_c3 == 3
    assert "counterexample db" in reason_c3

    # Column arity mismatch (2 columns vs 1 column)
    arity_gold = run(db, "SELECT id FROM experiments WHERE status = 'failed'")
    l_ar, r_ar = gate(db, "SELECT id, operator FROM experiments WHERE status = 'failed'", arity_gold)
    assert l_ar == 3 and "column count 2 vs gold 1" in r_ar

    # Same row count (2 rows) with different cell contents gives clear `row content mismatch`
    g7 = run(db, "SELECT name FROM instruments WHERE last_calibrated < '2026-06-01'")
    l7, r7 = gate(db, "SELECT name FROM instruments WHERE last_calibrated > '2026-06-01'", g7)
    assert l7 == 3 and "row content mismatch (2 rows)" in r7


# ---- Issue #11: Typed schema, foreign keys, and NULL-aware edge cases ----
def test_issue_11_typed_schema_foreign_keys_and_nullable_columns(db):
    assert "instrument_id" in SCHEMA["experiments"]
    # Running experiment 7 has NULL yield_pct and NULL instrument_id
    r_null = run(db, "SELECT id FROM experiments WHERE yield_pct IS NULL AND instrument_id IS NULL")
    assert r_null.rows == ((7,),)

    # Multi-hop join instruments <-> experiments <-> samples works cleanly
    hop_sql = (
        "SELECT i.name, COUNT(s.id) "
        "FROM instruments i "
        "JOIN experiments e ON e.instrument_id = i.id "
        "JOIN samples s ON s.experiment_id = e.id "
        "GROUP BY i.name"
    )
    layer, reason = gate(db, hop_sql, None)
    assert layer is None, reason


# ---- Issue #12: Type-safe float `isclose`, bool/int/str distinctness, NaN guard ----
def test_issue_12_numeric_isclose_and_type_distinctness(db):
    assert cells_equal(1, 1.0) is True
    assert cells_equal(1, True) is False
    assert cells_equal(0, False) is False
    assert cells_equal(1, "1") is False
    assert cells_equal(None, 0) is False
    assert cells_equal(float("nan"), float("nan")) is False
    assert cells_equal(float("inf"), float("inf")) is False
    # Halfway rounding boundary cliff where round(x, 6) differs (`0.12345649` vs `0.12345651`)
    assert round(0.12345649, 6) != round(0.12345651, 6)
    assert cells_equal(0.12345649, 0.12345651) is True

    # Non-finite SQL float overflow (`1e308 * 10` -> Inf in SQLite) is caught at Layer 4
    layer_inf, reason_inf = gate(db, "SELECT 1e308 * 10 FROM experiments LIMIT 1", None)
    assert layer_inf == 3
    assert "non-finite" in reason_inf


# ---- Issue #13 & #14: Benchmark 22/22 parity, non-zero CLI failure exit, JSON Schema ----
def test_issue_13_14_benchmark_parity_schema_and_gold_validation(tmp_path):
    cand_schema = json.loads((REPO_ROOT / "schema" / "candidates.schema.json").read_text(encoding="utf-8"))
    for fname in ("candidates.json", "candidates_extended.json"):
        items = json.loads((REPO_ROOT / "demo" / fname).read_text(encoding="utf-8"))
        jsonschema.validate(items, cand_schema)
        assert validate_candidates_schema(items) == []

    # Duplicate qid rejected by schema validator
    dup_errs = validate_candidates_schema(
        [
            {"qid": 1, "question": "q", "gold": "SELECT 1", "candidates": [{"label": "correct", "sql": "SELECT 1"}]},
            {"qid": 1, "question": "q2", "gold": "SELECT 1", "candidates": [{"label": "correct", "sql": "SELECT 1"}]},
        ]
    )
    assert any("duplicate qid" in e for e in dup_errs)

    # Invalid gold query rejected by BatchGateEvaluator
    con = build_db()
    ev = BatchGateEvaluator(con)
    with pytest.raises(ValueError, match="Gold SQL failed gate"):
        ev.get_validated_gold("SELECT nonexistent_col FROM experiments")
    con.close()

    # Demo CLI output matches demo/output.txt and exits 0
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "demo" / "sql_gate.py")],
        capture_output=True,
        text=True,
        check=True,
    )
    expected = (REPO_ROOT / "demo" / "output.txt").read_text(encoding="utf-8")
    assert proc.stdout.strip() == expected.strip()

    # Mislabeled candidate file must exit non-zero (code 1)!
    bad_bench = tmp_path / "bad_candidates.json"
    bad_bench.write_text(
        json.dumps(
            [
                {
                    "qid": 1,
                    "question": "Done count",
                    "gold": "SELECT COUNT(*) FROM experiments WHERE status = 'done'",
                    "candidates": [{"label": "correct", "sql": "SELECT COUNT(*) FROM experiments"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    bad_proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "demo" / "sql_gate.py"), "--candidates", str(bad_bench)],
        capture_output=True,
        text=True,
    )
    assert bad_proc.returncode == 1


# ---- Issue #15: Unified VerifyVerdict, Lean 4 checker, and Protocol checker ----
def test_issue_15_unified_verdict_lean_and_protocol_checkers():
    # 1. Clean Lean 4 code (even with 'sorry' mentioned inside a comment!) passes
    clean_lean = """
    -- Proven without sorry or native_decide
    /- Block comment mentioning axiom and admit -/
    theorem add_zero_right (n : Nat) : n + 0 = n := by rfl
    """
    v_ok = verify("lean", clean_lean)
    assert isinstance(v_ok, VerifyVerdict) and v_ok.passed is True

    # 2. Sorry, native_decide, custom axiom, and vacuous theorems are rejected
    for bad_lean in [
        "theorem bad (n : Nat) : n = n + 1 := by sorry",
        "theorem fast : 2 + 2 = 4 := by native_decide",
        "axiom magic_truth : False",
        "theorem vacuous : True := trivial",
        "theorem ex_falso : False -> 1 = 2 := False.elim",
    ]:
        v_bad = verify_lean(bad_lean)
        assert v_bad.passed is False

    # 3. Protocol gate checks valid & broken protocols
    good_proto = [
        {"op": "pick_up_tip"},
        {"op": "aspirate", "loc": "res:1", "vol": 100},
        {"op": "dispense", "loc": "plate:A1", "vol": 100},
        {"op": "drop_tip"},
    ]
    assert verify("protocol", good_proto).passed is True
    broken_proto = [
        {"op": "pick_up_tip"},
        {"op": "aspirate", "loc": "res:1", "vol": 5},  # < 20 uL
        {"op": "drop_tip"},  # wet drop
    ]
    vp = verify_protocol(broken_proto)
    assert vp.passed is False and len(vp.diagnostics) >= 2


# ---- Issue #16: Red-team adversarial SQL suite across Layers 1-2 ----
@pytest.mark.parametrize(
    "attack_sql",
    [
        "DELETE FROM experiments",
        "UPDATE experiments SET yield_pct = 100",
        "DROP TABLE samples",
        "INSERT INTO instruments VALUES (9, 'X', '2026-01-01') RETURNING *",
        "REPLACE INTO instruments VALUES (1, 'Hack', '2026-01-01')",
        "ATTACH DATABASE ':memory:' AS pwn",
        "DETACH DATABASE pwn",
        "VACUUM",
        "PRAGMA writable_schema = ON",
        "PRAGMA table_info('experiments')",
        "WITH d AS (SELECT id FROM experiments) DELETE FROM experiments WHERE id IN (SELECT id FROM d)",
        "EXPLAIN QUERY PLAN SELECT * FROM experiments",
        "VALUES (1, 2, 3)",
        "BEGIN EXCLUSIVE TRANSACTION",
        "SELECT 1; ATTACH DATABASE 'foo.db' AS aux",
        "ALTER TABLE experiments ADD COLUMN secret TEXT",
        "CREATE TEMP TABLE t AS SELECT * FROM experiments",
    ],
)
def test_issue_16_red_team_write_and_admin_attacks_blocked_at_layer_2(db, attack_sql):
    layer, reason = gate(db, attack_sql, None)
    assert layer == 1, f"{attack_sql!r} -> layer={layer}, reason={reason}"


# ---- Issue #17: Property-based verification without gold reference SQL ----
def test_issue_17_property_checks_catch_fanout_and_range_violations_without_gold(db):
    props = [
        non_empty(),
        expected_columns(2),
        no_join_fanout(db, "experiments", key_col=0),
        unique_column(0),
        no_nulls(1),
        column_in_range(1, 0.0, 100.0),
    ]
    # Valid grouped query passes all runtime semantic properties without gold SQL
    good_q = (
        "SELECT e.id, AVG(e.yield_pct) AS avg_y "
        "FROM experiments e JOIN samples s ON s.experiment_id = e.id "
        "WHERE e.yield_pct IS NOT NULL GROUP BY e.id"
    )
    assert gate(db, good_q, None, properties=props) == (None, "match")

    # Ungrouped join duplicates experiment IDs (fanout explosion!) -> caught by properties!
    fanout_q = (
        "SELECT e.id, e.yield_pct "
        "FROM experiments e JOIN samples s ON s.experiment_id = e.id "
        "WHERE e.yield_pct IS NOT NULL"
    )
    l_fan, r_fan = gate(db, fanout_q, None, properties=props)
    assert l_fan == 3 and "fanout" in r_fan

    # Out-of-range metric (`yield_pct * 10 > 100`) -> caught by column_in_range!
    oor_q = "SELECT id, yield_pct * 10 FROM experiments WHERE yield_pct IS NOT NULL"
    l_oor, r_oor = gate(db, oor_q, None, properties=[column_in_range(1, 0.0, 100.0)])
    assert l_oor == 3 and "outside [0.0, 100.0]" in r_oor

    assert gate(db, "SELECT id FROM experiments", None, properties=[max_rows_bound(5)])[0] == 3


# ---- Issue #18: External SQLite `mode=ro` introspection & `--json` CLI ----
def test_issue_18_external_sqlite_introspection_and_json_cli(tmp_path):
    ext_db = tmp_path / "stock.sqlite"
    wcon = sqlite3.connect(ext_db)
    wcon.execute("CREATE TABLE reagents (id INTEGER PRIMARY KEY, smiles TEXT, stock_mg REAL)")
    wcon.execute("INSERT INTO reagents VALUES (1, 'CCO', 250.0), (2, 'c1ccccc1', 100.0)")
    wcon.commit()
    wcon.close()

    rcon, dyn_schema = open_readonly_db(ext_db)
    assert dyn_schema == {"reagents": ["id", "smiles", "stock_mg"]}
    assert introspect_sqlite_schema(rcon) == dyn_schema
    # Verify read-only URI enforcement blocks writes at OS/SQLite level
    with pytest.raises(sqlite3.DatabaseError):
        rcon.execute("DELETE FROM reagents")
    rcon.close()

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "lab_verify.cli",
            "--db",
            str(ext_db),
            "--sql",
            "SELECT smiles FROM reagents WHERE stock_mg > 5000",
            "--json",
        ],
        env={**dict(__import__("os").environ), "PYTHONPATH": str(SRC_DIR)},
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["passed"] is True and payload["reason"] == "match"


# ---- Issue #19: Implicit Cartesian join lint in Layer 3 ----
def test_issue_19_cartesian_join_blocked_unless_explicit_cross_join_allowed(db):
    comma_join = "SELECT e.id, s.well FROM experiments e, samples s"
    l1, r1 = gate(db, comma_join, None)
    assert l1 == 2 and "Cartesian join" in r1

    missing_on = "SELECT e.id, SUM(s.volume_ul) FROM experiments e JOIN samples s WHERE e.operator = 'Kim' GROUP BY e.id"
    l2, r2 = gate(db, missing_on, None)
    assert l2 == 2 and "Cartesian join" in r2

    cross_sql = "SELECT e.id, i.name FROM experiments e CROSS JOIN instruments i"
    assert gate(db, cross_sql, None, allow_cross_join=False)[0] == 2
    assert gate(db, cross_sql, None, allow_cross_join=True) == (None, "match")


# ---- Issue #20: Catalog SPDX, CC-BY-SA-4.0 ShareAlike, and URL health ----
def test_issue_20_sources_catalog_spdx_and_share_alike():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import check_catalog

    assert check_catalog.validate_catalog(REPO_ROOT, online=False) == []
    data = json.loads((REPO_ROOT / "catalog" / "sources.json").read_text(encoding="utf-8"))
    ds = {d["id"]: d for d in data["datasets"]}
    assert ds["spider"]["share_alike"] is True
    assert ds["bird"]["share_alike"] is True
    assert ds["leandojo-benchmark"]["commercial_use_ok"] is False


# ---- Issue #21: SetOperation (`UNION` / `EXCEPT`) arity & isolated branch scoping ----
def test_issue_21_set_operations_scope_isolation_and_arity(db):
    # Valid UNION
    valid_union = (
        "SELECT id FROM experiments WHERE status = 'done' "
        "UNION "
        "SELECT experiment_id FROM samples WHERE reagent = 'Taq'"
    )
    assert gate(db, valid_union, None) == (None, "match")

    # Cross-branch alias leakage (`s` is only defined in second branch!)
    leak_union = "SELECT s.well FROM experiments e UNION SELECT s.well FROM samples s"
    l_leak, r_leak = gate(db, leak_union, None)
    assert l_leak == 2 and "unknown table alias s" in r_leak

    # Column arity mismatch across UNION branches (`2 != 1`)
    arity_union = "SELECT id, protocol FROM experiments UNION SELECT id FROM samples"
    l_ar, r_ar = gate(db, arity_union, None)
    assert l_ar == 2 and "column count mismatch (2 vs 1)" in r_ar


# ---- Issue #22: Canonical-AST memoization across candidate batches & UTF-8 ----
def test_issue_22_batch_evaluator_canonical_sql_memoization(db, ce_dbs):
    ev = BatchGateEvaluator(db, counterexample_cons=ce_dbs)
    gold = "SELECT COUNT(*) FROM experiments WHERE status = 'done'"
    v1 = ev.evaluate_candidate("SELECT  count(id)  FROM experiments WHERE status = 'done'", gold)
    v2 = ev.evaluate_candidate("select COUNT(id) from experiments where status = 'done';", gold)
    assert v1 == (None, "match") and v2 == (None, "match")
    assert ev.cache_hits == 1
