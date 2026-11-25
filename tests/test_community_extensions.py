"""Tests for lab-verify community extensions (Ideas #12 and #13) and LabVerifyLean parity."""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from community_extensions.lean_mcp_firewall import (  # noqa: E402
    LeanMcpFirewall,
    McpExecutionRequest,
    canonical_sha256,
    run_benchmark as run_firewall_benchmark,
)
from community_extensions.mutant_sql_synthesizer import (  # noqa: E402
    build_clean_lims_seed_db,
    evaluate_sql_against_mutants,
    run_benchmark as run_mutant_sql_benchmark,
    synthesize_five_sqlite_mutants,
)

CJK_RE = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")


def test_lean_mcp_firewall_rejects_identical_keys() -> None:
    with pytest.raises(ValueError, match="distinct keys"):
        LeanMcpFirewall(b"same-key", b"same-key")


def test_lean_mcp_firewall_blocks_replays_tampering_and_unsigned_frontier() -> None:
    fw = LeanMcpFirewall(
        firewall_secret=b"proof-gate-secret",
        supervisor_secret=b"human-supervisor-secret",
        initial_deck_epoch=10,
    )
    proto_hash = canonical_sha256({"sop": "serial_dilution_v1"})
    params = {"src": "A1", "dst": "B1", "vol_ul": 50.0}

    # 1. Valid Lean-certified routine call -> allowed and advances deck epoch to 11
    tok_ok = fw.issue_capability_token(proto_hash, params, lean_verified=True, nonce="n1")
    req_ok = McpExecutionRequest(
        tool_name="pipette_transfer",
        protocol_sha256=proto_hash,
        parameters=params,
        token=tok_ok,
        mutates_deck_state=True,
    )
    dec_ok = fw.authorize_and_execute(req_ok)
    assert dec_ok.allowed is True
    assert fw.current_deck_epoch == 11

    # 2. Stale-epoch replay of tok_ok (epoch 10 != 11) -> blocked
    dec_stale = fw.authorize_and_execute(req_ok)
    assert dec_stale.allowed is False
    assert dec_stale.rule_violated == "mcp_epoch_freshness"

    # 3. Same-epoch nonce replay -> blocked
    tok_e11 = fw.issue_capability_token(proto_hash, params, lean_verified=True, nonce="n2")
    req_e11 = McpExecutionRequest(
        tool_name="pipette_transfer",
        protocol_sha256=proto_hash,
        parameters=params,
        token=tok_e11,
        mutates_deck_state=False,
    )
    assert fw.authorize_and_execute(req_e11).allowed is True
    dec_dup = fw.authorize_and_execute(req_e11)
    assert dec_dup.allowed is False
    assert dec_dup.rule_violated == "nonce_replay_detected"

    # 4. Tampered parameter payload -> blocked
    tok_tamp = fw.issue_capability_token(proto_hash, params, lean_verified=True, nonce="n3")
    req_tamp = McpExecutionRequest(
        tool_name="pipette_transfer",
        protocol_sha256=proto_hash,
        parameters={"src": "A1", "dst": "B1", "vol_ul": 500.0},
        token=tok_tamp,
    )
    dec_tamp = fw.authorize_and_execute(req_tamp)
    assert dec_tamp.allowed is False
    assert dec_tamp.rule_violated == "parameter_or_protocol_tampered"

    # 5. Frontier exception without human supervisor HMAC -> blocked; with supervisor HMAC -> allowed
    tok_front_bad = fw.issue_capability_token(
        proto_hash,
        params,
        lean_verified=True,
        is_frontier_exception=True,
        human_cosign_hmac=None,
        nonce="n4",
    )
    dec_front_bad = fw.authorize_and_execute(
        McpExecutionRequest("pipette_transfer", proto_hash, params, tok_front_bad)
    )
    assert dec_front_bad.allowed is False
    assert dec_front_bad.rule_violated == "mcp_proof_or_cosigned_exception"

    sup_sig = fw.sign_human_supervisor_override(
        "n5", fw.current_deck_epoch, proto_hash, canonical_sha256(params)
    )
    tok_front_ok = fw.issue_capability_token(
        proto_hash,
        params,
        lean_verified=False,
        is_frontier_exception=True,
        human_cosign_hmac=sup_sig,
        nonce="n5",
    )
    dec_front_ok = fw.authorize_and_execute(
        McpExecutionRequest("pipette_transfer", proto_hash, params, tok_front_ok)
    )
    assert dec_front_ok.allowed is True


def test_idea_12_benchmark_200_requests() -> None:
    report = run_firewall_benchmark(num_requests=200, seed=2026)
    assert report["num_requests"] == 200
    assert report["valid_requests"] == 80
    assert report["adversarial_requests"] == 120

    bearer = report["stateless_bearer_gate"]
    fw = report["lean_mcp_firewall"]
    assert bearer["replay_and_tamper_block_rate"] < 0.10
    assert fw["replay_and_tamper_block_rate"] == 1.0
    assert fw["adversarial_blocked"] == 120
    assert fw["false_positive_blocks"] == 0
    assert fw["mean_verification_latency_us"] < 500.0


def test_mutant_sql_synthesizer_readonly_lock_and_counterexample_detection() -> None:
    seed_conn = build_clean_lims_seed_db(lock_readonly=False)
    mutants = synthesize_five_sqlite_mutants(seed_conn, lock_readonly=True)
    assert len(mutants) == 5

    # Read-only authorizer blocks DDL/DML and sqlite_master introspection on synthesized mutants
    m1 = mutants["mutant_1_duplicate_join_keys"]
    with pytest.raises(sqlite3.DatabaseError):
        m1.execute("DELETE FROM readouts")
    with pytest.raises(sqlite3.DatabaseError):
        m1.execute("SELECT * FROM sqlite_master")

    gold_sql = (
        "SELECT p.plate_id, COUNT(DISTINCT s.sample_id) "
        "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
        "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "GROUP BY p.plate_id ORDER BY p.plate_id"
    )
    buggy_sql = (
        "SELECT p.plate_id, COUNT(s.sample_id) "
        "FROM plates p INNER JOIN samples s ON p.plate_id = s.plate_id "
        "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "GROUP BY p.plate_id ORDER BY p.plate_id"
    )
    verdict = evaluate_sql_against_mutants(buggy_sql, gold_sql, seed_conn, mutants)
    assert verdict.passed_seed_db is True
    assert verdict.passed_all_mutants is False
    assert "mutant_1_duplicate_join_keys" in verdict.failing_mutants
    assert "mutant_4_empty_group_strata" in verdict.failing_mutants

    for m in mutants.values():
        m.close()
    seed_conn.close()


def test_idea_13_benchmark_24_sql_candidates() -> None:
    report = run_mutant_sql_benchmark()
    assert report["num_candidates"] == 24
    assert report["gold_candidates"] == 6
    assert report["buggy_candidates"] == 18
    assert report["num_mutants_per_schema"] == 5

    seed_m = report["single_seed_db"]
    mut_m = report["mutant_db_gate"]

    assert seed_m["semantic_bug_catch_rate"] == 0.0
    assert seed_m["gold_acceptance_rate"] == 1.0

    assert mut_m["semantic_bugs_caught"] == 18
    assert mut_m["semantic_bug_catch_rate"] == 1.0
    assert mut_m["gold_accepted"] == 6
    assert mut_m["gold_acceptance_rate"] == 1.0
    assert all(count >= 2 for count in mut_m["catches_by_mutant"].values())


def test_issue_29_inner_cte_order_by_and_int_float_sum_total_parity() -> None:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE samples (id INT, grp TEXT, v REAL, cnt INT)")
    con.executemany(
        "INSERT INTO samples VALUES (?, ?, ?, ?)",
        [(1, "G1", 0.2, 3), (2, "G2", 0.5, 7), (3, "G3", 0.9, 11)],
    )
    try:
        # 1. Outer GROUP BY is unordered even though inner CTE contains ORDER BY ... LIMIT 2
        verdict = evaluate_sql_against_mutants(
            candidate_sql=(
                "SELECT grp, SUM(v) FROM samples WHERE grp = 'G2' "
                "UNION ALL SELECT grp, SUM(v) FROM samples WHERE grp = 'G1'"
            ),
            gold_sql=(
                "WITH top2 AS (SELECT * FROM samples ORDER BY v ASC LIMIT 2) "
                "SELECT grp, SUM(v) FROM top2 GROUP BY grp"
            ),
            seed_conn=con,
            mutants={},
        )
        assert verdict.passed_seed_db is True
        assert verdict.passed_all_mutants is True

        # 2. SQLite SUM(int_col) (int) vs TOTAL(int_col) (float) and midpoint float tolerance
        v_parity = evaluate_sql_against_mutants(
            candidate_sql="SELECT grp, TOTAL(cnt), SUM(v) * 1.0 / COUNT(v) FROM samples GROUP BY grp",
            gold_sql="SELECT grp, SUM(cnt), AVG(v) FROM samples GROUP BY grp",
            seed_conn=con,
            mutants={},
        )
        assert v_parity.passed_seed_db is True
    finally:
        con.close()


def _strip_lean_comments_and_strings(src: str) -> str:
    no_block = re.sub(r"/-.*?-/", " ", src, flags=re.DOTALL)
    no_line = re.sub(r"--[^\n]*", " ", no_block)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', no_line)


def test_pure_english_and_lean_file_integrity() -> None:
    lean_file = REPO_ROOT / "lean" / "LabVerifyLean.lean"
    assert lean_file.exists()
    lean_src = lean_file.read_text(encoding="utf-8")
    lean_code = _strip_lean_comments_and_strings(lean_src)
    assert "sorry" not in re.findall(r"\bsorry\b", lean_code)
    assert "axiom" not in re.findall(r"\baxiom\b", lean_code)

    checked_paths = [
        lean_file,
        REPO_ROOT / "lean" / "README.md",
        REPO_ROOT / "lean" / "lakefile.toml",
        REPO_ROOT / "community_extensions" / "__init__.py",
        REPO_ROOT / "community_extensions" / "lean_mcp_firewall.py",
        REPO_ROOT / "community_extensions" / "mutant_sql_synthesizer.py",
        Path(__file__).resolve(),
    ]
    for path in checked_paths:
        text = path.read_text(encoding="utf-8")
        assert CJK_RE.search(text) is None, f"CJK character found in {path}"
