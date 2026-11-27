"""Tests for `lab-verify` Auto-Lab wire node (`autolab_wire.py`, `autolab-wire/v1`)."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
for _p in (str(SRC_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autolab_wire  # noqa: E402
from autolab_wire import (  # noqa: E402
    INVARIANT_NAME,
    LAYER,
    REPO_DIR,
    REPO_ID,
    WIRE_SCHEMA_VERSION,
    cosign_and_release_for_stepbot,
    cosign_deferred_packet,
    mint_for_compiled_stepbot,
    process_packet,
)
from lab_verify.mcp_gate import (  # noqa: E402
    LEAN_MCP_SCHEMA_VERSION,
    LeanMcpGate,
    compute_protocol_sha256,
    verify_mcp_envelope,
)

CJK_RE = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")

SAMPLE_COMPILED_STEPBOT_PY = """metadata = {
    "protocolName": "Auto-Lab Rehearsed Transfer",
    "apiLevel": "2.16",
}


def run(protocol):
    tips = protocol.load_labware("opentrons_96_tiprack_300ul", 1)
    reservoir = protocol.load_labware("nest_12_reservoir_15ml", 2)
    plate = protocol.load_labware("corning_96_wellplate_360ul_flat", 3)
    pipette = protocol.load_instrument("p300_single_gen2", "right", tip_racks=[tips])
    pipette.transfer(100.0, reservoir["A1"], plate["A1"], new_tip="once")
"""


def test_wire_metadata_and_default_valid_sql_plus_mcp_minting() -> None:
    assert REPO_ID == "lab-verify"
    assert LAYER == "L4"
    assert REPO_DIR == REPO_ROOT

    rehearsal_ir = {
        "metadata": {"protocolName": "Rehearsed 96-Well Transfer", "apiLevel": "2.16"},
        "deck": {
            "1": {"load_name": "opentrons_96_tiprack_300ul"},
            "2": {"load_name": "nest_12_reservoir_15ml"},
            "3": {"load_name": "corning_96_wellplate_360ul_flat"},
        },
        "pipettes": {"right": {"instrument_name": "p300_single_gen2", "tip_racks": ["1"]}},
        "steps": [
            {
                "action": "transfer",
                "pipette": "right",
                "source": "2:A1",
                "dest": "3:A1",
                "volume": 100.0,
            }
        ],
    }
    raw_packet = {
        "deck_epoch": 3,
        "mcp_secret_key": "wire-unit-test-secret",
        "rehearsal": {"passed": True, "violations": [], "protocol_yaml_dict": rehearsal_ir},
    }

    out = process_packet(raw_packet)
    assert "verification" not in raw_packet  # deep-copied, never mutates caller dict

    assert out["schema_version"] == WIRE_SCHEMA_VERSION
    assert out["halted"] is False
    assert out["halt_reason"] is None
    assert out["verification"]["sql_passed"] is True

    env = out["verification"]["mcp_envelope"]
    assert isinstance(env, dict)
    assert env["schema_version"] == LEAN_MCP_SCHEMA_VERSION
    assert env["token_epoch"] == 3
    assert env["lean_proof_valid"] is True
    assert env["is_frontier_exception"] is False
    assert env["protocol_sha256"] == compute_protocol_sha256(rehearsal_ir)

    verdict = verify_mcp_envelope(
        env,
        secret_key="wire-unit-test-secret",
        current_deck_epoch=3,
        actual_protocol=rehearsal_ir,
        check_lean_kernel=False,
    )
    assert verdict.passed is True

    assert len(out["trace"]) == 1
    assert out["trace"][0]["repo"] == "lab-verify"
    assert out["trace"][0]["layer"] == "L4"
    assert out["trace"][0]["status"] == "PASS"

    assert len(out["bottom_reasoning_traces"]) == 1
    assert out["bottom_reasoning_traces"][0]["repo"] == "lab-verify"
    assert out["bottom_reasoning_traces"][0]["invariant"] == INVARIANT_NAME


@pytest.mark.parametrize(
    "bad_sql",
    [
        "DROP TABLE samples",
        "SELECT COUNT(*) FROM samples; DROP TABLE samples",
        "DELETE FROM samples WHERE id = 101",
        "UPDATE experiments SET status = 'done'",
        "SELECT nonexistent_col FROM samples",
        "",
    ],
)
def test_mutating_or_invalid_sql_blocks_with_l4_verify_sql_block(bad_sql: str) -> None:
    out = process_packet({"sql_query": bad_sql, "deck_epoch": 1})

    assert out["halted"] is True
    assert out["halt_reason"] == "L4_VERIFY_SQL_BLOCK"
    assert out["verification"] == {
        "sql_passed": False,
        "mcp_envelope": None,
    }
    assert out["trace"][-1]["repo"] == "lab-verify"
    assert out["trace"][-1]["layer"] == "L4"
    assert out["trace"][-1]["status"] == "BLOCK"
    assert out["bottom_reasoning_traces"][-1]["invariant"] == INVARIANT_NAME


def test_mint_for_compiled_stepbot_binds_exact_python_sha256() -> None:
    expected_sha = hashlib.sha256(SAMPLE_COMPILED_STEPBOT_PY.encode("utf-8")).hexdigest()
    bounds = {
        "deck_slots": [1, 2, 3],
        "max_transfer_ul": 100.0,
        "api_level": "2.16",
    }

    # Simulate two-stage wire flow: rehearsal -> lab-verify -> stepbot.compile_stage -> mint_for_compiled_stepbot
    stage1 = process_packet(
        {
            "sql_query": "SELECT protocol, AVG(yield_pct) FROM experiments WHERE status = 'done' GROUP BY protocol",
            "mcp_secret_key": "stepbot-wire-secret",
            "deck_epoch": 2,
            "rehearsal": {"protocol_yaml_dict": {"steps": [{"action": "transfer"}]}},
        }
    )
    assert stage1["halted"] is False
    assert stage1["verification"]["mcp_envelope"]["protocol_sha256"] != expected_sha

    stage1["stepbot_compiled"] = {
        "python_code": SAMPLE_COMPILED_STEPBOT_PY,
        "protocol_sha256": expected_sha,
        "envelope_bounds": bounds,
    }
    stage2 = mint_for_compiled_stepbot(stage1)

    assert stage2["halted"] is False
    assert stage2["verification"]["sql_passed"] is True
    env = stage2["verification"]["mcp_envelope"]
    assert env["protocol_sha256"] == expected_sha
    assert env["token_epoch"] == 2
    assert env["lean_proof_valid"] is True
    assert env["envelope_bounds"] == bounds

    # Verify the minted token passes stateful LeanMcpGate hardware verification on exact python_code
    hw_gate = LeanMcpGate(
        secret_key="stepbot-wire-secret",
        initial_deck_epoch=2,
        check_lean_kernel=False,
    )
    hw_verdict = hw_gate.verify(
        env,
        actual_protocol=SAMPLE_COMPILED_STEPBOT_PY,
        mutates_deck_state=True,
    )
    assert hw_verdict.passed is True
    assert hw_gate.current_deck_epoch == 3

    # Trace and bottom_reasoning_traces remain single-entry per repo on re-mint
    assert len(stage2["trace"]) == 1
    assert stage2["trace"][0]["status"] == "PASS"
    assert len(stage2["bottom_reasoning_traces"]) == 1


def test_mint_for_compiled_stepbot_blocks_mutating_sql_and_validates_input() -> None:
    blocked = mint_for_compiled_stepbot(
        {
            "sql_query": "DROP TABLE samples",
            "stepbot_compiled": {
                "python_code": SAMPLE_COMPILED_STEPBOT_PY,
                "envelope_bounds": {"deck_slots": [1, 2, 3], "max_transfer_ul": 100.0, "api_level": "2.16"},
            },
        }
    )
    assert blocked["halted"] is True
    assert blocked["halt_reason"] == "L4_VERIFY_SQL_BLOCK"
    assert blocked["verification"] == {"sql_passed": False, "mcp_envelope": None}
    assert blocked["trace"][-1]["status"] == "BLOCK"

    with pytest.raises(ValueError, match="stepbot_compiled"):
        mint_for_compiled_stepbot({"sql_query": "SELECT COUNT(*) FROM samples"})


def test_halted_packet_passthrough_unchanged() -> None:
    upstream_halted = {
        "schema_version": WIRE_SCHEMA_VERSION,
        "halted": True,
        "halt_reason": "L2_SPEECH_PRIVACY_BLOCK",
        "sql_query": "DROP TABLE samples",
        "trace": [{"repo": "lab-ears", "layer": "L2", "status": "BLOCK", "summary": "speech band"}],
        "bottom_reasoning_traces": [],
    }

    out1 = process_packet(upstream_halted)
    assert out1 == upstream_halted
    assert out1 is not upstream_halted
    assert "verification" not in out1

    out2 = mint_for_compiled_stepbot(upstream_halted)
    assert out2 == upstream_halted
    assert "verification" not in out2


def test_issue_28_unsafe_python_import_and_failed_rehearsal_blocked() -> None:
    # 1. Exact reproducer from Issue #28: forbidden `import os` script MUST be blocked, never minted
    unsafe_pkt = process_packet(
        {
            "compiled_python_code": "import os\nos.system('echo unsafe')\n",
            "is_frontier_exception": True,
            "deck_epoch": 2,
        }
    )
    assert unsafe_pkt["halted"] is True
    assert unsafe_pkt["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"
    assert unsafe_pkt["verification"]["sql_passed"] is True
    assert unsafe_pkt["verification"]["mcp_envelope"] is None
    assert unsafe_pkt["trace"][-1]["status"] == "BLOCK"

    # 2. Routine packet with empty steps or failed rehearsal halts with L4_VERIFY_PROTOCOL_BLOCK
    empty_steps_pkt = process_packet(
        {
            "deck_epoch": 1,
            "rehearsal": {"protocol_yaml_dict": {"steps": []}},
        }
    )
    assert empty_steps_pkt["halted"] is True
    assert empty_steps_pkt["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"

    failed_rehearsal_pkt = process_packet(
        {
            "deck_epoch": 1,
            "rehearsal": {
                "passed": False,
                "protocol_yaml_dict": {"steps": [{"action": "transfer", "volume": 100.0}]},
            },
        }
    )
    assert failed_rehearsal_pkt["halted"] is True
    assert failed_rehearsal_pkt["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"

    # 3. Unsigned frontier exception without deferral blocks autonomously
    unsigned_frontier = process_packet(
        {
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "is_frontier_exception": True,
            "deck_epoch": 2,
        }
    )
    assert unsigned_frontier["halted"] is True
    assert unsigned_frontier["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"
    assert unsigned_frontier["verification"]["mcp_envelope"] is None


def test_issue_28_overnight_frontier_deferral_and_daytime_cosign_release(tmp_path: Path) -> None:
    shared_secret = "overnight-wire-stepbot-secret"
    supervisor_secret = "overnight-wire-supervisor-secret"
    state_path = tmp_path / "wire_mcp_state.json"
    gate = LeanMcpGate(
        secret_key=shared_secret,
        supervisor_secret_key=supervisor_secret,
        initial_deck_epoch=1,
        check_lean_kernel=False,
        state_path=state_path,
    )
    stepbot_src = REPO_ROOT.parent / "stepbot" / "src"
    compiled_script = SAMPLE_COMPILED_STEPBOT_PY
    if stepbot_src.is_dir():
        if str(stepbot_src) not in sys.path:
            sys.path.insert(0, str(stepbot_src))
        from stepbot import compile_file  # type: ignore[import-not-found]

        compiled_script = compile_file(
            REPO_ROOT.parent / "stepbot" / "examples" / "dilution_series.yaml"
        )

    expected_sha = compute_protocol_sha256(compiled_script)

    # 1. 02:00 AM overnight: out-of-regime frontier packet arrives and is parked non-blockingly
    frontier_req = {
        "mcp_secret_key": shared_secret,
        "mcp_nonce": "overnight-wire-frontier-01",
        "decision": {"is_frontier_exception": True},
        "stepbot_compiled": {
            "python_code": compiled_script,
            "protocol_sha256": expected_sha,
        },
    }
    deferred_pkt = mint_for_compiled_stepbot(
        frontier_req,
        mcp_gate=gate,
        defer_unsigned_frontier=True,
    )
    assert deferred_pkt["halted"] is True
    assert deferred_pkt["halt_reason"] == "L4_VERIFY_FRONTIER_DEFERRED"
    assert deferred_pkt["verification"]["frontier_deferred"] is True
    assert deferred_pkt["verification"]["deferred_nonce"] == "overnight-wire-frontier-01"
    assert len(gate.deferred_daytime_queue) == 1
    assert gate.current_deck_epoch == 1

    # 2. Routine overnight jobs execute autonomously, advancing physical deck_epoch 1 -> 3
    for idx in (1, 2):
        routine_pkt = mint_for_compiled_stepbot(
            {
                "mcp_secret_key": shared_secret,
                "mcp_nonce": f"overnight-routine-{idx}",
                "stepbot_compiled": {
                    "python_code": compiled_script,
                },
            },
            mcp_gate=gate,
        )
        assert routine_pkt["halted"] is False
        assert (
            gate.verify(
                routine_pkt["verification"]["mcp_envelope"],
                actual_protocol=compiled_script,
                mutates_deck_state=True,
            ).passed
            is True
        )
    assert gate.current_deck_epoch == 3

    # 3. 09:00 AM daytime: human supervisor co-signs and releases parked packet bound to epoch 3
    released_pkt = cosign_and_release_for_stepbot(
        gate,
        "overnight-wire-frontier-01",
        supervisor_id="dr_elena_rostova",
    )
    assert released_pkt["halted"] is False
    assert released_pkt["halt_reason"] is None
    assert released_pkt["deck_epoch"] == 3
    assert released_pkt["trace"][-1]["status"] == "PASS"
    assert len(gate.deferred_daytime_queue) == 0

    released_env = released_pkt["verification"]["mcp_envelope"]
    assert released_env["token_epoch"] == 3
    assert released_env["protocol_sha256"] == expected_sha
    assert released_env["is_frontier_exception"] is True
    assert released_env["human_supervisor_signed"] is True
    assert released_env["human_supervisor_id"] == "dr_elena_rostova"

    # Also verify direct packet-based cosign_deferred_packet(deferred_pkt, ...) helper
    direct_released = cosign_deferred_packet(
        deferred_pkt,
        supervisor_id="dr_elena_rostova",
        supervisor_secret_key=supervisor_secret,
        current_deck_epoch=3,
        new_nonce="daytime-direct-release-02",
    )
    assert direct_released["halted"] is False
    assert direct_released["verification"]["mcp_envelope"]["token_epoch"] == 3
    assert (
        verify_mcp_envelope(
            direct_released["verification"]["mcp_envelope"],
            secret_key=shared_secret,
            supervisor_secret_key=supervisor_secret,
            current_deck_epoch=3,
            actual_protocol=compiled_script,
            check_lean_kernel=False,
        ).passed
        is True
    )

    # 4. End-to-end dispatch into sibling stepbot.StepbotMcpExecutor when available
    if stepbot_src.is_dir():
        from stepbot import StepbotMcpExecutor  # type: ignore[import-not-found]

        executor = StepbotMcpExecutor(
            secret_key=shared_secret,
            current_deck_epoch=3,
            use_mock=True,
        )
        receipt = executor.dispatch(
            released_pkt["stepbot_compiled"]["python_code"],
            released_env,
        )
        assert receipt["ok"] is True
        assert executor.current_deck_epoch == 4


def test_issue_34_wire_blocks_empty_packet_self_declared_cosign_dev_key_and_supports_db_path(
    tmp_path: Path,
) -> None:
    import sqlite3

    # 1. Empty packet carries no protocol -> blocked (never mints lean_proof_valid: true)
    empty_out = process_packet({})
    assert empty_out["halted"] is True
    assert empty_out["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"
    assert empty_out["verification"]["mcp_envelope"] is None
    assert empty_out["verification"]["static_check_passed"] is False

    # 2. Missing explicit secret_key or public dev key is blocked unless allow_insecure_dev_key=True
    dev_key_out = process_packet(
        {
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "mcp_secret_key": autolab_wire.DEFAULT_MCP_SECRET,
        }
    )
    assert dev_key_out["halted"] is True
    assert dev_key_out["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"
    assert dev_key_out["verification"]["mcp_envelope"] is None

    # 3. Packet-level self-declared human_supervisor_signed without verifiable supervisor signature is blocked
    self_cosigned = process_packet(
        {
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "mcp_secret_key": "explicit-wire-minter-key",
            "is_frontier_exception": True,
            "human_supervisor_signed": True,
            "human_supervisor_id": "self_declared_agent",
        }
    )
    assert self_cosigned["halted"] is True
    assert self_cosigned["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"
    assert self_cosigned["verification"]["mcp_envelope"] is None

    # Same secret for minter and supervisor is also rejected (role separation)
    same_secret_cosigned = process_packet(
        {
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "mcp_secret_key": "same-secret-key",
            "mcp_supervisor_secret_key": "same-secret-key",
            "is_frontier_exception": True,
            "human_supervisor_signed": True,
            "human_supervisor_id": "self_declared_agent",
        }
    )
    assert same_secret_cosigned["halted"] is True
    assert same_secret_cosigned["halt_reason"] == "L4_VERIFY_PROTOCOL_BLOCK"

    # Distinct cryptographic supervisor secret passes and verifies only with both keys
    valid_cosigned = process_packet(
        {
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "mcp_secret_key": "explicit-wire-minter-key",
            "mcp_supervisor_secret_key": "distinct-wire-supervisor-key",
            "is_frontier_exception": True,
            "human_supervisor_signed": True,
            "human_supervisor_id": "dr_rostova",
            "deck_epoch": 5,
        }
    )
    assert valid_cosigned["halted"] is False
    assert (
        verify_mcp_envelope(
            valid_cosigned["verification"]["mcp_envelope"],
            secret_key="explicit-wire-minter-key",
            supervisor_secret_key="distinct-wire-supervisor-key",
            current_deck_epoch=5,
            actual_protocol=SAMPLE_COMPILED_STEPBOT_PY,
        ).passed
        is True
    )
    assert (
        verify_mcp_envelope(
            valid_cosigned["verification"]["mcp_envelope"],
            secret_key="explicit-wire-minter-key",
            current_deck_epoch=5,
            actual_protocol=SAMPLE_COMPILED_STEPBOT_PY,
        ).passed
        is False
    )

    # 4. Custom SQLite db_path allows domain tables such as `plates`
    custom_db = tmp_path / "custom_lims.sqlite"
    con = sqlite3.connect(custom_db)
    con.execute("CREATE TABLE plates (id INTEGER PRIMARY KEY, barcode TEXT)")
    con.executemany("INSERT INTO plates VALUES (?, ?)", [(1, "PLT-001"), (2, "PLT-002")])
    con.commit()
    con.close()

    custom_out = process_packet(
        {
            "sql_query": "SELECT COUNT(*) FROM plates",
            "compiled_python_code": SAMPLE_COMPILED_STEPBOT_PY,
            "mcp_secret_key": "custom-db-wire-secret",
            "deck_epoch": 1,
        },
        db_path=custom_db,
    )
    assert custom_out["halted"] is False
    assert custom_out["verification"]["sql_passed"] is True
    assert custom_out["verification"]["static_check_passed"] is True
    assert custom_out["verification"]["mcp_envelope"] is not None


def test_pure_english_across_wire_and_docs() -> None:
    for path in (
        Path(autolab_wire.__file__).resolve(),
        Path(__file__).resolve(),
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "ARCHITECTURE_AND_HISTORY.md",
    ):
        content = path.read_text(encoding="utf-8")
        assert CJK_RE.search(content) is None, f"Unexpected CJK character in {path}"
