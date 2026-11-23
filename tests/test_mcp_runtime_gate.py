"""Unit, adversarial, and CLI integration tests for `lab_verify.mcp_gate` (`lean-mcp/v1`)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify import (  # noqa: E402
    LEAN_MCP_SCHEMA_VERSION,
    LeanMcpEnvelope,
    LeanMcpGate,
    Verdict,
    VerifyVerdict,
    compute_protocol_sha256,
    mint_mcp_envelope,
    verify,
    verify_mcp_envelope,
)
from lab_verify.cli import main as cli_main  # noqa: E402

CJK_RE = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")

SAMPLE_PROTOCOL_STEPS = [
    {"op": "pick_up_tip"},
    {"op": "aspirate", "loc": "res:1", "vol": 100.0},
    {"op": "dispense", "loc": "plate:A1", "vol": 100.0},
    {"op": "drop_tip"},
]

SAMPLE_OPENTRONS_PY = '''metadata = {
    "protocolName": "Routine Plate Transfer",
    "apiLevel": "2.16",
}


def run(protocol):
    plate = protocol.load_labware('corning_96_wellplate_360ul_flat', 1)
    reservoir = protocol.load_labware('nest_12_reservoir_15ml', 2)
    tips = protocol.load_labware('opentrons_96_tiprack_300ul', 4)
    pipette_left = protocol.load_instrument('p300_single_gen2', 'left', tip_racks=[tips])
    pipette_left.transfer(100, reservoir["A1"], plate["A1"], new_tip='once')
'''


def test_zero_click_routine_envelope_pass_and_unified_verify() -> None:
    secret = "test-shared-secret-key-01"
    env = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        secret_key=secret,
        token_epoch=1,
        nonce="routine-001",
    )
    assert env.schema_version == LEAN_MCP_SCHEMA_VERSION
    assert env.lean_proof_valid is True
    assert env.is_frontier_exception is False
    assert env.human_supervisor_signed is False
    assert env.envelope_bounds["deck_slots"] == [1, 2, 4]
    assert env.envelope_bounds["max_transfer_ul"] == 100.0
    assert env.envelope_bounds["api_level"] == "2.16"

    verdict = verify_mcp_envelope(
        env,
        secret_key=secret,
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
    )
    assert isinstance(verdict, Verdict)
    assert isinstance(verdict, VerifyVerdict)
    assert verdict.passed is True
    assert verdict.layer is None

    # Unified lab_verify.verify("mcp", ...) entry point
    v2 = verify("mcp", env.to_dict(), secret_key=secret, current_deck_epoch=1)
    assert v2.passed is True


def test_stale_epoch_replay_blocked_after_deck_mutation() -> None:
    gate = LeanMcpGate(secret_key="epoch-secret", initial_deck_epoch=3)
    env = gate.mint(SAMPLE_PROTOCOL_STEPS, nonce="epoch3-call")

    first = gate.verify(env, actual_protocol=SAMPLE_PROTOCOL_STEPS, mutates_deck_state=True)
    assert first.passed is True
    assert gate.current_deck_epoch == 4

    # Replaying the epoch-3 token against updated deck epoch 4 must fail at mcp_epoch_freshness
    replay = gate.verify(env, actual_protocol=SAMPLE_PROTOCOL_STEPS)
    assert replay.passed is False
    assert replay.layer == "mcp_epoch_freshness"


def test_same_epoch_nonce_replay_blocked() -> None:
    gate = LeanMcpGate(secret_key="nonce-secret", initial_deck_epoch=1)
    env = gate.mint(SAMPLE_PROTOCOL_STEPS, nonce="single-use-nonce-77")

    ok = gate.verify(env, actual_protocol=SAMPLE_PROTOCOL_STEPS, mutates_deck_state=False)
    assert ok.passed is True
    assert gate.current_deck_epoch == 1
    assert "single-use-nonce-77" in gate.consumed_nonces

    dup = gate.verify(env, actual_protocol=SAMPLE_PROTOCOL_STEPS, mutates_deck_state=False)
    assert dup.passed is False
    assert dup.layer == "mcp_nonce_single_use"


def test_hmac_tampering_on_any_envelope_field_blocked() -> None:
    secret = "hmac-integrity-secret"
    env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key=secret, token_epoch=2, nonce="n-hmac")

    for field_name, forged_val in [
        ("token_epoch", 99),
        ("lean_proof_valid", False),
        ("human_supervisor_signed", True),
        ("envelope_bounds", {"deck_slots": [1, 2, 4], "max_transfer_ul": 999.0, "api_level": "2.16"}),
    ]:
        tampered = env.to_dict()
        tampered[field_name] = forged_val
        verdict = verify_mcp_envelope(tampered, secret_key=secret, current_deck_epoch=2)
        assert verdict.passed is False
        assert verdict.layer == "mcp_hmac_authentic"

    # Wrong secret key also fails HMAC check
    wrong_key = verify_mcp_envelope(env, secret_key="attacker-guessed-key", current_deck_epoch=2)
    assert wrong_key.passed is False
    assert wrong_key.layer == "mcp_hmac_authentic"


def test_payload_sha256_mismatch_blocks_post_verification_script_swap() -> None:
    secret = "payload-binding-secret"
    env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key=secret, token_epoch=1, nonce="bind-1")

    swapped_script = SAMPLE_OPENTRONS_PY.replace("transfer(100,", "transfer(250,")
    assert compute_protocol_sha256(swapped_script) != env.protocol_sha256

    verdict = verify_mcp_envelope(
        env,
        secret_key=secret,
        current_deck_epoch=1,
        actual_protocol=swapped_script,
    )
    assert verdict.passed is False
    assert verdict.layer == "mcp_payload_binding"


def test_unsigned_frontier_exception_denied_by_default() -> None:
    gate = LeanMcpGate(secret_key="frontier-secret", initial_deck_epoch=1)
    unsigned_frontier = gate.mint(
        SAMPLE_OPENTRONS_PY,
        nonce="frontier-raw",
        lean_proof_valid=False,
        is_frontier_exception=True,
        human_supervisor_signed=False,
    )
    verdict = gate.verify(unsigned_frontier, actual_protocol=SAMPLE_OPENTRONS_PY)
    assert verdict.passed is False
    assert verdict.layer == "mcp_proof_or_cosigned_exception"
    assert len(gate.deferred_daytime_queue) == 0


def test_overnight_frontier_deferral_and_daytime_human_cosign_release() -> None:
    gate = LeanMcpGate(secret_key="overnight-secret", initial_deck_epoch=1)

    # 1. 02:00 AM overnight: agent proposes an unsigned OOD frontier probe -> parked without crashing queue
    frontier_env = gate.mint(
        SAMPLE_OPENTRONS_PY,
        nonce="overnight-frontier-01",
        lean_proof_valid=False,
        is_frontier_exception=True,
        human_supervisor_signed=False,
    )
    deferred = gate.verify(
        frontier_env,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        mutates_deck_state=True,
        defer_unsigned_frontier=True,
    )
    assert deferred.passed is False
    assert deferred.layer == "mcp_deferred_daytime_review"
    assert len(gate.deferred_daytime_queue) == 1
    assert gate.current_deck_epoch == 1  # Not executed yet, so deck state untouched

    # 2. 02:05 AM overnight: certified routine transfer continues autonomously (zero-click!) -> epoch 1 -> 2
    routine_env = gate.mint(
        SAMPLE_PROTOCOL_STEPS,
        nonce="overnight-routine-02",
    )
    routine_ok = gate.verify(
        routine_env,
        actual_protocol=SAMPLE_PROTOCOL_STEPS,
        mutates_deck_state=True,
        defer_unsigned_frontier=True,
    )
    assert routine_ok.passed is True
    assert gate.current_deck_epoch == 2

    # 3. 09:00 AM daytime: human supervisor inspects current deck (epoch 2) and co-signs deferred call
    cosigned = gate.cosign_deferred_exception(
        "overnight-frontier-01",
        supervisor_id="dr_elena_rostova",
    )
    assert len(gate.deferred_daytime_queue) == 0
    assert cosigned.token_epoch == 2
    assert cosigned.human_supervisor_signed is True
    assert cosigned.human_supervisor_id == "dr_elena_rostova"

    released = gate.verify(
        cosigned,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        mutates_deck_state=True,
    )
    assert released.passed is True
    assert gate.current_deck_epoch == 3


def test_malformed_schema_and_type_confusion_rejected() -> None:
    env = mint_mcp_envelope(SAMPLE_PROTOCOL_STEPS, secret_key="schema-sec", nonce="s1")
    base = env.to_dict()

    wrong_ver = {**base, "schema_version": "lean-mcp/v0"}
    assert verify_mcp_envelope(wrong_ver, secret_key="schema-sec").layer == "mcp_schema"

    bool_epoch = {**base, "token_epoch": True}
    assert verify_mcp_envelope(bool_epoch, secret_key="schema-sec").layer == "mcp_schema"

    missing_nonce = {k: v for k, v in base.items() if k != "nonce"}
    assert verify_mcp_envelope(missing_nonce, secret_key="schema-sec").layer == "mcp_schema"

    with pytest.raises(ValueError, match="supervisor_id"):
        LeanMcpGate().cosign_deferred_exception(supervisor_id="   ")


def test_pure_python_fallback_when_lean_kernel_binary_absent(tmp_path: Path) -> None:
    missing_bin = tmp_path / "nonexistent-autolab-lean"
    env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key="fallback-sec", token_epoch=5)

    v_pass = verify_mcp_envelope(
        env,
        secret_key="fallback-sec",
        current_deck_epoch=5,
        check_lean_kernel=True,
        lean_kernel_bin=missing_bin,
    )
    assert v_pass.passed is True

    v_stale = verify_mcp_envelope(
        env,
        secret_key="fallback-sec",
        current_deck_epoch=6,
        check_lean_kernel=True,
        lean_kernel_bin=missing_bin,
    )
    assert v_stale.passed is False
    assert v_stale.layer == "mcp_epoch_freshness"


def test_cross_repo_wire_compatibility_with_stepbot_if_present() -> None:
    stepbot_src = REPO_ROOT.parent / "stepbot" / "src"
    if not stepbot_src.is_dir():
        pytest.skip("Sibling stepbot repository not present in isolated CI environment")
    if str(stepbot_src) not in sys.path:
        sys.path.insert(0, str(stepbot_src))

    from stepbot import StepbotMcpExecutor, compile_file  # type: ignore[import-not-found]

    shared_secret = "lab-verify-to-stepbot-e2e-key"
    compiled_py = compile_file(REPO_ROOT.parent / "stepbot" / "examples" / "dilution_series.yaml")
    minted = mint_mcp_envelope(compiled_py, secret_key=shared_secret, token_epoch=1, nonce="lv-to-sb-1")

    executor = StepbotMcpExecutor(secret_key=shared_secret, current_deck_epoch=1, use_mock=True)
    receipt = executor.dispatch(compiled_py, minted.to_dict())
    assert receipt["ok"] is True
    assert executor.current_deck_epoch == 2


def test_cli_mcp_mint_and_mcp_verify_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    proto_file = tmp_path / "transfer_run.py"
    proto_file.write_text(SAMPLE_OPENTRONS_PY, encoding="utf-8")
    env_file = tmp_path / "envelope.json"

    rc_mint = cli_main(
        [
            "mcp-mint",
            "--protocol",
            str(proto_file),
            "--epoch",
            "7",
            "--secret-key",
            "cli-secret-99",
            "--nonce",
            "cli-nonce-1",
            "--output",
            str(env_file),
        ]
    )
    assert rc_mint == 0
    assert env_file.exists()
    capsys.readouterr()

    rc_ok = cli_main(
        [
            "mcp-verify",
            str(env_file),
            "--protocol",
            str(proto_file),
            "--epoch",
            "7",
            "--secret-key",
            "cli-secret-99",
            "--json",
        ]
    )
    assert rc_ok == 0
    verdict_json = json.loads(capsys.readouterr().out)
    assert verdict_json["passed"] is True

    # Stale epoch on CLI returns exit code 1
    rc_stale = cli_main(
        [
            "mcp-verify",
            str(env_file),
            "--protocol",
            str(proto_file),
            "--epoch",
            "8",
            "--secret-key",
            "cli-secret-99",
        ]
    )
    assert rc_stale == 1
    assert "mcp_epoch_freshness" in capsys.readouterr().out


def test_cli_flag_mode_and_subprocess_invocation(tmp_path: Path) -> None:
    proto_json = tmp_path / "bench_proto.json"
    proto_json.write_text(json.dumps(SAMPLE_PROTOCOL_STEPS), encoding="utf-8")
    env_file = tmp_path / "flag_env.json"

    env_vars = {**os.environ, "PYTHONPATH": str(SRC_DIR), "LEAN_MCP_SECRET_KEY": "env-var-secret"}
    mint_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "lab_verify.cli",
            "--mcp-mint",
            str(proto_json),
            "--mcp-epoch",
            "4",
            "--mcp-output",
            str(env_file),
        ],
        env=env_vars,
        capture_output=True,
        text=True,
        check=True,
    )
    assert mint_proc.returncode == 0
    assert env_file.exists()

    verify_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "lab_verify.cli",
            "--mcp-verify",
            str(env_file),
            "--mcp-protocol",
            str(proto_json),
            "--mcp-epoch",
            "4",
            "--json",
        ],
        env=env_vars,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(verify_proc.stdout)["passed"] is True


def test_pure_english_across_mcp_gate_files() -> None:
    paths = [
        REPO_ROOT / "src" / "lab_verify" / "mcp_gate.py",
        REPO_ROOT / "src" / "lab_verify" / "cli.py",
        REPO_ROOT / "src" / "lab_verify" / "__init__.py",
        REPO_ROOT / "src" / "lab_verify" / "verdict.py",
        REPO_ROOT / "lean" / "LabVerifyLean.lean",
        REPO_ROOT / "README.md",
        Path(__file__).resolve(),
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert CJK_RE.search(text) is None, f"Unexpected CJK character in {path}"
