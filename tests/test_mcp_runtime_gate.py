"""Unit, adversarial, and CLI integration tests for `lab_verify.mcp_gate` (`lean-mcp/v1`)."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
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
    AUTH_MODE_ED25519,
    LEAN_MCP_SCHEMA_VERSION,
    LeanMcpEnvelope,
    LeanMcpGate,
    McpStateStore,
    Verdict,
    VerifyVerdict,
    compute_protocol_sha256,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    mint_mcp_envelope,
    sign_supervisor_cosignature,
    verify,
    verify_lean,
    verify_mcp_envelope,
)
from lab_verify.cli import main as cli_main  # noqa: E402
from lab_verify.mcp_gate import (  # noqa: E402
    _pure_ed25519_pubkey,
    _pure_ed25519_sign,
    _pure_ed25519_verify,
)

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
    v2 = verify(
        "mcp",
        env.to_dict(),
        secret_key=secret,
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
    )
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
    gate = LeanMcpGate(
        secret_key="overnight-secret",
        supervisor_secret_key="overnight-supervisor-secret",
        initial_deck_epoch=1,
    )

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
        LeanMcpGate(secret_key="schema-sec").cosign_deferred_exception(supervisor_id="   ")


def test_lean_kernel_check_fails_closed_when_binary_absent(tmp_path: Path) -> None:
    missing_bin = tmp_path / "nonexistent-autolab-lean"
    env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key="fallback-sec", token_epoch=5)

    v_missing = verify_mcp_envelope(
        env,
        secret_key="fallback-sec",
        current_deck_epoch=5,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        check_lean_kernel=True,
        lean_kernel_bin=missing_bin,
    )
    assert v_missing.passed is False
    assert v_missing.layer == "mcp_lean_kernel"
    assert "not found" in v_missing.reason

    v_stale = verify_mcp_envelope(
        env,
        secret_key="fallback-sec",
        current_deck_epoch=6,
        actual_protocol=SAMPLE_OPENTRONS_PY,
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


def _race_verify_worker(args: tuple[str, str, str]) -> tuple[bool, str | None]:
    env_path_str, state_path_str, secret = args
    gate = LeanMcpGate(
        secret_key=secret,
        initial_deck_epoch=1,
        check_lean_kernel=False,
        state_path=Path(state_path_str),
    )
    v = gate.verify(Path(env_path_str), actual_protocol=SAMPLE_OPENTRONS_PY, mutates_deck_state=True)
    return v.passed, v.layer


def test_issue_24_ed25519_pure_python_and_backend_bit_parity() -> None:
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    # RFC 8032 Section 7.1 Test Vector 1 (empty message)
    expected_pub_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    expected_sig_hex = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    pub = _pure_ed25519_pubkey(seed)
    sig = _pure_ed25519_sign(seed, b"")
    assert pub.hex() == expected_pub_hex
    assert sig.hex() == expected_sig_hex
    assert _pure_ed25519_verify(pub, b"", sig) is True
    assert ed25519_sign(seed, b"") == expected_sig_hex
    assert ed25519_verify(expected_pub_hex, b"", expected_sig_hex) is True
    assert ed25519_verify(expected_pub_hex, b"tampered", expected_sig_hex) is False


def test_issue_24_ed25519_role_separation_and_compromised_verifier() -> None:
    minter_priv, minter_pub = generate_ed25519_keypair()
    sup_priv, sup_pub = generate_ed25519_keypair()
    assert minter_pub != sup_pub

    # 1. Verifier-only hardware gate (e.g. stepbot) holds ONLY public keys -> cannot mint!
    verifier_gate = LeanMcpGate(
        auth_mode=AUTH_MODE_ED25519,
        minter_public_key=minter_pub,
        supervisor_public_key=sup_pub,
        initial_deck_epoch=1,
        check_lean_kernel=False,
    )
    with pytest.raises(PermissionError):
        verifier_gate.mint(SAMPLE_OPENTRONS_PY, nonce="compromised-verifier-attempt")

    # 2. Routine Ed25519 envelope signed by L4 minter private key passes public-key verifier
    routine_env = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        minter_private_key=minter_priv,
        minter_key_id="l4-minter-k1",
        token_epoch=1,
        nonce="ed-routine-01",
    )
    assert routine_env.auth_mode == AUTH_MODE_ED25519
    assert len(routine_env.minter_ed25519_sig) == 128
    v_routine = verifier_gate.verify(routine_env, actual_protocol=SAMPLE_OPENTRONS_PY)
    assert v_routine.passed is True

    # 3. Autonomous minter CANNOT self-sign a frontier exception without supervisor private key
    with pytest.raises(PermissionError):
        mint_mcp_envelope(
            SAMPLE_OPENTRONS_PY,
            minter_private_key=minter_priv,
            token_epoch=1,
            nonce="ed-forged-frontier-1",
            is_frontier_exception=True,
            human_supervisor_signed=True,
            human_supervisor_id="forged_pi",
        )
    with pytest.raises(ValueError, match="distinct"):
        mint_mcp_envelope(
            SAMPLE_OPENTRONS_PY,
            minter_private_key=minter_priv,
            supervisor_private_key=minter_priv,
            token_epoch=1,
            nonce="ed-same-key-frontier",
            is_frontier_exception=True,
            human_supervisor_signed=True,
            human_supervisor_id="self_signed_agent",
        )

    # Even if minter manually signs bogus supervisor_ed25519_sig bytes with its own key, verifier blocks it!
    bogus_sup_sig = sign_supervisor_cosignature(
        minter_priv,
        nonce="ed-self-cosign",
        token_epoch=1,
        protocol_sha256=compute_protocol_sha256(SAMPLE_OPENTRONS_PY),
        envelope_bounds=routine_env.envelope_bounds,
    )
    forged_env = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        minter_private_key=minter_priv,
        supervisor_ed25519_sig=bogus_sup_sig,
        token_epoch=1,
        nonce="ed-self-cosign",
        lean_proof_valid=False,
        is_frontier_exception=True,
        human_supervisor_signed=True,
        human_supervisor_id="forged_pi",
    )
    v_forged = verifier_gate.verify(forged_env, actual_protocol=SAMPLE_OPENTRONS_PY)
    assert v_forged.passed is False
    assert v_forged.layer == "mcp_proof_or_cosigned_exception"

    # 4. Detached human supervisor Ed25519 signature under distinct sup_priv passes!
    valid_sup_sig = sign_supervisor_cosignature(
        sup_priv,
        nonce="ed-valid-cosign",
        token_epoch=1,
        protocol_sha256=compute_protocol_sha256(SAMPLE_OPENTRONS_PY),
        envelope_bounds=routine_env.envelope_bounds,
    )
    cosigned_env = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        minter_private_key=minter_priv,
        supervisor_ed25519_sig=valid_sup_sig,
        supervisor_key_id="pi-yubikey-01",
        token_epoch=1,
        nonce="ed-valid-cosign",
        lean_proof_valid=False,
        is_frontier_exception=True,
        human_supervisor_signed=True,
        human_supervisor_id="dr_rostova",
    )
    v_cosigned = verifier_gate.verify(cosigned_env, actual_protocol=SAMPLE_OPENTRONS_PY)
    assert v_cosigned.passed is True


def test_issue_24_require_explicit_key_policy_and_default_wire_keys() -> None:
    # Default hmac-sha256 envelope keeps exact 11 keys for 100% stepbot wire compatibility
    default_env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key="explicit-prod-secret", token_epoch=1)
    assert set(default_env.to_dict().keys()) == {
        "schema_version",
        "tool_name",
        "protocol_sha256",
        "token_epoch",
        "nonce",
        "lean_proof_valid",
        "is_frontier_exception",
        "human_supervisor_signed",
        "human_supervisor_id",
        "envelope_bounds",
        "hmac_sha256",
    }

    # Strict key policy rejects DEFAULT_MCP_SECRET_KEY unless allow_insecure_dev_key=True
    with pytest.raises(ValueError, match="DEFAULT_MCP_SECRET_KEY"):
        mint_mcp_envelope(
            SAMPLE_OPENTRONS_PY,
            require_explicit_key=True,
            allow_insecure_dev_key=False,
        )
    dev_env = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        require_explicit_key=True,
        allow_insecure_dev_key=True,
    )
    v_strict = verify_mcp_envelope(
        dev_env,
        require_explicit_key=True,
        allow_insecure_dev_key=False,
        check_lean_kernel=False,
    )
    assert v_strict.passed is False
    assert v_strict.layer == "mcp_hmac_authentic"


def test_issue_25_cli_persistent_state_blocks_replays_and_tracks_epoch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proto = tmp_path / "transfer.py"
    proto.write_text("def run(protocol):\n    pass\n", encoding="utf-8")
    env_json = tmp_path / "envelope.json"
    state_file = tmp_path / "mcp_state.json"
    cli_sec = "persistent-state-cli-secret"

    assert (
        cli_main(
            [
                "mcp-mint",
                "--protocol",
                str(proto),
                "--secret-key",
                cli_sec,
                "--state",
                str(state_file),
                "--nonce",
                "once-only-42",
                "-o",
                str(env_json),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Stateless dry-run inspects without consuming the single-use nonce
    assert (
        cli_main(
            [
                "mcp-verify",
                str(env_json),
                "--protocol",
                str(proto),
                "--secret-key",
                cli_sec,
                "--state",
                str(state_file),
                "--stateless-dry-run",
            ]
        )
        == 0
    )
    capsys.readouterr()

    # First real stateful CLI verification succeeds and consumes nonce
    assert (
        cli_main(
            [
                "mcp-verify",
                str(env_json),
                "--protocol",
                str(proto),
                "--secret-key",
                cli_sec,
                "--state",
                str(state_file),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Second CLI invocation replaying the exact same JSON fails at mcp_nonce_single_use!
    rc_replay = cli_main(
        [
            "mcp-verify",
            str(env_json),
            "--protocol",
            str(proto),
            "--secret-key",
            cli_sec,
            "--state",
            str(state_file),
            "--json",
        ]
    )
    assert rc_replay == 1
    replay_verdict = json.loads(capsys.readouterr().out)
    assert replay_verdict["passed"] is False
    assert replay_verdict["layer"] == "mcp_nonce_single_use"

    # State-mutating verification advances persistent current_deck_epoch 1 -> 2 across processes
    env_json_2 = tmp_path / "envelope2.json"
    assert (
        cli_main(
            [
                "mcp-mint",
                "--protocol",
                str(proto),
                "--secret-key",
                cli_sec,
                "--state",
                str(state_file),
                "--nonce",
                "mutate-epoch-1",
                "-o",
                str(env_json_2),
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "mcp-verify",
                str(env_json_2),
                "--protocol",
                str(proto),
                "--secret-key",
                cli_sec,
                "--state",
                str(state_file),
                "--mutates-deck-state",
            ]
        )
        == 0
    )
    capsys.readouterr()
    store = McpStateStore(state_file)
    assert store.load().current_deck_epoch == 2


def test_issue_25_multiprocess_race_and_bounded_nonces(tmp_path: Path) -> None:
    state_file = tmp_path / "race_state.json"
    env_file = tmp_path / "race_env.json"
    secret = "multiprocess-lock-secret"

    init_gate = LeanMcpGate(
        secret_key=secret,
        initial_deck_epoch=1,
        check_lean_kernel=False,
        state_path=state_file,
        max_consumed_nonces=5,
    )
    env = init_gate.mint(SAMPLE_OPENTRONS_PY, nonce="race-nonce-001")
    env_file.write_text(env.to_json(), encoding="utf-8")

    tasks = [(str(env_file), str(state_file), secret) for _ in range(8)]
    with ProcessPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(_race_verify_worker, tasks))

    wins = [ok for ok, _ in outcomes if ok]
    losses = [layer for ok, layer in outcomes if not ok]
    assert len(wins) == 1
    assert len(losses) == 7
    assert all(layer in ("mcp_nonce_single_use", "mcp_epoch_freshness") for layer in losses)

    # Verify bounded FIFO nonce eviction
    bounded_gate = LeanMcpGate(
        secret_key=secret,
        check_lean_kernel=False,
        state_path=state_file,
        max_consumed_nonces=5,
    )
    assert bounded_gate.current_deck_epoch == 2
    for i in range(10):
        e_i = bounded_gate.mint(SAMPLE_PROTOCOL_STEPS, nonce=f"bnonce-{i}")
        assert bounded_gate.verify(e_i, actual_protocol=SAMPLE_PROTOCOL_STEPS).passed is True
    assert len(bounded_gate.consumed_nonces) == 5
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert len(persisted["consumed_nonces"]) == 5


def test_issue_27_key_epoch_ttl_and_lean_kernel_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Revoked signing key epoch is rejected at mcp_key_epoch_active
    env_k1 = mint_mcp_envelope(
        SAMPLE_OPENTRONS_PY,
        secret_key="rot-sec",
        token_epoch=1,
        key_epoch=1,
        issued_at_unix=1000,
        ttl_seconds=600,
        cosigned_expires_at_unix=1500,
    )
    v_revoked = verify_mcp_envelope(
        env_k1,
        secret_key="rot-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        min_active_key_epoch=2,
        now_unix=1100,
        check_lean_kernel=False,
    )
    assert v_revoked.passed is False
    assert v_revoked.layer == "mcp_key_epoch_active"

    # 2. Unexpired key_epoch and TTL passes; expired TTL or cosigned_expires_at_unix fails
    v_ok = verify_mcp_envelope(
        env_k1,
        secret_key="rot-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        min_active_key_epoch=1,
        now_unix=1200,
        check_lean_kernel=False,
    )
    assert v_ok.passed is True

    v_cosign_exp = verify_mcp_envelope(
        env_k1,
        secret_key="rot-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        min_active_key_epoch=1,
        now_unix=1550,
        check_lean_kernel=False,
    )
    assert v_cosign_exp.passed is False
    assert v_cosign_exp.layer == "mcp_ttl_unexpired"

    v_ttl_exp = verify_mcp_envelope(
        env_k1,
        secret_key="rot-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        min_active_key_epoch=1,
        now_unix=1700,
        check_lean_kernel=False,
    )
    assert v_ttl_exp.passed is False
    assert v_ttl_exp.layer == "mcp_ttl_unexpired"

    # 3. Existing non-executable binary file fails closed on OSError instead of failing open!
    dummy_bin = tmp_path / "broken-autolab-lean.bin"
    dummy_bin.write_text("not an executable binary", encoding="utf-8")
    env_basic = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key="kern-sec", token_epoch=1)

    v_oserr = verify_mcp_envelope(
        env_basic,
        secret_key="kern-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        check_lean_kernel=True,
        lean_kernel_bin=dummy_bin,
    )
    assert v_oserr.passed is False
    assert v_oserr.layer == "mcp_lean_kernel"

    # 4. Hung Lean kernel binary raising TimeoutExpired is caught and fails closed at mcp_lean_kernel
    def _raise_timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="autolab-lean", timeout=0.05)

    monkeypatch.setattr("lab_verify.mcp_gate.subprocess.run", _raise_timeout)
    v_timeout = verify_mcp_envelope(
        env_basic,
        secret_key="kern-sec",
        current_deck_epoch=1,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        check_lean_kernel=True,
        lean_kernel_bin=dummy_bin,
        lean_kernel_timeout_s=0.05,
    )
    assert v_timeout.passed is False
    assert v_timeout.layer == "mcp_lean_kernel"
    assert "timed out" in v_timeout.reason

    # 5. LabVerifyLean.lean static proof check and theorem coverage
    lean_path = REPO_ROOT / "lean" / "LabVerifyLean.lean"
    lean_verdict = verify_lean(lean_path, static_only=True)
    assert lean_verdict.passed is True
    lean_src = lean_path.read_text(encoding="utf-8")
    for thm in (
        "revoked_key_epoch_always_denied",
        "expired_ttl_mcp_always_denied",
        "expired_cosign_mcp_always_denied",
        "cosigned_frontier_wire_envelope_soundness",
    ):
        assert f"theorem {thm}" in lean_src


def test_issue_34_fail_closed_defaults_and_volume_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from lab_verify import DEFAULT_MCP_SECRET_KEY, compute_envelope_hmac

    monkeypatch.delenv("LEAN_MCP_SECRET_KEY", raising=False)
    monkeypatch.delenv("LEAN_MCP_SUPERVISOR_SECRET_KEY", raising=False)

    proto_file = tmp_path / "opentrons_valid.py"
    valid_with_import = (
        "from opentrons import protocol_api\n\n"
        'metadata = {"apiLevel": "2.16"}\n\n'
        "def run(protocol: protocol_api.ProtocolContext) -> None:\n"
        "    tips = protocol.load_labware('opentrons_96_tiprack_300ul', 1)\n"
        "    plate = protocol.load_labware('corning_96_wellplate_360ul_flat', 2)\n"
        "    pip = protocol.load_instrument('p300_single_gen2', 'left', tip_racks=[tips])\n"
        "    pip.transfer(100, plate['A1'], plate['A2'])\n"
    )
    proto_file.write_text(valid_with_import, encoding="utf-8")

    # 1. Public dev key & missing secret key are rejected without --allow-insecure-dev-key
    with pytest.raises(ValueError, match="DEFAULT_MCP_SECRET_KEY"):
        mint_mcp_envelope(valid_with_import)
    with pytest.raises(ValueError, match="DEFAULT_MCP_SECRET_KEY"):
        mint_mcp_envelope(valid_with_import, secret_key=DEFAULT_MCP_SECRET_KEY)

    env_out = tmp_path / "env.json"
    assert cli_main(["mcp-mint", "--protocol", str(proto_file), "-o", str(env_out)]) == 1
    assert cli_main(["mcp-mint", "--protocol", str(proto_file), "--secret-key", "", "-o", str(env_out)]) == 1
    capsys.readouterr()

    dev_env = mint_mcp_envelope(valid_with_import, allow_insecure_dev_key=True)
    dev_env_file = tmp_path / "dev_env.json"
    dev_env_file.write_text(dev_env.to_json(), encoding="utf-8")
    assert (
        verify_mcp_envelope(dev_env, actual_protocol=valid_with_import).layer
        == "mcp_hmac_authentic"
    )
    assert cli_main(["mcp-verify", str(dev_env_file), "--protocol", str(proto_file)]) == 1
    capsys.readouterr()

    # 2. Valid Opentrons script with `from opentrons import protocol_api` passes with explicit key & payload binding
    sec = "issue-34-explicit-secret"
    assert (
        cli_main(
            ["mcp-mint", "--protocol", str(proto_file), "--secret-key", sec, "-o", str(env_out)]
        )
        == 0
    )
    capsys.readouterr()
    minted_env = LeanMcpEnvelope.from_json(env_out)
    assert minted_env.lean_proof_valid is True
    assert minted_env.static_check_passed is True

    # Missing --protocol fails at mcp_payload_binding unless --no-payload-binding is passed
    v_no_proto = verify_mcp_envelope(env_out, secret_key=sec)
    assert v_no_proto.passed is False
    assert v_no_proto.layer == "mcp_payload_binding"
    assert cli_main(["mcp-verify", str(env_out), "--secret-key", sec]) == 1
    assert (
        cli_main(["mcp-verify", str(env_out), "--secret-key", sec, "--no-payload-binding"]) == 0
    )
    capsys.readouterr()
    assert (
        cli_main(["mcp-verify", str(env_out), "--protocol", str(proto_file), "--secret-key", sec, "--json"])
        == 0
    )
    verdict_json = json.loads(capsys.readouterr().out)
    assert verdict_json["passed"] is True
    assert verdict_json["static_check_passed"] is True

    # 3. CLI `--lean-proof-valid` override is gone; missing protocol never sets lean_proof_valid=True
    with pytest.raises(SystemExit):
        cli_main(
            [
                "mcp-mint",
                "--protocol",
                str(proto_file),
                "--secret-key",
                sec,
                "--lean-proof-valid",
                "true",
            ]
        )
    sha_only_env = mint_mcp_envelope(protocol_sha256="ab" * 32, secret_key=sec)
    assert sha_only_env.lean_proof_valid is False
    assert sha_only_env.static_check_passed is False
    with pytest.raises(ValueError, match="cannot set lean_proof_valid=True"):
        mint_mcp_envelope(protocol_sha256="ab" * 32, secret_key=sec, lean_proof_valid=True)

    # 4. Self-declared co-signature fails at both mint and verify without distinct supervisor secret
    assert (
        cli_main(
            [
                "mcp-mint",
                "--protocol",
                str(proto_file),
                "--secret-key",
                sec,
                "--frontier-exception",
                "--supervisor-signed",
                "--supervisor-id",
                "nobody",
                "-o",
                str(tmp_path / "forged.json"),
            ]
        )
        == 1
    )
    capsys.readouterr()

    forged_body = {
        "schema_version": "lean-mcp/v1",
        "tool_name": "opentrons.execute_protocol",
        "protocol_sha256": compute_protocol_sha256(valid_with_import),
        "token_epoch": 1,
        "nonce": "self-declared-cosign-01",
        "lean_proof_valid": False,
        "is_frontier_exception": True,
        "human_supervisor_signed": True,
        "human_supervisor_id": "nobody",
        "envelope_bounds": {"deck_slots": [1, 2], "max_transfer_ul": 100.0, "api_level": "2.16"},
    }
    forged_body["hmac_sha256"] = compute_envelope_hmac(forged_body, sec)
    v_forged_cosign = verify_mcp_envelope(
        forged_body,
        secret_key=sec,
        actual_protocol=valid_with_import,
    )
    assert v_forged_cosign.passed is False
    assert v_forged_cosign.layer == "mcp_proof_or_cosigned_exception"

    # Real supervisor co-signature with distinct --supervisor-secret-key passes
    cosign_file = tmp_path / "cosigned.json"
    sup_sec = "distinct-supervisor-hmac-secret"
    assert (
        cli_main(
            [
                "mcp-mint",
                "--protocol",
                str(proto_file),
                "--secret-key",
                sec,
                "--supervisor-secret-key",
                sup_sec,
                "--frontier-exception",
                "--supervisor-signed",
                "--supervisor-id",
                "dr_rostova",
                "-o",
                str(cosign_file),
            ]
        )
        == 0
    )
    assert cli_main(["mcp-verify", str(cosign_file), "--protocol", str(proto_file), "--secret-key", sec]) == 1
    assert (
        cli_main(
            [
                "mcp-verify",
                str(cosign_file),
                "--protocol",
                str(proto_file),
                "--secret-key",
                sec,
                "--supervisor-secret-key",
                sup_sec,
            ]
        )
        == 0
    )
    capsys.readouterr()

    # 5. Import-free 5,000 uL script gets static_check_passed=False, lean_proof_valid=False, and fails verification
    bad_5000_py = (
        "def run(protocol):\n"
        "    plate = protocol.load_labware('corning_96_wellplate_360ul_flat', 1)\n"
        "    pip = protocol.load_instrument('p300_single_gen2', 'left')\n"
        "    pip.transfer(5000, plate['A1'], plate['A2'])\n"
    )
    env_5000 = mint_mcp_envelope(bad_5000_py, secret_key=sec)
    assert env_5000.static_check_passed is False
    assert env_5000.lean_proof_valid is False
    assert env_5000.envelope_bounds["max_transfer_ul"] <= 300.0
    v_5000 = verify_mcp_envelope(env_5000, secret_key=sec, actual_protocol=bad_5000_py)
    assert v_5000.passed is False

    # Even if an attacker signs a forged envelope claiming lean_proof_valid=True, actual_protocol volume check rejects it
    forged_5000 = {
        "schema_version": "lean-mcp/v1",
        "tool_name": "opentrons.execute_protocol",
        "protocol_sha256": compute_protocol_sha256(bad_5000_py),
        "token_epoch": 1,
        "nonce": "forged-5000-ul",
        "lean_proof_valid": True,
        "is_frontier_exception": False,
        "human_supervisor_signed": False,
        "human_supervisor_id": "",
        "envelope_bounds": {"deck_slots": [1], "max_transfer_ul": 300.0, "api_level": "2.16"},
    }
    forged_5000["hmac_sha256"] = compute_envelope_hmac(forged_5000, sec)
    v_forged_5000 = verify_mcp_envelope(forged_5000, secret_key=sec, actual_protocol=bad_5000_py)
    assert v_forged_5000.passed is False
    assert v_forged_5000.layer == "mcp_bounds_exceeded"


def test_live_lab_verify_lean_mcp_kernel_crosscheck() -> None:
    bin_dir = REPO_ROOT / "lean" / ".lake" / "build" / "bin"
    candidates = [bin_dir / "lab-verify-lean.exe", bin_dir / "lab-verify-lean"]
    built_bin = next((c for c in candidates if c.is_file()), None)
    if os.environ.get("REQUIRE_LIVE_LEAN") == "1":
        assert built_bin is not None, "lab-verify-lean binary must exist when REQUIRE_LIVE_LEAN=1"
    if built_bin is None:
        pytest.skip("lab-verify-lean binary not built in Python-only test environment")

    sec = "live-lean-kernel-secret"
    env = mint_mcp_envelope(SAMPLE_OPENTRONS_PY, secret_key=sec, token_epoch=3)
    v_ok = verify_mcp_envelope(
        env,
        secret_key=sec,
        current_deck_epoch=3,
        actual_protocol=SAMPLE_OPENTRONS_PY,
        check_lean_kernel=True,
        lean_kernel_bin=built_bin,
    )
    assert v_ok.passed is True


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
