"""Command-line interface for `lab-verify` (`--db`, `--sql`, `--candidates`, `--lean`, `--protocol`, `--json`)."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Sequence

from .lean_gate import verify_lean
from .mcp_gate import (
    AUTH_MODE_ED25519,
    AUTH_MODE_HMAC,
    DEFAULT_MCP_TOOL_NAME,
    LeanMcpEnvelope,
    LeanMcpGate,
    mint_mcp_envelope,
    verify_mcp_envelope,
)
from .protocol_gate import verify_protocol
from .sql_gate import (
    EXPERIMENTS,
    INSTRUMENTS,
    LAYERS,
    SAMPLES,
    SCHEMA,
    BatchGateEvaluator,
    build_counterexample_dbs,
    build_db,
    open_readonly_db,
    validate_candidates_schema,
    verify_sql,
)


def evaluate_benchmark_file(
    candidates_path: Path,
    *,
    db_path: Path | None = None,
    as_json: bool = False,
    allow_cross_join: bool = False,
    max_vm_steps: int = 5_000_000,
    timeout_s: float = 2.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_000_000,
) -> int:
    items = json.loads(candidates_path.read_text(encoding="utf-8"))
    schema_errors = validate_candidates_schema(items)
    if schema_errors:
        if as_json:
            print(json.dumps({"passed": False, "schema_errors": schema_errors}, indent=2))
        else:
            for e in schema_errors:
                print(f"SCHEMA ERROR: {e}")
        return 1

    if db_path is not None:
        con, db_schema = open_readonly_db(db_path)
        ce_cons = []
    else:
        con = build_db()
        db_schema = SCHEMA
        ce_cons = build_counterexample_dbs()

    evaluator = BatchGateEvaluator(
        con,
        counterexample_cons=ce_cons,
        schema=db_schema,
        strict_joins=True,
        allow_cross_join=allow_cross_join,
        max_vm_steps=max_vm_steps,
        timeout_s=timeout_s,
        max_rows=max_rows,
        max_value_bytes=max_value_bytes,
    )

    if not as_json and db_path is None:
        print(
            "Toy lab database with SYNTHETIC data: "
            f"{len(EXPERIMENTS)} experiments, {len(SAMPLES)} samples, {len(INSTRUMENTS)} instruments."
        )
        print(f"{len(items)} questions, {sum(len(i['candidates']) for i in items)} candidates\n")
        print(f"{'q':>2}  {'label':<24} {'first failed layer':<20} reason")
        print("-" * 96)

    fails: Counter[int] = Counter()
    wrong = passed = passed_wrong = passed_static_wrong = agree = 0
    rows_json: list[dict[str, Any]] = []

    for item in items:
        try:
            evaluator.get_validated_gold(item["gold"])
        except ValueError as exc:
            if as_json:
                print(json.dumps({"passed": False, "gold_error": str(exc), "qid": item["qid"]}, indent=2))
            else:
                print(f"GOLD VALIDATION ERROR on qid {item['qid']}: {exc}")
            return 1

        for cand in item["candidates"]:
            layer, reason = evaluator.evaluate_candidate(cand["sql"], item["gold"])
            is_wrong = cand["label"] != "correct"
            shown = "PASS" if layer is None else f"{layer + 1} {LAYERS[layer]}"
            if not as_json:
                print(f"{item['qid']:>2}  {cand['label']:<24} {shown:<20} {reason[:48]}")
            rows_json.append(
                {
                    "qid": item["qid"],
                    "label": cand["label"],
                    "sql": cand["sql"],
                    "passed": layer is None,
                    "failed_layer": None if layer is None else LAYERS[layer],
                    "failed_layer_index": layer,
                    "reason": reason,
                    "agrees_with_label": bool(is_wrong == (layer is not None)),
                }
            )
            wrong += int(is_wrong)
            agree += int(is_wrong == (layer is not None))
            if layer is None:
                passed += 1
                passed_wrong += int(is_wrong)
            else:
                fails[layer] += 1
            if is_wrong and (layer is None or layer == 3):
                passed_static_wrong += 1

    total = sum(len(i["candidates"]) for i in items)
    if as_json:
        summary = {
            "total": total,
            "agree": agree,
            "wrong": wrong,
            "passed": passed,
            "passed_wrong": passed_wrong,
            "passed_static_wrong": passed_static_wrong,
            "stopped_by_layer": {LAYERS[i]: fails[i] for i in range(len(LAYERS))},
            "cache_hits": evaluator.cache_hits,
            "results": rows_json,
        }
        print(json.dumps(summary, indent=2))
    else:
        print("\nCandidates stopped at each layer:")
        for i, name in enumerate(LAYERS):
            print(f"  layer {i + 1} {name:<10} {fails[i]}")
        print(f"  passed all     {passed}")
        print(f"\nGate verdict agrees with hand label: {agree}/{total}")
        print(f"Wrong candidates: {wrong}; wrong ones passing the full gate: {passed_wrong}")
        print(f"Wrong candidates that would pass with layers 1-3 only: {passed_static_wrong}/{wrong}")

    if passed_wrong > 0 or agree != total:
        return 1
    return 0


def _resolve_state_path(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    env_state = os.environ.get("LEAN_MCP_STATE_FILE", "").strip()
    if env_state:
        return Path(env_state)
    return None


def _resolve_secret(explicit: str | None, env_var: str) -> str | None:
    """Resolve an explicit secret from CLI or environment, treating empty strings as unset."""
    if explicit is not None:
        return explicit if explicit.strip() else None
    env_val = os.environ.get(env_var, "")
    return env_val if env_val.strip() else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab-verify",
        description=(
            "Default-deny verification gate for SQL queries, Lean 4 proofs, lab protocols, "
            "and Lean-MCP capability envelopes (subcommands: mcp-mint, mcp-verify)."
        ),
    )
    parser.add_argument("--db", type=Path, default=None, help="Path to read-only SQLite database file.")
    parser.add_argument("--sql", type=str, default=None, help="Candidate SQL query to verify.")
    parser.add_argument("--gold", type=str, default=None, help="Optional reference gold SQL query.")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=None,
        help="Benchmark candidates JSON file (defaults to demo/candidates.json).",
    )
    parser.add_argument(
        "--max-vm-steps",
        type=int,
        default=5_000_000,
        help="Maximum SQLite VM opcodes before aborting execution (default: 5000000).",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=2.0,
        help="Wall-clock SQL execution timeout in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=10_000,
        help="Maximum result rows fetched per SQL query (default: 10000).",
    )
    parser.add_argument(
        "--max-value-bytes",
        type=int,
        default=1_000_000,
        help="Maximum byte size of a single SQL cell value (default: 1000000).",
    )
    parser.add_argument("--lean", type=Path, default=None, help="Lean 4 source file to compile and audit.")
    parser.add_argument(
        "--lean-project",
        type=Path,
        default=None,
        help="Optional Lake project directory for compiling --lean imports.",
    )
    parser.add_argument(
        "--lean-static-only",
        action="store_true",
        help="Run heuristic static Lean scan without invoking the Lean 4 compiler.",
    )
    parser.add_argument(
        "--leanchecker",
        action="store_true",
        help="Replay compiled .olean output through leanchecker when --lean succeeds.",
    )
    parser.add_argument("--protocol", type=Path, default=None, help="Benchtop protocol JSON file to verify.")
    parser.add_argument(
        "--mcp-mint",
        type=str,
        default=None,
        help="Protocol file or 64-hex SHA-256 to mint into a lean-mcp/v1 envelope.",
    )
    parser.add_argument(
        "--mcp-verify",
        type=Path,
        default=None,
        help="Path to a lean-mcp/v1 envelope JSON file to verify.",
    )
    parser.add_argument(
        "--mcp-epoch",
        type=int,
        default=None,
        help="Deck epoch for Lean-MCP envelope minting or verification (default: 1 or state epoch).",
    )
    parser.add_argument(
        "--mcp-secret-key",
        type=str,
        default=None,
        help="Shared HMAC secret key for Lean-MCP envelopes (or set LEAN_MCP_SECRET_KEY).",
    )
    parser.add_argument(
        "--mcp-supervisor-secret-key",
        type=str,
        default=None,
        help="Distinct HMAC secret key for human supervisor co-signatures (or LEAN_MCP_SUPERVISOR_SECRET_KEY).",
    )
    parser.add_argument(
        "--mcp-protocol",
        type=Path,
        default=None,
        help="Actual protocol script/IR file to bind against during --mcp-verify.",
    )
    parser.add_argument(
        "--no-payload-binding",
        action="store_true",
        help="Explicitly skip payload binding check during MCP verification (dry-run only).",
    )
    parser.add_argument(
        "--allow-insecure-dev-key",
        action="store_true",
        help="Explicitly opt into DEFAULT_MCP_SECRET_KEY for local development/testing only.",
    )
    parser.add_argument(
        "--check-lean-kernel",
        action="store_true",
        help="Cross-check MCP invariants against compiled lab-verify-lean binary (fails closed if missing).",
    )
    parser.add_argument(
        "--lean-kernel-bin",
        type=Path,
        default=None,
        help="Explicit path to compiled lab-verify-lean / autolab-lean binary.",
    )
    parser.add_argument(
        "--mcp-output",
        type=Path,
        default=None,
        help="Optional output JSON path for --mcp-mint.",
    )
    parser.add_argument(
        "--state",
        "--state-file",
        "--mcp-state",
        dest="mcp_state",
        type=Path,
        default=None,
        help="Persistent JSON state file for atomic epoch, nonce, and deferral tracking.",
    )
    parser.add_argument(
        "--mutates-deck-state",
        action="store_true",
        help="Advance persistent current_deck_epoch by 1 when verification passes.",
    )
    parser.add_argument(
        "--stateless-dry-run",
        action="store_true",
        help="Inspect envelope without recording nonce consumption or mutating state.",
    )
    parser.add_argument(
        "--allow-cross-join",
        action="store_true",
        help="Allow explicit SQL CROSS JOIN in Layer 3.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit untruncated machine-readable JSON verdict output.",
    )
    return parser


def _run_mcp_mint_subcommand(sub_argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lab-verify mcp-mint",
        description="Mint a wire-compatible lean-mcp/v1 capability envelope.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Optional protocol file path or 64-hex protocol SHA-256.",
    )
    parser.add_argument(
        "--protocol",
        type=Path,
        default=None,
        help="Protocol file (compiled .py or protocol .json) to hash and statically check.",
    )
    parser.add_argument(
        "--protocol-sha256",
        type=str,
        default=None,
        help="Explicit 64-hex SHA-256 of canonical protocol IR or compiled script.",
    )
    parser.add_argument(
        "--lean-proof",
        type=Path,
        default=None,
        help="Optional Lean 4 proof source file that must compile cleanly to certify lean_proof_valid.",
    )
    parser.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="Deck epoch token_epoch (defaults to persistent --state epoch or 1).",
    )
    parser.add_argument(
        "--state",
        "--state-file",
        dest="state_file",
        type=Path,
        default=None,
        help="Persistent atomic JSON state file path (or LEAN_MCP_STATE_FILE).",
    )
    parser.add_argument(
        "--secret-key",
        type=str,
        default=None,
        help="Shared HMAC secret key (or LEAN_MCP_SECRET_KEY; required unless --allow-insecure-dev-key).",
    )
    parser.add_argument(
        "--supervisor-secret-key",
        type=str,
        default=None,
        help="Distinct HMAC secret key for human supervisor co-signature (or LEAN_MCP_SUPERVISOR_SECRET_KEY).",
    )
    parser.add_argument(
        "--supervisor-hmac",
        type=str,
        default="",
        help="Detached 64-hex human supervisor HMAC-SHA256.",
    )
    parser.add_argument(
        "--auth-mode",
        choices=(AUTH_MODE_HMAC, AUTH_MODE_ED25519),
        default=None,
        help="Cryptographic envelope authentication mode (default: hmac-sha256, or ed25519 with --minter-private-key).",
    )
    parser.add_argument(
        "--minter-private-key",
        type=str,
        default=None,
        help="64-hex Ed25519 private seed (or file path) for L4 proof-gate minter.",
    )
    parser.add_argument("--minter-key-id", type=str, default="", help="Key identifier for minter Ed25519 key.")
    parser.add_argument(
        "--supervisor-private-key",
        type=str,
        default=None,
        help="Distinct 64-hex Ed25519 private seed (or file path) for human supervisor co-signature.",
    )
    parser.add_argument(
        "--supervisor-sig",
        type=str,
        default="",
        help="Detached 128-hex Ed25519 supervisor co-signature.",
    )
    parser.add_argument("--supervisor-key-id", type=str, default="", help="Key identifier for supervisor key.")
    parser.add_argument("--key-epoch", type=int, default=None, help="Cryptographic signing key epoch.")
    parser.add_argument("--ttl-seconds", type=int, default=None, help="Envelope TTL window in seconds.")
    parser.add_argument(
        "--require-explicit-key",
        action="store_true",
        help="Require explicit non-dev key (enabled by default unless --allow-insecure-dev-key is set).",
    )
    parser.add_argument(
        "--allow-insecure-dev-key",
        action="store_true",
        help="Explicitly allow DEFAULT_MCP_SECRET_KEY in development/testing.",
    )
    parser.add_argument(
        "--tool-name",
        type=str,
        default=DEFAULT_MCP_TOOL_NAME,
        help="Target MCP hardware tool identifier.",
    )
    parser.add_argument("--nonce", type=str, default=None, help="Explicit single-use nonce.")
    parser.add_argument(
        "--frontier-exception",
        action="store_true",
        help="Mark call as an out-of-regime frontier exception.",
    )
    parser.add_argument(
        "--supervisor-signed",
        action="store_true",
        help="Include cryptographic human supervisor co-signature.",
    )
    parser.add_argument(
        "--supervisor-id",
        type=str,
        default="",
        help="Human supervisor identifier when co-signed.",
    )
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output JSON file path.")
    ns = parser.parse_args(sub_argv)

    secret = _resolve_secret(ns.secret_key, "LEAN_MCP_SECRET_KEY")
    sup_secret = _resolve_secret(ns.supervisor_secret_key, "LEAN_MCP_SUPERVISOR_SECRET_KEY")
    minter_priv = _resolve_secret(ns.minter_private_key, "LEAN_MCP_MINTER_PRIVATE_KEY")
    sup_priv = _resolve_secret(ns.supervisor_private_key, "LEAN_MCP_SUPERVISOR_PRIVATE_KEY")
    proto_arg: Path | str | None = ns.protocol if ns.protocol is not None else ns.target
    state_path = _resolve_state_path(ns.state_file)
    allow_dev = bool(ns.allow_insecure_dev_key)
    issued_at = int(time.time()) if ns.ttl_seconds is not None else None
    proof_flag = False if ns.frontier_exception else None

    try:
        if state_path is not None:
            gate = LeanMcpGate(
                secret_key=secret,
                supervisor_secret_key=sup_secret,
                initial_deck_epoch=1 if ns.epoch is None else ns.epoch,
                check_lean_kernel=False,
                state_path=state_path,
                auth_mode=ns.auth_mode,
                minter_private_key=minter_priv,
                minter_key_id=ns.minter_key_id,
                key_epoch=ns.key_epoch,
                default_ttl_seconds=ns.ttl_seconds,
                require_explicit_key=True,
                allow_insecure_dev_key=allow_dev,
            )
            env = gate.mint(
                proto_arg,
                protocol_sha256=ns.protocol_sha256,
                token_epoch=ns.epoch,
                tool_name=ns.tool_name,
                nonce=ns.nonce,
                lean_proof_valid=proof_flag,
                lean_proof_source=ns.lean_proof,
                is_frontier_exception=ns.frontier_exception,
                human_supervisor_signed=ns.supervisor_signed,
                human_supervisor_id=ns.supervisor_id,
                supervisor_private_key=sup_priv,
                supervisor_ed25519_sig=ns.supervisor_sig,
                supervisor_key_id=ns.supervisor_key_id,
                supervisor_secret_key=sup_secret,
                supervisor_hmac_sha256=ns.supervisor_hmac,
                key_epoch=ns.key_epoch,
                issued_at_unix=issued_at,
                ttl_seconds=ns.ttl_seconds,
            )
        else:
            env = mint_mcp_envelope(
                proto_arg,
                protocol_sha256=ns.protocol_sha256,
                secret_key=secret,
                token_epoch=1 if ns.epoch is None else ns.epoch,
                tool_name=ns.tool_name,
                nonce=ns.nonce,
                lean_proof_valid=proof_flag,
                lean_proof_source=ns.lean_proof,
                is_frontier_exception=ns.frontier_exception,
                human_supervisor_signed=ns.supervisor_signed,
                human_supervisor_id=ns.supervisor_id,
                auth_mode=ns.auth_mode,
                minter_private_key=minter_priv,
                minter_key_id=ns.minter_key_id,
                supervisor_private_key=sup_priv,
                supervisor_ed25519_sig=ns.supervisor_sig,
                supervisor_key_id=ns.supervisor_key_id,
                supervisor_secret_key=sup_secret,
                supervisor_hmac_sha256=ns.supervisor_hmac,
                key_epoch=ns.key_epoch,
                issued_at_unix=issued_at,
                ttl_seconds=ns.ttl_seconds,
                require_explicit_key=True,
                allow_insecure_dev_key=allow_dev,
            )
    except (OSError, PermissionError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    rendered = env.to_json(indent=2)
    if ns.output is not None:
        ns.output.parent.mkdir(parents=True, exist_ok=True)
        ns.output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    else:
        print(rendered)
    return 0


def _run_mcp_verify_subcommand(sub_argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lab-verify mcp-verify",
        description="Verify a lean-mcp/v1 hardware capability envelope.",
    )
    parser.add_argument(
        "envelope_pos",
        nargs="?",
        type=Path,
        default=None,
        help="Path to lean-mcp/v1 envelope JSON file.",
    )
    parser.add_argument(
        "--envelope",
        type=Path,
        default=None,
        help="Path to lean-mcp/v1 envelope JSON file.",
    )
    parser.add_argument(
        "--protocol",
        type=Path,
        default=None,
        help="Actual protocol script/JSON file to verify against protocol_sha256.",
    )
    parser.add_argument(
        "--protocol-sha256",
        type=str,
        default=None,
        help="Actual 64-hex protocol SHA-256 to verify against protocol_sha256.",
    )
    parser.add_argument(
        "--no-payload-binding",
        action="store_true",
        help="Explicitly skip payload SHA-256 binding check (dry-run inspection only).",
    )
    parser.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="Current physical deck epoch (defaults to persistent --state epoch or 1).",
    )
    parser.add_argument(
        "--state",
        "--state-file",
        dest="state_file",
        type=Path,
        default=None,
        help="Persistent atomic JSON state file path (or LEAN_MCP_STATE_FILE).",
    )
    parser.add_argument(
        "--mutates-deck-state",
        action="store_true",
        help="Increment persistent current_deck_epoch by 1 upon successful verification.",
    )
    parser.add_argument(
        "--defer-unsigned-frontier",
        action="store_true",
        help="Park unsigned frontier exceptions in persistent deferred_daytime_queue.",
    )
    parser.add_argument(
        "--stateless-dry-run",
        action="store_true",
        help="Inspect envelope without consuming nonce or mutating persistent state.",
    )
    parser.add_argument(
        "--secret-key",
        type=str,
        default=None,
        help="Shared HMAC secret key (or LEAN_MCP_SECRET_KEY; required unless --allow-insecure-dev-key).",
    )
    parser.add_argument(
        "--supervisor-secret-key",
        type=str,
        default=None,
        help="Distinct HMAC secret key for supervisor co-signature verification (or LEAN_MCP_SUPERVISOR_SECRET_KEY).",
    )
    parser.add_argument(
        "--auth-mode",
        choices=(AUTH_MODE_HMAC, AUTH_MODE_ED25519),
        default=None,
        help="Cryptographic authentication mode.",
    )
    parser.add_argument(
        "--minter-public-key",
        type=str,
        default=None,
        help="64-hex Ed25519 public key (or file path) for L4 minter signature verification.",
    )
    parser.add_argument(
        "--supervisor-public-key",
        type=str,
        default=None,
        help="Distinct 64-hex Ed25519 public key (or file path) for supervisor co-signature verification.",
    )
    parser.add_argument(
        "--min-active-key-epoch",
        type=int,
        default=None,
        help="Minimum non-revoked signing key epoch.",
    )
    parser.add_argument(
        "--check-lean-kernel",
        action="store_true",
        help="Cross-check against compiled lab-verify-lean binary (fails closed if missing).",
    )
    parser.add_argument(
        "--lean-kernel-bin",
        type=Path,
        default=None,
        help="Explicit path to compiled lab-verify-lean / autolab-lean binary.",
    )
    parser.add_argument(
        "--require-explicit-key",
        action="store_true",
        help="Require explicit non-dev key (enabled by default unless --allow-insecure-dev-key is set).",
    )
    parser.add_argument(
        "--allow-insecure-dev-key",
        action="store_true",
        help="Explicitly allow DEFAULT_MCP_SECRET_KEY in development/testing.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON VerifyVerdict.",
    )
    ns = parser.parse_args(sub_argv)

    env_path = ns.envelope if ns.envelope is not None else ns.envelope_pos
    if env_path is None:
        print("ERROR: mcp-verify requires an envelope JSON file path", file=sys.stderr)
        return 1

    secret = _resolve_secret(ns.secret_key, "LEAN_MCP_SECRET_KEY")
    sup_secret = _resolve_secret(ns.supervisor_secret_key, "LEAN_MCP_SUPERVISOR_SECRET_KEY")
    minter_pub = _resolve_secret(ns.minter_public_key, "LEAN_MCP_MINTER_PUBLIC_KEY")
    sup_pub = _resolve_secret(ns.supervisor_public_key, "LEAN_MCP_SUPERVISOR_PUBLIC_KEY")
    state_path = _resolve_state_path(ns.state_file)
    allow_dev = bool(ns.allow_insecure_dev_key)
    require_binding = not bool(ns.no_payload_binding)

    try:
        if state_path is not None:
            gate = LeanMcpGate(
                secret_key=secret if minter_pub is None else None,
                supervisor_secret_key=sup_secret,
                initial_deck_epoch=1 if ns.epoch is None else ns.epoch,
                check_lean_kernel=ns.check_lean_kernel,
                lean_kernel_bin=ns.lean_kernel_bin,
                state_path=state_path,
                auth_mode=ns.auth_mode,
                minter_public_key=minter_pub,
                supervisor_public_key=sup_pub,
                min_active_key_epoch=ns.min_active_key_epoch,
                require_explicit_key=True,
                allow_insecure_dev_key=allow_dev,
            )
            if ns.epoch is not None and not state_path.exists():
                gate.current_deck_epoch = ns.epoch
            verdict = gate.verify(
                env_path,
                actual_protocol=ns.protocol,
                actual_protocol_sha256=ns.protocol_sha256,
                require_payload_binding=require_binding,
                supervisor_secret_key=sup_secret,
                mutates_deck_state=ns.mutates_deck_state,
                defer_unsigned_frontier=ns.defer_unsigned_frontier,
                stateless_dry_run=ns.stateless_dry_run,
            )
        else:
            verdict = verify_mcp_envelope(
                env_path,
                secret_key=secret if minter_pub is None else None,
                supervisor_secret_key=sup_secret,
                current_deck_epoch=1 if ns.epoch is None else ns.epoch,
                actual_protocol=ns.protocol,
                actual_protocol_sha256=ns.protocol_sha256,
                require_payload_binding=require_binding,
                check_lean_kernel=ns.check_lean_kernel,
                lean_kernel_bin=ns.lean_kernel_bin,
                minter_public_key=minter_pub,
                supervisor_public_key=sup_pub,
                min_active_key_epoch=ns.min_active_key_epoch,
                require_explicit_key=True,
                allow_insecure_dev_key=allow_dev,
            )
    except (OSError, PermissionError, TimeoutError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if ns.json:
        payload = verdict.to_dict()
        try:
            parsed_env = LeanMcpEnvelope.from_json(env_path)
            payload["static_check_passed"] = bool(parsed_env.static_check_passed and verdict.passed)
        except (OSError, ValueError, json.JSONDecodeError):
            payload["static_check_passed"] = False
        print(json.dumps(payload, indent=2))
    else:
        status = "PASS" if verdict.passed else f"FAIL ({verdict.layer})"
        print(f"{status}: {verdict.reason}")
    return 0 if verdict.passed else 1


def main(argv: Sequence[str] | None = None, *, default_candidates: Path | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if effective_argv:
        if effective_argv[0] == "mcp-mint":
            return _run_mcp_mint_subcommand(effective_argv[1:])
        if effective_argv[0] == "mcp-verify":
            return _run_mcp_verify_subcommand(effective_argv[1:])

    args = build_parser().parse_args(effective_argv)
    repo_root = Path(__file__).resolve().parents[2]
    state_path = _resolve_state_path(args.mcp_state)

    if args.mcp_mint is not None:
        secret = _resolve_secret(args.mcp_secret_key, "LEAN_MCP_SECRET_KEY")
        sup_secret = _resolve_secret(args.mcp_supervisor_secret_key, "LEAN_MCP_SUPERVISOR_SECRET_KEY")
        allow_dev = bool(args.allow_insecure_dev_key)
        try:
            if state_path is not None:
                gate = LeanMcpGate(
                    secret_key=secret,
                    supervisor_secret_key=sup_secret,
                    initial_deck_epoch=1 if args.mcp_epoch is None else args.mcp_epoch,
                    check_lean_kernel=False,
                    state_path=state_path,
                    allow_insecure_dev_key=allow_dev,
                )
                env = gate.mint(args.mcp_mint, token_epoch=args.mcp_epoch)
            else:
                env = mint_mcp_envelope(
                    args.mcp_mint,
                    secret_key=secret,
                    supervisor_secret_key=sup_secret,
                    token_epoch=1 if args.mcp_epoch is None else args.mcp_epoch,
                    allow_insecure_dev_key=allow_dev,
                )
        except (OSError, PermissionError, TypeError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        rendered = env.to_json(indent=2)
        if args.mcp_output is not None:
            args.mcp_output.parent.mkdir(parents=True, exist_ok=True)
            args.mcp_output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
        else:
            print(rendered)
        return 0

    if args.mcp_verify is not None:
        secret = _resolve_secret(args.mcp_secret_key, "LEAN_MCP_SECRET_KEY")
        sup_secret = _resolve_secret(args.mcp_supervisor_secret_key, "LEAN_MCP_SUPERVISOR_SECRET_KEY")
        allow_dev = bool(args.allow_insecure_dev_key)
        require_binding = not bool(args.no_payload_binding)
        try:
            if state_path is not None:
                gate = LeanMcpGate(
                    secret_key=secret,
                    supervisor_secret_key=sup_secret,
                    initial_deck_epoch=1 if args.mcp_epoch is None else args.mcp_epoch,
                    check_lean_kernel=args.check_lean_kernel,
                    lean_kernel_bin=args.lean_kernel_bin,
                    state_path=state_path,
                    allow_insecure_dev_key=allow_dev,
                )
                verdict = gate.verify(
                    args.mcp_verify,
                    actual_protocol=args.mcp_protocol,
                    require_payload_binding=require_binding,
                    supervisor_secret_key=sup_secret,
                    mutates_deck_state=args.mutates_deck_state,
                    stateless_dry_run=args.stateless_dry_run,
                )
            else:
                verdict = verify_mcp_envelope(
                    args.mcp_verify,
                    secret_key=secret,
                    supervisor_secret_key=sup_secret,
                    current_deck_epoch=1 if args.mcp_epoch is None else args.mcp_epoch,
                    actual_protocol=args.mcp_protocol,
                    require_payload_binding=require_binding,
                    check_lean_kernel=args.check_lean_kernel,
                    lean_kernel_bin=args.lean_kernel_bin,
                    allow_insecure_dev_key=allow_dev,
                )
        except (OSError, PermissionError, TimeoutError, TypeError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        if args.json:
            payload = verdict.to_dict()
            try:
                parsed_env = LeanMcpEnvelope.from_json(args.mcp_verify)
                payload["static_check_passed"] = bool(parsed_env.static_check_passed and verdict.passed)
            except (OSError, ValueError, json.JSONDecodeError):
                payload["static_check_passed"] = False
            print(json.dumps(payload, indent=2))
        else:
            status = "PASS" if verdict.passed else f"FAIL ({verdict.layer})"
            print(f"{status}: {verdict.reason}")
        return 0 if verdict.passed else 1

    if args.lean is not None:
        verdict = verify_lean(
            args.lean,
            project_dir=args.lean_project,
            static_only=args.lean_static_only,
            run_leanchecker=args.leanchecker,
        )
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            print(f"{'PASS' if verdict.passed else 'FAIL'}: {verdict.reason}")
        return 0 if verdict.passed else 1

    if args.protocol is not None:
        verdict = verify_protocol(args.protocol)
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            print(f"{'PASS' if verdict.passed else 'FAIL'}: {verdict.reason}")
        return 0 if verdict.passed else 1

    if args.sql is not None:
        if args.db is not None:
            con, db_schema = open_readonly_db(args.db)
            ce_cons = []
        else:
            con = build_db()
            db_schema = SCHEMA
            ce_cons = build_counterexample_dbs() if args.gold else []

        verdict = verify_sql(
            con,
            args.sql,
            gold_sql=args.gold,
            counterexample_cons=ce_cons,
            schema=db_schema,
            allow_cross_join=args.allow_cross_join,
            max_vm_steps=args.max_vm_steps,
            timeout_s=args.timeout_s,
            max_rows=args.max_rows,
            max_value_bytes=args.max_value_bytes,
        )
        if args.json:
            print(json.dumps(verdict.to_dict(), indent=2))
        else:
            status = "PASS" if verdict.passed else f"FAIL ({verdict.layer})"
            print(f"{status}: {verdict.reason}")
        return 0 if verdict.passed else 1

    cand_file = args.candidates or default_candidates or (repo_root / "demo" / "candidates.json")
    return evaluate_benchmark_file(
        cand_file,
        db_path=args.db,
        as_json=args.json,
        allow_cross_join=args.allow_cross_join,
        max_vm_steps=args.max_vm_steps,
        timeout_s=args.timeout_s,
        max_rows=args.max_rows,
        max_value_bytes=args.max_value_bytes,
    )


if __name__ == "__main__":
    raise SystemExit(main())
