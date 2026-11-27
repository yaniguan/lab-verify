"""Auto-Lab 15-repository wire node (`autolab-wire/v1`) for `lab-verify` (Layer L4).

Enforces the 4-layer read-only SQLite gate (`lab_verify.sql_gate`), validates
static protocol/AST/volume soundness, supports overnight unsigned frontier deferral
(`L4_VERIFY_FRONTIER_DEFERRED`) plus daytime human supervisor co-sign release
(`cosign_deferred_packet`), and mints fail-closed `lean-mcp/v1` zero-trust hardware
capability envelopes (`lab_verify.mcp_gate.LeanMcpGate`) for downstream
`stepbot` execution, pairing pre-execution verification (`lab-rehearsal`,
`lab-verify`) with post-execution causal attribution (`lab-attrib`).
"""

from __future__ import annotations

import copy
import hmac
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

REPO_ID = "lab-verify"
LAYER = "L4"
WIRE_SCHEMA_VERSION = "autolab-wire/v1"
DEFAULT_SQL_QUERY = "SELECT COUNT(DISTINCT experiment_id) FROM samples"
DEFAULT_MCP_SECRET = "lean-mcp-dev-secret-v1"
INVARIANT_NAME = "autonomous_wire_envelope_soundness"
FIRST_PRINCIPLES_NOTE = (
    "Read-only AST plus SQLite query_only and authorizer isolation blocks mutating "
    "or schema-invalid SQL before execution, while zero-click hardware MCP dispatch "
    "requires canonical HMAC-SHA256 or Ed25519 authenticity with an explicit non-dev key, "
    "exact SHA-256 protocol binding, active key-rotation epoch, fresh deck epoch, "
    "single-use nonce, unexpired TTL window, and a verified protocol/Lean proof certificate "
    "or role-separated cryptographic supervisor co-signature."
)

REPO_DIR = Path(__file__).resolve().parent
SRC_DIR = REPO_DIR / "src"
for _candidate_path in (str(SRC_DIR), str(REPO_DIR)):
    if _candidate_path not in sys.path:
        sys.path.insert(0, _candidate_path)

from lab_verify.mcp_gate import (  # noqa: E402
    LeanMcpEnvelope,
    LeanMcpGate,
    _infer_static_proof_and_bounds,
    compute_protocol_sha256,
    compute_supervisor_hmac,
    ed25519_public_key_from_private,
    mint_mcp_envelope,
    verify_supervisor_cosignature,
)
from lab_verify.sql_gate import SCHEMA, build_db, open_readonly_db, verify_sql  # noqa: E402
from lab_verify.verdict import VerifyVerdict  # noqa: E402


def _init_wire_packet(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-copy an incoming packet and populate `autolab-wire/v1` default keys."""
    out: dict[str, Any] = copy.deepcopy(dict(packet))
    out.setdefault("schema_version", WIRE_SCHEMA_VERSION)
    out.setdefault("halted", False)
    out.setdefault("halt_reason", None)
    out.setdefault("trace", [])
    out.setdefault("bottom_reasoning_traces", [])
    return out


def _evaluate_readonly_sql(
    out: Mapping[str, Any],
    *,
    db_path: str | Path | None = None,
) -> VerifyVerdict:
    """Run `lab-verify`'s 4-layer read-only SQLite gate against `db_path` or the synthetic lab DB."""
    effective_db = db_path if db_path is not None else out.get("db_path")
    has_explicit_sql = "sql_query" in out and out["sql_query"] is not None
    if has_explicit_sql:
        sql_query = out["sql_query"]
    elif effective_db is not None:
        sql_query = "SELECT 1"
    else:
        sql_query = DEFAULT_SQL_QUERY

    gold_sql = out.get("gold_sql")
    max_vm_steps = int(out.get("max_vm_steps", 5_000_000))
    timeout_s = float(out.get("timeout_s", 2.0))
    max_rows = int(out.get("max_rows", 10_000))
    max_value_bytes = int(out.get("max_value_bytes", 1_000_000))

    if effective_db is not None:
        try:
            con, db_schema = open_readonly_db(effective_db)
        except (FileNotFoundError, OSError, ValueError) as exc:
            return VerifyVerdict(
                passed=False,
                layer="schema",
                reason=f"failed to open read-only SQLite db_path: {exc}",
                diagnostics=[str(exc)],
            )
    else:
        con = build_db()
        db_schema = SCHEMA

    try:
        return verify_sql(
            con,
            sql_query,
            gold_sql=gold_sql if isinstance(gold_sql, str) else None,
            schema=db_schema,
            allow_cross_join=bool(out.get("allow_cross_join", False)),
            allow_recursive_cte=bool(out.get("allow_recursive_cte", True)),
            max_vm_steps=max_vm_steps,
            timeout_s=timeout_s,
            max_rows=max_rows,
            max_value_bytes=max_value_bytes,
        )
    finally:
        con.close()


def _extract_explicit_max_transfer_ul(out: Mapping[str, Any]) -> float | None:
    stepbot_compiled = (
        out["stepbot_compiled"]
        if isinstance(out.get("stepbot_compiled"), Mapping)
        else {}
    )
    raw_bounds = (
        out.get("envelope_bounds")
        if isinstance(out.get("envelope_bounds"), Mapping)
        else (
            stepbot_compiled.get("envelope_bounds")
            if isinstance(stepbot_compiled.get("envelope_bounds"), Mapping)
            else None
        )
    )
    if raw_bounds is not None and raw_bounds.get("max_transfer_ul") is not None:
        val = raw_bounds["max_transfer_ul"]
        if not isinstance(val, bool) and isinstance(val, (int, float)):
            return float(val)
    return None


def _resolve_and_validate_protocol_target(
    out: Mapping[str, Any],
    *,
    explicit_python_code: str | None = None,
) -> tuple[Any, bool, bool, bool, dict[str, Any] | None, str | None]:
    """Resolve `(protocol_target, static_check_passed, proof_valid, ast_malicious_or_broken, inferred_bounds, err_reason)`."""
    stepbot_compiled = (
        out["stepbot_compiled"]
        if isinstance(out.get("stepbot_compiled"), Mapping)
        else {}
    )
    rehearsal = (
        out["rehearsal"]
        if isinstance(out.get("rehearsal"), Mapping)
        else {}
    )
    rehearsal_passed = rehearsal.get("passed") is not False
    max_ul_limit = _extract_explicit_max_transfer_ul(out)

    py_candidate = explicit_python_code
    if py_candidate is None:
        raw_py = out.get("compiled_python_code")
        if not isinstance(raw_py, str):
            raw_py = stepbot_compiled.get("python_code")
        if isinstance(raw_py, str):
            py_candidate = raw_py

    if py_candidate is not None:
        py_ok, inferred_bounds = _infer_static_proof_and_bounds(
            py_candidate, max_transfer_ul_limit=max_ul_limit
        )
        if not py_ok:
            return (
                py_candidate,
                False,
                False,
                True,
                inferred_bounds,
                "compiled Python script failed static AST safety, lacks def run(protocol), or exceeds max_transfer_ul",
            )
        override = out.get("lean_proof_valid")
        proof_ok = bool(py_ok and rehearsal_passed and (True if override is None else bool(override)))
        reason = None if proof_ok else "upstream rehearsal or Lean proof flag rejected protocol"
        return py_candidate, True, proof_ok, False, inferred_bounds, reason

    if "protocol_yaml_dict" in rehearsal and rehearsal["protocol_yaml_dict"] is not None:
        ir = rehearsal["protocol_yaml_dict"]
        if not isinstance(ir, (Mapping, Sequence)) or isinstance(ir, (str, bytes)):
            return (
                ir,
                False,
                False,
                True,
                None,
                "protocol_yaml_dict must be a mapping or sequence of steps",
            )
        ir_ok, inferred_bounds = _infer_static_proof_and_bounds(
            ir, max_transfer_ul_limit=max_ul_limit
        )
        override = out.get("lean_proof_valid")
        proof_ok = bool(ir_ok and rehearsal_passed and (True if override is None else bool(override)))
        err = None if proof_ok else "protocol_yaml_dict failed static/volume check or upstream rehearsal"
        return ir, ir_ok, proof_ok, not ir_ok, inferred_bounds, err

    return (
        None,
        False,
        False,
        True,
        None,
        "wire packet carries no protocol (missing compiled_python_code, stepbot_compiled.python_code, or rehearsal.protocol_yaml_dict)",
    )


def _resolve_gate_for_packet(
    out: Mapping[str, Any],
    mcp_gate: LeanMcpGate | None,
) -> tuple[LeanMcpGate, int]:
    if mcp_gate is not None:
        epoch = (
            int(out["deck_epoch"])
            if out.get("deck_epoch") is not None
            else mcp_gate.current_deck_epoch
        )
        return mcp_gate, epoch

    raw_secret = out.get("mcp_secret_key")
    secret_key = raw_secret if isinstance(raw_secret, (str, bytes)) and str(raw_secret).strip() else None
    raw_sup_secret = out.get("mcp_supervisor_secret_key")
    sup_secret_key = (
        raw_sup_secret
        if isinstance(raw_sup_secret, (str, bytes)) and str(raw_sup_secret).strip()
        else None
    )
    allow_dev = bool(out.get("allow_insecure_dev_key", False))
    deck_epoch = int(out["deck_epoch"]) if out.get("deck_epoch") is not None else 1
    minter_priv = out.get("mcp_minter_private_key")
    state_path = out.get("mcp_state_path")
    gate = LeanMcpGate(
        secret_key=secret_key if minter_priv is None else None,
        supervisor_secret_key=sup_secret_key,
        supervisor_public_key=out.get("mcp_supervisor_public_key"),
        initial_deck_epoch=deck_epoch,
        check_lean_kernel=False,
        state_path=state_path,
        minter_private_key=minter_priv,
        minter_key_id=str(out.get("mcp_minter_key_id", "")),
        key_epoch=out.get("mcp_key_epoch"),
        default_ttl_seconds=out.get("mcp_ttl_seconds"),
        require_explicit_key=True,
        allow_insecure_dev_key=allow_dev,
    )
    return gate, gate.current_deck_epoch


def _has_verifiable_packet_supervisor_signature(
    out: Mapping[str, Any],
    *,
    protocol_target: Any,
    bounds_map: Mapping[str, Any] | None,
    epoch: int,
    mcp_gate: LeanMcpGate | None,
) -> bool:
    """Return True ONLY when packet carries a verifiable cryptographic supervisor credential."""
    if not bool(out.get("human_supervisor_signed", False)):
        return False

    nonce_raw = out.get("mcp_nonce")
    sup_priv = out.get("mcp_supervisor_private_key")
    minter_priv = out.get("mcp_minter_private_key") or (
        mcp_gate._minter_private_key if mcp_gate is not None else None
    )
    if sup_priv is not None:
        try:
            sup_pub = ed25519_public_key_from_private(sup_priv, as_hex=True)
            if minter_priv is not None:
                minter_pub = ed25519_public_key_from_private(minter_priv, as_hex=True)
                if hmac.compare_digest(str(sup_pub), str(minter_pub)):
                    return False
            return True
        except (TypeError, ValueError, OSError):
            return False

    sup_ed_sig = str(out.get("mcp_supervisor_ed25519_sig", "")).strip()
    sup_pub_key = out.get("mcp_supervisor_public_key") or (
        mcp_gate._supervisor_public_key if mcp_gate is not None else None
    )
    if sup_ed_sig and sup_pub_key is not None and isinstance(nonce_raw, str) and nonce_raw.strip():
        try:
            proto_sha = compute_protocol_sha256(protocol_target)
            return verify_supervisor_cosignature(
                sup_pub_key,
                sup_ed_sig,
                nonce=nonce_raw.strip(),
                token_epoch=epoch,
                protocol_sha256=proto_sha,
                envelope_bounds=bounds_map,
            )
        except (TypeError, ValueError, OSError):
            return False

    sup_secret = out.get("mcp_supervisor_secret_key") or (
        mcp_gate._supervisor_secret_key if mcp_gate is not None else None
    )
    if sup_secret is None:
        return False

    minter_secret = out.get("mcp_secret_key") or (
        mcp_gate._secret_key if mcp_gate is not None else None
    )
    sup_bytes = sup_secret if isinstance(sup_secret, bytes) else str(sup_secret).encode("utf-8")
    if not sup_bytes:
        return False
    if not bool(out.get("allow_insecure_dev_key", False)) and hmac.compare_digest(
        sup_bytes, DEFAULT_MCP_SECRET.encode("utf-8")
    ):
        return False
    if minter_secret is not None:
        minter_bytes = (
            minter_secret if isinstance(minter_secret, bytes) else str(minter_secret).encode("utf-8")
        )
        if hmac.compare_digest(sup_bytes, minter_bytes):
            return False

    sup_hmac = str(out.get("mcp_supervisor_hmac_sha256", "")).strip()
    if sup_hmac:
        if not isinstance(nonce_raw, str) or not nonce_raw.strip():
            return False
        proto_sha = compute_protocol_sha256(protocol_target)
        expected = compute_supervisor_hmac(
            sup_secret,
            nonce=nonce_raw.strip(),
            token_epoch=epoch,
            protocol_sha256=proto_sha,
            envelope_bounds=bounds_map,
        )
        return hmac.compare_digest(sup_hmac.lower(), expected.lower())

    return True


def _mint_capability_envelope(
    out: Mapping[str, Any],
    protocol_target: Any,
    envelope_bounds: Mapping[str, Any] | None,
    *,
    mcp_gate: LeanMcpGate | None = None,
    lean_proof_valid: bool = True,
    is_frontier_exception: bool = False,
    human_supervisor_signed: bool = False,
    human_supervisor_id: str = "",
) -> LeanMcpEnvelope:
    """Mint a `lean-mcp/v1` capability envelope bound to `protocol_target`."""
    gate, epoch = _resolve_gate_for_packet(out, mcp_gate)
    nonce = out.get("mcp_nonce")
    return gate.mint(
        protocol_target,
        token_epoch=epoch,
        nonce=str(nonce) if isinstance(nonce, str) and nonce.strip() else None,
        lean_proof_valid=lean_proof_valid,
        is_frontier_exception=is_frontier_exception,
        human_supervisor_signed=human_supervisor_signed,
        human_supervisor_id=human_supervisor_id,
        envelope_bounds=envelope_bounds,
        supervisor_private_key=out.get("mcp_supervisor_private_key"),
        supervisor_ed25519_sig=str(out.get("mcp_supervisor_ed25519_sig", "")),
        supervisor_key_id=str(out.get("mcp_supervisor_key_id", "")),
        supervisor_secret_key=out.get("mcp_supervisor_secret_key"),
        supervisor_hmac_sha256=str(out.get("mcp_supervisor_hmac_sha256", "")),
    )


def _record_traces(
    out: dict[str, Any],
    *,
    summary: str,
    replace_existing_repo_trace: bool = False,
) -> None:
    """Append (or update) `trace` and `bottom_reasoning_traces` entries for `lab-verify`."""
    trace_entry = {
        "repo": REPO_ID,
        "layer": LAYER,
        "status": "BLOCK" if out["halted"] else "PASS",
        "summary": summary,
    }
    traces = out.setdefault("trace", [])
    if replace_existing_repo_trace:
        for idx, existing in enumerate(traces):
            if isinstance(existing, Mapping) and existing.get("repo") == REPO_ID:
                traces[idx] = trace_entry
                break
        else:
            traces.append(trace_entry)
    else:
        traces.append(trace_entry)

    bottom_traces = out.setdefault("bottom_reasoning_traces", [])
    if not any(
        isinstance(item, Mapping)
        and item.get("repo") == REPO_ID
        and item.get("invariant") == INVARIANT_NAME
        for item in bottom_traces
    ):
        bottom_traces.append(
            {
                "repo": REPO_ID,
                "invariant": INVARIANT_NAME,
                "first_principles": FIRST_PRINCIPLES_NOTE,
            }
        )


def _gate_and_mint_stage(
    out: dict[str, Any],
    *,
    protocol_target: Any,
    static_check_passed: bool,
    static_proof_valid: bool,
    ast_malicious_or_broken: bool,
    protocol_err: str | None,
    bounds_map: Mapping[str, Any] | None,
    mcp_gate: LeanMcpGate | None,
    defer_unsigned_frontier: bool | None,
    replace_existing_repo_trace: bool,
    stage_label: str,
) -> dict[str, Any]:
    decision = out.get("decision") if isinstance(out.get("decision"), Mapping) else {}
    is_frontier = bool(
        out.get("is_frontier_exception", decision.get("is_frontier_exception", False))
    )
    supervisor_id = str(out.get("human_supervisor_id", ""))
    effective_defer = (
        bool(out.get("defer_unsigned_frontier", False))
        if defer_unsigned_frontier is None
        else bool(defer_unsigned_frontier)
    )

    if protocol_target is None or ast_malicious_or_broken or (not is_frontier and not static_proof_valid):
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
        out["verification"] = {
            "sql_passed": True,
            "static_check_passed": False,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                f"Protocol/AST verification blocked {stage_label}: "
                f"{protocol_err or 'invalid or missing protocol'}"
            ),
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    try:
        active_gate, epoch = _resolve_gate_for_packet(out, mcp_gate)
    except (PermissionError, TypeError, ValueError) as exc:
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
        out["verification"] = {
            "sql_passed": True,
            "static_check_passed": static_check_passed,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=f"MCP key policy blocked {stage_label}: {exc}",
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    supervisor_signed = _has_verifiable_packet_supervisor_signature(
        out,
        protocol_target=protocol_target,
        bounds_map=bounds_map,
        epoch=epoch,
        mcp_gate=active_gate,
    )

    if is_frontier and not supervisor_signed:
        if effective_defer:
            nonce = out.get("mcp_nonce")
            try:
                unsigned_frontier_env = active_gate.mint(
                    protocol_target,
                    token_epoch=epoch,
                    nonce=str(nonce) if isinstance(nonce, str) and nonce.strip() else None,
                    lean_proof_valid=False,
                    is_frontier_exception=True,
                    human_supervisor_signed=False,
                    human_supervisor_id="",
                    envelope_bounds=bounds_map,
                )
            except (PermissionError, TypeError, ValueError) as exc:
                out["halted"] = True
                out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
                out["verification"] = {
                    "sql_passed": True,
                    "static_check_passed": static_check_passed,
                    "mcp_envelope": None,
                }
                _record_traces(
                    out,
                    summary=f"MCP minting blocked frontier deferral: {exc}",
                    replace_existing_repo_trace=replace_existing_repo_trace,
                )
                return out

            out["halted"] = True
            out["halt_reason"] = "L4_VERIFY_FRONTIER_DEFERRED"
            out["verification"] = {
                "sql_passed": True,
                "static_check_passed": static_check_passed,
                "mcp_envelope": unsigned_frontier_env.to_dict(),
                "frontier_deferred": True,
                "deferred_nonce": unsigned_frontier_env.nonce,
            }
            _record_traces(
                out,
                summary=(
                    f"Unsigned frontier exception {unsigned_frontier_env.nonce!r} deferred "
                    f"for daytime human supervisor co-signature (epoch={epoch})"
                ),
                replace_existing_repo_trace=replace_existing_repo_trace,
            )
            active_gate.verify(
                unsigned_frontier_env,
                actual_protocol=protocol_target,
                defer_unsigned_frontier=True,
                wire_packet=out,
            )
            return out

        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
        out["verification"] = {
            "sql_passed": True,
            "static_check_passed": static_check_passed,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                "Unsigned or self-declared frontier exception blocked at L4 "
                "(requires verifiable supervisor signature or defer_unsigned_frontier=True)"
            ),
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    try:
        minted = _mint_capability_envelope(
            out,
            protocol_target,
            bounds_map,
            mcp_gate=active_gate,
            lean_proof_valid=static_proof_valid if not is_frontier else False,
            is_frontier_exception=is_frontier,
            human_supervisor_signed=supervisor_signed,
            human_supervisor_id=supervisor_id,
        )
    except (PermissionError, TypeError, ValueError) as exc:
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
        out["verification"] = {
            "sql_passed": True,
            "static_check_passed": static_check_passed,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=f"MCP capability minting blocked {stage_label}: {exc}",
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    out["verification"] = {
        "sql_passed": True,
        "static_check_passed": static_check_passed,
        "mcp_envelope": minted.to_dict(),
    }
    _record_traces(
        out,
        summary=(
            f"SQL read-only gate passed and minted {stage_label} lean-mcp/v1 envelope "
            f"(epoch={minted.token_epoch}, sha256={minted.protocol_sha256[:12]}...)"
        ),
        replace_existing_repo_trace=replace_existing_repo_trace,
    )
    return out


def process_packet(
    packet: dict[str, Any],
    *,
    mcp_gate: LeanMcpGate | None = None,
    defer_unsigned_frontier: bool | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute the Layer L4 `lab-verify` SQL & `lean-mcp/v1` capability wire gate."""
    out = _init_wire_packet(packet)
    if out["halted"]:
        return out

    sql_verdict = _evaluate_readonly_sql(out, db_path=db_path)
    if not sql_verdict.passed:
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_SQL_BLOCK"
        out["verification"] = {
            "sql_passed": False,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                f"SQL gate blocked query at layer {sql_verdict.layer or 'unknown'}: "
                f"{sql_verdict.reason}"
            ),
        )
        return out

    stepbot_compiled = (
        out["stepbot_compiled"]
        if isinstance(out.get("stepbot_compiled"), Mapping)
        else {}
    )
    (
        protocol_target,
        static_check_passed,
        static_proof_valid,
        ast_malicious_or_broken,
        inferred_bounds,
        protocol_err,
    ) = _resolve_and_validate_protocol_target(out)

    raw_bounds = (
        out.get("envelope_bounds")
        if out.get("envelope_bounds") is not None
        else stepbot_compiled.get("envelope_bounds")
    )
    bounds_map = raw_bounds if isinstance(raw_bounds, Mapping) else inferred_bounds

    return _gate_and_mint_stage(
        out,
        protocol_target=protocol_target,
        static_check_passed=static_check_passed,
        static_proof_valid=static_proof_valid,
        ast_malicious_or_broken=ast_malicious_or_broken,
        protocol_err=protocol_err,
        bounds_map=bounds_map,
        mcp_gate=mcp_gate,
        defer_unsigned_frontier=defer_unsigned_frontier,
        replace_existing_repo_trace=False,
        stage_label="routine",
    )


def mint_for_compiled_stepbot(
    packet: dict[str, Any],
    *,
    mcp_gate: LeanMcpGate | None = None,
    defer_unsigned_frontier: bool | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify SQL and mint a `lean-mcp/v1` envelope bound to `stepbot_compiled.python_code`."""
    out = _init_wire_packet(packet)
    if out["halted"]:
        return out

    stepbot_compiled = out.get("stepbot_compiled")
    if not isinstance(stepbot_compiled, Mapping) or not isinstance(
        stepbot_compiled.get("python_code"), str
    ):
        raise ValueError(
            "mint_for_compiled_stepbot requires packet['stepbot_compiled']['python_code'] as a string"
        )

    python_code: str = stepbot_compiled["python_code"]
    raw_bounds = (
        stepbot_compiled.get("envelope_bounds")
        if stepbot_compiled.get("envelope_bounds") is not None
        else out.get("envelope_bounds")
    )

    sql_verdict = _evaluate_readonly_sql(out, db_path=db_path)
    if not sql_verdict.passed:
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_SQL_BLOCK"
        out["verification"] = {
            "sql_passed": False,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                f"SQL gate blocked query before stepbot minting at layer "
                f"{sql_verdict.layer or 'unknown'}: {sql_verdict.reason}"
            ),
            replace_existing_repo_trace=True,
        )
        return out

    (
        _,
        static_check_passed,
        static_proof_valid,
        ast_malicious_or_broken,
        inferred_bounds,
        protocol_err,
    ) = _resolve_and_validate_protocol_target(out, explicit_python_code=python_code)
    bounds_map = raw_bounds if isinstance(raw_bounds, Mapping) else inferred_bounds

    return _gate_and_mint_stage(
        out,
        protocol_target=python_code,
        static_check_passed=static_check_passed,
        static_proof_valid=static_proof_valid,
        ast_malicious_or_broken=ast_malicious_or_broken,
        protocol_err=protocol_err,
        bounds_map=bounds_map,
        mcp_gate=mcp_gate,
        defer_unsigned_frontier=defer_unsigned_frontier,
        replace_existing_repo_trace=True,
        stage_label="stepbot-bound",
    )


def cosign_deferred_packet(
    packet_or_gate: Mapping[str, Any] | LeanMcpGate,
    nonce: str | None = None,
    *,
    supervisor_id: str,
    mcp_gate: LeanMcpGate | None = None,
    current_deck_epoch: int | None = None,
    secret_key: str | bytes | None = None,
    supervisor_secret_key: str | bytes | None = None,
    supervisor_hmac_sha256: str = "",
    supervisor_private_key: Any | None = None,
    supervisor_ed25519_sig: str = "",
    supervisor_key_id: str = "",
    new_nonce: str | None = None,
    ttl_seconds: int | None = None,
    allow_insecure_dev_key: bool = False,
) -> dict[str, Any]:
    """Release a deferred overnight frontier packet with a cryptographic human supervisor co-signature."""
    if not isinstance(supervisor_id, str) or not supervisor_id.strip():
        raise ValueError("supervisor_id must be a non-empty string")
    clean_sup_id = supervisor_id.strip()

    if isinstance(packet_or_gate, LeanMcpGate):
        gate = packet_or_gate
        cosigned_env = gate.cosign_deferred_exception(
            nonce,
            supervisor_id=clean_sup_id,
            new_nonce=new_nonce,
            supervisor_private_key=supervisor_private_key,
            supervisor_ed25519_sig=supervisor_ed25519_sig,
            supervisor_key_id=supervisor_key_id,
            supervisor_secret_key=supervisor_secret_key,
            supervisor_hmac_sha256=supervisor_hmac_sha256,
            current_deck_epoch=current_deck_epoch,
            ttl_seconds=ttl_seconds,
        )
        lookup_nonce = nonce if nonce is not None else cosigned_env.nonce
        stored_pkt = gate.deferred_wire_packets.pop(lookup_nonce, None)
        if stored_pkt is None and new_nonce is not None:
            for k in list(gate.deferred_wire_packets.keys()):
                if gate.deferred_wire_packets[k].get("verification", {}).get(
                    "mcp_envelope", {}
                ).get("protocol_sha256") == cosigned_env.protocol_sha256:
                    stored_pkt = gate.deferred_wire_packets.pop(k)
                    break
        if gate._state_store is not None:
            with gate._state_store.transaction(write=True) as st:
                st.deferred_wire_packets.pop(lookup_nonce, None)
        out = _init_wire_packet(stored_pkt or {})
    elif isinstance(packet_or_gate, Mapping):
        out = _init_wire_packet(packet_or_gate)
        ver_block = out.get("verification") if isinstance(out.get("verification"), Mapping) else {}
        if out.get("halt_reason") != "L4_VERIFY_FRONTIER_DEFERRED" and not ver_block.get(
            "frontier_deferred"
        ):
            raise ValueError(
                "cosign_deferred_packet requires a packet halted with L4_VERIFY_FRONTIER_DEFERRED"
            )
        prev_env_raw = ver_block.get("mcp_envelope")
        if not isinstance(prev_env_raw, Mapping):
            raise ValueError("deferred packet is missing verification['mcp_envelope']")
        prev_env = LeanMcpEnvelope.from_dict(prev_env_raw)
        target_nonce = nonce or prev_env.nonce

        if mcp_gate is not None and any(
            item.nonce == target_nonce for item in mcp_gate.deferred_daytime_queue
        ):
            cosigned_env = mcp_gate.cosign_deferred_exception(
                target_nonce,
                supervisor_id=clean_sup_id,
                new_nonce=new_nonce,
                supervisor_private_key=supervisor_private_key,
                supervisor_ed25519_sig=supervisor_ed25519_sig,
                supervisor_key_id=supervisor_key_id,
                supervisor_secret_key=supervisor_secret_key,
                supervisor_hmac_sha256=supervisor_hmac_sha256,
                current_deck_epoch=current_deck_epoch,
                ttl_seconds=ttl_seconds,
            )
            mcp_gate.deferred_wire_packets.pop(target_nonce, None)
        else:
            epoch = (
                current_deck_epoch
                if current_deck_epoch is not None
                else (
                    mcp_gate.current_deck_epoch
                    if mcp_gate is not None
                    else int(out.get("deck_epoch", prev_env.token_epoch))
                )
            )
            eff_secret = secret_key if secret_key is not None else out.get("mcp_secret_key")
            eff_sup_secret = (
                supervisor_secret_key
                if supervisor_secret_key is not None
                else out.get("mcp_supervisor_secret_key")
            )
            eff_allow_dev = bool(allow_insecure_dev_key or out.get("allow_insecure_dev_key", False))
            stepbot_compiled = (
                out["stepbot_compiled"]
                if isinstance(out.get("stepbot_compiled"), Mapping)
                else {}
            )
            proto_target = (
                stepbot_compiled.get("python_code")
                or out.get("compiled_python_code")
            )
            proto_sha = (
                None if isinstance(proto_target, str) else prev_env.protocol_sha256
            )
            clean_bounds = {
                k: v for k, v in prev_env.envelope_bounds.items() if k != "supervisor_hmac_sha256"
            }
            cosigned_env = mint_mcp_envelope(
                proto_target if isinstance(proto_target, str) else None,
                protocol_sha256=proto_sha,
                secret_key=eff_secret if out.get("mcp_minter_private_key") is None else None,
                token_epoch=epoch,
                tool_name=prev_env.tool_name,
                nonce=prev_env.nonce if new_nonce is None else new_nonce,
                lean_proof_valid=False,
                is_frontier_exception=True,
                human_supervisor_signed=True,
                human_supervisor_id=clean_sup_id,
                envelope_bounds=clean_bounds,
                minter_private_key=out.get("mcp_minter_private_key"),
                minter_key_id=str(out.get("mcp_minter_key_id", prev_env.minter_key_id)),
                supervisor_private_key=supervisor_private_key or out.get("mcp_supervisor_private_key"),
                supervisor_ed25519_sig=supervisor_ed25519_sig,
                supervisor_key_id=supervisor_key_id,
                supervisor_secret_key=eff_sup_secret,
                supervisor_hmac_sha256=supervisor_hmac_sha256,
                ttl_seconds=ttl_seconds,
                allow_insecure_dev_key=eff_allow_dev,
            )
    else:
        raise TypeError("packet_or_gate must be a deferred packet mapping or LeanMcpGate")

    prev_static = bool(
        (out.get("verification") or {}).get("static_check_passed", cosigned_env.static_check_passed)
    )
    out["halted"] = False
    out["halt_reason"] = None
    out["deck_epoch"] = cosigned_env.token_epoch
    out["is_frontier_exception"] = True
    out["human_supervisor_signed"] = True
    out["human_supervisor_id"] = clean_sup_id
    out["verification"] = {
        "sql_passed": True,
        "static_check_passed": prev_static,
        "mcp_envelope": cosigned_env.to_dict(),
    }
    _record_traces(
        out,
        summary=(
            f"Human supervisor {clean_sup_id!r} co-signed deferred frontier envelope "
            f"(epoch={cosigned_env.token_epoch}, sha256={cosigned_env.protocol_sha256[:12]}...)"
        ),
        replace_existing_repo_trace=True,
    )
    return out


cosign_and_release_for_stepbot = cosign_deferred_packet


__all__ = [
    "DEFAULT_MCP_SECRET",
    "DEFAULT_SQL_QUERY",
    "INVARIANT_NAME",
    "LAYER",
    "REPO_DIR",
    "REPO_ID",
    "WIRE_SCHEMA_VERSION",
    "cosign_and_release_for_stepbot",
    "cosign_deferred_packet",
    "mint_for_compiled_stepbot",
    "process_packet",
]
