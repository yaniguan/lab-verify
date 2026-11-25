"""Auto-Lab 15-repository wire node (`autolab-wire/v1`) for `lab-verify` (Layer L4).

Enforces the 4-layer read-only SQLite gate (`lab_verify.sql_gate`), validates
static protocol/AST soundness, supports overnight unsigned frontier deferral
(`L4_VERIFY_FRONTIER_DEFERRED`) plus daytime human supervisor co-sign release
(`cosign_deferred_packet`), and mints `lean-mcp/v1` zero-trust hardware
capability envelopes (`lab_verify.mcp_gate.LeanMcpGate`) for downstream
`stepbot` execution, pairing pre-execution verification (`lab-rehearsal`,
`lab-verify`) with post-execution causal attribution (`lab-attrib`).
"""

from __future__ import annotations

import copy
import math
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
    "requires canonical HMAC-SHA256 or Ed25519 authenticity, exact SHA-256 protocol "
    "binding, active key-rotation epoch, fresh deck epoch, single-use nonce, unexpired "
    "TTL window, and a valid Lean proof certificate or role-separated supervisor co-signature."
)

DEFAULT_WIRE_PROTOCOL_IR: dict[str, Any] = {
    "steps": [
        {"op": "pick_up_tip"},
        {"op": "aspirate", "loc": "res:1", "vol": 50.0},
        {"op": "dispense", "loc": "plate:A1", "vol": 50.0},
        {"op": "drop_tip"},
    ]
}

REPO_DIR = Path(__file__).resolve().parent
SRC_DIR = REPO_DIR / "src"
for _candidate_path in (str(SRC_DIR), str(REPO_DIR)):
    if _candidate_path not in sys.path:
        sys.path.insert(0, _candidate_path)

from lab_verify.mcp_gate import (  # noqa: E402
    LeanMcpEnvelope,
    LeanMcpGate,
    _infer_static_proof_and_bounds,
    mint_mcp_envelope,
)
from lab_verify.protocol_gate import verify_protocol  # noqa: E402
from lab_verify.sql_gate import build_db, verify_sql  # noqa: E402
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


def _evaluate_readonly_sql(out: Mapping[str, Any]) -> VerifyVerdict:
    """Run `lab-verify`'s 4-layer read-only SQLite gate against the synthetic lab DB."""
    sql_query = (
        DEFAULT_SQL_QUERY
        if "sql_query" not in out or out["sql_query"] is None
        else out["sql_query"]
    )
    gold_sql = out.get("gold_sql")
    con = build_db()
    try:
        return verify_sql(
            con,
            sql_query,
            gold_sql=gold_sql if isinstance(gold_sql, str) else None,
            allow_cross_join=bool(out.get("allow_cross_join", False)),
            allow_recursive_cte=bool(out.get("allow_recursive_cte", True)),
        )
    finally:
        con.close()


def _is_valid_stepbot_ir(ir: Mapping[str, Any]) -> bool:
    steps = ir.get("steps")
    if not isinstance(steps, list) or len(steps) == 0:
        return False
    for step in steps:
        if not isinstance(step, Mapping):
            return False
        action = step.get("action")
        if not isinstance(action, str) or not action.strip():
            return False
        vol = step.get("volume")
        if vol is not None:
            if isinstance(vol, bool) or not isinstance(vol, (int, float)):
                return False
            if not math.isfinite(float(vol)) or float(vol) <= 0:
                return False
    return True


def _resolve_and_validate_protocol_target(
    out: Mapping[str, Any],
    *,
    explicit_python_code: str | None = None,
) -> tuple[Any, bool, bool, dict[str, Any] | None, str | None]:
    """Resolve `(protocol_target, static_proof_valid, ast_malicious_or_broken, inferred_bounds, err_reason)`."""
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

    py_candidate = explicit_python_code
    if py_candidate is None:
        raw_py = out.get("compiled_python_code") or stepbot_compiled.get("python_code")
        if isinstance(raw_py, str):
            py_candidate = raw_py

    if py_candidate is not None:
        py_ok, inferred_bounds = _infer_static_proof_and_bounds(py_candidate)
        if not py_ok:
            return (
                py_candidate,
                False,
                True,
                inferred_bounds,
                "compiled Python script failed static AST safety or lacks def run(protocol)",
            )
        override = out.get("lean_proof_valid")
        proof_ok = rehearsal_passed and (True if override is None else bool(override))
        reason = None if proof_ok else "upstream rehearsal or Lean proof flag rejected protocol"
        return py_candidate, proof_ok, False, inferred_bounds, reason

    if "protocol_yaml_dict" in rehearsal and rehearsal["protocol_yaml_dict"] is not None:
        ir = rehearsal["protocol_yaml_dict"]
        if isinstance(ir, Mapping) and "steps" in ir:
            steps = ir.get("steps")
            if not isinstance(steps, list) or len(steps) == 0:
                return ir, False, False, None, "protocol_yaml_dict steps list must be non-empty"
            first = steps[0]
            if isinstance(first, Mapping) and "action" in first and "op" not in first and "type" not in first:
                ir_ok = _is_valid_stepbot_ir(ir)
                err = None if ir_ok else "invalid stepbot protocol_yaml_dict step specification"
            else:
                v = verify_protocol(ir)
                ir_ok = v.passed
                err = None if ir_ok else v.reason
        elif isinstance(ir, Sequence) and not isinstance(ir, (str, bytes)):
            v = verify_protocol(ir)
            ir_ok = v.passed
            err = None if ir_ok else v.reason
        else:
            ir_ok = False
            err = "protocol_yaml_dict must be a mapping or sequence of steps"

        override = out.get("lean_proof_valid")
        proof_ok = ir_ok and rehearsal_passed and (True if override is None else bool(override))
        if not proof_ok and err is None:
            err = "upstream rehearsal or Lean proof check failed"
        return ir, proof_ok, False, None, err

    override = out.get("lean_proof_valid")
    proof_ok = rehearsal_passed and (True if override is None else bool(override))
    err = None if proof_ok else "upstream rehearsal or Lean proof check failed"
    return DEFAULT_WIRE_PROTOCOL_IR, proof_ok, False, None, err


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

    secret_key = out.get("mcp_secret_key") or DEFAULT_MCP_SECRET
    deck_epoch = int(out["deck_epoch"]) if out.get("deck_epoch") is not None else 1
    minter_priv = out.get("mcp_minter_private_key")
    state_path = out.get("mcp_state_path")
    gate = LeanMcpGate(
        secret_key=secret_key if minter_priv is None else None,
        initial_deck_epoch=deck_epoch,
        check_lean_kernel=False,
        state_path=state_path,
        minter_private_key=minter_priv,
        minter_key_id=str(out.get("mcp_minter_key_id", "")),
        key_epoch=out.get("mcp_key_epoch"),
        default_ttl_seconds=out.get("mcp_ttl_seconds"),
    )
    return gate, gate.current_deck_epoch


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
    supervisor_signed = bool(out.get("human_supervisor_signed", False))
    supervisor_id = str(out.get("human_supervisor_id", ""))
    effective_defer = (
        bool(out.get("defer_unsigned_frontier", False))
        if defer_unsigned_frontier is None
        else bool(defer_unsigned_frontier)
    )

    if ast_malicious_or_broken or (not is_frontier and not static_proof_valid):
        out["halted"] = True
        out["halt_reason"] = "L4_VERIFY_PROTOCOL_BLOCK"
        out["verification"] = {
            "sql_passed": True,
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                f"Protocol/AST verification blocked {stage_label}: "
                f"{protocol_err or 'invalid protocol'}"
            ),
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    if is_frontier and not supervisor_signed:
        active_gate, epoch = _resolve_gate_for_packet(out, mcp_gate)
        nonce = out.get("mcp_nonce")
        unsigned_frontier_env = active_gate.mint(
            protocol_target,
            token_epoch=epoch,
            nonce=str(nonce) if isinstance(nonce, str) and nonce.strip() else None,
            lean_proof_valid=bool(out.get("lean_proof_valid", False)),
            is_frontier_exception=True,
            human_supervisor_signed=False,
            human_supervisor_id="",
            envelope_bounds=bounds_map,
        )
        if effective_defer:
            out["halted"] = True
            out["halt_reason"] = "L4_VERIFY_FRONTIER_DEFERRED"
            out["verification"] = {
                "sql_passed": True,
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
            "mcp_envelope": None,
        }
        _record_traces(
            out,
            summary=(
                "Unsigned out-of-regime frontier exception blocked at L4 "
                "(requires human supervisor co-signature or defer_unsigned_frontier=True)"
            ),
            replace_existing_repo_trace=replace_existing_repo_trace,
        )
        return out

    minted = _mint_capability_envelope(
        out,
        protocol_target,
        bounds_map,
        mcp_gate=mcp_gate,
        lean_proof_valid=static_proof_valid if not is_frontier else bool(out.get("lean_proof_valid", False)),
        is_frontier_exception=is_frontier,
        human_supervisor_signed=supervisor_signed,
        human_supervisor_id=supervisor_id,
    )
    out["verification"] = {
        "sql_passed": True,
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
) -> dict[str, Any]:
    """Execute the Layer L4 `lab-verify` SQL & `lean-mcp/v1` capability wire gate."""
    out = _init_wire_packet(packet)
    if out["halted"]:
        return out

    sql_verdict = _evaluate_readonly_sql(out)
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

    sql_verdict = _evaluate_readonly_sql(out)
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
        static_proof_valid,
        ast_malicious_or_broken,
        inferred_bounds,
        protocol_err,
    ) = _resolve_and_validate_protocol_target(out, explicit_python_code=python_code)
    bounds_map = raw_bounds if isinstance(raw_bounds, Mapping) else inferred_bounds

    return _gate_and_mint_stage(
        out,
        protocol_target=python_code,
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
    supervisor_private_key: Any | None = None,
    supervisor_ed25519_sig: str = "",
    supervisor_key_id: str = "",
    new_nonce: str | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Release a deferred overnight frontier packet with a human supervisor co-signature for `stepbot`."""
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
            eff_secret = (
                secret_key
                if secret_key is not None
                else (out.get("mcp_secret_key") or DEFAULT_MCP_SECRET)
            )
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
            cosigned_env = mint_mcp_envelope(
                proto_target if isinstance(proto_target, str) else None,
                protocol_sha256=proto_sha,
                secret_key=eff_secret if out.get("mcp_minter_private_key") is None else None,
                token_epoch=epoch,
                tool_name=prev_env.tool_name,
                nonce=prev_env.nonce if new_nonce is None else new_nonce,
                lean_proof_valid=prev_env.lean_proof_valid,
                is_frontier_exception=True,
                human_supervisor_signed=True,
                human_supervisor_id=clean_sup_id,
                envelope_bounds=prev_env.envelope_bounds,
                minter_private_key=out.get("mcp_minter_private_key"),
                minter_key_id=str(out.get("mcp_minter_key_id", prev_env.minter_key_id)),
                supervisor_private_key=supervisor_private_key or out.get("mcp_supervisor_private_key"),
                supervisor_ed25519_sig=supervisor_ed25519_sig,
                supervisor_key_id=supervisor_key_id,
                ttl_seconds=ttl_seconds,
            )
    else:
        raise TypeError("packet_or_gate must be a deferred packet mapping or LeanMcpGate")

    out["halted"] = False
    out["halt_reason"] = None
    out["deck_epoch"] = cosigned_env.token_epoch
    out["is_frontier_exception"] = True
    out["human_supervisor_signed"] = True
    out["human_supervisor_id"] = clean_sup_id
    out["verification"] = {
        "sql_passed": True,
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
