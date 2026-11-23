"""Idea #12: Zero-Trust Lean-MCP Capability Firewall.

Inspired by nygmeta/OpenLabAI hardware capability debates and Lean4Agent workflow
verification. Stateless API-key or bearer-token wrappers around robotic lab tools remain
vulnerable to stale deck-epoch replays, post-signing parameter tampering, and unsigned
frontier overrides.

This stateful capability firewall:
  1. Issues HMAC-SHA256 capability tokens bound to (nonce, deck_epoch, protocol_sha256,
     params_sha256, lean_verified, is_frontier_exception, human_cosign_tag).
  2. Separates the autonomous Proof-Gate HMAC key from the Human-Supervisor Co-Sign HMAC
     key so an agent process can never self-sign a frontier override.
  3. Enforces exact epoch freshness (`token.deck_epoch == current_deck_epoch`), single-use
     nonce replay prevention, payload hash binding, and `LabVerifyLean.checkMcpHardwareCall`
     authorization semantics in constant time (`hmac.compare_digest`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import statistics
import time
from dataclasses import dataclass
from typing import Any


def canonical_sha256(payload: Any) -> str:
    """Compute a deterministic SHA-256 hex digest over canonical JSON."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CapabilityToken:
    """Cryptographic capability token bound to a specific deck epoch and verified payload."""

    nonce: str
    deck_epoch: int
    protocol_sha256: str
    params_sha256: str
    lean_verified: bool
    is_frontier_exception: bool
    token_hmac: str
    human_cosign_hmac: str | None = None


@dataclass(frozen=True)
class McpExecutionRequest:
    """Incoming hardware MCP execution request presented to the capability firewall."""

    tool_name: str
    protocol_sha256: str
    parameters: dict[str, Any]
    token: CapabilityToken
    mutates_deck_state: bool = False


@dataclass(frozen=True)
class FirewallDecision:
    """Authorization decision returned by the capability firewall."""

    allowed: bool
    rule_violated: str | None
    detail: str
    new_deck_epoch: int
    latency_us: float


class StatelessBearerGate:
    """Baseline stateless bearer check verifying only that a static API token string is non-empty."""

    def __init__(self, expected_key: str = "static-bearer-token") -> None:
        self.expected_key = expected_key

    def verify(self, api_key: str, req: McpExecutionRequest) -> bool:
        _ = req
        return hmac.compare_digest(api_key, self.expected_key)


class LeanMcpFirewall:
    """Stateful epoch-tracking zero-trust Lean-MCP capability firewall."""

    def __init__(
        self,
        firewall_secret: bytes,
        supervisor_secret: bytes,
        initial_deck_epoch: int = 1,
    ) -> None:
        if firewall_secret == supervisor_secret:
            raise ValueError("firewall_secret and supervisor_secret must be distinct keys")
        self._firewall_secret = firewall_secret
        self._supervisor_secret = supervisor_secret
        self.current_deck_epoch = initial_deck_epoch
        self._consumed_nonces: set[str] = set()

    def advance_deck_epoch(self, delta: int = 1) -> int:
        if delta < 1:
            raise ValueError("epoch delta must be >= 1")
        self.current_deck_epoch += delta
        return self.current_deck_epoch

    def _compute_token_hmac(
        self,
        nonce: str,
        deck_epoch: int,
        protocol_sha256: str,
        params_sha256: str,
        lean_verified: bool,
        is_frontier_exception: bool,
    ) -> str:
        msg = (
            f"{nonce}|{deck_epoch}|{protocol_sha256}|{params_sha256}|"
            f"{int(lean_verified)}|{int(is_frontier_exception)}"
        ).encode("utf-8")
        return hmac.new(self._firewall_secret, msg, hashlib.sha256).hexdigest()

    def sign_human_supervisor_override(
        self,
        nonce: str,
        deck_epoch: int,
        protocol_sha256: str,
        params_sha256: str,
    ) -> str:
        """Issue an explicit human supervisor co-signature for a frontier exception."""
        msg = f"SUPERVISOR_COSIGN|{nonce}|{deck_epoch}|{protocol_sha256}|{params_sha256}".encode(
            "utf-8"
        )
        return hmac.new(self._supervisor_secret, msg, hashlib.sha256).hexdigest()

    def issue_capability_token(
        self,
        protocol_sha256: str,
        parameters: dict[str, Any],
        *,
        lean_verified: bool,
        is_frontier_exception: bool = False,
        human_cosign_hmac: str | None = None,
        deck_epoch_override: int | None = None,
        nonce: str | None = None,
    ) -> CapabilityToken:
        epoch = self.current_deck_epoch if deck_epoch_override is None else deck_epoch_override
        tok_nonce = nonce if nonce is not None else secrets.token_hex(12)
        p_hash = canonical_sha256(parameters)
        mac = self._compute_token_hmac(
            tok_nonce,
            epoch,
            protocol_sha256,
            p_hash,
            lean_verified,
            is_frontier_exception,
        )
        return CapabilityToken(
            nonce=tok_nonce,
            deck_epoch=epoch,
            protocol_sha256=protocol_sha256,
            params_sha256=p_hash,
            lean_verified=lean_verified,
            is_frontier_exception=is_frontier_exception,
            token_hmac=mac,
            human_cosign_hmac=human_cosign_hmac,
        )

    def authorize_and_execute(self, req: McpExecutionRequest) -> FirewallDecision:
        """Verify HMAC authenticity, parameter binding, epoch freshness, nonce uniqueness,
        and LabVerifyLean proof/cosign authorization rules."""
        t0 = time.perf_counter_ns()
        tok = req.token

        # 1. Constant-time capability HMAC check
        expected_mac = self._compute_token_hmac(
            tok.nonce,
            tok.deck_epoch,
            tok.protocol_sha256,
            tok.params_sha256,
            tok.lean_verified,
            tok.is_frontier_exception,
        )
        if not hmac.compare_digest(tok.token_hmac, expected_mac):
            lat = (time.perf_counter_ns() - t0) / 1000.0
            return FirewallDecision(
                False,
                "invalid_token_hmac",
                "capability token HMAC-SHA256 verification failed",
                self.current_deck_epoch,
                lat,
            )

        # 2. Request payload & protocol hash binding check
        live_params_hash = canonical_sha256(req.parameters)
        if not (
            hmac.compare_digest(tok.protocol_sha256, req.protocol_sha256)
            and hmac.compare_digest(tok.params_sha256, live_params_hash)
        ):
            lat = (time.perf_counter_ns() - t0) / 1000.0
            return FirewallDecision(
                False,
                "parameter_or_protocol_tampered",
                "live MCP parameters or protocol hash diverge from signed token commitment",
                self.current_deck_epoch,
                lat,
            )

        # 3. Deck-state epoch freshness check (mirrors LabVerifyLean.checkMcpHardwareCall)
        if tok.deck_epoch != self.current_deck_epoch:
            lat = (time.perf_counter_ns() - t0) / 1000.0
            return FirewallDecision(
                False,
                "mcp_epoch_freshness",
                f"stale token deck_epoch={tok.deck_epoch} != live={self.current_deck_epoch}",
                self.current_deck_epoch,
                lat,
            )

        # 4. Single-use nonce replay guard within the same epoch
        if tok.nonce in self._consumed_nonces:
            lat = (time.perf_counter_ns() - t0) / 1000.0
            return FirewallDecision(
                False,
                "nonce_replay_detected",
                "capability token nonce was already consumed",
                self.current_deck_epoch,
                lat,
            )

        # 5. Proof-or-cosigned-exception check (exact mirror of LabVerifyLean)
        human_sign_valid = False
        if tok.human_cosign_hmac is not None:
            expected_sup = self.sign_human_supervisor_override(
                tok.nonce,
                tok.deck_epoch,
                tok.protocol_sha256,
                tok.params_sha256,
            )
            human_sign_valid = hmac.compare_digest(tok.human_cosign_hmac, expected_sup)

        authorized = (tok.lean_verified and not tok.is_frontier_exception) or (
            tok.is_frontier_exception and human_sign_valid
        )
        if not authorized:
            lat = (time.perf_counter_ns() - t0) / 1000.0
            return FirewallDecision(
                False,
                "mcp_proof_or_cosigned_exception",
                "call lacks a valid Lean proof (routine) or valid human supervisor HMAC (frontier)",
                self.current_deck_epoch,
                lat,
            )

        # Commit nonce consumption and advance deck epoch if state-mutating
        self._consumed_nonces.add(tok.nonce)
        if req.mutates_deck_state:
            self.current_deck_epoch += 1
        lat = (time.perf_counter_ns() - t0) / 1000.0
        return FirewallDecision(
            True,
            None,
            "authorized_by_lean_mcp_firewall",
            self.current_deck_epoch,
            lat,
        )


def run_benchmark(num_requests: int = 200, seed: int = 2026) -> dict[str, Any]:
    """Evaluate LeanMcpFirewall across 200 valid + replay/tampered/unsigned MCP requests."""
    _ = seed
    fw = LeanMcpFirewall(
        firewall_secret=b"autolab-l4-proof-gate-hmac-key-2026",
        supervisor_secret=b"autolab-human-pi-hardware-cosign-key-2026",
        initial_deck_epoch=1,
    )
    bearer = StatelessBearerGate(expected_key="valid-session-bearer")

    valid_count = int(round(num_requests * 0.40))  # 80 valid requests
    adv_count = num_requests - valid_count  # 120 adversarial requests

    latencies_us: list[float] = []
    fw_false_blocks = 0
    fw_adv_blocked = 0
    bearer_adv_blocked = 0
    blocked_by_category: dict[str, int] = {
        "stale_epoch_replay": 0,
        "same_epoch_nonce_replay": 0,
        "tampered_parameters": 0,
        "unsigned_frontier_override": 0,
        "forged_or_unverified_token": 0,
    }

    saved_stale_tokens: list[tuple[str, dict[str, Any], CapabilityToken]] = []
    last_same_epoch_req: McpExecutionRequest | None = None

    # Phase 1: Execute legitimate routine Lean-certified & human-cosigned frontier calls
    for idx in range(valid_count):
        proto_hash = canonical_sha256({"protocol_idx": idx, "version": "1.0"})
        params = {"src_well": f"A{(idx % 12) + 1}", "volume_ul": 25.0 + (idx % 50)}
        is_frontier = idx % 8 == 7
        nonce = f"valid-nonce-{idx:04d}"
        sup_hmac = (
            fw.sign_human_supervisor_override(
                nonce, fw.current_deck_epoch, proto_hash, canonical_sha256(params)
            )
            if is_frontier
            else None
        )
        tok = fw.issue_capability_token(
            proto_hash,
            params,
            lean_verified=not is_frontier,
            is_frontier_exception=is_frontier,
            human_cosign_hmac=sup_hmac,
            nonce=nonce,
        )
        # Mutate deck epoch every 4th call so earlier tokens become stale-epoch candidates
        mutates = (idx % 4 == 2) and (idx < valid_count - 2)
        if mutates:
            saved_stale_tokens.append((proto_hash, dict(params), tok))
        req = McpExecutionRequest(
            tool_name="stepbot_aspirate_dispense",
            protocol_sha256=proto_hash,
            parameters=params,
            token=tok,
            mutates_deck_state=mutates,
        )
        dec = fw.authorize_and_execute(req)
        latencies_us.append(dec.latency_us)
        if not dec.allowed:
            fw_false_blocks += 1
        if not mutates:
            last_same_epoch_req = req

    assert last_same_epoch_req is not None

    # Phase 2: Execute 120 adversarial attacks across 5 distinct threat classes
    for a_idx in range(adv_count):
        mode = a_idx % 5
        api_key = "valid-session-bearer"

        if mode == 0:
            # Stale deck-epoch replay of a previously valid token
            p_hash, orig_params, old_tok = saved_stale_tokens[a_idx % len(saved_stale_tokens)]
            adv_req = McpExecutionRequest(
                tool_name="stepbot_aspirate_dispense",
                protocol_sha256=p_hash,
                parameters=orig_params,
                token=old_tok,
            )
            cat = "stale_epoch_replay"
        elif mode == 1:
            # Same-epoch duplicate nonce replay
            adv_req = last_same_epoch_req
            cat = "same_epoch_nonce_replay"
        elif mode == 2:
            # Post-signing parameter tampering (e.g. inflating volume_ul from 50 uL to 950 uL)
            p_hash = canonical_sha256({"attack_proto": a_idx})
            signed_params = {"src_well": "B2", "volume_ul": 50.0}
            tok = fw.issue_capability_token(
                p_hash,
                signed_params,
                lean_verified=True,
                nonce=f"tamper-nonce-{a_idx:04d}",
            )
            adv_req = McpExecutionRequest(
                tool_name="stepbot_aspirate_dispense",
                protocol_sha256=p_hash,
                parameters={"src_well": "B2", "volume_ul": 950.0},
                token=tok,
            )
            cat = "tampered_parameters"
        elif mode == 3:
            # Unsigned or agent-forged frontier exception override
            p_hash = canonical_sha256({"frontier_attack": a_idx})
            params = {"temp_c": 105.0, "override_safety": True}
            forged_sup = (
                "deadbeef" * 8 if (a_idx % 2 == 0) else None
            )
            tok = fw.issue_capability_token(
                p_hash,
                params,
                lean_verified=True,
                is_frontier_exception=True,
                human_cosign_hmac=forged_sup,
                nonce=f"frontier-attack-{a_idx:04d}",
            )
            adv_req = McpExecutionRequest(
                tool_name="stepbot_incubate",
                protocol_sha256=p_hash,
                parameters=params,
                token=tok,
            )
            cat = "unsigned_frontier_override"
        else:
            # Forged capability HMAC or unverified autonomous call
            p_hash = canonical_sha256({"forged_attack": a_idx})
            params = {"src_well": "C3", "volume_ul": 40.0}
            if a_idx % 2 == 0:
                tok = CapabilityToken(
                    nonce=f"forged-{a_idx:04d}",
                    deck_epoch=fw.current_deck_epoch,
                    protocol_sha256=p_hash,
                    params_sha256=canonical_sha256(params),
                    lean_verified=True,
                    is_frontier_exception=False,
                    token_hmac="00112233" * 8,
                )
                api_key = "forged-bearer" if (a_idx % 4 == 0) else "valid-session-bearer"
            else:
                tok = fw.issue_capability_token(
                    p_hash,
                    params,
                    lean_verified=False,
                    is_frontier_exception=False,
                    nonce=f"unverified-{a_idx:04d}",
                )
            adv_req = McpExecutionRequest(
                tool_name="stepbot_aspirate_dispense",
                protocol_sha256=p_hash,
                parameters=params,
                token=tok,
            )
            cat = "forged_or_unverified_token"

        if not bearer.verify(api_key, adv_req):
            bearer_adv_blocked += 1

        dec = fw.authorize_and_execute(adv_req)
        latencies_us.append(dec.latency_us)
        if not dec.allowed:
            fw_adv_blocked += 1
            blocked_by_category[cat] += 1

    sorted_lat = sorted(latencies_us)
    p95_idx = min(len(sorted_lat) - 1, max(0, int(0.95 * len(sorted_lat)) - 1))

    return {
        "benchmark": "idea_12_lean_mcp_firewall",
        "num_requests": num_requests,
        "valid_requests": valid_count,
        "adversarial_requests": adv_count,
        "stateless_bearer_gate": {
            "adversarial_blocked": bearer_adv_blocked,
            "replay_and_tamper_block_rate": round(bearer_adv_blocked / adv_count, 4),
        },
        "lean_mcp_firewall": {
            "adversarial_blocked": fw_adv_blocked,
            "replay_and_tamper_block_rate": round(fw_adv_blocked / adv_count, 4),
            "false_positive_blocks": fw_false_blocks,
            "blocked_by_category": blocked_by_category,
            "mean_verification_latency_us": round(statistics.mean(latencies_us), 2),
            "p95_verification_latency_us": round(sorted_lat[p95_idx], 2),
        },
    }


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run_benchmark(), indent=2))
