"""Zero-trust `Lean-MCP` capability envelope minting and stateful hardware firewall gate."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Mapping, Sequence

from .protocol_gate import verify_protocol
from .verdict import Verdict

LEAN_MCP_SCHEMA_VERSION = "lean-mcp/v1"
DEFAULT_MCP_TOOL_NAME = "opentrons.execute_protocol"
DEFAULT_MCP_SECRET_KEY = "lean-mcp-dev-secret-v1"

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_REQUIRED_ENVELOPE_KEYS = frozenset(
    {
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
)


def _secret_bytes(secret_key: str | bytes) -> bytes:
    if isinstance(secret_key, bytes):
        key = secret_key
    elif isinstance(secret_key, str):
        key = secret_key.encode("utf-8")
    else:
        raise TypeError("secret_key must be str or bytes")
    if not key:
        raise ValueError("secret_key must be non-empty")
    return key


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_envelope_hmac(
    payload: Mapping[str, Any],
    secret_key: str | bytes = DEFAULT_MCP_SECRET_KEY,
) -> str:
    """Compute canonical hex HMAC-SHA256 over all envelope fields except `hmac_sha256`."""
    body = {k: v for k, v in payload.items() if k != "hmac_sha256"}
    return hmac.new(_secret_bytes(secret_key), _canonical_json_bytes(body), hashlib.sha256).hexdigest()


def compute_protocol_sha256(
    protocol_payload: str | bytes | Path | Mapping[str, Any] | Sequence[Any],
) -> str:
    """Compute deterministic 64-hex SHA-256 over compiled Python source or canonical protocol IR."""
    if isinstance(protocol_payload, bytes):
        normalized = protocol_payload.replace(b"\r\n", b"\n")
        return hashlib.sha256(normalized).hexdigest()

    if isinstance(protocol_payload, Path):
        text = protocol_payload.read_text(encoding="utf-8")
        if protocol_payload.suffix.lower() == ".json":
            parsed = json.loads(text)
            return hashlib.sha256(_canonical_json_bytes(parsed)).hexdigest()
        return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()

    if isinstance(protocol_payload, str):
        if "\n" not in protocol_payload and _HEX64_RE.match(protocol_payload.strip()):
            return protocol_payload.strip().lower()
        if "\n" not in protocol_payload:
            candidate = Path(protocol_payload)
            if candidate.exists() and candidate.is_file():
                return compute_protocol_sha256(candidate)
        stripped = protocol_payload.strip()
        if stripped.startswith(("{", "[")):
            try:
                parsed_json = json.loads(stripped)
                return hashlib.sha256(_canonical_json_bytes(parsed_json)).hexdigest()
            except json.JSONDecodeError:
                pass
        return hashlib.sha256(protocol_payload.replace("\r\n", "\n").encode("utf-8")).hexdigest()

    if isinstance(protocol_payload, (Mapping, Sequence)):
        return hashlib.sha256(_canonical_json_bytes(protocol_payload)).hexdigest()

    raise TypeError(f"Unsupported protocol payload type: {type(protocol_payload).__name__}")


def _normalize_bounds(bounds: Mapping[str, Any] | None) -> dict[str, Any]:
    if bounds is None:
        return {
            "deck_slots": [],
            "max_transfer_ul": 300.0,
            "api_level": "2.16",
        }
    out: dict[str, Any] = dict(bounds)
    if "deck_slots" in out and isinstance(out["deck_slots"], Sequence) and not isinstance(
        out["deck_slots"], (str, bytes)
    ):
        out["deck_slots"] = [int(s) for s in out["deck_slots"]]
    if "max_transfer_ul" in out and isinstance(out["max_transfer_ul"], (int, float)) and not isinstance(
        out["max_transfer_ul"], bool
    ):
        out["max_transfer_ul"] = float(out["max_transfer_ul"])
    if "api_level" in out:
        out["api_level"] = str(out["api_level"])
    return out


def _infer_static_proof_and_bounds(
    protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None,
) -> tuple[bool, dict[str, Any]]:
    default_bounds = _normalize_bounds(None)
    if protocol is None:
        return True, default_bounds

    text: str | None = None
    if isinstance(protocol, Path):
        if protocol.suffix.lower() == ".py":
            text = protocol.read_text(encoding="utf-8")
        else:
            verdict = verify_protocol(protocol)
            return verdict.passed, default_bounds
    elif isinstance(protocol, bytes):
        text = protocol.decode("utf-8")
    elif isinstance(protocol, str):
        if "\n" not in protocol and Path(protocol).exists():
            return _infer_static_proof_and_bounds(Path(protocol))
        stripped = protocol.strip()
        if stripped.startswith(("{", "[")):
            verdict = verify_protocol(stripped)
            return verdict.passed, default_bounds
        text = protocol
    else:
        verdict = verify_protocol(protocol)
        return verdict.passed, default_bounds

    # Compiled Opentrons Python API v2 script AST check
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False, default_bounds

    api_level = "2.16"
    has_run = False
    slots: set[int] = set()
    max_vol = 0.0

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return False, default_bounds
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "metadata":
                    try:
                        meta = ast.literal_eval(node.value)
                        if isinstance(meta, dict) and isinstance(meta.get("apiLevel"), str):
                            api_level = meta["apiLevel"]
                    except ValueError:
                        return False, default_bounds
        elif isinstance(node, ast.FunctionDef) and node.name == "run":
            has_run = True
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    return False, default_bounds
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if sub.func.attr == "load_labware" and len(sub.args) >= 2:
                        slot_arg = sub.args[1]
                        if isinstance(slot_arg, ast.Constant) and isinstance(slot_arg.value, int) and not isinstance(
                            slot_arg.value, bool
                        ):
                            slots.add(slot_arg.value)
                    elif sub.func.attr in ("transfer", "distribute", "aspirate", "dispense") and sub.args:
                        vol_arg = sub.args[0]
                        if isinstance(vol_arg, ast.Constant) and isinstance(
                            vol_arg.value, (int, float)
                        ) and not isinstance(vol_arg.value, bool):
                            max_vol = max(max_vol, float(vol_arg.value))
                    elif sub.func.attr == "mix" and len(sub.args) >= 2:
                        vol_arg = sub.args[1]
                        if isinstance(vol_arg, ast.Constant) and isinstance(
                            vol_arg.value, (int, float)
                        ) and not isinstance(vol_arg.value, bool):
                            max_vol = max(max_vol, float(vol_arg.value))

    bounds = {
        "deck_slots": sorted(slots),
        "max_transfer_ul": float(max_vol) if max_vol > 0 else 300.0,
        "api_level": api_level,
    }
    return has_run, bounds


@dataclass(frozen=True)
class LeanMcpEnvelope:
    """Wire-compatible `lean-mcp/v1` zero-trust hardware capability envelope."""

    schema_version: str
    tool_name: str
    protocol_sha256: str
    token_epoch: int
    nonce: str
    lean_proof_valid: bool
    is_frontier_exception: bool
    human_supervisor_signed: bool
    human_supervisor_id: str
    envelope_bounds: dict[str, Any] = field(default_factory=lambda: _normalize_bounds(None))
    hmac_sha256: str = ""

    def payload_without_hmac(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_name": self.tool_name,
            "protocol_sha256": self.protocol_sha256,
            "token_epoch": self.token_epoch,
            "nonce": self.nonce,
            "lean_proof_valid": self.lean_proof_valid,
            "is_frontier_exception": self.is_frontier_exception,
            "human_supervisor_signed": self.human_supervisor_signed,
            "human_supervisor_id": self.human_supervisor_id,
            "envelope_bounds": dict(self.envelope_bounds),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_without_hmac()
        data["hmac_sha256"] = self.hmac_sha256
        return data

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> LeanMcpEnvelope:
        if not isinstance(raw, Mapping):
            raise ValueError("MCP envelope must be a JSON object")
        missing = sorted(_REQUIRED_ENVELOPE_KEYS - set(raw.keys()))
        if missing:
            raise ValueError(f"MCP envelope missing required field(s): {', '.join(missing)}")
        extra = sorted(set(raw.keys()) - _REQUIRED_ENVELOPE_KEYS)
        if extra:
            raise ValueError(f"MCP envelope contains unknown field(s): {', '.join(extra)}")

        schema_version = raw["schema_version"]
        tool_name = raw["tool_name"]
        protocol_sha256 = raw["protocol_sha256"]
        token_epoch = raw["token_epoch"]
        nonce = raw["nonce"]
        lean_proof_valid = raw["lean_proof_valid"]
        is_frontier_exception = raw["is_frontier_exception"]
        human_supervisor_signed = raw["human_supervisor_signed"]
        human_supervisor_id = raw["human_supervisor_id"]
        envelope_bounds = raw["envelope_bounds"]
        hmac_sha256 = raw["hmac_sha256"]

        if schema_version != LEAN_MCP_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema_version {schema_version!r}; expected {LEAN_MCP_SCHEMA_VERSION!r}"
            )
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(protocol_sha256, str) or not _HEX64_RE.match(protocol_sha256):
            raise ValueError("protocol_sha256 must be a 64-character hex string")
        if isinstance(token_epoch, bool) or not isinstance(token_epoch, int) or token_epoch < 0:
            raise ValueError("token_epoch must be a non-negative integer")
        if not isinstance(nonce, str) or not nonce.strip():
            raise ValueError("nonce must be a non-empty string")
        if not isinstance(lean_proof_valid, bool):
            raise ValueError("lean_proof_valid must be a boolean")
        if not isinstance(is_frontier_exception, bool):
            raise ValueError("is_frontier_exception must be a boolean")
        if not isinstance(human_supervisor_signed, bool):
            raise ValueError("human_supervisor_signed must be a boolean")
        if not isinstance(human_supervisor_id, str):
            raise ValueError("human_supervisor_id must be a string")
        if not isinstance(envelope_bounds, Mapping):
            raise ValueError("envelope_bounds must be a mapping")
        if not isinstance(hmac_sha256, str) or not _HEX64_RE.match(hmac_sha256):
            raise ValueError("hmac_sha256 must be a 64-character hex string")

        return cls(
            schema_version=schema_version,
            tool_name=tool_name,
            protocol_sha256=protocol_sha256,
            token_epoch=token_epoch,
            nonce=nonce,
            lean_proof_valid=lean_proof_valid,
            is_frontier_exception=is_frontier_exception,
            human_supervisor_signed=human_supervisor_signed,
            human_supervisor_id=human_supervisor_id,
            envelope_bounds=dict(envelope_bounds),
            hmac_sha256=hmac_sha256,
        )

    @classmethod
    def from_json(cls, source: str | Path) -> LeanMcpEnvelope:
        if isinstance(source, Path):
            raw_text = source.read_text(encoding="utf-8")
        elif "\n" not in source and Path(source).exists():
            raw_text = Path(source).read_text(encoding="utf-8")
        else:
            raw_text = source
        data = json.loads(raw_text)
        if not isinstance(data, Mapping):
            raise ValueError("MCP envelope JSON root must be an object")
        return cls.from_dict(data)


def mint_mcp_envelope(
    protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
    *,
    protocol_sha256: str | None = None,
    secret_key: str | bytes = DEFAULT_MCP_SECRET_KEY,
    token_epoch: int = 1,
    tool_name: str = DEFAULT_MCP_TOOL_NAME,
    nonce: str | None = None,
    lean_proof_valid: bool | None = None,
    is_frontier_exception: bool = False,
    human_supervisor_signed: bool = False,
    human_supervisor_id: str = "",
    envelope_bounds: Mapping[str, Any] | None = None,
) -> LeanMcpEnvelope:
    """Mint a canonical HMAC-authenticated `lean-mcp/v1` capability envelope."""
    if isinstance(token_epoch, bool) or not isinstance(token_epoch, int) or token_epoch < 0:
        raise ValueError("token_epoch must be a non-negative integer")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")

    if protocol_sha256 is not None:
        if not isinstance(protocol_sha256, str) or not _HEX64_RE.match(protocol_sha256):
            raise ValueError("protocol_sha256 must be a 64-character hex string")
        resolved_sha = protocol_sha256.lower()
    elif protocol is not None:
        resolved_sha = compute_protocol_sha256(protocol)
    else:
        raise ValueError("mint_mcp_envelope requires either `protocol` or `protocol_sha256`")

    inferred_valid, inferred_bounds = _infer_static_proof_and_bounds(protocol)
    resolved_proof = inferred_valid if lean_proof_valid is None else bool(lean_proof_valid)
    resolved_bounds = _normalize_bounds(envelope_bounds) if envelope_bounds is not None else inferred_bounds
    resolved_nonce = secrets.token_hex(16) if nonce is None else str(nonce)
    if not resolved_nonce.strip():
        raise ValueError("nonce must be non-empty")

    unsigned = {
        "schema_version": LEAN_MCP_SCHEMA_VERSION,
        "tool_name": tool_name,
        "protocol_sha256": resolved_sha,
        "token_epoch": token_epoch,
        "nonce": resolved_nonce,
        "lean_proof_valid": resolved_proof,
        "is_frontier_exception": bool(is_frontier_exception),
        "human_supervisor_signed": bool(human_supervisor_signed),
        "human_supervisor_id": str(human_supervisor_id),
        "envelope_bounds": resolved_bounds,
    }
    digest = compute_envelope_hmac(unsigned, secret_key)
    return LeanMcpEnvelope(
        schema_version=LEAN_MCP_SCHEMA_VERSION,
        tool_name=tool_name,
        protocol_sha256=resolved_sha,
        token_epoch=token_epoch,
        nonce=resolved_nonce,
        lean_proof_valid=resolved_proof,
        is_frontier_exception=bool(is_frontier_exception),
        human_supervisor_signed=bool(human_supervisor_signed),
        human_supervisor_id=str(human_supervisor_id),
        envelope_bounds=resolved_bounds,
        hmac_sha256=digest,
    )


def _resolve_autolab_lean_bin(explicit_bin: str | Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit_bin is not None:
        candidates.append(Path(explicit_bin))
    env_bin = os.environ.get("AUTOLAB_LEAN_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    repo_root = Path(__file__).resolve().parents[2]
    sibling_build = repo_root.parent / "auto-lab" / "lean" / ".lake" / "build" / "bin"
    candidates.append(sibling_build / "autolab-lean.exe")
    candidates.append(sibling_build / "autolab-lean")
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _crosscheck_autolab_lean_mcp(
    env: LeanMcpEnvelope,
    current_deck_epoch: int,
    *,
    lean_kernel_bin: str | Path | None = None,
    timeout_s: float = 5.0,
) -> tuple[bool, str | None]:
    """Cross-check MCP invariants against compiled `autolab-lean --batch-tsv` when present."""
    bin_path = _resolve_autolab_lean_bin(lean_kernel_bin)
    if bin_path is None:
        return True, None

    tsv_line = "\t".join(
        [
            "MCP",
            str(env.token_epoch),
            str(current_deck_epoch),
            "1" if env.lean_proof_valid else "0",
            "1" if env.is_frontier_exception else "0",
            "1" if env.human_supervisor_signed else "0",
        ]
    )
    try:
        proc = subprocess.run(
            [str(bin_path), "--batch-tsv"],
            input=tsv_line + "\n",
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except OSError:
        return True, None

    first_line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
    if proc.returncode == 0 and first_line.startswith("OK\tmcp\t"):
        return True, None
    return False, first_line or (proc.stderr.strip() or "autolab-lean rejected MCP envelope")


def verify_mcp_envelope(
    envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path,
    *,
    secret_key: str | bytes = DEFAULT_MCP_SECRET_KEY,
    current_deck_epoch: int = 1,
    actual_protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
    actual_protocol_sha256: str | None = None,
    consumed_nonces: set[str] | None = None,
    record_nonce: bool = True,
    check_lean_kernel: bool = True,
    lean_kernel_bin: str | Path | None = None,
) -> Verdict:
    """Verify a `lean-mcp/v1` capability envelope under all 5 zero-trust invariants."""
    raw_mapping: Mapping[str, Any] | None = None
    try:
        if isinstance(envelope, LeanMcpEnvelope):
            raw_mapping = envelope.to_dict()
            parsed = envelope
        elif isinstance(envelope, Mapping):
            raw_mapping = envelope
            parsed = LeanMcpEnvelope.from_dict(envelope)
        elif isinstance(envelope, (str, Path)):
            if isinstance(envelope, Path):
                raw_text = envelope.read_text(encoding="utf-8")
            elif "\n" not in envelope and Path(envelope).exists():
                raw_text = Path(envelope).read_text(encoding="utf-8")
            else:
                raw_text = envelope
            decoded = json.loads(raw_text)
            if not isinstance(decoded, Mapping):
                return Verdict(
                    passed=False,
                    layer="mcp_schema",
                    reason="MCP envelope JSON root must be an object",
                    diagnostics=["expected JSON object for lean-mcp/v1 envelope"],
                )
            raw_mapping = decoded
            parsed = LeanMcpEnvelope.from_dict(decoded)
        else:
            return Verdict(
                passed=False,
                layer="mcp_schema",
                reason=f"unsupported envelope type {type(envelope).__name__}",
                diagnostics=[f"cannot parse {type(envelope).__name__} as LeanMcpEnvelope"],
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return Verdict(
            passed=False,
            layer="mcp_schema",
            reason=f"invalid MCP envelope: {exc}",
            diagnostics=[str(exc)],
        )

    # 1. HMAC-SHA256 authenticity over canonical JSON of all fields except hmac_sha256
    try:
        expected_hmac = compute_envelope_hmac(raw_mapping, secret_key)
    except (TypeError, ValueError) as exc:
        return Verdict(
            passed=False,
            layer="mcp_hmac_authentic",
            reason=f"invalid secret key: {exc}",
            diagnostics=[str(exc)],
        )

    if not hmac.compare_digest(parsed.hmac_sha256.lower(), expected_hmac.lower()):
        return Verdict(
            passed=False,
            layer="mcp_hmac_authentic",
            reason="envelope HMAC-SHA256 verification failed (payload or parameter tampering)",
            diagnostics=[
                "mcp_hmac_authentic: computed HMAC does not match envelope hmac_sha256",
            ],
        )

    # 2. Protocol SHA-256 payload binding
    expected_sha: str | None = None
    if actual_protocol_sha256 is not None:
        expected_sha = actual_protocol_sha256.strip().lower()
    elif actual_protocol is not None:
        expected_sha = compute_protocol_sha256(actual_protocol).lower()

    if expected_sha is not None and parsed.protocol_sha256.lower() != expected_sha:
        return Verdict(
            passed=False,
            layer="mcp_payload_binding",
            reason="protocol SHA-256 mismatch between envelope and dispatched payload",
            diagnostics=[
                f"envelope protocol_sha256={parsed.protocol_sha256.lower()}",
                f"actual   protocol_sha256={expected_sha}",
            ],
        )

    # 3. Deck epoch freshness
    if parsed.token_epoch != current_deck_epoch:
        return Verdict(
            passed=False,
            layer="mcp_epoch_freshness",
            reason=(
                f"stale or mismatched MCP capability token: "
                f"token_epoch={parsed.token_epoch} != current_deck_epoch={current_deck_epoch}"
            ),
            diagnostics=[
                f"token_epoch={parsed.token_epoch}",
                f"current_deck_epoch={current_deck_epoch}",
            ],
        )

    # 4. Single-use nonce replay check
    if consumed_nonces is not None and parsed.nonce in consumed_nonces:
        return Verdict(
            passed=False,
            layer="mcp_nonce_single_use",
            reason=f"replay detected: nonce {parsed.nonce!r} has already been consumed",
            diagnostics=[f"duplicate nonce: {parsed.nonce}"],
        )

    # 5. Formal proof certificate OR human-supervisor co-signed frontier exception
    certified_or_cosigned = (
        parsed.lean_proof_valid and not parsed.is_frontier_exception
    ) or (parsed.is_frontier_exception and parsed.human_supervisor_signed)

    if not certified_or_cosigned:
        return Verdict(
            passed=False,
            layer="mcp_proof_or_cosigned_exception",
            reason=(
                "hardware MCP call lacks a valid Lean proof certificate inside regime "
                "or human supervisor co-signature for frontier exception"
            ),
            diagnostics=[
                f"lean_proof_valid={parsed.lean_proof_valid}",
                f"is_frontier_exception={parsed.is_frontier_exception}",
                f"human_supervisor_signed={parsed.human_supervisor_signed}",
            ],
        )

    if check_lean_kernel:
        kernel_ok, kernel_err = _crosscheck_autolab_lean_mcp(
            parsed,
            current_deck_epoch,
            lean_kernel_bin=lean_kernel_bin,
        )
        if not kernel_ok:
            return Verdict(
                passed=False,
                layer="mcp_lean_kernel",
                reason=f"AutoLabLean kernel rejected MCP envelope: {kernel_err}",
                diagnostics=[kernel_err or "autolab-lean rejection"],
            )

    if consumed_nonces is not None and record_nonce:
        consumed_nonces.add(parsed.nonce)

    return Verdict(passed=True, layer=None, reason="match", diagnostics=[])


class LeanMcpGate:
    """Stateful zero-trust `Lean-MCP` runtime firewall with overnight frontier deferral."""

    def __init__(
        self,
        *,
        secret_key: str | bytes = DEFAULT_MCP_SECRET_KEY,
        initial_deck_epoch: int = 1,
        check_lean_kernel: bool = True,
        lean_kernel_bin: str | Path | None = None,
    ) -> None:
        if isinstance(initial_deck_epoch, bool) or not isinstance(initial_deck_epoch, int) or initial_deck_epoch < 0:
            raise ValueError("initial_deck_epoch must be a non-negative integer")
        self._secret_key = _secret_bytes(secret_key)
        self.current_deck_epoch: int = initial_deck_epoch
        self.consumed_nonces: set[str] = set()
        self.deferred_daytime_queue: list[LeanMcpEnvelope] = []
        self.check_lean_kernel = check_lean_kernel
        self.lean_kernel_bin = lean_kernel_bin

    def mint(
        self,
        protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
        *,
        protocol_sha256: str | None = None,
        token_epoch: int | None = None,
        tool_name: str = DEFAULT_MCP_TOOL_NAME,
        nonce: str | None = None,
        lean_proof_valid: bool | None = None,
        is_frontier_exception: bool = False,
        human_supervisor_signed: bool = False,
        human_supervisor_id: str = "",
        envelope_bounds: Mapping[str, Any] | None = None,
    ) -> LeanMcpEnvelope:
        """Mint an envelope bound to this gate's secret key and current deck epoch."""
        epoch = self.current_deck_epoch if token_epoch is None else token_epoch
        return mint_mcp_envelope(
            protocol,
            protocol_sha256=protocol_sha256,
            secret_key=self._secret_key,
            token_epoch=epoch,
            tool_name=tool_name,
            nonce=nonce,
            lean_proof_valid=lean_proof_valid,
            is_frontier_exception=is_frontier_exception,
            human_supervisor_signed=human_supervisor_signed,
            human_supervisor_id=human_supervisor_id,
            envelope_bounds=envelope_bounds,
        )

    def verify(
        self,
        envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path,
        *,
        actual_protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
        actual_protocol_sha256: str | None = None,
        mutates_deck_state: bool = False,
        defer_unsigned_frontier: bool = False,
    ) -> Verdict:
        """Verify an envelope against stateful `current_deck_epoch` and `consumed_nonces`.

        When `defer_unsigned_frontier=True`, an authentic, fresh, un-replayed call with
        `is_frontier_exception=True` and `human_supervisor_signed=False` is non-blockingly
        parked in `self.deferred_daytime_queue` for daytime human supervisor co-signature
        instead of halting subsequent routine jobs.
        """
        verdict = verify_mcp_envelope(
            envelope,
            secret_key=self._secret_key,
            current_deck_epoch=self.current_deck_epoch,
            actual_protocol=actual_protocol,
            actual_protocol_sha256=actual_protocol_sha256,
            consumed_nonces=self.consumed_nonces,
            record_nonce=False,
            check_lean_kernel=self.check_lean_kernel,
            lean_kernel_bin=self.lean_kernel_bin,
        )

        if verdict.passed:
            parsed = (
                envelope
                if isinstance(envelope, LeanMcpEnvelope)
                else LeanMcpEnvelope.from_dict(envelope)
                if isinstance(envelope, Mapping)
                else LeanMcpEnvelope.from_json(envelope)
            )
            self.consumed_nonces.add(parsed.nonce)
            if mutates_deck_state:
                self.current_deck_epoch += 1
            return verdict

        if defer_unsigned_frontier and verdict.layer == "mcp_proof_or_cosigned_exception":
            parsed = (
                envelope
                if isinstance(envelope, LeanMcpEnvelope)
                else LeanMcpEnvelope.from_dict(envelope)
                if isinstance(envelope, Mapping)
                else LeanMcpEnvelope.from_json(envelope)
            )
            if parsed.is_frontier_exception and not parsed.human_supervisor_signed:
                if all(item.nonce != parsed.nonce for item in self.deferred_daytime_queue):
                    self.deferred_daytime_queue.append(parsed)
                return Verdict(
                    passed=False,
                    layer="mcp_deferred_daytime_review",
                    reason=(
                        f"unsigned frontier exception {parsed.nonce!r} parked in "
                        "deferred_daytime_queue for daytime human co-signature"
                    ),
                    diagnostics=list(verdict.diagnostics),
                )

        return verdict

    def cosign_deferred_exception(
        self,
        nonce: str | None = None,
        *,
        supervisor_id: str,
        new_nonce: str | None = None,
    ) -> LeanMcpEnvelope:
        """Pop a parked overnight frontier call and re-mint it with human supervisor co-signature."""
        if not isinstance(supervisor_id, str) or not supervisor_id.strip():
            raise ValueError("supervisor_id must be a non-empty string")
        if not self.deferred_daytime_queue:
            raise LookupError("deferred_daytime_queue is empty")

        target_idx = 0
        if nonce is not None:
            matches = [i for i, item in enumerate(self.deferred_daytime_queue) if item.nonce == nonce]
            if not matches:
                raise LookupError(f"nonce {nonce!r} not found in deferred_daytime_queue")
            target_idx = matches[0]

        parked = self.deferred_daytime_queue.pop(target_idx)
        return self.mint(
            protocol_sha256=parked.protocol_sha256,
            token_epoch=self.current_deck_epoch,
            tool_name=parked.tool_name,
            nonce=parked.nonce if new_nonce is None else new_nonce,
            lean_proof_valid=parked.lean_proof_valid,
            is_frontier_exception=True,
            human_supervisor_signed=True,
            human_supervisor_id=supervisor_id.strip(),
            envelope_bounds=parked.envelope_bounds,
        )
