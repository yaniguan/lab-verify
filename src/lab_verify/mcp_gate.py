"""Zero-trust `Lean-MCP` capability envelope minting, Ed25519 role separation, and stateful firewall gate."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from typing import Any, Mapping, Sequence

from .protocol_gate import verify_protocol
from .verdict import Verdict

try:
    from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _CryptoEd25519PrivateKey,
        Ed25519PublicKey as _CryptoEd25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _CryptoEncoding,
        NoEncryption as _CryptoNoEncryption,
        PrivateFormat as _CryptoPrivateFormat,
        PublicFormat as _CryptoPublicFormat,
    )

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - pure-Python RFC 8032 fallback exercised directly in tests
    _CryptoInvalidSignature = Exception  # type: ignore[assignment,misc]
    _CryptoEd25519PrivateKey = None  # type: ignore[assignment,misc]
    _CryptoEd25519PublicKey = None  # type: ignore[assignment,misc]
    _CryptoEncoding = None  # type: ignore[assignment,misc]
    _CryptoNoEncryption = None  # type: ignore[assignment,misc]
    _CryptoPrivateFormat = None  # type: ignore[assignment,misc]
    _CryptoPublicFormat = None  # type: ignore[assignment,misc]
    _HAS_CRYPTOGRAPHY = False

LEAN_MCP_SCHEMA_VERSION = "lean-mcp/v1"
LEAN_MCP_STATE_SCHEMA_VERSION = "lean-mcp-state/v1"
DEFAULT_MCP_TOOL_NAME = "opentrons.execute_protocol"
DEFAULT_MCP_SECRET_KEY = "lean-mcp-dev-secret-v1"
AUTH_MODE_HMAC = "hmac-sha256"
AUTH_MODE_ED25519 = "ed25519"
SUPPORTED_AUTH_MODES = frozenset({AUTH_MODE_HMAC, AUTH_MODE_ED25519})

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-fA-F]{128}$")

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

_OPTIONAL_ENVELOPE_KEYS = frozenset(
    {
        "auth_mode",
        "minter_key_id",
        "minter_ed25519_sig",
        "supervisor_key_id",
        "supervisor_ed25519_sig",
        "supervisor_hmac_sha256",
        "key_epoch",
        "issued_at_unix",
        "ttl_seconds",
        "cosigned_expires_at_unix",
    }
)

_ALL_ALLOWED_ENVELOPE_KEYS = _REQUIRED_ENVELOPE_KEYS | _OPTIONAL_ENVELOPE_KEYS

# ---- Pure-Python RFC 8032 Ed25519 Implementation (zero-dependency fallback) ----
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    x2 = ((y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
assert _ED_BX is not None
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)
_ED_ZERO = (0, 1, 1, 0)


def _ed_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_scalarmult(pt: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    res = _ED_ZERO
    cur = pt
    k = scalar
    while k > 0:
        if k & 1:
            res = _ed_add(res, cur)
        cur = _ed_add(cur, cur)
        k >>= 1
    return res


def _ed_encode(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    return (yp | ((xp & 1) << 255)).to_bytes(32, "little")


def _ed_decode(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    n = int.from_bytes(raw, "little")
    y = n & ((1 << 255) - 1)
    sign = n >> 255
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _ED_P)


def _pure_ed25519_pubkey(seed32: bytes) -> bytes:
    if len(seed32) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    clamped = bytearray(h[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    a = int.from_bytes(clamped, "little")
    return _ed_encode(_ed_scalarmult(_ED_B, a))


def _pure_ed25519_sign(seed32: bytes, message: bytes) -> bytes:
    if len(seed32) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    clamped = bytearray(h[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    a = int.from_bytes(clamped, "little")
    prefix = h[32:]
    pub = _ed_encode(_ed_scalarmult(_ED_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED_L
    r_bytes = _ed_encode(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return r_bytes + s.to_bytes(32, "little")


def _pure_ed25519_verify(pub32: bytes, message: bytes, sig64: bytes) -> bool:
    if len(pub32) != 32 or len(sig64) != 64:
        return False
    r_bytes = sig64[:32]
    s = int.from_bytes(sig64[32:], "little")
    if s >= _ED_L:
        return False
    a_pt = _ed_decode(pub32)
    r_pt = _ed_decode(r_bytes)
    if a_pt is None or r_pt is None:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pub32 + message).digest(), "little") % _ED_L
    lhs = _ed_encode(_ed_scalarmult(_ED_B, 8 * s))
    rhs = _ed_encode(_ed_add(_ed_scalarmult(r_pt, 8), _ed_scalarmult(a_pt, 8 * k)))
    return hmac.compare_digest(lhs, rhs)


def _normalize_ed25519_private_bytes(private_key: Any) -> bytes:
    if _HAS_CRYPTOGRAPHY and isinstance(private_key, _CryptoEd25519PrivateKey):
        return private_key.private_bytes(
            encoding=_CryptoEncoding.Raw,
            format=_CryptoPrivateFormat.Raw,
            encryption_algorithm=_CryptoNoEncryption(),
        )
    if isinstance(private_key, bytes):
        if len(private_key) == 32:
            return private_key
        raise ValueError(f"Ed25519 private key bytes must be 32 bytes (got {len(private_key)})")
    if isinstance(private_key, str):
        s = private_key.strip()
        if _HEX64_RE.match(s):
            return bytes.fromhex(s)
        p = Path(s)
        if "\n" not in s and p.is_file():
            return _normalize_ed25519_private_bytes(p.read_text(encoding="utf-8").strip())
        raise ValueError("Ed25519 private key string must be 64-character hex (32-byte seed)")
    if isinstance(private_key, Path):
        return _normalize_ed25519_private_bytes(private_key.read_text(encoding="utf-8").strip())
    raise TypeError(f"Unsupported Ed25519 private key type: {type(private_key).__name__}")


def _normalize_ed25519_public_bytes(public_key: Any) -> bytes:
    if _HAS_CRYPTOGRAPHY and isinstance(public_key, _CryptoEd25519PublicKey):
        return public_key.public_bytes(
            encoding=_CryptoEncoding.Raw,
            format=_CryptoPublicFormat.Raw,
        )
    if isinstance(public_key, bytes):
        if len(public_key) == 32:
            return public_key
        raise ValueError(f"Ed25519 public key bytes must be 32 bytes (got {len(public_key)})")
    if isinstance(public_key, str):
        s = public_key.strip()
        if _HEX64_RE.match(s):
            return bytes.fromhex(s)
        p = Path(s)
        if "\n" not in s and p.is_file():
            return _normalize_ed25519_public_bytes(p.read_text(encoding="utf-8").strip())
        raise ValueError("Ed25519 public key string must be 64-character hex (32-byte key)")
    if isinstance(public_key, Path):
        return _normalize_ed25519_public_bytes(public_key.read_text(encoding="utf-8").strip())
    raise TypeError(f"Unsupported Ed25519 public key type: {type(public_key).__name__}")


def generate_ed25519_keypair(*, as_hex: bool = True) -> tuple[str, str] | tuple[bytes, bytes]:
    """Generate a fresh `(private_key, public_key)` Ed25519 keypair (64-char hex strings by default)."""
    if _HAS_CRYPTOGRAPHY:
        priv_obj = _CryptoEd25519PrivateKey.generate()
        priv_raw = priv_obj.private_bytes(
            encoding=_CryptoEncoding.Raw,
            format=_CryptoPrivateFormat.Raw,
            encryption_algorithm=_CryptoNoEncryption(),
        )
        pub_raw = priv_obj.public_key().public_bytes(
            encoding=_CryptoEncoding.Raw,
            format=_CryptoPublicFormat.Raw,
        )
    else:
        priv_raw = secrets.token_bytes(32)
        pub_raw = _pure_ed25519_pubkey(priv_raw)
    if as_hex:
        return priv_raw.hex(), pub_raw.hex()
    return priv_raw, pub_raw


def ed25519_public_key_from_private(private_key: Any, *, as_hex: bool = True) -> str | bytes:
    """Derive the 32-byte Ed25519 public verifying key from a private key."""
    seed = _normalize_ed25519_private_bytes(private_key)
    if _HAS_CRYPTOGRAPHY:
        pub_raw = _CryptoEd25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            encoding=_CryptoEncoding.Raw,
            format=_CryptoPublicFormat.Raw,
        )
    else:
        pub_raw = _pure_ed25519_pubkey(seed)
    return pub_raw.hex() if as_hex else pub_raw


def ed25519_sign(private_key: Any, message: bytes) -> str:
    """Sign `message` with an Ed25519 private key and return a 128-character hex signature."""
    seed = _normalize_ed25519_private_bytes(private_key)
    if _HAS_CRYPTOGRAPHY:
        sig = _CryptoEd25519PrivateKey.from_private_bytes(seed).sign(message)
    else:
        sig = _pure_ed25519_sign(seed, message)
    return sig.hex()


def ed25519_verify(public_key: Any, message: bytes, signature_hex: str | bytes) -> bool:
    """Verify an Ed25519 signature (`128-hex` string or `64-byte` bytes) against `public_key`."""
    try:
        pub_raw = _normalize_ed25519_public_bytes(public_key)
        if isinstance(signature_hex, bytes):
            sig_raw = signature_hex
        elif isinstance(signature_hex, str) and _HEX128_RE.match(signature_hex.strip()):
            sig_raw = bytes.fromhex(signature_hex.strip())
        else:
            return False
        if len(sig_raw) != 64:
            return False
    except (TypeError, ValueError, OSError):
        return False

    if _HAS_CRYPTOGRAPHY:
        try:
            _CryptoEd25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, message)
            return True
        except (_CryptoInvalidSignature, ValueError):
            return False
    return _pure_ed25519_verify(pub_raw, message, sig_raw)


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


def _is_default_dev_secret(secret_key: str | bytes | None) -> bool:
    if secret_key is None:
        return True
    try:
        return hmac.compare_digest(_secret_bytes(secret_key), DEFAULT_MCP_SECRET_KEY.encode("utf-8"))
    except (TypeError, ValueError):
        return False


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _minter_signing_message(payload: Mapping[str, Any]) -> bytes:
    excluded = {"hmac_sha256", "minter_ed25519_sig"}
    body = {k: v for k, v in payload.items() if k not in excluded}
    return b"LEAN_MCP_V1_MINTER|" + _canonical_json_bytes(body)


def compute_supervisor_cosign_payload(
    *,
    nonce: str,
    token_epoch: int,
    protocol_sha256: str,
    envelope_bounds: Mapping[str, Any] | None,
) -> bytes:
    """Build canonical `SUPERVISOR_COSIGN|<nonce>|<token_epoch>|<protocol_sha256>|<bounds_sha256>` bytes."""
    norm_bounds = _normalize_bounds(envelope_bounds)
    bounds_sha256 = hashlib.sha256(_canonical_json_bytes(norm_bounds)).hexdigest()
    return (
        f"SUPERVISOR_COSIGN|{nonce}|{token_epoch}|{protocol_sha256.lower()}|{bounds_sha256}"
    ).encode("utf-8")


def sign_supervisor_cosignature(
    supervisor_private_key: Any,
    *,
    nonce: str,
    token_epoch: int,
    protocol_sha256: str,
    envelope_bounds: Mapping[str, Any] | None = None,
) -> str:
    """Produce a detached human-supervisor Ed25519 signature over a frontier exception commitment."""
    msg = compute_supervisor_cosign_payload(
        nonce=nonce,
        token_epoch=token_epoch,
        protocol_sha256=protocol_sha256,
        envelope_bounds=envelope_bounds,
    )
    return ed25519_sign(supervisor_private_key, msg)


def verify_supervisor_cosignature(
    supervisor_public_key: Any,
    signature_hex: str,
    *,
    nonce: str,
    token_epoch: int,
    protocol_sha256: str,
    envelope_bounds: Mapping[str, Any] | None = None,
) -> bool:
    """Verify a detached human-supervisor Ed25519 signature against `supervisor_public_key`."""
    msg = compute_supervisor_cosign_payload(
        nonce=nonce,
        token_epoch=token_epoch,
        protocol_sha256=protocol_sha256,
        envelope_bounds=envelope_bounds,
    )
    return ed25519_verify(supervisor_public_key, msg, signature_hex)


def compute_supervisor_hmac(
    supervisor_secret_key: str | bytes,
    *,
    nonce: str,
    token_epoch: int,
    protocol_sha256: str,
    envelope_bounds: Mapping[str, Any] | None = None,
) -> str:
    """Compute role-separated human-supervisor HMAC-SHA256 over `SUPERVISOR_COSIGN|...`."""
    msg = compute_supervisor_cosign_payload(
        nonce=nonce,
        token_epoch=token_epoch,
        protocol_sha256=protocol_sha256,
        envelope_bounds=envelope_bounds,
    )
    return hmac.new(_secret_bytes(supervisor_secret_key), msg, hashlib.sha256).hexdigest()


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
    auth_mode: str = AUTH_MODE_HMAC
    minter_key_id: str = ""
    minter_ed25519_sig: str = ""
    supervisor_key_id: str = ""
    supervisor_ed25519_sig: str = ""
    supervisor_hmac_sha256: str = ""
    key_epoch: int | None = None
    issued_at_unix: int | None = None
    ttl_seconds: int | None = None
    cosigned_expires_at_unix: int | None = None

    def payload_without_hmac(self) -> dict[str, Any]:
        out: dict[str, Any] = {
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
        if self.auth_mode != AUTH_MODE_HMAC:
            out["auth_mode"] = self.auth_mode
        if self.minter_key_id:
            out["minter_key_id"] = self.minter_key_id
        if self.minter_ed25519_sig:
            out["minter_ed25519_sig"] = self.minter_ed25519_sig
        if self.supervisor_key_id:
            out["supervisor_key_id"] = self.supervisor_key_id
        if self.supervisor_ed25519_sig:
            out["supervisor_ed25519_sig"] = self.supervisor_ed25519_sig
        if self.supervisor_hmac_sha256:
            out["supervisor_hmac_sha256"] = self.supervisor_hmac_sha256
        if self.key_epoch is not None:
            out["key_epoch"] = self.key_epoch
        if self.issued_at_unix is not None:
            out["issued_at_unix"] = self.issued_at_unix
        if self.ttl_seconds is not None:
            out["ttl_seconds"] = self.ttl_seconds
        if self.cosigned_expires_at_unix is not None:
            out["cosigned_expires_at_unix"] = self.cosigned_expires_at_unix
        return out

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
        extra = sorted(set(raw.keys()) - _ALL_ALLOWED_ENVELOPE_KEYS)
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

        auth_mode = raw.get("auth_mode", AUTH_MODE_HMAC)
        minter_key_id = raw.get("minter_key_id", "")
        minter_ed25519_sig = raw.get("minter_ed25519_sig", "")
        supervisor_key_id = raw.get("supervisor_key_id", "")
        supervisor_ed25519_sig = raw.get("supervisor_ed25519_sig", "")
        supervisor_hmac_sha256 = raw.get("supervisor_hmac_sha256", "")
        key_epoch = raw.get("key_epoch")
        issued_at_unix = raw.get("issued_at_unix")
        ttl_seconds = raw.get("ttl_seconds")
        cosigned_expires_at_unix = raw.get("cosigned_expires_at_unix")

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

        if not isinstance(auth_mode, str) or auth_mode not in SUPPORTED_AUTH_MODES:
            raise ValueError(f"Unsupported auth_mode {auth_mode!r}; expected one of {sorted(SUPPORTED_AUTH_MODES)}")
        if not isinstance(minter_key_id, str):
            raise ValueError("minter_key_id must be a string")
        if not isinstance(minter_ed25519_sig, str) or (
            minter_ed25519_sig and not _HEX128_RE.match(minter_ed25519_sig)
        ):
            raise ValueError("minter_ed25519_sig must be a 128-character hex string when present")
        if auth_mode == AUTH_MODE_ED25519 and not minter_ed25519_sig:
            raise ValueError("auth_mode 'ed25519' requires minter_ed25519_sig")
        if not isinstance(supervisor_key_id, str):
            raise ValueError("supervisor_key_id must be a string")
        if not isinstance(supervisor_ed25519_sig, str) or (
            supervisor_ed25519_sig and not _HEX128_RE.match(supervisor_ed25519_sig)
        ):
            raise ValueError("supervisor_ed25519_sig must be a 128-character hex string when present")
        if not isinstance(supervisor_hmac_sha256, str) or (
            supervisor_hmac_sha256 and not _HEX64_RE.match(supervisor_hmac_sha256)
        ):
            raise ValueError("supervisor_hmac_sha256 must be a 64-character hex string when present")

        for field_label, opt_int in (
            ("key_epoch", key_epoch),
            ("issued_at_unix", issued_at_unix),
            ("ttl_seconds", ttl_seconds),
            ("cosigned_expires_at_unix", cosigned_expires_at_unix),
        ):
            if opt_int is not None and (isinstance(opt_int, bool) or not isinstance(opt_int, int) or opt_int < 0):
                raise ValueError(f"{field_label} must be a non-negative integer")

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
            auth_mode=auth_mode,
            minter_key_id=minter_key_id,
            minter_ed25519_sig=minter_ed25519_sig,
            supervisor_key_id=supervisor_key_id,
            supervisor_ed25519_sig=supervisor_ed25519_sig,
            supervisor_hmac_sha256=supervisor_hmac_sha256,
            key_epoch=key_epoch,
            issued_at_unix=issued_at_unix,
            ttl_seconds=ttl_seconds,
            cosigned_expires_at_unix=cosigned_expires_at_unix,
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
    secret_key: str | bytes | None = DEFAULT_MCP_SECRET_KEY,
    token_epoch: int = 1,
    tool_name: str = DEFAULT_MCP_TOOL_NAME,
    nonce: str | None = None,
    lean_proof_valid: bool | None = None,
    is_frontier_exception: bool = False,
    human_supervisor_signed: bool = False,
    human_supervisor_id: str = "",
    envelope_bounds: Mapping[str, Any] | None = None,
    auth_mode: str | None = None,
    minter_private_key: Any | None = None,
    minter_key_id: str = "",
    supervisor_private_key: Any | None = None,
    supervisor_ed25519_sig: str = "",
    supervisor_key_id: str = "",
    supervisor_secret_key: str | bytes | None = None,
    supervisor_hmac_sha256: str = "",
    key_epoch: int | None = None,
    issued_at_unix: int | None = None,
    ttl_seconds: int | None = None,
    cosigned_expires_at_unix: int | None = None,
    require_explicit_key: bool = False,
    allow_insecure_dev_key: bool = True,
) -> LeanMcpEnvelope:
    """Mint a canonical `lean-mcp/v1` capability envelope (`hmac-sha256` default or `ed25519`)."""
    if isinstance(token_epoch, bool) or not isinstance(token_epoch, int) or token_epoch < 0:
        raise ValueError("token_epoch must be a non-negative integer")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")

    for field_label, opt_int in (
        ("key_epoch", key_epoch),
        ("issued_at_unix", issued_at_unix),
        ("ttl_seconds", ttl_seconds),
        ("cosigned_expires_at_unix", cosigned_expires_at_unix),
    ):
        if opt_int is not None and (isinstance(opt_int, bool) or not isinstance(opt_int, int) or opt_int < 0):
            raise ValueError(f"{field_label} must be a non-negative integer")
    if ttl_seconds is not None and ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer (> 0)")

    resolved_mode = (
        (AUTH_MODE_ED25519 if minter_private_key is not None else AUTH_MODE_HMAC)
        if auth_mode is None
        else auth_mode
    )
    if resolved_mode not in SUPPORTED_AUTH_MODES:
        raise ValueError(f"Unsupported auth_mode {resolved_mode!r}")

    strict_key_policy = (
        require_explicit_key or os.environ.get("LEAN_MCP_REQUIRE_EXPLICIT_KEY") == "1"
    ) and not allow_insecure_dev_key

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

    resolved_sup_ed_sig = supervisor_ed25519_sig.strip().lower() if supervisor_ed25519_sig else ""
    resolved_sup_hmac = supervisor_hmac_sha256.strip().lower() if supervisor_hmac_sha256 else ""

    if resolved_mode == AUTH_MODE_ED25519:
        if minter_private_key is None:
            raise PermissionError("auth_mode='ed25519' requires minter_private_key to mint envelopes")
        minter_pub_bytes = _normalize_ed25519_public_bytes(
            ed25519_public_key_from_private(minter_private_key, as_hex=False)
        )
        if supervisor_private_key is not None:
            sup_pub_bytes = _normalize_ed25519_public_bytes(
                ed25519_public_key_from_private(supervisor_private_key, as_hex=False)
            )
            if hmac.compare_digest(minter_pub_bytes, sup_pub_bytes):
                raise ValueError("minter_private_key and supervisor_private_key must be distinct Ed25519 keys")
            resolved_sup_ed_sig = sign_supervisor_cosignature(
                supervisor_private_key,
                nonce=resolved_nonce,
                token_epoch=token_epoch,
                protocol_sha256=resolved_sha,
                envelope_bounds=resolved_bounds,
            )
        if bool(human_supervisor_signed) and not resolved_sup_ed_sig:
            raise PermissionError(
                "human_supervisor_signed=True in ed25519 mode requires a detached "
                "supervisor_ed25519_sig or distinct supervisor_private_key"
            )
    else:
        if secret_key is None:
            raise PermissionError("secret_key is required to mint hmac-sha256 capability envelopes")
        if strict_key_policy and _is_default_dev_secret(secret_key):
            raise ValueError(
                "refusing to mint with DEFAULT_MCP_SECRET_KEY when require_explicit_key=True "
                "(configure an explicit secret_key or pass allow_insecure_dev_key=True for dev testing)"
            )
        if supervisor_secret_key is not None:
            if hmac.compare_digest(_secret_bytes(secret_key), _secret_bytes(supervisor_secret_key)):
                raise ValueError("secret_key and supervisor_secret_key must be distinct keys")
            if bool(human_supervisor_signed) and not resolved_sup_hmac:
                resolved_sup_hmac = compute_supervisor_hmac(
                    supervisor_secret_key,
                    nonce=resolved_nonce,
                    token_epoch=token_epoch,
                    protocol_sha256=resolved_sha,
                    envelope_bounds=resolved_bounds,
                )

    unsigned: dict[str, Any] = {
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
    if resolved_mode != AUTH_MODE_HMAC:
        unsigned["auth_mode"] = resolved_mode
    if minter_key_id:
        unsigned["minter_key_id"] = minter_key_id
    if supervisor_key_id:
        unsigned["supervisor_key_id"] = supervisor_key_id
    if resolved_sup_ed_sig:
        unsigned["supervisor_ed25519_sig"] = resolved_sup_ed_sig
    if resolved_sup_hmac:
        unsigned["supervisor_hmac_sha256"] = resolved_sup_hmac
    if key_epoch is not None:
        unsigned["key_epoch"] = key_epoch
    if issued_at_unix is not None:
        unsigned["issued_at_unix"] = issued_at_unix
    if ttl_seconds is not None:
        unsigned["ttl_seconds"] = ttl_seconds
    if cosigned_expires_at_unix is not None:
        unsigned["cosigned_expires_at_unix"] = cosigned_expires_at_unix

    if resolved_mode == AUTH_MODE_ED25519:
        minter_sig = ed25519_sign(minter_private_key, _minter_signing_message(unsigned))
        digest = hashlib.sha256(bytes.fromhex(minter_sig)).hexdigest()
    else:
        minter_sig = ""
        assert secret_key is not None
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
        auth_mode=resolved_mode,
        minter_key_id=minter_key_id,
        minter_ed25519_sig=minter_sig,
        supervisor_key_id=supervisor_key_id,
        supervisor_ed25519_sig=resolved_sup_ed_sig,
        supervisor_hmac_sha256=resolved_sup_hmac,
        key_epoch=key_epoch,
        issued_at_unix=issued_at_unix,
        ttl_seconds=ttl_seconds,
        cosigned_expires_at_unix=cosigned_expires_at_unix,
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
    except subprocess.TimeoutExpired:
        return False, f"autolab-lean kernel check timed out after {timeout_s:.2f}s"
    except OSError as exc:
        return False, f"autolab-lean kernel execution failed: {exc}"

    first_line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
    if proc.returncode == 0 and first_line.startswith("OK\tmcp\t"):
        return True, None
    return False, first_line or (proc.stderr.strip() or "autolab-lean rejected MCP envelope")


def verify_mcp_envelope(
    envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path,
    *,
    secret_key: str | bytes | None = DEFAULT_MCP_SECRET_KEY,
    current_deck_epoch: int = 1,
    actual_protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
    actual_protocol_sha256: str | None = None,
    consumed_nonces: set[str] | None = None,
    record_nonce: bool = True,
    check_lean_kernel: bool = True,
    lean_kernel_bin: str | Path | None = None,
    lean_kernel_timeout_s: float = 5.0,
    minter_public_key: Any | None = None,
    supervisor_public_key: Any | None = None,
    supervisor_secret_key: str | bytes | None = None,
    min_active_key_epoch: int | None = None,
    now_unix: int | float | None = None,
    require_explicit_key: bool = False,
    allow_insecure_dev_key: bool = True,
) -> Verdict:
    """Verify a `lean-mcp/v1` capability envelope under all zero-trust cryptographic and epoch invariants."""
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

    strict_key_policy = (
        require_explicit_key or os.environ.get("LEAN_MCP_REQUIRE_EXPLICIT_KEY") == "1"
    ) and not allow_insecure_dev_key

    # 1. Cryptographic signature / HMAC authenticity
    if parsed.auth_mode == AUTH_MODE_ED25519 or minter_public_key is not None:
        if parsed.auth_mode != AUTH_MODE_ED25519 or not parsed.minter_ed25519_sig:
            return Verdict(
                passed=False,
                layer="mcp_signature_authentic",
                reason="verifier requires an Ed25519-signed envelope (auth_mode='ed25519')",
                diagnostics=[f"envelope auth_mode={parsed.auth_mode!r}"],
            )
        if minter_public_key is None:
            return Verdict(
                passed=False,
                layer="mcp_signature_authentic",
                reason="missing minter_public_key required to verify Ed25519 envelope",
                diagnostics=["minter_public_key is None"],
            )
        expected_sig_hash = hashlib.sha256(bytes.fromhex(parsed.minter_ed25519_sig)).hexdigest()
        if not hmac.compare_digest(parsed.hmac_sha256.lower(), expected_sig_hash.lower()):
            return Verdict(
                passed=False,
                layer="mcp_signature_authentic",
                reason="envelope signature commitment digest mismatch",
                diagnostics=["hmac_sha256 does not match SHA-256(minter_ed25519_sig)"],
            )
        if not ed25519_verify(
            minter_public_key,
            _minter_signing_message(raw_mapping),
            parsed.minter_ed25519_sig,
        ):
            return Verdict(
                passed=False,
                layer="mcp_signature_authentic",
                reason="Ed25519 minter signature verification failed (payload tampering or wrong key)",
                diagnostics=["mcp_signature_authentic: invalid minter_ed25519_sig"],
            )
    else:
        if secret_key is None:
            return Verdict(
                passed=False,
                layer="mcp_hmac_authentic",
                reason="missing secret_key required to verify hmac-sha256 envelope",
                diagnostics=["secret_key is None"],
            )
        if strict_key_policy and _is_default_dev_secret(secret_key):
            return Verdict(
                passed=False,
                layer="mcp_hmac_authentic",
                reason="insecure default development key rejected under require_explicit_key policy",
                diagnostics=["configure an explicit secret_key or Ed25519 public key"],
            )
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

    # 3. Cryptographic signing key-epoch freshness (when configured)
    if min_active_key_epoch is not None:
        if parsed.key_epoch is None or parsed.key_epoch < min_active_key_epoch:
            return Verdict(
                passed=False,
                layer="mcp_key_epoch_active",
                reason=(
                    f"revoked or missing signing key epoch: "
                    f"key_epoch={parsed.key_epoch} < min_active_key_epoch={min_active_key_epoch}"
                ),
                diagnostics=[
                    f"key_epoch={parsed.key_epoch}",
                    f"min_active_key_epoch={min_active_key_epoch}",
                ],
            )

    # 4. Deck epoch freshness
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

    # 5. Single-use nonce replay check
    if consumed_nonces is not None and parsed.nonce in consumed_nonces:
        return Verdict(
            passed=False,
            layer="mcp_nonce_single_use",
            reason=f"replay detected: nonce {parsed.nonce!r} has already been consumed",
            diagnostics=[f"duplicate nonce: {parsed.nonce}"],
        )

    # 6. Wall-clock TTL & supervisor co-signature expiration check
    if (
        parsed.ttl_seconds is not None
        or parsed.issued_at_unix is not None
        or parsed.cosigned_expires_at_unix is not None
    ):
        effective_now = int(time.time()) if now_unix is None else int(now_unix)
        if parsed.ttl_seconds is not None and parsed.ttl_seconds <= 0:
            return Verdict(
                passed=False,
                layer="mcp_ttl_unexpired",
                reason=f"invalid non-positive ttl_seconds={parsed.ttl_seconds}",
                diagnostics=[f"ttl_seconds={parsed.ttl_seconds}"],
            )
        if parsed.issued_at_unix is not None:
            if effective_now < parsed.issued_at_unix:
                return Verdict(
                    passed=False,
                    layer="mcp_ttl_unexpired",
                    reason=(
                        f"envelope issued_at_unix={parsed.issued_at_unix} is in the future "
                        f"relative to now={effective_now}"
                    ),
                    diagnostics=[f"issued_at_unix={parsed.issued_at_unix}", f"now={effective_now}"],
                )
            if parsed.ttl_seconds is not None and (effective_now - parsed.issued_at_unix) > parsed.ttl_seconds:
                return Verdict(
                    passed=False,
                    layer="mcp_ttl_unexpired",
                    reason=(
                        f"expired MCP capability token: age {effective_now - parsed.issued_at_unix}s "
                        f"> ttl_seconds={parsed.ttl_seconds}"
                    ),
                    diagnostics=[
                        f"issued_at_unix={parsed.issued_at_unix}",
                        f"ttl_seconds={parsed.ttl_seconds}",
                        f"now={effective_now}",
                    ],
                )
        if parsed.cosigned_expires_at_unix is not None and effective_now > parsed.cosigned_expires_at_unix:
            return Verdict(
                passed=False,
                layer="mcp_ttl_unexpired",
                reason=(
                    f"expired human supervisor co-signature: now={effective_now} "
                    f"> cosigned_expires_at_unix={parsed.cosigned_expires_at_unix}"
                ),
                diagnostics=[
                    f"cosigned_expires_at_unix={parsed.cosigned_expires_at_unix}",
                    f"now={effective_now}",
                ],
            )

    # 7. Formal proof certificate OR role-separated human-supervisor co-signed frontier exception
    supervisor_verified = parsed.human_supervisor_signed
    if parsed.is_frontier_exception and parsed.human_supervisor_signed:
        if parsed.auth_mode == AUTH_MODE_ED25519 or supervisor_public_key is not None:
            if supervisor_public_key is None or not parsed.supervisor_ed25519_sig:
                return Verdict(
                    passed=False,
                    layer="mcp_proof_or_cosigned_exception",
                    reason=(
                        "frontier exception requires a detached supervisor_ed25519_sig "
                        "verified against a distinct supervisor_public_key"
                    ),
                    diagnostics=["missing supervisor_public_key or supervisor_ed25519_sig"],
                )
            try:
                sup_pub_raw = _normalize_ed25519_public_bytes(supervisor_public_key)
                if minter_public_key is not None and hmac.compare_digest(
                    sup_pub_raw, _normalize_ed25519_public_bytes(minter_public_key)
                ):
                    return Verdict(
                        passed=False,
                        layer="mcp_proof_or_cosigned_exception",
                        reason="role separation violation: supervisor_public_key must differ from minter_public_key",
                        diagnostics=["identical minter and supervisor public keys"],
                    )
            except (TypeError, ValueError, OSError) as exc:
                return Verdict(
                    passed=False,
                    layer="mcp_proof_or_cosigned_exception",
                    reason=f"invalid supervisor_public_key: {exc}",
                    diagnostics=[str(exc)],
                )
            supervisor_verified = verify_supervisor_cosignature(
                supervisor_public_key,
                parsed.supervisor_ed25519_sig,
                nonce=parsed.nonce,
                token_epoch=parsed.token_epoch,
                protocol_sha256=parsed.protocol_sha256,
                envelope_bounds=parsed.envelope_bounds,
            )
        elif supervisor_secret_key is not None:
            if secret_key is not None and hmac.compare_digest(
                _secret_bytes(secret_key), _secret_bytes(supervisor_secret_key)
            ):
                return Verdict(
                    passed=False,
                    layer="mcp_proof_or_cosigned_exception",
                    reason="role separation violation: supervisor_secret_key must differ from secret_key",
                    diagnostics=["identical minter and supervisor HMAC secrets"],
                )
            expected_sup_hmac = compute_supervisor_hmac(
                supervisor_secret_key,
                nonce=parsed.nonce,
                token_epoch=parsed.token_epoch,
                protocol_sha256=parsed.protocol_sha256,
                envelope_bounds=parsed.envelope_bounds,
            )
            supervisor_verified = bool(
                parsed.supervisor_hmac_sha256
                and hmac.compare_digest(parsed.supervisor_hmac_sha256.lower(), expected_sup_hmac.lower())
            )

    certified_or_cosigned = (
        parsed.lean_proof_valid and not parsed.is_frontier_exception
    ) or (parsed.is_frontier_exception and supervisor_verified)

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
                f"supervisor_verified={supervisor_verified}",
            ],
        )

    if check_lean_kernel:
        kernel_ok, kernel_err = _crosscheck_autolab_lean_mcp(
            parsed,
            current_deck_epoch,
            lean_kernel_bin=lean_kernel_bin,
            timeout_s=lean_kernel_timeout_s,
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


# ---- Crash-Safe Atomic State Store (`--state <path.json>`) ----
@contextmanager
def _exclusive_file_lock(lock_path: Path, *, timeout_s: float = 10.0) -> Iterator[None]:
    """Acquire an OS-level exclusive lock on `lock_path` (`msvcrt.locking` on Windows, `fcntl.flock` on POSIX)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+b")
    deadline = time.monotonic() + max(0.1, timeout_s)
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                fh.write(b"\x00")
                fh.flush()
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"timed out acquiring exclusive state lock {lock_path}"
                        ) from exc
                    time.sleep(0.005 + (secrets.randbelow(8) * 0.001))
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"timed out acquiring exclusive state lock {lock_path}"
                        ) from exc
                    time.sleep(0.005 + (secrets.randbelow(8) * 0.001))
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


@dataclass
class McpStateData:
    """In-memory mutable snapshot of persistent `LeanMcpGate` state."""

    current_deck_epoch: int
    consumed_nonces_order: list[str]
    deferred_daytime_queue: list[LeanMcpEnvelope]
    deferred_wire_packets: dict[str, dict[str, Any]]
    max_consumed_nonces: int = 4096

    def record_nonce(self, nonce: str) -> None:
        if nonce not in self.consumed_nonces_order:
            self.consumed_nonces_order.append(nonce)
            if len(self.consumed_nonces_order) > self.max_consumed_nonces:
                overflow = len(self.consumed_nonces_order) - self.max_consumed_nonces
                del self.consumed_nonces_order[:overflow]


class McpStateStore:
    """Crash-safe persistent state store using an exclusive lockfile + `os.fsync` + atomic `os.replace`."""

    def __init__(
        self,
        state_path: str | Path,
        *,
        initial_deck_epoch: int = 1,
        max_consumed_nonces: int = 4096,
        lock_timeout_s: float = 10.0,
    ) -> None:
        if isinstance(initial_deck_epoch, bool) or not isinstance(initial_deck_epoch, int) or initial_deck_epoch < 0:
            raise ValueError("initial_deck_epoch must be a non-negative integer")
        if isinstance(max_consumed_nonces, bool) or not isinstance(max_consumed_nonces, int) or max_consumed_nonces < 1:
            raise ValueError("max_consumed_nonces must be >= 1")
        self.path = Path(state_path).resolve()
        self.lock_path = self.path.parent / f"{self.path.name}.lock"
        self.initial_deck_epoch = initial_deck_epoch
        self.max_consumed_nonces = max_consumed_nonces
        self.lock_timeout_s = lock_timeout_s

    def _read_unlocked(self) -> McpStateData:
        if not self.path.exists():
            return McpStateData(
                current_deck_epoch=self.initial_deck_epoch,
                consumed_nonces_order=[],
                deferred_daytime_queue=[],
                deferred_wire_packets={},
                max_consumed_nonces=self.max_consumed_nonces,
            )
        raw_text = self.path.read_text(encoding="utf-8")
        obj = json.loads(raw_text)
        if not isinstance(obj, Mapping):
            raise ValueError(f"corrupt MCP state file {self.path}: root must be an object")
        epoch = obj.get("current_deck_epoch", self.initial_deck_epoch)
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError(f"corrupt MCP state file {self.path}: invalid current_deck_epoch")
        raw_nonces = obj.get("consumed_nonces", [])
        if not isinstance(raw_nonces, list) or not all(isinstance(n, str) for n in raw_nonces):
            raise ValueError(f"corrupt MCP state file {self.path}: invalid consumed_nonces")
        dedup_nonces: list[str] = []
        seen: set[str] = set()
        for n in raw_nonces:
            if n not in seen:
                seen.add(n)
                dedup_nonces.append(n)
        if len(dedup_nonces) > self.max_consumed_nonces:
            dedup_nonces = dedup_nonces[-self.max_consumed_nonces :]

        raw_queue = obj.get("deferred_daytime_queue", [])
        if not isinstance(raw_queue, list):
            raise ValueError(f"corrupt MCP state file {self.path}: invalid deferred_daytime_queue")
        parsed_queue = [LeanMcpEnvelope.from_dict(item) for item in raw_queue]

        raw_packets = obj.get("deferred_wire_packets", {})
        if not isinstance(raw_packets, Mapping):
            raise ValueError(f"corrupt MCP state file {self.path}: invalid deferred_wire_packets")
        parsed_packets = {str(k): dict(v) for k, v in raw_packets.items() if isinstance(v, Mapping)}

        return McpStateData(
            current_deck_epoch=epoch,
            consumed_nonces_order=dedup_nonces,
            deferred_daytime_queue=parsed_queue,
            deferred_wire_packets=parsed_packets,
            max_consumed_nonces=self.max_consumed_nonces,
        )

    def _write_atomic_unlocked(self, state: McpStateData) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if len(state.consumed_nonces_order) > self.max_consumed_nonces:
            state.consumed_nonces_order = state.consumed_nonces_order[-self.max_consumed_nonces :]
        payload = {
            "schema_version": LEAN_MCP_STATE_SCHEMA_VERSION,
            "current_deck_epoch": state.current_deck_epoch,
            "consumed_nonces": list(state.consumed_nonces_order),
            "deferred_daytime_queue": [env.to_dict() for env in state.deferred_daytime_queue],
            "deferred_wire_packets": dict(state.deferred_wire_packets),
        }
        serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        tmp_path = self.path.parent / f".{self.path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(serialized)
                fh.flush()
                os.fsync(fh.fileno())
            for attempt in range(10):
                try:
                    os.replace(tmp_path, self.path)
                    break
                except PermissionError:
                    if attempt == 9:
                        raise
                    time.sleep(0.005 * (attempt + 1))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def load(self) -> McpStateData:
        with _exclusive_file_lock(self.lock_path, timeout_s=self.lock_timeout_s):
            return self._read_unlocked()

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[McpStateData]:
        with _exclusive_file_lock(self.lock_path, timeout_s=self.lock_timeout_s):
            state = self._read_unlocked()
            yield state
            if write:
                self._write_atomic_unlocked(state)


class LeanMcpGate:
    """Stateful zero-trust `Lean-MCP` runtime firewall with Ed25519 role separation and atomic state persistence."""

    def __init__(
        self,
        *,
        secret_key: str | bytes | None = DEFAULT_MCP_SECRET_KEY,
        initial_deck_epoch: int = 1,
        check_lean_kernel: bool = True,
        lean_kernel_bin: str | Path | None = None,
        state_path: str | Path | None = None,
        max_consumed_nonces: int = 4096,
        auth_mode: str | None = None,
        minter_private_key: Any | None = None,
        minter_public_key: Any | None = None,
        minter_key_id: str = "",
        supervisor_public_key: Any | None = None,
        supervisor_secret_key: str | bytes | None = None,
        key_epoch: int | None = None,
        min_active_key_epoch: int | None = None,
        default_ttl_seconds: int | None = None,
        require_explicit_key: bool = False,
        allow_insecure_dev_key: bool = True,
    ) -> None:
        if isinstance(initial_deck_epoch, bool) or not isinstance(initial_deck_epoch, int) or initial_deck_epoch < 0:
            raise ValueError("initial_deck_epoch must be a non-negative integer")
        if isinstance(max_consumed_nonces, bool) or not isinstance(max_consumed_nonces, int) or max_consumed_nonces < 1:
            raise ValueError("max_consumed_nonces must be >= 1")

        resolved_mode = (
            (
                AUTH_MODE_ED25519
                if (minter_private_key is not None or minter_public_key is not None)
                else AUTH_MODE_HMAC
            )
            if auth_mode is None
            else auth_mode
        )
        if resolved_mode not in SUPPORTED_AUTH_MODES:
            raise ValueError(f"Unsupported auth_mode {resolved_mode!r}")

        strict_key_policy = (
            require_explicit_key or os.environ.get("LEAN_MCP_REQUIRE_EXPLICIT_KEY") == "1"
        ) and not allow_insecure_dev_key

        self.auth_mode = resolved_mode
        self.require_explicit_key = require_explicit_key
        self.allow_insecure_dev_key = allow_insecure_dev_key
        self.minter_key_id = minter_key_id
        self.key_epoch = key_epoch
        self.min_active_key_epoch = min_active_key_epoch
        self.default_ttl_seconds = default_ttl_seconds
        self.max_consumed_nonces = max_consumed_nonces

        if resolved_mode == AUTH_MODE_ED25519:
            self._secret_key: bytes | None = None
            self._minter_private_key = (
                _normalize_ed25519_private_bytes(minter_private_key)
                if minter_private_key is not None
                else None
            )
            if minter_public_key is not None:
                self._minter_public_key: bytes | None = _normalize_ed25519_public_bytes(minter_public_key)
            elif self._minter_private_key is not None:
                self._minter_public_key = _normalize_ed25519_public_bytes(
                    ed25519_public_key_from_private(self._minter_private_key, as_hex=False)
                )
            else:
                self._minter_public_key = None
        else:
            if secret_key is None:
                self._secret_key = None
            else:
                if strict_key_policy and _is_default_dev_secret(secret_key):
                    raise ValueError(
                        "refusing to initialize LeanMcpGate with DEFAULT_MCP_SECRET_KEY "
                        "when require_explicit_key=True"
                    )
                self._secret_key = _secret_bytes(secret_key)
            self._minter_private_key = None
            self._minter_public_key = None

        self._supervisor_public_key: bytes | None = (
            _normalize_ed25519_public_bytes(supervisor_public_key)
            if supervisor_public_key is not None
            else None
        )
        if (
            self._supervisor_public_key is not None
            and self._minter_public_key is not None
            and hmac.compare_digest(self._supervisor_public_key, self._minter_public_key)
        ):
            raise ValueError("minter_public_key and supervisor_public_key must be distinct Ed25519 keys")

        self._supervisor_secret_key: bytes | None = (
            _secret_bytes(supervisor_secret_key) if supervisor_secret_key is not None else None
        )
        if (
            self._supervisor_secret_key is not None
            and self._secret_key is not None
            and hmac.compare_digest(self._supervisor_secret_key, self._secret_key)
        ):
            raise ValueError("secret_key and supervisor_secret_key must be distinct keys")

        self.current_deck_epoch: int = initial_deck_epoch
        self._nonce_order: list[str] = []
        self.consumed_nonces: set[str] = set()
        self.deferred_daytime_queue: list[LeanMcpEnvelope] = []
        self.deferred_wire_packets: dict[str, dict[str, Any]] = {}
        self.check_lean_kernel = check_lean_kernel
        self.lean_kernel_bin = lean_kernel_bin
        self._state_store: McpStateStore | None = (
            McpStateStore(
                state_path,
                initial_deck_epoch=initial_deck_epoch,
                max_consumed_nonces=max_consumed_nonces,
            )
            if state_path is not None
            else None
        )
        if self._state_store is not None:
            with self._state_store.transaction(write=not self._state_store.path.exists()) as st:
                self._sync_from_state(st)

    def _sync_from_state(self, st: McpStateData) -> None:
        self.current_deck_epoch = st.current_deck_epoch
        self._nonce_order = list(st.consumed_nonces_order)
        self.consumed_nonces = set(self._nonce_order)
        self.deferred_daytime_queue = list(st.deferred_daytime_queue)
        self.deferred_wire_packets = dict(st.deferred_wire_packets)

    def _record_in_memory_nonce(self, nonce: str) -> None:
        if nonce not in self.consumed_nonces:
            self._nonce_order.append(nonce)
            self.consumed_nonces.add(nonce)
            while len(self._nonce_order) > self.max_consumed_nonces:
                evicted = self._nonce_order.pop(0)
                self.consumed_nonces.discard(evicted)

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
        supervisor_private_key: Any | None = None,
        supervisor_ed25519_sig: str = "",
        supervisor_key_id: str = "",
        supervisor_hmac_sha256: str = "",
        key_epoch: int | None = None,
        issued_at_unix: int | None = None,
        ttl_seconds: int | None = None,
        cosigned_expires_at_unix: int | None = None,
    ) -> LeanMcpEnvelope:
        """Mint an envelope bound to this gate's signing key and current deck epoch."""
        if self._state_store is not None:
            st = self._state_store.load()
            self._sync_from_state(st)
        epoch = self.current_deck_epoch if token_epoch is None else token_epoch
        effective_key_epoch = self.key_epoch if key_epoch is None else key_epoch
        effective_ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        effective_issued = (
            (int(time.time()) if effective_ttl is not None else None)
            if issued_at_unix is None
            else issued_at_unix
        )
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
            auth_mode=self.auth_mode,
            minter_private_key=self._minter_private_key,
            minter_key_id=self.minter_key_id,
            supervisor_private_key=supervisor_private_key,
            supervisor_ed25519_sig=supervisor_ed25519_sig,
            supervisor_key_id=supervisor_key_id,
            supervisor_secret_key=self._supervisor_secret_key,
            supervisor_hmac_sha256=supervisor_hmac_sha256,
            key_epoch=effective_key_epoch,
            issued_at_unix=effective_issued,
            ttl_seconds=effective_ttl,
            cosigned_expires_at_unix=cosigned_expires_at_unix,
            require_explicit_key=self.require_explicit_key,
            allow_insecure_dev_key=self.allow_insecure_dev_key,
        )

    @staticmethod
    def _parse_envelope(envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path) -> LeanMcpEnvelope:
        if isinstance(envelope, LeanMcpEnvelope):
            return envelope
        if isinstance(envelope, Mapping):
            return LeanMcpEnvelope.from_dict(envelope)
        return LeanMcpEnvelope.from_json(envelope)

    def verify(
        self,
        envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path,
        *,
        actual_protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None = None,
        actual_protocol_sha256: str | None = None,
        mutates_deck_state: bool = False,
        defer_unsigned_frontier: bool = False,
        stateless_dry_run: bool = False,
        now_unix: int | float | None = None,
        wire_packet: Mapping[str, Any] | None = None,
    ) -> Verdict:
        """Verify an envelope against stateful `current_deck_epoch` and `consumed_nonces`."""
        if self._state_store is not None:
            with self._state_store.transaction(write=not stateless_dry_run) as st:
                self._sync_from_state(st)
                verdict = self._verify_inner(
                    envelope,
                    actual_protocol=actual_protocol,
                    actual_protocol_sha256=actual_protocol_sha256,
                    mutates_deck_state=mutates_deck_state,
                    defer_unsigned_frontier=defer_unsigned_frontier,
                    stateless_dry_run=stateless_dry_run,
                    now_unix=now_unix,
                    wire_packet=wire_packet,
                )
                st.current_deck_epoch = self.current_deck_epoch
                st.consumed_nonces_order = list(self._nonce_order)
                st.deferred_daytime_queue = list(self.deferred_daytime_queue)
                st.deferred_wire_packets = dict(self.deferred_wire_packets)
                return verdict

        return self._verify_inner(
            envelope,
            actual_protocol=actual_protocol,
            actual_protocol_sha256=actual_protocol_sha256,
            mutates_deck_state=mutates_deck_state,
            defer_unsigned_frontier=defer_unsigned_frontier,
            stateless_dry_run=stateless_dry_run,
            now_unix=now_unix,
            wire_packet=wire_packet,
        )

    def _verify_inner(
        self,
        envelope: LeanMcpEnvelope | Mapping[str, Any] | str | Path,
        *,
        actual_protocol: str | bytes | Path | Mapping[str, Any] | Sequence[Any] | None,
        actual_protocol_sha256: str | None,
        mutates_deck_state: bool,
        defer_unsigned_frontier: bool,
        stateless_dry_run: bool,
        now_unix: int | float | None,
        wire_packet: Mapping[str, Any] | None,
    ) -> Verdict:
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
            minter_public_key=self._minter_public_key,
            supervisor_public_key=self._supervisor_public_key,
            supervisor_secret_key=self._supervisor_secret_key,
            min_active_key_epoch=self.min_active_key_epoch,
            now_unix=now_unix,
            require_explicit_key=self.require_explicit_key,
            allow_insecure_dev_key=self.allow_insecure_dev_key,
        )

        if verdict.passed:
            if not stateless_dry_run:
                parsed = self._parse_envelope(envelope)
                self._record_in_memory_nonce(parsed.nonce)
                if mutates_deck_state:
                    self.current_deck_epoch += 1
            return verdict

        if defer_unsigned_frontier and verdict.layer == "mcp_proof_or_cosigned_exception":
            parsed = self._parse_envelope(envelope)
            if parsed.is_frontier_exception and not parsed.human_supervisor_signed:
                if not stateless_dry_run:
                    if all(item.nonce != parsed.nonce for item in self.deferred_daytime_queue):
                        self.deferred_daytime_queue.append(parsed)
                    if wire_packet is not None:
                        self.deferred_wire_packets[parsed.nonce] = dict(wire_packet)
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
        supervisor_private_key: Any | None = None,
        supervisor_ed25519_sig: str = "",
        supervisor_key_id: str = "",
        current_deck_epoch: int | None = None,
        ttl_seconds: int | None = None,
    ) -> LeanMcpEnvelope:
        """Pop a parked overnight frontier call and re-mint it with human supervisor co-signature."""
        if not isinstance(supervisor_id, str) or not supervisor_id.strip():
            raise ValueError("supervisor_id must be a non-empty string")

        if self._state_store is not None:
            with self._state_store.transaction(write=True) as st:
                self._sync_from_state(st)
                minted = self._cosign_inner(
                    nonce,
                    supervisor_id=supervisor_id,
                    new_nonce=new_nonce,
                    supervisor_private_key=supervisor_private_key,
                    supervisor_ed25519_sig=supervisor_ed25519_sig,
                    supervisor_key_id=supervisor_key_id,
                    current_deck_epoch=current_deck_epoch,
                    ttl_seconds=ttl_seconds,
                )
                st.current_deck_epoch = self.current_deck_epoch
                st.consumed_nonces_order = list(self._nonce_order)
                st.deferred_daytime_queue = list(self.deferred_daytime_queue)
                st.deferred_wire_packets = dict(self.deferred_wire_packets)
                return minted

        return self._cosign_inner(
            nonce,
            supervisor_id=supervisor_id,
            new_nonce=new_nonce,
            supervisor_private_key=supervisor_private_key,
            supervisor_ed25519_sig=supervisor_ed25519_sig,
            supervisor_key_id=supervisor_key_id,
            current_deck_epoch=current_deck_epoch,
            ttl_seconds=ttl_seconds,
        )

    def _cosign_inner(
        self,
        nonce: str | None,
        *,
        supervisor_id: str,
        new_nonce: str | None,
        supervisor_private_key: Any | None,
        supervisor_ed25519_sig: str,
        supervisor_key_id: str,
        current_deck_epoch: int | None,
        ttl_seconds: int | None,
    ) -> LeanMcpEnvelope:
        if not self.deferred_daytime_queue:
            raise LookupError("deferred_daytime_queue is empty")

        target_idx = 0
        if nonce is not None:
            matches = [i for i, item in enumerate(self.deferred_daytime_queue) if item.nonce == nonce]
            if not matches:
                raise LookupError(f"nonce {nonce!r} not found in deferred_daytime_queue")
            target_idx = matches[0]

        parked = self.deferred_daytime_queue[target_idx]
        target_epoch = self.current_deck_epoch if current_deck_epoch is None else current_deck_epoch
        resolved_nonce = parked.nonce if new_nonce is None else new_nonce

        if self._supervisor_public_key is not None and supervisor_private_key is None and supervisor_ed25519_sig:
            if not verify_supervisor_cosignature(
                self._supervisor_public_key,
                supervisor_ed25519_sig,
                nonce=resolved_nonce,
                token_epoch=target_epoch,
                protocol_sha256=parked.protocol_sha256,
                envelope_bounds=parked.envelope_bounds,
            ):
                raise PermissionError("detached supervisor_ed25519_sig failed supervisor_public_key verification")

        effective_ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        effective_issued = int(time.time()) if effective_ttl is not None else None

        minted = mint_mcp_envelope(
            protocol_sha256=parked.protocol_sha256,
            secret_key=self._secret_key,
            token_epoch=target_epoch,
            tool_name=parked.tool_name,
            nonce=resolved_nonce,
            lean_proof_valid=parked.lean_proof_valid,
            is_frontier_exception=True,
            human_supervisor_signed=True,
            human_supervisor_id=supervisor_id.strip(),
            envelope_bounds=parked.envelope_bounds,
            auth_mode=self.auth_mode,
            minter_private_key=self._minter_private_key,
            minter_key_id=self.minter_key_id,
            supervisor_private_key=supervisor_private_key,
            supervisor_ed25519_sig=supervisor_ed25519_sig,
            supervisor_key_id=supervisor_key_id,
            supervisor_secret_key=self._supervisor_secret_key,
            key_epoch=self.key_epoch,
            issued_at_unix=effective_issued,
            ttl_seconds=effective_ttl,
            require_explicit_key=self.require_explicit_key,
            allow_insecure_dev_key=self.allow_insecure_dev_key,
        )
        self.deferred_daytime_queue.pop(target_idx)
        return minted
