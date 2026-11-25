"""Public package API for `lab-verify`."""

from __future__ import annotations

from typing import Any

from .lean_gate import strip_lean_comments, verify_lean
from .mcp_gate import (
    AUTH_MODE_ED25519,
    AUTH_MODE_HMAC,
    DEFAULT_MCP_SECRET_KEY,
    LEAN_MCP_SCHEMA_VERSION,
    LeanMcpEnvelope,
    LeanMcpGate,
    McpStateStore,
    compute_envelope_hmac,
    compute_protocol_sha256,
    compute_supervisor_cosign_payload,
    ed25519_public_key_from_private,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    mint_mcp_envelope,
    sign_supervisor_cosignature,
    verify_mcp_envelope,
    verify_supervisor_cosignature,
)
from .properties import (
    PropertyCheck,
    column_in_range,
    expected_columns,
    max_rows_bound,
    no_join_fanout,
    no_nulls,
    non_empty,
    unique_column,
)
from .protocol_gate import verify_protocol
from .sql_gate import (
    EXPERIMENTS,
    FORBIDDEN_SQLITE_FUNCTIONS,
    FORBIDDEN_SYSTEM_TABLES,
    INSTRUMENTS,
    LAYERS,
    SAMPLES,
    SCHEMA,
    BatchGateEvaluator,
    ExecutionLimitError,
    QueryResult,
    build_counterexample_dbs,
    build_db,
    cells_equal,
    check_parse,
    check_read_only,
    check_schema,
    compare_results,
    gate,
    introspect_sqlite_schema,
    lock_connection_readonly,
    open_readonly_db,
    rows_equal,
    run,
    run_query,
    validate_candidates_schema,
    verify_sql,
)
from .verdict import Verdict, VerifyVerdict


def verify(domain: str, target: Any, **kwargs: Any) -> VerifyVerdict:
    """Unified verification entry point across `'sql'`, `'lean'`, `'protocol'`, and `'mcp'` targets."""
    key = domain.strip().lower()
    if key == "sql":
        con = kwargs.pop("con", None) or build_db()
        return verify_sql(con, target, **kwargs)
    if key == "lean":
        return verify_lean(target, **kwargs)
    if key == "protocol":
        return verify_protocol(target, **kwargs)
    if key == "mcp":
        return verify_mcp_envelope(target, **kwargs)
    raise ValueError(
        f"unknown verification domain {domain!r} (expected 'sql', 'lean', 'protocol', or 'mcp')"
    )


__all__ = [
    "AUTH_MODE_ED25519",
    "AUTH_MODE_HMAC",
    "BatchGateEvaluator",
    "DEFAULT_MCP_SECRET_KEY",
    "EXPERIMENTS",
    "ExecutionLimitError",
    "FORBIDDEN_SQLITE_FUNCTIONS",
    "FORBIDDEN_SYSTEM_TABLES",
    "INSTRUMENTS",
    "LAYERS",
    "LEAN_MCP_SCHEMA_VERSION",
    "LeanMcpEnvelope",
    "LeanMcpGate",
    "McpStateStore",
    "PropertyCheck",
    "QueryResult",
    "SAMPLES",
    "SCHEMA",
    "Verdict",
    "VerifyVerdict",
    "build_counterexample_dbs",
    "build_db",
    "cells_equal",
    "check_parse",
    "check_read_only",
    "check_schema",
    "column_in_range",
    "compare_results",
    "compute_envelope_hmac",
    "compute_protocol_sha256",
    "compute_supervisor_cosign_payload",
    "ed25519_public_key_from_private",
    "ed25519_sign",
    "ed25519_verify",
    "expected_columns",
    "gate",
    "generate_ed25519_keypair",
    "introspect_sqlite_schema",
    "lock_connection_readonly",
    "max_rows_bound",
    "mint_mcp_envelope",
    "no_join_fanout",
    "no_nulls",
    "non_empty",
    "open_readonly_db",
    "rows_equal",
    "run",
    "run_query",
    "sign_supervisor_cosignature",
    "strip_lean_comments",
    "unique_column",
    "validate_candidates_schema",
    "verify",
    "verify_lean",
    "verify_mcp_envelope",
    "verify_protocol",
    "verify_sql",
    "verify_supervisor_cosignature",
]
