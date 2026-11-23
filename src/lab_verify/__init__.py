"""Public package API for `lab-verify`."""

from __future__ import annotations

from typing import Any

from .lean_gate import strip_lean_comments, verify_lean
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
from .verdict import VerifyVerdict


def verify(domain: str, target: Any, **kwargs: Any) -> VerifyVerdict:
    """Unified verification entry point across `'sql'`, `'lean'`, and `'protocol'` targets."""
    key = domain.strip().lower()
    if key == "sql":
        con = kwargs.pop("con", None) or build_db()
        return verify_sql(con, target, **kwargs)
    if key == "lean":
        return verify_lean(target, **kwargs)
    if key == "protocol":
        return verify_protocol(target, **kwargs)
    raise ValueError(f"unknown verification domain {domain!r} (expected 'sql', 'lean', or 'protocol')")


__all__ = [
    "BatchGateEvaluator",
    "EXPERIMENTS",
    "ExecutionLimitError",
    "FORBIDDEN_SQLITE_FUNCTIONS",
    "FORBIDDEN_SYSTEM_TABLES",
    "INSTRUMENTS",
    "LAYERS",
    "PropertyCheck",
    "QueryResult",
    "SAMPLES",
    "SCHEMA",
    "VerifyVerdict",
    "build_counterexample_dbs",
    "build_db",
    "cells_equal",
    "check_parse",
    "check_read_only",
    "check_schema",
    "column_in_range",
    "compare_results",
    "expected_columns",
    "gate",
    "introspect_sqlite_schema",
    "lock_connection_readonly",
    "max_rows_bound",
    "no_join_fanout",
    "no_nulls",
    "non_empty",
    "open_readonly_db",
    "rows_equal",
    "run",
    "run_query",
    "strip_lean_comments",
    "unique_column",
    "validate_candidates_schema",
    "verify",
    "verify_lean",
    "verify_protocol",
    "verify_sql",
]
