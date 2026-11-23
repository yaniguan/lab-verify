"""Composable runtime semantic property checks for Layer 4 when no gold query exists."""

from __future__ import annotations

import math
import sqlite3
from typing import Any, Callable, Sequence

PropertyCheck = Callable[[Any], str | None]


def _resolve_col_idx(result: Any, col: int | str) -> int:
    if isinstance(col, int):
        if 0 <= col < len(result.columns):
            return col
        raise IndexError(f"column index {col} out of range for {result.columns}")
    col_lc = col.lower()
    for idx, name in enumerate(result.columns):
        if name.lower() == col_lc:
            return idx
    raise KeyError(f"column {col!r} not found in result columns {list(result.columns)}")


def non_empty() -> PropertyCheck:
    """Require at least one result row."""

    def _check(res: Any) -> str | None:
        if len(res.rows) == 0:
            return "property violation: result set is empty (0 rows)"
        return None

    return _check


def max_rows_bound(limit: int) -> PropertyCheck:
    """Require row count not to exceed `limit`."""

    def _check(res: Any) -> str | None:
        if len(res.rows) > limit:
            return f"property violation: result count {len(res.rows)} exceeds bound {limit}"
        return None

    return _check


def no_join_fanout(
    con: sqlite3.Connection,
    base_table: str,
    *,
    key_col: int | str | None = None,
) -> PropertyCheck:
    """Detect join fanout explosions exceeding base table cardinality or duplicating entity keys."""
    if not base_table.replace("_", "").isalnum():
        raise ValueError(f"invalid table identifier: {base_table!r}")
    base_count = int(con.execute(f"SELECT COUNT(*) FROM {base_table}").fetchone()[0])

    def _check(res: Any) -> str | None:
        if len(res.rows) > base_count:
            return (
                f"property violation: join fanout explosion ({len(res.rows)} rows > "
                f"{base_count} rows in base table {base_table})"
            )
        if key_col is not None:
            try:
                idx = _resolve_col_idx(res, key_col)
            except (IndexError, KeyError) as exc:
                return f"property violation: {exc}"
            vals = [r[idx] for r in res.rows]
            if len(vals) != len(set(vals)):
                return f"property violation: duplicate primary/group key in column {key_col!r} (join fanout)"
        return None

    return _check


def column_in_range(col: int | str, low: float, high: float, *, allow_null: bool = True) -> PropertyCheck:
    """Require numeric values in column `col` to fall within `[low, high]`."""

    def _check(res: Any) -> str | None:
        try:
            idx = _resolve_col_idx(res, col)
        except (IndexError, KeyError) as exc:
            return f"property violation: {exc}"
        for row_i, row in enumerate(res.rows, 1):
            val = row[idx]
            if val is None:
                if allow_null:
                    continue
                return f"property violation: NULL value at row {row_i} column {col!r}"
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(float(val)):
                return f"property violation: non-numeric value {val!r} at row {row_i} column {col!r}"
            if not (low <= float(val) <= high):
                return (
                    f"property violation: column {col!r} value {val} at row {row_i} "
                    f"outside [{low}, {high}]"
                )
        return None

    return _check


def unique_column(col: int | str) -> PropertyCheck:
    """Require values in column `col` to be strictly unique across returned rows."""

    def _check(res: Any) -> str | None:
        try:
            idx = _resolve_col_idx(res, col)
        except (IndexError, KeyError) as exc:
            return f"property violation: {exc}"
        seen: set[Any] = set()
        for row_i, row in enumerate(res.rows, 1):
            val = row[idx]
            if val in seen:
                return f"property violation: duplicate key {val!r} at row {row_i} in column {col!r}"
            seen.add(val)
        return None

    return _check


def no_nulls(col: int | str) -> PropertyCheck:
    """Forbid `NULL` values in column `col`."""

    def _check(res: Any) -> str | None:
        try:
            idx = _resolve_col_idx(res, col)
        except (IndexError, KeyError) as exc:
            return f"property violation: {exc}"
        for row_i, row in enumerate(res.rows, 1):
            if row[idx] is None:
                return f"property violation: unexpected NULL at row {row_i} in column {col!r}"
        return None

    return _check


def expected_columns(expected: int | Sequence[str]) -> PropertyCheck:
    """Require column arity (if `int`) or case-insensitive column names (if `Sequence[str]`)."""

    def _check(res: Any) -> str | None:
        if isinstance(expected, int):
            if len(res.columns) != expected:
                return f"property violation: expected {expected} column(s), got {len(res.columns)}"
            return None
        got_lc = [c.lower() for c in res.columns]
        exp_lc = [c.lower() for c in expected]
        if got_lc != exp_lc:
            return f"property violation: expected columns {list(expected)}, got {list(res.columns)}"
        return None

    return _check
