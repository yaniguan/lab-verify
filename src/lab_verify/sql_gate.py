"""Hardened 4-layer default-deny SQL verification gate over laboratory databases."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, deque
from dataclasses import dataclass
import json
import logging
import math
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Mapping, Sequence

import sqlglot
from sqlglot import exp

from .verdict import VerifyVerdict

LAYERS = ["parse", "read-only", "schema", "execution"]

SCHEMA: dict[str, list[str]] = {
    "experiments": [
        "id",
        "date",
        "operator",
        "protocol",
        "temperature_c",
        "yield_pct",
        "status",
        "instrument_id",
    ],
    "samples": ["id", "experiment_id", "well", "reagent", "volume_ul"],
    "instruments": ["id", "name", "last_calibrated"],
}

DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE instruments (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        last_calibrated TEXT CHECK (
            last_calibrated IS NULL
            OR last_calibrated GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
        )
    )
    """,
    """
    CREATE TABLE experiments (
        id INTEGER PRIMARY KEY,
        date TEXT NOT NULL CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
        operator TEXT NOT NULL,
        protocol TEXT NOT NULL,
        temperature_c REAL NOT NULL,
        yield_pct REAL,
        status TEXT NOT NULL,
        instrument_id INTEGER REFERENCES instruments(id)
    )
    """,
    """
    CREATE TABLE samples (
        id INTEGER PRIMARY KEY,
        experiment_id INTEGER NOT NULL REFERENCES experiments(id),
        well TEXT NOT NULL,
        reagent TEXT NOT NULL,
        volume_ul REAL NOT NULL
    )
    """,
)

# SYNTHETIC data: deterministic rows (12 experiments + 14 samples + 4 instruments = 30 rows).
# Experiment 7 ('Western', 'running') intentionally has NULL yield_pct and NULL instrument_id (manual run).
INSTRUMENTS: list[tuple[Any, ...]] = [
    (1, "Thermocycler T1", "2026-01-15"),
    (2, "Plate reader P2", "2026-07-02"),
    (3, "Imager G3", "2026-05-20"),
    (4, "Pipette robot R4", "2026-09-30"),
]

EXPERIMENTS: list[tuple[Any, ...]] = [
    (1, "2026-02-10", "Kim", "PCR", 37.0, 82.5, "done", 1),
    (2, "2026-02-14", "Patel", "ELISA", 25.0, 64.0, "done", 2),
    (3, "2026-02-20", "Novak", "Western", 4.0, 41.0, "failed", 3),
    (4, "2026-03-02", "Kim", "PCR", 42.0, 91.0, "done", 1),
    (5, "2026-03-05", "Patel", "PCR", 37.0, 55.5, "failed", 1),
    (6, "2026-03-11", "Novak", "ELISA", 25.0, 70.0, "done", 2),
    (7, "2026-03-18", "Kim", "Western", 4.0, None, "running", None),
    (8, "2026-03-27", "Patel", "ELISA", 30.0, 77.0, "done", 2),
    (9, "2026-04-03", "Novak", "PCR", 45.0, 88.0, "done", 4),
    (10, "2026-04-09", "Kim", "ELISA", 25.0, 59.5, "failed", 2),
    (11, "2026-04-15", "Patel", "Western", 4.0, 47.0, "done", 3),
    (12, "2026-04-22", "Novak", "PCR", 39.0, 73.0, "running", 4),
]

SAMPLES: list[tuple[Any, ...]] = [
    (101, 1, "A1", "Taq", 20.0),
    (102, 1, "A2", "Taq", 20.0),
    (103, 2, "B1", "Antibody-X", 50.0),
    (104, 4, "A3", "Taq", 25.0),
    (105, 4, "A4", "Polymerase-Q", 25.0),
    (106, 4, "A5", "Taq", 25.0),
    (107, 5, "C1", "Taq", 20.0),
    (108, 6, "B2", "Antibody-Y", 50.0),
    (109, 7, "D1", "Blocking buffer", 100.0),
    (110, 9, "A6", "Polymerase-Q", 30.0),
    (111, 9, "A7", "Polymerase-Q", 30.0),
    (112, 10, "B3", "Antibody-X", 40.0),
    (113, 12, "A8", "Taq", 22.5),
    (114, 12, "A9", "Polymerase-Q", 22.5),
]

FORBIDDEN_SYSTEM_TABLES: frozenset[str] = frozenset(
    {
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
        "sqlite_sequence",
        "sqlite_stat1",
        "sqlite_stat2",
        "sqlite_stat3",
        "sqlite_stat4",
    }
)

FORBIDDEN_SQLITE_FUNCTIONS: frozenset[str] = frozenset(
    {
        "load_extension",
        "randomblob",
        "zeroblob",
        "printf",
        "format",
        "fts3_tokenizer",
        "writefile",
        "readfile",
        "edit",
        "sqlar_compress",
        "sqlar_uncompress",
        "sqlite_compileoption_used",
        "sqlite_compileoption_get",
        "sqlite_offset",
    }
)

_FORBIDDEN_AST_NAMES = (
    "Insert",
    "Update",
    "Delete",
    "Drop",
    "Create",
    "Alter",
    "Merge",
    "Command",
    "Pragma",
    "Transaction",
    "Commit",
    "Rollback",
    "Set",
    "Attach",
    "Detach",
    "Analyze",
    "LoadData",
    "Lock",
    "Kill",
    "Describe",
    "Show",
    "Use",
)
FORBIDDEN_AST_TYPES: tuple[type, ...] = tuple(
    getattr(exp, name) for name in _FORBIDDEN_AST_NAMES if hasattr(exp, name)
)


def _read_only_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    dbname: str | None,
    source: str | None,
) -> int:
    if action == sqlite3.SQLITE_SELECT or action == sqlite3.SQLITE_RECURSIVE:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        tbl = (arg1 or "").lower()
        if tbl in FORBIDDEN_SYSTEM_TABLES or tbl.startswith("sqlite_"):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        fn = (arg2 or "").lower()
        if fn in FORBIDDEN_SQLITE_FUNCTIONS or fn.startswith("pragma_"):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _allow_all_authorizer(*_args: Any) -> int:
    """Permissive authorizer used during setup/introspection (avoids CPython 3.10 set_authorizer(None) bug)."""
    return sqlite3.SQLITE_OK


def lock_connection_readonly(con: sqlite3.Connection) -> sqlite3.Connection:
    """Apply defense-in-depth engine locks (`query_only`, no extensions, strict authorizer)."""
    con.set_authorizer(_allow_all_authorizer)
    con.execute("PRAGMA query_only = ON")
    if hasattr(con, "enable_load_extension"):
        try:
            con.enable_load_extension(False)
        except sqlite3.Error:
            pass
    con.set_authorizer(_read_only_authorizer)
    return con


def introspect_sqlite_schema(con: sqlite3.Connection) -> dict[str, list[str]]:
    """Dynamically extract `{table_name: [col_names...]}` from any SQLite connection."""
    con.set_authorizer(_allow_all_authorizer)
    try:
        tables_rows = con.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        out: dict[str, list[str]] = {}
        for (t_name,) in tables_rows:
            safe_q = str(t_name).replace('"', '""')
            col_rows = con.execute(f'PRAGMA table_info("{safe_q}")').fetchall()
            out[str(t_name)] = [str(r[1]) for r in col_rows]
        return out
    finally:
        con.set_authorizer(_read_only_authorizer)


def open_readonly_db(db_path: str | Path) -> tuple[sqlite3.Connection, dict[str, list[str]]]:
    """Open an existing SQLite file strictly via `mode=ro` URI, introspect schema, and lock authorizer."""
    p = Path(db_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"SQLite database not found: {p}")
    uri = f"file:{p.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    schema = introspect_sqlite_schema(con)
    lock_connection_readonly(con)
    return con, schema


def _populate_synthetic_db(
    experiments: Sequence[tuple[Any, ...]],
    samples: Sequence[tuple[Any, ...]],
    instruments: Sequence[tuple[Any, ...]],
) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys = ON")
    for ddl in DDL_STATEMENTS:
        con.execute(ddl)
    con.executemany("INSERT INTO instruments VALUES (?, ?, ?)", instruments)
    con.executemany("INSERT INTO experiments VALUES (?, ?, ?, ?, ?, ?, ?, ?)", experiments)
    con.executemany("INSERT INTO samples VALUES (?, ?, ?, ?, ?)", samples)
    con.commit()
    return lock_connection_readonly(con)


def build_db() -> sqlite3.Connection:
    """Create the synthetic 30-row laboratory SQLite database and lock it to read-only queries."""
    return _populate_synthetic_db(EXPERIMENTS, SAMPLES, INSTRUMENTS)


def build_counterexample_dbs() -> list[sqlite3.Connection]:
    """Build deterministic perturbation DBs catching accidental scalar/row-count coincidences."""
    # Perturbation 1: ELISA becomes highest yield (96.5%), adds a 6th distinct reagent, adds extra March done exp
    exps_1 = list(EXPERIMENTS) + [
        (13, "2026-03-29", "Patel", "ELISA", 28.0, 96.5, "done", 2),
        (14, "2026-05-04", "Novak", "Western", 4.0, 35.0, "failed", 3),
    ]
    samps_1 = list(SAMPLES) + [
        (115, 13, "B4", "RNase-Inhibitor", 15.0),
        (116, 4, "A10", "Taq", 25.0),
    ]
    inst_1 = list(INSTRUMENTS) + [
        (5, "Centrifuge C5", "2026-03-10"),
    ]

    # Perturbation 2: Western becomes highest yield (94.0%), new PCR operator 'Chen', different >37C sample count
    exps_2 = list(EXPERIMENTS) + [
        (13, "2026-05-10", "Chen", "PCR", 41.0, 80.0, "done", 1),
        (14, "2026-05-12", "Kim", "Western", 4.0, 94.0, "done", 3),
    ]
    samps_2 = list(SAMPLES) + [
        (115, 13, "C2", "Taq", 30.0),
        (116, 14, "D2", "Blocking buffer", 60.0),
    ]
    inst_2 = list(INSTRUMENTS)

    # Perturbation 3: In-progress ELISA run with NULL yield_pct (exposes SUM/COUNT(*) vs AVG NULL-denominator bug)
    exps_3 = list(EXPERIMENTS) + [
        (13, "2026-03-19", "Kim", "ELISA", 25.0, None, "running", 2),
    ]
    samps_3 = list(SAMPLES)
    inst_3 = list(INSTRUMENTS)

    return [
        _populate_synthetic_db(exps_1, samps_1, inst_1),
        _populate_synthetic_db(exps_2, samps_2, inst_2),
        _populate_synthetic_db(exps_3, samps_3, inst_3),
    ]


# ---- Layer 1: Syntax Parse ----
def check_parse(sql: Any) -> tuple[list[exp.Expression] | None, str | None]:
    """Parse SQLite SQL strictly; reject empty/comment-only inputs and syntax errors at Layer 1."""
    if not isinstance(sql, str) or not sql.strip():
        return None, "empty SQL input"
    sg_logger = logging.getLogger("sqlglot")
    prev_level = sg_logger.level
    sg_logger.setLevel(logging.ERROR)
    try:
        parsed = sqlglot.parse(
            sql,
            read="sqlite",
            error_level=sqlglot.ErrorLevel.RAISE,
        )
    except sqlglot.errors.SqlglotError as exc:
        return None, str(exc).splitlines()[0]
    finally:
        sg_logger.setLevel(prev_level)
    stmts = [s for s in parsed if s is not None]
    if not stmts:
        return None, "empty SQL input"
    return stmts, None


# ---- Layer 2: Read-Only & Function Gate ----
def check_read_only(stmts: Sequence[exp.Expression]) -> str | None:
    """Allow strictly a single read-only `SELECT` or compound `SetOperation` with safe functions."""
    if len(stmts) != 1:
        return f"{len(stmts)} statements ({', '.join(type(s).__name__ for s in stmts)})"
    stmt = stmts[0]
    if not isinstance(stmt, (exp.Select, exp.SetOperation)):
        return f"{type(stmt).__name__} statement"

    for node in stmt.walk():
        if isinstance(node, FORBIDDEN_AST_TYPES):
            return f"{type(node).__name__} statement"
        if isinstance(node, exp.Anonymous):
            fn = (node.name or "").lower()
            if fn in FORBIDDEN_SQLITE_FUNCTIONS or fn.startswith("pragma_"):
                return f"forbidden function {node.name}"
        elif isinstance(node, exp.Func):
            for candidate_name in (node.sql_name(), getattr(node, "name", "")):
                fn = str(candidate_name or "").lower()
                if fn in FORBIDDEN_SQLITE_FUNCTIONS or fn.startswith("pragma_"):
                    return f"forbidden function {candidate_name}"
    return None


# ---- Layer 3: Lexical Schema, CTE, Alias, Join, & SetOperation Validator ----
def _ast_references_table(expr: exp.Expression, table_lc: str) -> bool:
    for tbl in expr.find_all(exp.Table):
        if not tbl.db and (tbl.name or "").lower() == table_lc:
            return True
    return False


def _flatten_union_branches(
    expr: exp.Expression,
) -> tuple[list[exp.Expression], list[exp.Expression]]:
    branches: list[exp.Expression] = []
    orders: list[exp.Expression] = []

    def _collect(cur: exp.Expression) -> bool:
        if isinstance(cur, exp.Subquery):
            return _collect(cur.this)
        if isinstance(cur, exp.Union):
            order_node = cur.args.get("order")
            if order_node is not None:
                orders.append(order_node)
            return _collect(cur.this) and _collect(cur.expression)
        branches.append(cur)
        return True

    _collect(expr)
    return branches, orders


def _check_recursive_string_expansion(
    branch: exp.Expression,
    cte_alias: str,
    cte_lc: str,
    rec_cols: Sequence[str],
) -> str | None:
    target = branch.this if isinstance(branch, exp.Subquery) else branch
    rec_aliases: set[str] = set()
    other_tables = 0
    for tbl in target.find_all(exp.Table):
        if not tbl.db and (tbl.name or "").lower() == cte_lc:
            rec_aliases.add((tbl.alias or tbl.name).lower())
        else:
            other_tables += 1
    if not rec_aliases:
        return None
    rec_col_set = {c.lower() for c in rec_cols}

    def _is_rec_col(col: exp.Column) -> bool:
        if col.table:
            return col.table.lower() in rec_aliases
        return other_tables == 0 or (col.name or "").lower() in rec_col_set

    def _count_rec_refs(sub: exp.Expression) -> int:
        return sum(1 for c in sub.find_all(exp.Column) if _is_rec_col(c))

    for node in target.walk():
        if isinstance(node, exp.DPipe) and _count_rec_refs(node) >= 2:
            return (
                f"recursive CTE {cte_alias} contains exponential string self-concatenation"
            )
        if isinstance(node, (exp.Anonymous, exp.Func)):
            cand_names = (
                [node.name]
                if isinstance(node, exp.Anonymous)
                else [node.sql_name(), getattr(node, "name", "")]
            )
            for raw_fn in cand_names:
                fn = str(raw_fn or "").lower()
                if fn in ("concat", "concat_ws") and _count_rec_refs(node) >= 2:
                    return (
                        f"recursive CTE {cte_alias} contains exponential string self-concatenation"
                    )
                if fn in ("replace", "hex", "quote") and _count_rec_refs(node) >= 1:
                    return (
                        f"recursive CTE {cte_alias} contains unbounded string expansion ({fn})"
                    )
    return None


def _is_single_row_query(q: exp.Expression, scalar_ctes: set[str]) -> bool:
    """Return True if `q` is statically guaranteed to emit at most 1 row (scalar CTE/subquery)."""
    target = q.this if isinstance(q, exp.Subquery) else q
    if not isinstance(target, exp.Select):
        return False

    limit_node = target.args.get("limit")
    if limit_node is not None:
        lim_expr = limit_node.expression
        if isinstance(lim_expr, exp.Literal) and lim_expr.is_int and 0 <= int(lim_expr.this) <= 32:
            return True

    from_node = target.args.get("from_")
    joins = target.args.get("joins") or []
    if from_node is None and not joins:
        return True

    if target.args.get("group") is None and target.expressions:
        has_agg = any(
            isinstance(sub, exp.AggFunc)
            for proj in target.expressions
            for sub in proj.walk()
        )
        has_window = any(
            isinstance(sub, exp.Window)
            for proj in target.expressions
            for sub in proj.walk()
        )
        if has_agg and not has_window:
            return True

    if from_node is not None:
        all_srcs = [from_node.this, *(j.this for j in joins)]
        all_single = True
        for src in all_srcs:
            if isinstance(src, exp.Table) and not src.db and (src.name or "").lower() in scalar_ctes:
                continue
            if isinstance(src, exp.Subquery) and _is_single_row_query(src.this, scalar_ctes):
                continue
            all_single = False
            break
        if all_single:
            return True

    return False


def _flatten_conjuncts(expr: exp.Expression | None) -> list[exp.Expression]:
    """Extract top-level conjunctive (`AND`) predicates from a `WHERE` expression."""
    if expr is None:
        return []
    cur = expr.this if isinstance(expr, exp.Where) else expr
    while isinstance(cur, exp.Paren):
        cur = cur.this
    if isinstance(cur, exp.And):
        return _flatten_conjuncts(cur.this) + _flatten_conjuncts(cur.expression)
    return [cur]


def check_schema(
    stmt: exp.Expression,
    schema: Mapping[str, Sequence[str]] | None = None,
    *,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
    allow_recursive_cte: bool = True,
    raw_sql: str = "",
) -> str | None:
    """Validate table/column visibility per lexical scope, CTEs, star expansions, joins, and unions."""
    target_schema = SCHEMA if schema is None else schema
    norm_schema: dict[str, list[str]] = {
        t.lower(): [c.lower() for c in cols] for t, cols in target_schema.items()
    }

    def _validate_query(
        node: exp.Expression,
        cte_env: dict[str, list[str]],
        outer_sources: dict[str, tuple[str, list[str]]],
        scalar_ctes: set[str] | None = None,
    ) -> tuple[list[str] | None, str | None]:
        if isinstance(node, exp.Subquery):
            return _validate_query(node.this, cte_env, outer_sources, scalar_ctes)

        local_cte_env = dict(cte_env)
        local_scalar_ctes: set[str] = set(scalar_ctes or ())
        with_clause = node.args.get("with_")
        if with_clause is not None:
            is_recursive = bool(with_clause.args.get("recursive"))
            for cte in with_clause.expressions:
                cte_alias = cte.alias
                cte_lc = cte_alias.lower()
                if cte_lc in FORBIDDEN_SYSTEM_TABLES or cte_lc.startswith("sqlite_") or cte_lc.startswith("pragma_"):
                    return None, f"system/pragma table {cte_alias} is forbidden"
                alias_obj = cte.args.get("alias")
                explicit_cols = [
                    c.name.lower() for c in (alias_obj.columns if alias_obj and alias_obj.columns else [])
                ]
                self_refs = is_recursive and _ast_references_table(cte.this, cte_lc)
                if self_refs:
                    if not allow_recursive_cte:
                        return None, f"recursive CTE {cte_alias} is forbidden by policy"
                    cte_body = cte.this.this if isinstance(cte.this, exp.Subquery) else cte.this
                    if not isinstance(cte_body, exp.Union):
                        return (
                            None,
                            f"recursive CTE {cte_alias} requires UNION or UNION ALL with a non-recursive anchor branch",
                        )
                    branches, union_orders = _flatten_union_branches(cte_body)
                    if len(branches) < 2 or _ast_references_table(branches[0], cte_lc):
                        return (
                            None,
                            f"recursive CTE {cte_alias} requires a non-recursive anchor branch",
                        )
                    anchor_env = {k: v for k, v in local_cte_env.items() if k != cte_lc}
                    anchor_scalars = {k for k in local_scalar_ctes if k != cte_lc}
                    anchor_cols, anchor_err = _validate_query(
                        branches[0], anchor_env, outer_sources, anchor_scalars
                    )
                    if anchor_err:
                        return None, anchor_err
                    assert anchor_cols is not None
                    if explicit_cols:
                        if len(explicit_cols) != len(anchor_cols):
                            return (
                                None,
                                f"CTE {cte_alias} column count mismatch ({len(explicit_cols)} vs {len(anchor_cols)})",
                            )
                        rec_cols = explicit_cols
                    else:
                        rec_cols = list(anchor_cols)
                    rec_env = {**local_cte_env, cte_lc: rec_cols}
                    for rec_branch in branches[1:]:
                        rb_cols, rb_err = _validate_query(
                            rec_branch, rec_env, outer_sources, anchor_scalars
                        )
                        if rb_err:
                            return None, rb_err
                        assert rb_cols is not None
                        if len(rb_cols) != len(rec_cols):
                            return (
                                None,
                                f"compound query column count mismatch ({len(rec_cols)} vs {len(rb_cols)})",
                            )
                        exp_err = _check_recursive_string_expansion(
                            rec_branch, cte_alias, cte_lc, rec_cols
                        )
                        if exp_err:
                            return None, exp_err
                    for order_clause in union_orders:
                        for o_col in order_clause.find_all(exp.Column):
                            if o_col.table:
                                return None, f"unknown table alias {o_col.table}"
                            if o_col.name.lower() not in rec_cols:
                                return None, f"unknown column {o_col.name} in compound query"
                    local_cte_env[cte_lc] = rec_cols
                    local_scalar_ctes.discard(cte_lc)
                else:
                    non_rec_env = {k: v for k, v in local_cte_env.items() if k != cte_lc} if not is_recursive else local_cte_env
                    non_rec_scalars = {k for k in local_scalar_ctes if k != cte_lc} if not is_recursive else local_scalar_ctes
                    cte_cols, cte_err = _validate_query(
                        cte.this, non_rec_env, outer_sources, non_rec_scalars
                    )
                    if cte_err:
                        return None, cte_err
                    assert cte_cols is not None
                    if explicit_cols:
                        if len(explicit_cols) != len(cte_cols):
                            return (
                                None,
                                f"CTE {cte_alias} column count mismatch ({len(explicit_cols)} vs {len(cte_cols)})",
                            )
                        local_cte_env[cte_lc] = explicit_cols
                    else:
                        local_cte_env[cte_lc] = cte_cols
                    if _is_single_row_query(cte.this, non_rec_scalars):
                        local_scalar_ctes.add(cte_lc)
                    else:
                        local_scalar_ctes.discard(cte_lc)

        if isinstance(node, exp.SetOperation):
            left_cols, left_err = _validate_query(
                node.this, local_cte_env, outer_sources, local_scalar_ctes
            )
            if left_err:
                return None, left_err
            right_cols, right_err = _validate_query(
                node.expression, local_cte_env, outer_sources, local_scalar_ctes
            )
            if right_err:
                return None, right_err
            assert left_cols is not None and right_cols is not None
            if len(left_cols) != len(right_cols):
                return (
                    None,
                    f"compound query column count mismatch ({len(left_cols)} vs {len(right_cols)})",
                )
            order_clause = node.args.get("order")
            if order_clause is not None:
                compound_sources = {"_compound": ("compound", left_cols)}
                for o_col in order_clause.find_all(exp.Column):
                    if o_col.table:
                        return None, f"unknown table alias {o_col.table}"
                    if o_col.name.lower() not in compound_sources["_compound"][1]:
                        return None, f"unknown column {o_col.name} in compound query"
            return left_cols, None

        if not isinstance(node, exp.Select):
            return None, f"unsupported query expression {type(node).__name__}"

        local_sources: dict[str, tuple[str, list[str]]] = {}
        single_row_sources: set[str] = set()
        using_merged_cols: set[str] = set()

        def _register_source(src: exp.Expression) -> str | None:
            if isinstance(src, exp.Table):
                t_raw = src.name
                t_lc = t_raw.lower()
                if src.db:
                    return f"qualified database {src.db}.{t_raw} is forbidden"
                if t_lc in FORBIDDEN_SYSTEM_TABLES or t_lc.startswith("sqlite_") or t_lc.startswith("pragma_"):
                    return f"system/pragma table {t_raw} is forbidden"
                if t_lc in local_cte_env:
                    cols = list(local_cte_env[t_lc])
                    canon = t_lc
                elif t_lc in norm_schema:
                    cols = list(norm_schema[t_lc])
                    canon = t_lc
                else:
                    return f"unknown table {t_raw}"
                bind_key = (src.alias or t_raw).lower()
                if bind_key in local_sources:
                    return f"duplicate table alias {src.alias or t_raw}"
                local_sources[bind_key] = (canon, cols)
                if canon in local_scalar_ctes:
                    single_row_sources.add(bind_key)
                return None

            if isinstance(src, exp.Subquery):
                sub_cols, sub_err = _validate_query(
                    src.this, local_cte_env, outer_sources, local_scalar_ctes
                )
                if sub_err:
                    return sub_err
                bind_key = (src.alias or f"_subquery_{len(local_sources)}").lower()
                if src.alias and bind_key in local_sources:
                    return f"duplicate table alias {src.alias}"
                local_sources[bind_key] = (bind_key, list(sub_cols or []))
                if _is_single_row_query(src.this, local_scalar_ctes):
                    single_row_sources.add(bind_key)
                return None

            return f"unsupported table source {src.sql(dialect='sqlite')}"

        from_clause = node.args.get("from_")
        if from_clause is not None:
            src_err = _register_source(from_clause.this)
            if src_err:
                return None, src_err

        joins = node.args.get("joins") or []
        for join in joins:
            prior_cols = {c for _, cols in local_sources.values() for c in cols}
            src_err = _register_source(join.this)
            if src_err:
                return None, src_err
            joined_key = list(local_sources.keys())[-1]
            joined_canon, joined_cols = local_sources[joined_key]

            using_list = join.args.get("using") or []
            for u_ident in using_list:
                u_lc = u_ident.name.lower()
                if u_lc not in prior_cols:
                    return None, f"unknown USING column {u_ident.name}"
                if u_lc not in joined_cols:
                    return None, f"unknown column {joined_canon}.{u_ident.name}"
                using_merged_cols.add(u_lc)

        if strict_joins and len(local_sources) >= 2:
            source_keys = list(local_sources.keys())
            adj_map: dict[str, set[str]] = {k: set() for k in source_keys}

            def _add_join_edge(a: str, b: str) -> None:
                if a != b and a in adj_map and b in adj_map:
                    adj_map[a].add(b)
                    adj_map[b].add(a)

            def _referenced_local_sources(sub_expr: exp.Expression) -> set[str]:
                refs: set[str] = set()
                for col in sub_expr.find_all(exp.Column):
                    if col.is_star or isinstance(col.this, exp.Star):
                        continue
                    if col.table:
                        tl = col.table.lower()
                        if tl in local_sources:
                            refs.add(tl)
                    else:
                        cl = (col.name or "").lower()
                        matches = [
                            alias for alias, (_, cols) in local_sources.items() if cl in cols
                        ]
                        if len(matches) == 1:
                            refs.add(matches[0])
                return refs

            for sk in single_row_sources:
                _add_join_edge(source_keys[0], sk)
                if sk == source_keys[0] and len(source_keys) >= 2:
                    _add_join_edge(source_keys[0], source_keys[1])

            has_unlinked_explicit_cross = False
            for j_idx, join in enumerate(joins):
                joined_key = source_keys[j_idx + 1]
                prior_key = source_keys[j_idx]
                using_list = join.args.get("using") or []
                on_expr = join.args.get("on")
                has_using = bool(using_list)
                has_on = (
                    on_expr is not None
                    and not isinstance(on_expr, exp.Boolean)
                    and bool(list(on_expr.find_all(exp.Column)))
                )
                is_cross_kind = str(join.args.get("kind", "")).upper() == "CROSS"
                is_explicit_cross = is_cross_kind and bool(
                    re.search(r"\bCROSS\s+JOIN\b", raw_sql, flags=re.IGNORECASE)
                )

                if has_using or has_on:
                    _add_join_edge(prior_key, joined_key)
                    if on_expr is not None:
                        on_refs = sorted(_referenced_local_sources(on_expr))
                        for r1 in on_refs:
                            for r2 in on_refs:
                                _add_join_edge(r1, r2)
                elif joined_key in single_row_sources or all(
                    pk in single_row_sources for pk in source_keys[: j_idx + 1]
                ):
                    _add_join_edge(prior_key, joined_key)
                elif is_explicit_cross:
                    if allow_cross_join:
                        _add_join_edge(prior_key, joined_key)
                    else:
                        has_unlinked_explicit_cross = True

            if has_unlinked_explicit_cross:
                return None, "unconstrained Cartesian join (missing ON or USING condition)"

            where_node = node.args.get("where")
            for conjunct in _flatten_conjuncts(where_node):
                if isinstance(conjunct, (exp.EQ, exp.NullSafeEQ)):
                    left_refs = _referenced_local_sources(conjunct.this)
                    right_refs = _referenced_local_sources(conjunct.expression)
                    for lr in left_refs:
                        for rr in right_refs:
                            _add_join_edge(lr, rr)

            visited_sources: set[str] = {source_keys[0]}
            bfs_queue: deque[str] = deque([source_keys[0]])
            while bfs_queue:
                cur_s = bfs_queue.popleft()
                for nxt_s in adj_map[cur_s]:
                    if nxt_s not in visited_sources:
                        visited_sources.add(nxt_s)
                        bfs_queue.append(nxt_s)
            if len(visited_sources) < len(source_keys):
                return None, "unconstrained Cartesian join (missing ON or USING condition)"

        def _check_expr(
            expr: exp.Expression | None,
            *,
            allow_output_aliases: bool,
            output_aliases: set[str],
        ) -> str | None:
            if expr is None:
                return None
            if isinstance(expr, (exp.Select, exp.SetOperation)):
                merged_outer = dict(outer_sources)
                merged_outer.update(local_sources)
                _, n_err = _validate_query(expr, local_cte_env, merged_outer, local_scalar_ctes)
                return n_err
            if isinstance(expr, exp.Subquery):
                merged_outer = dict(outer_sources)
                merged_outer.update(local_sources)
                _, n_err = _validate_query(expr.this, local_cte_env, merged_outer, local_scalar_ctes)
                return n_err
            if isinstance(expr, exp.Star):
                if not local_sources:
                    return "SELECT * without FROM table"
                return None
            if isinstance(expr, exp.Column):
                col_raw = expr.name
                col_lc = col_raw.lower()
                is_star = bool(expr.is_star or isinstance(expr.this, exp.Star))
                if expr.table:
                    tbl_lc = expr.table.lower()
                    if tbl_lc in local_sources:
                        canon_tbl, tbl_cols = local_sources[tbl_lc]
                    elif tbl_lc in outer_sources:
                        canon_tbl, tbl_cols = outer_sources[tbl_lc]
                    else:
                        return f"unknown table alias {expr.table}"
                    if is_star:
                        return None
                    if col_lc not in tbl_cols:
                        return f"unknown column {canon_tbl}.{col_raw}"
                    return None

                if is_star:
                    return "SELECT * without FROM table" if not local_sources else None

                matching_local = [
                    alias for alias, (_, cols) in local_sources.items() if col_lc in cols
                ]
                if len(matching_local) > 1 and col_lc not in using_merged_cols:
                    return f"ambiguous column {col_raw}"
                if len(matching_local) >= 1:
                    return None

                if allow_output_aliases and col_lc in output_aliases:
                    return None

                matching_outer = [
                    alias for alias, (_, cols) in outer_sources.items() if col_lc in cols
                ]
                if len(matching_outer) > 1:
                    return f"ambiguous column {col_raw}"
                if len(matching_outer) == 1:
                    return None

                canon_names = sorted({canon for canon, _ in local_sources.values()})
                in_clause = ", ".join(canon_names) if canon_names else "<no tables>"
                return f"unknown column {col_raw} in {in_clause}"

            for child in expr.iter_expressions():
                c_err = _check_expr(
                    child,
                    allow_output_aliases=allow_output_aliases,
                    output_aliases=output_aliases,
                )
                if c_err:
                    return c_err
            return None

        projected_cols: list[str] = []
        output_aliases: set[str] = set()
        for proj in node.expressions:
            if isinstance(proj, exp.Alias):
                p_err = _check_expr(proj.this, allow_output_aliases=False, output_aliases=set())
                if p_err:
                    return None, p_err
                a_lc = proj.alias.lower()
                output_aliases.add(a_lc)
                projected_cols.append(a_lc)
            elif isinstance(proj, exp.Star):
                p_err = _check_expr(proj, allow_output_aliases=False, output_aliases=set())
                if p_err:
                    return None, p_err
                for _, (_, cols) in local_sources.items():
                    projected_cols.extend(cols)
            elif isinstance(proj, exp.Column) and (proj.is_star or isinstance(proj.this, exp.Star)):
                p_err = _check_expr(proj, allow_output_aliases=False, output_aliases=set())
                if p_err:
                    return None, p_err
                _, cols = local_sources[proj.table.lower()]
                projected_cols.extend(cols)
            else:
                p_err = _check_expr(proj, allow_output_aliases=False, output_aliases=set())
                if p_err:
                    return None, p_err
                if isinstance(proj, exp.Column):
                    projected_cols.append(proj.name.lower())
                else:
                    projected_cols.append(f"_col_{len(projected_cols)}")

        for join in joins:
            on_expr = join.args.get("on")
            if on_expr is not None:
                j_err = _check_expr(on_expr, allow_output_aliases=False, output_aliases=set())
                if j_err:
                    return None, j_err

        where_clause = node.args.get("where")
        if where_clause is not None:
            w_err = _check_expr(where_clause, allow_output_aliases=False, output_aliases=set())
            if w_err:
                return None, w_err

        for post_clause_key in ("group", "having", "order"):
            clause = node.args.get(post_clause_key)
            if clause is not None:
                c_err = _check_expr(
                    clause,
                    allow_output_aliases=True,
                    output_aliases=output_aliases,
                )
                if c_err:
                    return None, c_err

        for limit_key in ("limit", "offset"):
            clause = node.args.get(limit_key)
            if clause is not None:
                l_err = _check_expr(clause, allow_output_aliases=False, output_aliases=set())
                if l_err:
                    return None, l_err

        return projected_cols, None

    _, err = _validate_query(stmt, {}, {})
    return err


# ---- Layer 4: Safe Execution, Type-Safe Float Comparison, Ordering, & Properties ----
@dataclass(frozen=True)
class QueryResult:
    """Structured execution output preserving row sequence, column arity, and ordering flag."""

    rows: tuple[tuple[Any, ...], ...]
    columns: tuple[str, ...]
    ordered: bool = False


class ExecutionLimitError(RuntimeError):
    """Raised when a query exceeds SQLite VM step budget, wall-clock timeout, or row cap."""


def _is_sql_number(val: Any) -> bool:
    return not isinstance(val, bool) and isinstance(val, (int, float))


def _cell_sort_key(val: Any) -> tuple[int, Any]:
    if val is None:
        return (0, 0)
    if isinstance(val, bool):
        return (1, int(val))
    if _is_sql_number(val):
        fval = float(val)
        if math.isnan(fval):
            return (2, float("inf"))
        return (2, 0.0 if fval == 0.0 else fval)
    if isinstance(val, str):
        return (3, val)
    if isinstance(val, (bytes, bytearray)):
        return (4, bytes(val))
    return (5, str(val))


def _row_sort_key(row: tuple[Any, ...]) -> tuple[tuple[int, Any], ...]:
    return tuple(_cell_sort_key(v) for v in row)


def cells_equal(a: Any, b: Any, *, rel_tol: float = 1e-6, abs_tol: float = 1e-6) -> bool:
    """Compare SQL scalar cells preserving strict type boundaries and `isclose` float tolerance."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if _is_sql_number(a) and _is_sql_number(b):
        fa, fb = float(a), float(b)
        if not (math.isfinite(fa) and math.isfinite(fb)):
            return False
        return math.isclose(fa, fb, rel_tol=rel_tol, abs_tol=abs_tol)
    if type(a) is not type(b):
        return False
    return bool(a == b)


def rows_equal(r1: tuple[Any, ...], r2: tuple[Any, ...], *, rel_tol: float = 1e-6, abs_tol: float = 1e-6) -> bool:
    if len(r1) != len(r2):
        return False
    return all(cells_equal(a, b, rel_tol=rel_tol, abs_tol=abs_tol) for a, b in zip(r1, r2))


def _has_nonfinite_float(rows: Sequence[tuple[Any, ...]]) -> str | None:
    for r_idx, row in enumerate(rows, 1):
        for c_idx, val in enumerate(row, 1):
            if _is_sql_number(val) and not math.isfinite(float(val)):
                return f"non-finite numeric value ({val}) at row {r_idx}, col {c_idx}"
    return None


def _coerce_gold(gold_result: QueryResult | Counter[tuple[Any, ...]] | Sequence[tuple[Any, ...]]) -> QueryResult:
    if isinstance(gold_result, QueryResult):
        return gold_result
    if isinstance(gold_result, Counter):
        expanded: list[tuple[Any, ...]] = []
        for row, cnt in gold_result.items():
            expanded.extend([tuple(row)] * int(cnt))
        cols = tuple(f"col_{i}" for i in range(len(expanded[0]))) if expanded else ()
        return QueryResult(rows=tuple(expanded), columns=cols, ordered=False)
    rows_t = tuple(tuple(r) for r in gold_result)
    cols = tuple(f"col_{i}" for i in range(len(rows_t[0]))) if rows_t else ()
    return QueryResult(rows=rows_t, columns=cols, ordered=False)


def _hopcroft_karp(
    n_left: int,
    n_right: int,
    adj: Sequence[Sequence[int]],
) -> tuple[int, list[int], list[int]]:
    """Iterative Hopcroft-Karp maximum bipartite matching in O(E * sqrt(V)) time."""
    pair_u = [-1] * n_left
    pair_v = [-1] * n_right
    dist = [0] * n_left
    matched = 0

    while True:
        queue: deque[int] = deque()
        found_aug = False
        for u in range(n_left):
            if pair_u[u] == -1:
                dist[u] = 0
                queue.append(u)
            else:
                dist[u] = -1

        while queue:
            u = queue.popleft()
            for v in adj[u]:
                pu = pair_v[v]
                if pu == -1:
                    found_aug = True
                elif dist[pu] == -1:
                    dist[pu] = dist[u] + 1
                    queue.append(pu)

        if not found_aug:
            break

        next_edge = [0] * n_left
        for start_u in range(n_left):
            if pair_u[start_u] != -1:
                continue
            stack: list[tuple[int, int]] = [(start_u, -1)]
            while stack:
                u, _ = stack[-1]
                idx = next_edge[u]
                neighbors = adj[u]
                if idx >= len(neighbors):
                    dist[u] = -1
                    stack.pop()
                    continue
                v = neighbors[idx]
                next_edge[u] = idx + 1
                pu = pair_v[v]
                if pu == -1:
                    stack[-1] = (u, v)
                    for su, sv in stack:
                        pair_u[su] = sv
                        pair_v[sv] = su
                    matched += 1
                    stack.clear()
                elif dist[pu] == dist[u] + 1 and next_edge[pu] < len(adj[pu]):
                    stack[-1] = (u, v)
                    stack.append((pu, -1))

    return matched, pair_u, pair_v


def _non_numeric_row_signature(row: tuple[Any, ...]) -> tuple[int, tuple[tuple[int, type, Any], ...]]:
    return (
        len(row),
        tuple((idx, type(val), val) for idx, val in enumerate(row) if not _is_sql_number(val)),
    )


def _multiset_match(
    got_rows: Sequence[tuple[Any, ...]],
    gold_rows: Sequence[tuple[Any, ...]],
    *,
    rel_tol: float = 1e-6,
    abs_tol: float = 1e-6,
) -> tuple[bool, tuple[Any, ...] | None, tuple[Any, ...] | None]:
    if len(got_rows) != len(gold_rows):
        return False, None, None
    n = len(got_rows)
    if n == 0:
        return True, None, None

    s_got = sorted(got_rows, key=_row_sort_key)
    s_gold = sorted(gold_rows, key=_row_sort_key)

    # O(N) fast-path: if canonical unrounded sort aligns every row 1-to-1, bijection holds immediately.
    if all(rows_equal(r1, r2, rel_tol=rel_tol, abs_tol=abs_tol) for r1, r2 in zip(s_got, s_gold)):
        return True, None, None

    got_groups: dict[Any, list[int]] = {}
    gold_groups: dict[Any, list[int]] = {}
    for idx, r in enumerate(s_got):
        got_groups.setdefault(_non_numeric_row_signature(r), []).append(idx)
    for idx, r in enumerate(s_gold):
        gold_groups.setdefault(_non_numeric_row_signature(r), []).append(idx)

    matched_got = [False] * n
    matched_gold = [False] * n
    denom = max(0.5, 1.0 - rel_tol)

    for key, g_idxs in got_groups.items():
        h_idxs = gold_groups.get(key)
        if not h_idxs:
            continue
        sample_row = s_got[g_idxs[0]]
        num_cols = [c for c, val in enumerate(sample_row) if _is_sql_number(val)]
        if not num_cols:
            k = min(len(g_idxs), len(h_idxs))
            for i in range(k):
                matched_got[g_idxs[i]] = True
                matched_gold[h_idxs[i]] = True
            continue

        c0 = num_cols[0]
        g_sorted = sorted(g_idxs, key=lambda idx: float(s_got[idx][c0]))
        h_sorted = sorted(h_idxs, key=lambda idx: float(s_gold[idx][c0]))
        h_x = [float(s_gold[idx][c0]) for idx in h_sorted]

        adj: list[list[int]] = []
        for g_global in g_sorted:
            gr = s_got[g_global]
            gx = float(gr[c0])
            radius = max(abs_tol, (rel_tol / denom) * abs(gx)) * 1.05 + 1e-15
            lo = bisect_left(h_x, gx - radius)
            hi = bisect_right(h_x, gx + radius)
            edges = [
                v_local
                for v_local in range(lo, hi)
                if rows_equal(gr, s_gold[h_sorted[v_local]], rel_tol=rel_tol, abs_tol=abs_tol)
            ]
            adj.append(edges)

        _, pair_u, _ = _hopcroft_karp(len(g_sorted), len(h_sorted), adj)
        for u_local, v_local in enumerate(pair_u):
            if v_local != -1:
                matched_got[g_sorted[u_local]] = True
                matched_gold[h_sorted[v_local]] = True

    if all(matched_got):
        return True, None, None

    first_unmatched_got = next((s_got[i] for i in range(n) if not matched_got[i]), None)
    first_unmatched_gold = next((s_gold[j] for j in range(n) if not matched_gold[j]), None)
    return False, first_unmatched_got, first_unmatched_gold


def _submultiset_match(
    sub_rows: Sequence[tuple[Any, ...]],
    super_rows: Sequence[tuple[Any, ...]],
    *,
    rel_tol: float = 1e-6,
    abs_tol: float = 1e-6,
) -> bool:
    """Return True iff `sub_rows` can be injected 1-to-1 into `super_rows` under `rows_equal`."""
    n_sub = len(sub_rows)
    n_sup = len(super_rows)
    if n_sub == 0:
        return True
    if n_sub > n_sup:
        return False
    adj: list[list[int]] = [
        [
            v_idx
            for v_idx, sup_r in enumerate(super_rows)
            if rows_equal(sub_r, sup_r, rel_tol=rel_tol, abs_tol=abs_tol)
        ]
        for sub_r in sub_rows
    ]
    matched, _, _ = _hopcroft_karp(n_sub, n_sup, adj)
    return matched == n_sub


def _resolve_order_by_projection_indices(
    stmt: exp.Expression,
    order_node: exp.Order,
    n_cols: int,
) -> list[int] | None:
    """If every `ORDER BY` key maps directly to an output column index in `0..n_cols-1`, return indices."""
    proj_exprs: list[exp.Expression] = []
    if isinstance(stmt, exp.Select):
        proj_exprs = list(stmt.expressions)
    elif isinstance(stmt, exp.SetOperation):
        left = stmt.this
        while isinstance(left, (exp.Subquery, exp.SetOperation)):
            left = left.this
        if isinstance(left, exp.Select):
            proj_exprs = list(left.expressions)

    has_star = any(
        isinstance(p, exp.Star) or (isinstance(p, exp.Column) and (p.is_star or isinstance(p.this, exp.Star)))
        for p in proj_exprs
    )

    alias_to_idx: dict[str, int] = {}
    sql_to_idx: dict[str, int] = {}
    col_to_idx: dict[str, int] = {}
    if not has_star and len(proj_exprs) == n_cols:
        for idx, proj in enumerate(proj_exprs):
            if isinstance(proj, exp.Alias):
                alias_to_idx[proj.alias.lower()] = idx
                inner = proj.this
                sql_to_idx.setdefault(inner.sql(dialect="sqlite").lower(), idx)
                if isinstance(inner, exp.Column) and not inner.table:
                    col_to_idx.setdefault(inner.name.lower(), idx)
            else:
                sql_to_idx.setdefault(proj.sql(dialect="sqlite").lower(), idx)
                if isinstance(proj, exp.Column):
                    col_to_idx.setdefault(proj.name.lower(), idx)

    key_idxs: list[int] = []
    for ord_item in order_node.expressions:
        ord_this = ord_item.this if isinstance(ord_item, exp.Ordered) else ord_item
        if isinstance(ord_this, exp.Literal) and ord_this.is_int:
            k = int(ord_this.this) - 1
            if 0 <= k < n_cols:
                key_idxs.append(k)
                continue
            return None
        if not has_star and len(proj_exprs) == n_cols:
            if isinstance(ord_this, exp.Column) and not ord_this.table:
                nm = ord_this.name.lower()
                if nm in alias_to_idx:
                    key_idxs.append(alias_to_idx[nm])
                    continue
                if nm in col_to_idx:
                    key_idxs.append(col_to_idx[nm])
                    continue
            rendered = ord_this.sql(dialect="sqlite").lower()
            if rendered in sql_to_idx:
                key_idxs.append(sql_to_idx[rendered])
                continue
        return None
    return key_idxs


def _extract_gold_tie_blocks(
    con: sqlite3.Connection,
    gold_sql: str,
    gold: QueryResult,
    *,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> tuple[list[list[tuple[Any, ...]]], bool] | None:
    """Extract ordered tie blocks `([block_0, ...], limit_cut_tie)` for `gold_sql` via `sqlglot`."""
    n_gold = len(gold.rows)
    if n_gold == 0:
        return [], False
    stmts, parse_err = check_parse(gold_sql)
    if parse_err or not stmts:
        return None
    stmt = stmts[0]
    order_node = stmt.args.get("order")
    if order_node is None or not order_node.expressions:
        return None

    n_proj = len(gold.rows[0])
    limit_node = stmt.args.get("limit")
    limit_val: int | None = None
    if limit_node is not None and isinstance(limit_node.expression, exp.Literal) and limit_node.expression.is_int:
        limit_val = int(limit_node.expression.this)
    may_hit_limit = limit_node is not None and (limit_val is None or n_gold == limit_val)
    probe_limit = min(max_rows, max(n_gold + 64, n_gold * 2)) if may_hit_limit else None

    direct_idxs = _resolve_order_by_projection_indices(stmt, order_node, n_proj)
    ext_proj_rows: list[tuple[Any, ...]]
    ext_sort_keys: list[tuple[Any, ...]]

    try:
        if direct_idxs is not None:
            if not may_hit_limit:
                ext_proj_rows = list(gold.rows)
            else:
                ext_stmt = stmt.copy()
                ext_stmt.set("limit", exp.Limit(expression=exp.Literal.number(probe_limit)))
                ext_res = run_query(
                    con,
                    ext_stmt.sql(dialect="sqlite"),
                    ordered=True,
                    max_vm_steps=max_vm_steps,
                    timeout_s=timeout_s,
                    max_rows=max_rows,
                    max_value_bytes=max_value_bytes,
                )
                ext_proj_rows = list(ext_res.rows)
            ext_sort_keys = [tuple(r[c] for c in direct_idxs) for r in ext_proj_rows]
        else:
            if not isinstance(stmt, exp.Select) or stmt.args.get("distinct") is not None:
                return None
            aug_stmt = stmt.copy()
            alias_to_expr: dict[str, exp.Expression] = {}
            for proj in stmt.expressions:
                if isinstance(proj, exp.Alias):
                    alias_to_expr[proj.alias.lower()] = proj.this

            for s_idx, ord_item in enumerate(order_node.expressions):
                raw_ord = (ord_item.this if isinstance(ord_item, exp.Ordered) else ord_item).copy()
                if isinstance(raw_ord, exp.Literal) and raw_ord.is_int:
                    ord_k = int(raw_ord.this) - 1
                    if 0 <= ord_k < len(stmt.expressions):
                        t_proj = stmt.expressions[ord_k]
                        raw_ord = (t_proj.this if isinstance(t_proj, exp.Alias) else t_proj).copy()

                def _subst_alias(node: exp.Expression) -> exp.Expression:
                    if isinstance(node, exp.Column) and not node.table:
                        nm = node.name.lower()
                        if nm in alias_to_expr:
                            return alias_to_expr[nm].copy()
                    return node

                resolved_ord = raw_ord.transform(_subst_alias)
                aug_stmt.expressions.append(exp.alias_(resolved_ord, f"__lv_sort_{s_idx}"))

            if may_hit_limit and probe_limit is not None:
                aug_stmt.set("limit", exp.Limit(expression=exp.Literal.number(probe_limit)))

            aug_res = run_query(
                con,
                aug_stmt.sql(dialect="sqlite"),
                ordered=True,
                max_vm_steps=max_vm_steps,
                timeout_s=timeout_s,
                max_rows=max_rows,
                max_value_bytes=max_value_bytes,
            )
            ext_proj_rows = [r[:n_proj] for r in aug_res.rows]
            ext_sort_keys = [r[n_proj:] for r in aug_res.rows]
    except (ExecutionLimitError, sqlite3.Error, sqlglot.errors.SqlglotError):
        return None

    if len(ext_proj_rows) < n_gold:
        return None

    limit_cut_tie = (
        may_hit_limit
        and len(ext_proj_rows) > n_gold
        and rows_equal(ext_sort_keys[n_gold - 1], ext_sort_keys[n_gold])
    )

    blocks: list[list[tuple[Any, ...]]] = []
    block_keys: list[tuple[Any, ...]] = []
    scan_limit = len(ext_proj_rows) if limit_cut_tie else n_gold
    for idx in range(scan_limit):
        p_row = ext_proj_rows[idx]
        s_key = ext_sort_keys[idx]
        if block_keys and rows_equal(s_key, block_keys[-1]):
            blocks[-1].append(p_row)
        else:
            if idx >= n_gold:
                break
            blocks.append([p_row])
            block_keys.append(s_key)

    return blocks, limit_cut_tie


def _compare_results_with_status(
    got: QueryResult,
    gold: QueryResult,
    *,
    con: sqlite3.Connection | None = None,
    gold_sql: str | None = None,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> tuple[str | None, str]:
    """Return `(error_or_none, pass_reason)` where `pass_reason` is `'match'` or `'ambiguous_gold'`."""
    nf_got = _has_nonfinite_float(got.rows)
    if nf_got:
        return nf_got, "match"
    nf_gold = _has_nonfinite_float(gold.rows)
    if nf_gold:
        return f"gold query produced {nf_gold}", "match"

    if got.columns and gold.columns and len(got.columns) != len(gold.columns):
        return f"column count {len(got.columns)} vs gold {len(gold.columns)}", "match"

    n_got, n_gold = len(got.rows), len(gold.rows)
    if n_got != n_gold:
        return f"{n_got} rows vs {n_gold} gold rows", "match"

    if n_got == 0:
        return None, "match"

    if gold.ordered:
        exact_match = all(rows_equal(r1, r2) for r1, r2 in zip(got.rows, gold.rows))
        if con is not None and gold_sql is not None:
            has_limit = "limit" in gold_sql.lower()
            if not exact_match or has_limit:
                tie_info = _extract_gold_tie_blocks(
                    con,
                    gold_sql,
                    gold,
                    max_vm_steps=max_vm_steps,
                    timeout_s=timeout_s,
                    max_rows=max_rows,
                    max_value_bytes=max_value_bytes,
                )
                if tie_info is not None:
                    blocks, limit_cut_tie = tie_info
                    if limit_cut_tie and blocks:
                        prefix_blocks = blocks[:-1]
                        boundary_block = blocks[-1]
                        offset = 0
                        prefix_ok = True
                        for blk in prefix_blocks:
                            seg = got.rows[offset : offset + len(blk)]
                            offset += len(blk)
                            if not _multiset_match(seg, blk)[0]:
                                prefix_ok = False
                                break
                        tail = got.rows[offset:n_got]
                        if prefix_ok and _submultiset_match(tail, boundary_block):
                            has_distinct_projections = any(
                                not rows_equal(r, boundary_block[0]) for r in boundary_block[1:]
                            )
                            if has_distinct_projections or not exact_match:
                                return None, "ambiguous_gold"
                            return None, "match"
                    elif not limit_cut_tie and not exact_match:
                        offset = 0
                        ties_ok = True
                        for blk in blocks:
                            seg = got.rows[offset : offset + len(blk)]
                            offset += len(blk)
                            if not _multiset_match(seg, blk)[0]:
                                ties_ok = False
                                break
                        if ties_ok and offset == n_got:
                            return None, "match"

        if exact_match:
            return None, "match"
        if n_got == 1:
            return f"value {got.rows[0]} vs gold {gold.rows[0]}", "match"
        for idx, (r_got, r_gold) in enumerate(zip(got.rows, gold.rows), 1):
            if not rows_equal(r_got, r_gold):
                ms_ok, diff_got, diff_gold = _multiset_match(got.rows, gold.rows)
                if ms_ok:
                    return f"row order mismatch ({n_got} rows): row {idx} {r_got} vs gold {r_gold}", "match"
                return f"row content mismatch ({n_got} rows): e.g. {diff_got} vs {diff_gold}", "match"
        return None, "match"

    if n_got == 1:
        if not rows_equal(got.rows[0], gold.rows[0]):
            return f"value {got.rows[0]} vs gold {gold.rows[0]}", "match"
        return None, "match"

    ms_ok, diff_got, diff_gold = _multiset_match(got.rows, gold.rows)
    if not ms_ok:
        return f"row content mismatch ({n_got} rows): e.g. {diff_got} vs {diff_gold}", "match"
    return None, "match"


def compare_results(
    got: QueryResult,
    gold: QueryResult,
    *,
    con: sqlite3.Connection | None = None,
    gold_sql: str | None = None,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> str | None:
    """Compare `got` vs `gold` enforcing column arity, non-finite guards, and tie-aware ordering/multiset match."""
    err, _ = _compare_results_with_status(
        got,
        gold,
        con=con,
        gold_sql=gold_sql,
        max_vm_steps=max_vm_steps,
        timeout_s=timeout_s,
        max_rows=max_rows,
        max_value_bytes=max_value_bytes,
    )
    return err


def run_query(
    con: sqlite3.Connection,
    sql: str,
    *,
    ordered: bool = False,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
    max_expr_depth: int = 100,
) -> QueryResult:
    """Execute read-only SQL under SQLite VM step budget, byte/depth limits, wall-clock timeout, and row cap."""
    tick_interval = min(100, max(1, max_vm_steps))
    max_callbacks = max(1, math.ceil(max_vm_steps / tick_interval))
    callbacks = 0
    t0 = time.monotonic()
    abort_reason: list[str] = []

    def _progress_cb() -> int:
        nonlocal callbacks
        callbacks += 1
        if callbacks > max_callbacks:
            abort_reason.append(f"exceeded SQLite VM budget ({max_vm_steps} steps)")
            return 1
        if (time.monotonic() - t0) > timeout_s:
            abort_reason.append(f"exceeded query timeout ({timeout_s:.2f}s)")
            return 1
        return 0

    saved_limits: list[tuple[int, int]] = []
    if hasattr(con, "setlimit"):
        limit_len_cat = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
        if limit_len_cat is not None and max_value_bytes > 0:
            try:
                prev_len = con.setlimit(limit_len_cat, max_value_bytes)
                saved_limits.append((limit_len_cat, prev_len))
            except sqlite3.Error:
                pass
        limit_expr_cat = getattr(sqlite3, "SQLITE_LIMIT_EXPR_DEPTH", None)
        if limit_expr_cat is not None and max_expr_depth > 0:
            try:
                prev_depth = con.setlimit(limit_expr_cat, max_expr_depth)
                saved_limits.append((limit_expr_cat, prev_depth))
            except sqlite3.Error:
                pass
    elif max_value_bytes > 0 and "recursive" in sql.lower():
        # Python 3.10 lacks sqlite3.Connection.setlimit; guard direct run_query() against recursive bombs
        stmts_fb, err_fb = check_parse(sql)
        if not err_fb and stmts_fb:
            for wc in stmts_fb[0].find_all(exp.With):
                if wc.args.get("recursive"):
                    for cte in wc.expressions:
                        cte_lc = (cte.alias or "").lower()
                        cte_body = cte.this.this if isinstance(cte.this, exp.Subquery) else cte.this
                        if isinstance(cte_body, exp.Union) and _ast_references_table(cte_body, cte_lc):
                            branches, _ = _flatten_union_branches(cte_body)
                            alias_obj = cte.args.get("alias")
                            explicit_cols = [
                                c.name.lower()
                                for c in (alias_obj.columns if alias_obj and alias_obj.columns else [])
                            ]
                            for rb in branches[1:]:
                                exp_err = _check_recursive_string_expansion(
                                    rb, cte.alias, cte_lc, explicit_cols
                                )
                                if exp_err:
                                    raise ExecutionLimitError(exp_err)

    con.set_progress_handler(_progress_cb, tick_interval)
    try:
        cur = con.execute(sql)
        cols = tuple(d[0] for d in (cur.description or ()))
        fetched = cur.fetchmany(max_rows + 1)
        if len(fetched) > max_rows:
            raise ExecutionLimitError(f"query exceeded max_rows cap ({max_rows})")
        for r_idx, row in enumerate(fetched, 1):
            for c_idx, val in enumerate(row, 1):
                if isinstance(val, str) and len(val.encode("utf-8")) > max_value_bytes:
                    raise ExecutionLimitError(
                        f"cell at row {r_idx}, col {c_idx} exceeded max_value_bytes ({max_value_bytes})"
                    )
                if isinstance(val, (bytes, bytearray)) and len(val) > max_value_bytes:
                    raise ExecutionLimitError(
                        f"blob at row {r_idx}, col {c_idx} exceeded max_value_bytes ({max_value_bytes})"
                    )
        rows = tuple(tuple(r) for r in fetched)
        return QueryResult(rows=rows, columns=cols, ordered=ordered)
    except sqlite3.DataError as exc:
        raise ExecutionLimitError(f"exceeded SQLite value size limit ({max_value_bytes} bytes): {exc}") from exc
    except sqlite3.OperationalError as exc:
        if abort_reason:
            raise ExecutionLimitError(abort_reason[0]) from exc
        err_lc = str(exc).lower()
        if "too big" in err_lc or "expression tree is too large" in err_lc:
            raise ExecutionLimitError(f"exceeded SQLite limit: {exc}") from exc
        raise
    finally:
        con.set_progress_handler(None, 0)
        for cat, prev_val in reversed(saved_limits):
            try:
                con.setlimit(cat, prev_val)
            except sqlite3.Error:
                pass


def run(
    con: sqlite3.Connection,
    sql: str,
    *,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> QueryResult:
    """Execute `sql` and detect whether `ORDER BY` is present on the outer query."""
    stmts, err = check_parse(sql)
    ordered = False
    if not err and stmts:
        ordered = stmts[0].args.get("order") is not None
    return run_query(
        con,
        sql,
        ordered=ordered,
        max_vm_steps=max_vm_steps,
        timeout_s=timeout_s,
        max_rows=max_rows,
        max_value_bytes=max_value_bytes,
    )


def gate(
    con: sqlite3.Connection,
    sql: Any,
    gold_result: QueryResult | Counter[tuple[Any, ...]] | Sequence[tuple[Any, ...]] | None = None,
    *,
    gold_sql: str | None = None,
    counterexample_cons: Sequence[sqlite3.Connection] | None = None,
    properties: Sequence[Callable[[QueryResult], str | None]] | None = None,
    schema: Mapping[str, Sequence[str]] | None = None,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
    allow_recursive_cte: bool = True,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> tuple[int | None, str]:
    """4-layer fail-fast default-deny SQL gate returning `(failed_layer_index | None, reason)`."""
    stmts, err = check_parse(sql)
    if err or stmts is None:
        return 0, err or "parse error"

    err = check_read_only(stmts)
    if err:
        return 1, err

    err = check_schema(
        stmts[0],
        schema=schema,
        strict_joins=strict_joins,
        allow_cross_join=allow_cross_join,
        allow_recursive_cte=allow_recursive_cte,
        raw_sql=str(sql),
    )
    if err:
        return 2, err

    cand_ordered = stmts[0].args.get("order") is not None
    try:
        got = run_query(
            con,
            str(sql),
            ordered=cand_ordered,
            max_vm_steps=max_vm_steps,
            timeout_s=timeout_s,
            max_rows=max_rows,
            max_value_bytes=max_value_bytes,
        )
    except ExecutionLimitError as exc:
        return 3, f"execution limit: {exc}"
    except sqlite3.Error as exc:
        return 3, f"sqlite error: {exc}"

    nf_err = _has_nonfinite_float(got.rows)
    if nf_err:
        return 3, nf_err

    pass_reason = "match"
    if gold_result is not None:
        gold_q = _coerce_gold(gold_result)
        cmp_err, pass_reason = _compare_results_with_status(
            got,
            gold_q,
            con=con,
            gold_sql=gold_sql,
            max_vm_steps=max_vm_steps,
            timeout_s=timeout_s,
            max_rows=max_rows,
            max_value_bytes=max_value_bytes,
        )
        if cmp_err:
            return 3, cmp_err

        if gold_sql and counterexample_cons:
            for idx, ce_con in enumerate(counterexample_cons, 1):
                try:
                    ce_gold = run(
                        ce_con,
                        gold_sql,
                        max_vm_steps=max_vm_steps,
                        timeout_s=timeout_s,
                        max_rows=max_rows,
                        max_value_bytes=max_value_bytes,
                    )
                    ce_got = run_query(
                        ce_con,
                        str(sql),
                        ordered=cand_ordered,
                        max_vm_steps=max_vm_steps,
                        timeout_s=timeout_s,
                        max_rows=max_rows,
                        max_value_bytes=max_value_bytes,
                    )
                except (ExecutionLimitError, sqlite3.Error) as exc:
                    return 3, f"counterexample db #{idx} error: {exc}"
                ce_err, _ = _compare_results_with_status(
                    ce_got,
                    ce_gold,
                    con=ce_con,
                    gold_sql=gold_sql,
                    max_vm_steps=max_vm_steps,
                    timeout_s=timeout_s,
                    max_rows=max_rows,
                    max_value_bytes=max_value_bytes,
                )
                if ce_err:
                    return 3, f"counterexample db #{idx} mismatch: {ce_err}"

    if properties:
        for prop in properties:
            p_err = prop(got)
            if p_err:
                return 3, p_err

    return None, pass_reason


def verify_sql(
    con: sqlite3.Connection,
    sql: Any,
    *,
    gold_sql: str | None = None,
    gold_result: QueryResult | None = None,
    counterexample_cons: Sequence[sqlite3.Connection] | None = None,
    properties: Sequence[Callable[[QueryResult], str | None]] | None = None,
    schema: Mapping[str, Sequence[str]] | None = None,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
    allow_recursive_cte: bool = True,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
    max_value_bytes: int = 1_048_576,
) -> VerifyVerdict:
    """Evaluate SQL through the 4-layer gate and return a unified `VerifyVerdict`."""
    resolved_gold = gold_result
    if resolved_gold is None and gold_sql is not None:
        g_stmts, g_parse_err = check_parse(gold_sql)
        if g_parse_err or g_stmts is None:
            g_reason = g_parse_err or "parse error"
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[0],
                reason=f"invalid gold query: {g_reason}",
                diagnostics=[f"gold failed layer 1 ({LAYERS[0]}): {g_reason}"],
            )
        g_ro_err = check_read_only(g_stmts)
        if g_ro_err:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[1],
                reason=f"invalid gold query: {g_ro_err}",
                diagnostics=[f"gold failed layer 2 ({LAYERS[1]}): {g_ro_err}"],
            )
        g_sch_err = check_schema(
            g_stmts[0],
            schema=schema,
            strict_joins=strict_joins,
            allow_cross_join=allow_cross_join,
            allow_recursive_cte=allow_recursive_cte,
            raw_sql=str(gold_sql),
        )
        if g_sch_err:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[2],
                reason=f"invalid gold query: {g_sch_err}",
                diagnostics=[f"gold failed layer 3 ({LAYERS[2]}): {g_sch_err}"],
            )
        try:
            resolved_gold = run_query(
                con,
                gold_sql,
                ordered=(g_stmts[0].args.get("order") is not None),
                max_vm_steps=max_vm_steps,
                timeout_s=timeout_s,
                max_rows=max_rows,
                max_value_bytes=max_value_bytes,
            )
        except ExecutionLimitError as exc:
            g_reason = f"execution limit: {exc}"
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[3],
                reason=f"invalid gold query: {g_reason}",
                diagnostics=[f"gold failed layer 4 ({LAYERS[3]}): {g_reason}"],
            )
        except sqlite3.Error as exc:
            g_reason = f"sqlite error: {exc}"
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[3],
                reason=f"invalid gold query: {g_reason}",
                diagnostics=[f"gold failed layer 4 ({LAYERS[3]}): {g_reason}"],
            )
        g_nf_err = _has_nonfinite_float(resolved_gold.rows)
        if g_nf_err:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[3],
                reason=f"invalid gold query: {g_nf_err}",
                diagnostics=[f"gold failed layer 4 ({LAYERS[3]}): {g_nf_err}"],
            )

    layer_idx, reason = gate(
        con,
        sql,
        resolved_gold,
        gold_sql=gold_sql,
        counterexample_cons=counterexample_cons,
        properties=properties,
        schema=schema,
        strict_joins=strict_joins,
        allow_cross_join=allow_cross_join,
        allow_recursive_cte=allow_recursive_cte,
        max_vm_steps=max_vm_steps,
        timeout_s=timeout_s,
        max_rows=max_rows,
        max_value_bytes=max_value_bytes,
    )
    if layer_idx is None:
        diag = (
            ["gold query LIMIT cuts through an ORDER BY tie block; candidate is a valid tie resolution"]
            if reason == "ambiguous_gold"
            else []
        )
        return VerifyVerdict(passed=True, layer=None, reason=reason, diagnostics=diag)
    layer_name = LAYERS[layer_idx]
    return VerifyVerdict(
        passed=False,
        layer=layer_name,
        reason=reason,
        diagnostics=[f"layer {layer_idx + 1} {layer_name}: {reason}"],
    )


class BatchGateEvaluator:
    """Memoized multi-candidate SQL evaluator deduplicating canonical ASTs and gold executions."""

    def __init__(
        self,
        con: sqlite3.Connection,
        *,
        counterexample_cons: Sequence[sqlite3.Connection] | None = None,
        schema: Mapping[str, Sequence[str]] | None = None,
        strict_joins: bool = True,
        allow_cross_join: bool = False,
        max_vm_steps: int = 100_000,
        timeout_s: float = 1.0,
        max_rows: int = 10_000,
        max_value_bytes: int = 1_048_576,
    ) -> None:
        self.con = con
        self.counterexample_cons = list(counterexample_cons or [])
        self.schema = introspect_sqlite_schema(con) if schema is None else schema
        self.strict_joins = strict_joins
        self.allow_cross_join = allow_cross_join
        self.max_vm_steps = max_vm_steps
        self.timeout_s = timeout_s
        self.max_rows = max_rows
        self.max_value_bytes = max_value_bytes
        self._gold_cache: dict[str, QueryResult] = {}
        self._verdict_cache: dict[tuple[str, str], tuple[int | None, str]] = {}
        self.cache_hits: int = 0

    def get_validated_gold(self, gold_sql: str) -> QueryResult:
        if gold_sql in self._gold_cache:
            return self._gold_cache[gold_sql]
        # Validate gold query through Layers 1-3 first before executing!
        pre_layer, pre_reason = gate(
            self.con,
            gold_sql,
            None,
            schema=self.schema,
            strict_joins=self.strict_joins,
            allow_cross_join=self.allow_cross_join,
            max_vm_steps=self.max_vm_steps,
            timeout_s=self.timeout_s,
            max_rows=self.max_rows,
            max_value_bytes=self.max_value_bytes,
        )
        if pre_layer is not None:
            raise ValueError(
                f"Gold SQL failed gate at layer {pre_layer + 1} ({LAYERS[pre_layer]}): {pre_reason}"
            )
        gold_res = run(
            self.con,
            gold_sql,
            max_vm_steps=self.max_vm_steps,
            timeout_s=self.timeout_s,
            max_rows=self.max_rows,
            max_value_bytes=self.max_value_bytes,
        )
        g_layer, g_reason = gate(
            self.con,
            gold_sql,
            gold_res,
            gold_sql=gold_sql,
            counterexample_cons=self.counterexample_cons,
            schema=self.schema,
            strict_joins=self.strict_joins,
            allow_cross_join=self.allow_cross_join,
            max_vm_steps=self.max_vm_steps,
            timeout_s=self.timeout_s,
            max_rows=self.max_rows,
            max_value_bytes=self.max_value_bytes,
        )
        if g_layer is not None:
            raise ValueError(
                f"Gold SQL failed gate at layer {g_layer + 1} ({LAYERS[g_layer]}): {g_reason}"
            )
        self._gold_cache[gold_sql] = gold_res
        return gold_res

    def evaluate_candidate(self, sql: str, gold_sql: str) -> tuple[int | None, str]:
        gold_res = self.get_validated_gold(gold_sql)
        stmts, parse_err = check_parse(sql)
        if parse_err or stmts is None:
            return 0, parse_err or "parse error"
        if len(stmts) == 1:
            canonical_key = (gold_sql, stmts[0].sql(dialect="sqlite"))
            if canonical_key in self._verdict_cache:
                self.cache_hits += 1
                return self._verdict_cache[canonical_key]
        else:
            canonical_key = None

        verdict = gate(
            self.con,
            sql,
            gold_res,
            gold_sql=gold_sql,
            counterexample_cons=self.counterexample_cons,
            schema=self.schema,
            strict_joins=self.strict_joins,
            allow_cross_join=self.allow_cross_join,
            max_vm_steps=self.max_vm_steps,
            timeout_s=self.timeout_s,
            max_rows=self.max_rows,
            max_value_bytes=self.max_value_bytes,
        )
        if canonical_key is not None:
            self._verdict_cache[canonical_key] = verdict
        return verdict


def validate_candidates_schema(items: Any) -> list[str]:
    """Validate `candidates.json` benchmark structure and unique `qid` invariant."""
    if not isinstance(items, list) or not items:
        return ["candidates benchmark must be a non-empty JSON list"]
    errors: list[str] = []
    seen_qids: set[int] = set()
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"item[{idx}] must be an object")
            continue
        allowed = {"qid", "question", "gold", "candidates"}
        missing = sorted(allowed - set(item.keys()))
        extra = sorted(set(item.keys()) - allowed)
        if missing:
            errors.append(f"item[{idx}] missing keys: {missing}")
            continue
        if extra:
            errors.append(f"item[{idx}] unexpected keys: {extra}")
        qid = item["qid"]
        if isinstance(qid, bool) or not isinstance(qid, int) or qid < 1:
            errors.append(f"item[{idx}] invalid qid: {qid!r}")
        elif qid in seen_qids:
            errors.append(f"duplicate qid: {qid}")
        else:
            seen_qids.add(qid)
        if not isinstance(item["question"], str) or not item["question"].strip():
            errors.append(f"qid {qid}: empty question")
        if not isinstance(item["gold"], str) or not item["gold"].strip():
            errors.append(f"qid {qid}: empty gold SQL")
        cands = item["candidates"]
        if not isinstance(cands, list) or not cands:
            errors.append(f"qid {qid}: candidates must be a non-empty list")
        else:
            for c_idx, cand in enumerate(cands):
                if not isinstance(cand, dict) or set(cand.keys()) != {"label", "sql"}:
                    errors.append(f"qid {qid} candidate[{c_idx}]: must have exact keys 'label' and 'sql'")
                    continue
                if not isinstance(cand["label"], str) or not cand["label"].strip():
                    errors.append(f"qid {qid} candidate[{c_idx}]: empty label")
                if not isinstance(cand["sql"], str) or not cand["sql"].strip():
                    errors.append(f"qid {qid} candidate[{c_idx}]: empty sql")
    return errors
