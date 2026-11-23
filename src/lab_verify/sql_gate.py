"""Hardened 4-layer default-deny SQL verification gate over laboratory databases."""

from __future__ import annotations

from collections import Counter
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
        last_calibrated TEXT
    )
    """,
    """
    CREATE TABLE experiments (
        id INTEGER PRIMARY KEY,
        date TEXT NOT NULL,
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


def lock_connection_readonly(con: sqlite3.Connection) -> sqlite3.Connection:
    """Apply defense-in-depth engine locks (`query_only`, no extensions, strict authorizer)."""
    con.set_authorizer(None)
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
    con.set_authorizer(None)
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

    return [
        _populate_synthetic_db(exps_1, samps_1, inst_1),
        _populate_synthetic_db(exps_2, samps_2, inst_2),
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
def check_schema(
    stmt: exp.Expression,
    schema: Mapping[str, Sequence[str]] | None = None,
    *,
    strict_joins: bool = True,
    allow_cross_join: bool = False,
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
    ) -> tuple[list[str] | None, str | None]:
        if isinstance(node, exp.Subquery):
            return _validate_query(node.this, cte_env, outer_sources)

        local_cte_env = dict(cte_env)
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
                if is_recursive:
                    if explicit_cols:
                        local_cte_env[cte_lc] = explicit_cols
                    elif isinstance(cte.this, exp.SetOperation):
                        base_cols, base_err = _validate_query(cte.this.this, local_cte_env, outer_sources)
                        if base_err:
                            return None, base_err
                        local_cte_env[cte_lc] = list(base_cols or [])
                cte_cols, cte_err = _validate_query(cte.this, local_cte_env, outer_sources)
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

        if isinstance(node, exp.SetOperation):
            left_cols, left_err = _validate_query(node.this, local_cte_env, outer_sources)
            if left_err:
                return None, left_err
            right_cols, right_err = _validate_query(node.expression, local_cte_env, outer_sources)
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
                return None

            if isinstance(src, exp.Subquery):
                sub_cols, sub_err = _validate_query(src.this, local_cte_env, outer_sources)
                if sub_err:
                    return sub_err
                bind_key = (src.alias or f"_subquery_{len(local_sources)}").lower()
                if src.alias and bind_key in local_sources:
                    return f"duplicate table alias {src.alias}"
                local_sources[bind_key] = (bind_key, list(sub_cols or []))
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

            on_expr = join.args.get("on")
            if strict_joins:
                has_using = bool(using_list)
                has_on = (
                    on_expr is not None
                    and not isinstance(on_expr, exp.Boolean)
                    and bool(list(on_expr.find_all(exp.Column)))
                )
                if not has_on and not has_using:
                    is_explicit_cross = (
                        str(join.args.get("kind", "")).upper() == "CROSS"
                        and bool(re.search(r"\bCROSS\s+JOIN\b", raw_sql, flags=re.IGNORECASE))
                    )
                    if not (allow_cross_join and is_explicit_cross):
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
                _, n_err = _validate_query(expr, local_cte_env, merged_outer)
                return n_err
            if isinstance(expr, exp.Subquery):
                merged_outer = dict(outer_sources)
                merged_outer.update(local_sources)
                _, n_err = _validate_query(expr.this, local_cte_env, merged_outer)
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
        return (2, round(fval, 5))
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


def _multiset_match(
    got_rows: Sequence[tuple[Any, ...]],
    gold_rows: Sequence[tuple[Any, ...]],
) -> tuple[bool, tuple[Any, ...] | None, tuple[Any, ...] | None]:
    if len(got_rows) != len(gold_rows):
        return False, None, None
    s_got = sorted(got_rows, key=_row_sort_key)
    s_gold = list(sorted(gold_rows, key=_row_sort_key))
    used = [False] * len(s_gold)
    for gr in s_got:
        matched_idx = -1
        for idx, gold_r in enumerate(s_gold):
            if not used[idx] and rows_equal(gr, gold_r):
                matched_idx = idx
                break
        if matched_idx == -1:
            first_unmatched_gold = next((s_gold[j] for j in range(len(s_gold)) if not used[j]), None)
            return False, gr, first_unmatched_gold
        used[matched_idx] = True
    return True, None, None


def compare_results(got: QueryResult, gold: QueryResult) -> str | None:
    """Compare `got` vs `gold` enforcing column arity, non-finite guards, and ordering/multiset match."""
    nf_got = _has_nonfinite_float(got.rows)
    if nf_got:
        return nf_got
    nf_gold = _has_nonfinite_float(gold.rows)
    if nf_gold:
        return f"gold query produced {nf_gold}"

    if got.columns and gold.columns and len(got.columns) != len(gold.columns):
        return f"column count {len(got.columns)} vs gold {len(gold.columns)}"

    n_got, n_gold = len(got.rows), len(gold.rows)
    if n_got != n_gold:
        return f"{n_got} rows vs {n_gold} gold rows"

    if n_got == 0:
        return None

    if n_got == 1:
        if not rows_equal(got.rows[0], gold.rows[0]):
            return f"value {got.rows[0]} vs gold {gold.rows[0]}"
        return None

    if gold.ordered:
        for idx, (r_got, r_gold) in enumerate(zip(got.rows, gold.rows), 1):
            if not rows_equal(r_got, r_gold):
                ms_ok, diff_got, diff_gold = _multiset_match(got.rows, gold.rows)
                if ms_ok:
                    return f"row order mismatch ({n_got} rows): row {idx} {r_got} vs gold {r_gold}"
                return f"row content mismatch ({n_got} rows): e.g. {diff_got} vs {diff_gold}"
        return None

    ms_ok, diff_got, diff_gold = _multiset_match(got.rows, gold.rows)
    if not ms_ok:
        return f"row content mismatch ({n_got} rows): e.g. {diff_got} vs {diff_gold}"
    return None


def run_query(
    con: sqlite3.Connection,
    sql: str,
    *,
    ordered: bool = False,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
) -> QueryResult:
    """Execute read-only SQL under SQLite VM step budget, wall-clock timeout, and row cap."""
    tick_interval = 1_000
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

    con.set_progress_handler(_progress_cb, tick_interval)
    try:
        cur = con.execute(sql)
        cols = tuple(d[0] for d in (cur.description or ()))
        fetched = cur.fetchmany(max_rows + 1)
        if len(fetched) > max_rows:
            raise ExecutionLimitError(f"query exceeded max_rows cap ({max_rows})")
        rows = tuple(tuple(r) for r in fetched)
        return QueryResult(rows=rows, columns=cols, ordered=ordered)
    except sqlite3.OperationalError as exc:
        if abort_reason:
            raise ExecutionLimitError(abort_reason[0]) from exc
        raise
    finally:
        con.set_progress_handler(None, 0)


def run(
    con: sqlite3.Connection,
    sql: str,
    *,
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
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
    max_vm_steps: int = 100_000,
    timeout_s: float = 1.0,
    max_rows: int = 10_000,
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
        )
    except ExecutionLimitError as exc:
        return 3, f"execution limit: {exc}"
    except sqlite3.Error as exc:
        return 3, f"sqlite error: {exc}"

    nf_err = _has_nonfinite_float(got.rows)
    if nf_err:
        return 3, nf_err

    if gold_result is not None:
        gold_q = _coerce_gold(gold_result)
        cmp_err = compare_results(got, gold_q)
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
                    )
                    ce_got = run_query(
                        ce_con,
                        str(sql),
                        ordered=cand_ordered,
                        max_vm_steps=max_vm_steps,
                        timeout_s=timeout_s,
                        max_rows=max_rows,
                    )
                except (ExecutionLimitError, sqlite3.Error) as exc:
                    return 3, f"counterexample db #{idx} error: {exc}"
                ce_err = compare_results(ce_got, ce_gold)
                if ce_err:
                    return 3, f"counterexample db #{idx} mismatch: {ce_err}"

    if properties:
        for prop in properties:
            p_err = prop(got)
            if p_err:
                return 3, p_err

    return None, "match"


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
) -> VerifyVerdict:
    """Evaluate SQL through the 4-layer gate and return a unified `VerifyVerdict`."""
    resolved_gold = gold_result
    if resolved_gold is None and gold_sql is not None:
        g_layer, g_reason = gate(
            con,
            gold_sql,
            None,
            schema=schema,
            strict_joins=strict_joins,
            allow_cross_join=allow_cross_join,
        )
        if g_layer is not None:
            return VerifyVerdict(
                passed=False,
                layer=LAYERS[g_layer],
                reason=f"invalid gold query: {g_reason}",
                diagnostics=[f"gold failed layer {g_layer + 1} ({LAYERS[g_layer]}): {g_reason}"],
            )
        resolved_gold = run(con, gold_sql)

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
    )
    if layer_idx is None:
        return VerifyVerdict(passed=True, layer=None, reason="match", diagnostics=[])
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
    ) -> None:
        self.con = con
        self.counterexample_cons = list(counterexample_cons or [])
        self.schema = introspect_sqlite_schema(con) if schema is None else schema
        self.strict_joins = strict_joins
        self.allow_cross_join = allow_cross_join
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
        )
        if pre_layer is not None:
            raise ValueError(
                f"Gold SQL failed gate at layer {pre_layer + 1} ({LAYERS[pre_layer]}): {pre_reason}"
            )
        gold_res = run(self.con, gold_sql)
        g_layer, g_reason = gate(
            self.con,
            gold_sql,
            gold_res,
            gold_sql=gold_sql,
            counterexample_cons=self.counterexample_cons,
            schema=self.schema,
            strict_joins=self.strict_joins,
            allow_cross_join=self.allow_cross_join,
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
