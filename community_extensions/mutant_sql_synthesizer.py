"""Idea #13: Adversarial Counterexample SQLite DB Synthesizer.

Inspired by BenchBench-Protocol (arXiv:2608.23898). Evaluating LLM-generated laboratory
SQL queries against a single clean seed SQLite database allows subtle semantic bugs
(missing DISTINCT under 1:N joins, INNER vs LEFT JOIN on empty strata, SUM/COUNT(*) vs
AVG NULL traps, != dropping NULLs, < vs <= boundary off-by-ones, missing ORDER BY
tie-breakers, and case-sensitive string predicates) to slip through undetected whenever
the seed DB happens to be 1-to-1, non-null, and uniquely valued.

Given any clean SQLite seed database, `synthesize_five_sqlite_mutants` introspects
`sqlite_master`, `PRAGMA table_info`, and `PRAGMA foreign_key_list` to automatically
generate 5 targeted in-memory SQLite counterexample mutants, locking every database
with a strict read-only SQLite authorizer before executing candidate SQL.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any

_SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from lab_verify.sql_gate import (  # noqa: E402
    FORBIDDEN_SQLITE_FUNCTIONS,
    ExecutionLimitError,
    compare_results,
    run,
)

ALLOWED_READONLY_ACTIONS: frozenset[int] = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
    | ({getattr(sqlite3, "SQLITE_RECURSIVE")} if hasattr(sqlite3, "SQLITE_RECURSIVE") else set())
)


def _readonly_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    dbname: str | None,
    source: str | None,
) -> int:
    _ = (dbname, source)
    if action not in ALLOWED_READONLY_ACTIONS:
        return sqlite3.SQLITE_DENY
    if arg1 and arg1.lower().startswith("sqlite_"):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and arg2:
        fn = arg2.lower()
        if fn in FORBIDDEN_SQLITE_FUNCTIONS or fn.startswith("pragma_"):
            return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


@dataclass(frozen=True)
class ColumnMeta:
    name: str
    col_type: str
    notnull: bool
    is_pk: bool


@dataclass(frozen=True)
class ForeignKeyMeta:
    from_col: str
    ref_table: str
    ref_col: str


@dataclass(frozen=True)
class TableMeta:
    name: str
    create_sql: str
    columns: tuple[ColumnMeta, ...]
    foreign_keys: tuple[ForeignKeyMeta, ...]
    rows: tuple[tuple[Any, ...], ...]


@dataclass(frozen=True)
class SqlBenchmarkCandidate:
    """Candidate SQL query paired with its gold reference SQL and ground-truth label."""

    candidate_id: str
    task_name: str
    candidate_sql: str
    gold_sql: str
    is_semantically_equivalent: bool
    bug_category: str


@dataclass(frozen=True)
class MutantGateVerdict:
    """Comparison outcome across the seed DB and all 5 synthesized mutant DBs."""

    passed_seed_db: bool
    passed_all_mutants: bool
    failing_mutants: tuple[str, ...]
    error_detail: str | None = None


def _introspect_seed_db(seed_conn: sqlite3.Connection) -> list[TableMeta]:
    cur = seed_conn.cursor()
    tbl_rows = cur.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    tables: list[TableMeta] = []
    for tbl_name, create_sql in tbl_rows:
        col_info = cur.execute(f'PRAGMA table_info("{tbl_name}")').fetchall()
        cols = tuple(
            ColumnMeta(
                name=str(c[1]),
                col_type=str(c[2] or "").upper(),
                notnull=bool(c[3]),
                is_pk=bool(c[5]),
            )
            for c in col_info
        )
        fk_info = cur.execute(f'PRAGMA foreign_key_list("{tbl_name}")').fetchall()
        fks = tuple(
            ForeignKeyMeta(from_col=str(f[3]), ref_table=str(f[2]), ref_col=str(f[4]))
            for f in fk_info
        )
        data_rows = tuple(cur.execute(f'SELECT * FROM "{tbl_name}"').fetchall())
        tables.append(
            TableMeta(
                name=tbl_name,
                create_sql=str(create_sql),
                columns=cols,
                foreign_keys=fks,
                rows=data_rows,
            )
        )
    return tables


def _topological_tables(tables: list[TableMeta]) -> list[TableMeta]:
    by_name = {t.name: t for t in tables}
    visited: set[str] = set()
    ordered: list[TableMeta] = []

    def _visit(name: str) -> None:
        if name in visited or name not in by_name:
            return
        visited.add(name)
        for fk in by_name[name].foreign_keys:
            if fk.ref_table != name:
                _visit(fk.ref_table)
        ordered.append(by_name[name])

    for t in tables:
        _visit(t.name)
    return ordered


def _clone_tables_into_memory(tables: list[TableMeta]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    for t in tables:
        conn.execute(t.create_sql)
    for t in tables:
        if t.rows:
            placeholders = ", ".join("?" for _ in t.columns)
            conn.executemany(f'INSERT INTO "{t.name}" VALUES ({placeholders})', t.rows)
    conn.commit()
    return conn


def _next_int_pk(conn: sqlite3.Connection, table: TableMeta, pk_col: str) -> int:
    val = conn.execute(f'SELECT COALESCE(MAX("{pk_col}"), 0) FROM "{table.name}"').fetchone()[0]
    return int(val) + 1


def _insert_row_dict(conn: sqlite3.Connection, table: TableMeta, row_map: dict[str, Any]) -> None:
    cols = [c.name for c in table.columns]
    placeholders = ", ".join("?" for _ in cols)
    values = tuple(row_map[c] for c in cols)
    conn.execute(f'INSERT INTO "{table.name}" VALUES ({placeholders})', values)


def synthesize_five_sqlite_mutants(
    seed_conn: sqlite3.Connection,
    *,
    lock_readonly: bool = True,
) -> dict[str, sqlite3.Connection]:
    """Synthesize 5 adversarial SQLite mutants from a clean seed connection via schema introspection."""
    tables = _topological_tables(_introspect_seed_db(seed_conn))
    fk_tables = [t for t in tables if t.foreign_keys and t.rows]
    root_tables = [t for t in tables if not t.foreign_keys and t.rows]

    mutants: dict[str, sqlite3.Connection] = {}

    # Mutant 1: Duplicate foreign-key child rows (exposes missing DISTINCT & join fan-out SUM/COUNT)
    m1 = _clone_tables_into_memory(tables)
    for t in fk_tables:
        pk_cols = [c.name for c in t.columns if c.is_pk]
        if len(pk_cols) == 1:
            pk = pk_cols[0]
            base = dict(zip((c.name for c in t.columns), t.rows[0]))
            base[pk] = _next_int_pk(m1, t, pk)
            _insert_row_dict(m1, t, base)
    m1.commit()
    mutants["mutant_1_duplicate_join_keys"] = m1

    # Mutant 2: NULL measurement & status cells (exposes AVG vs SUM/COUNT(*), != NULL traps)
    m2 = _clone_tables_into_memory(tables)
    new_fk_ids: dict[tuple[str, str], Any] = {}
    for t in tables:
        if not t.rows:
            continue
        pk_cols = [c.name for c in t.columns if c.is_pk]
        nullable_cols = [c for c in t.columns if not c.notnull and not c.is_pk]
        fk_col_names = {fk.from_col for fk in t.foreign_keys}
        if len(pk_cols) == 1 and (nullable_cols or t.foreign_keys):
            pk = pk_cols[0]
            row_map = dict(zip((c.name for c in t.columns), t.rows[-1]))
            new_id = _next_int_pk(m2, t, pk)
            row_map[pk] = new_id
            for fk in t.foreign_keys:
                if (fk.ref_table, fk.ref_col) in new_fk_ids:
                    row_map[fk.from_col] = new_fk_ids[(fk.ref_table, fk.ref_col)]
            for c in t.columns:
                if c.is_pk or c.name in fk_col_names:
                    continue
                if not c.notnull:
                    row_map[c.name] = None
                elif "CHAR" in c.col_type or "TEXT" in c.col_type:
                    row_map[c.name] = f"{row_map[c.name]}_NULLPROBE"
            _insert_row_dict(m2, t, row_map)
            new_fk_ids[(t.name, pk)] = new_id
    m2.commit()
    mutants["mutant_2_null_measurement_cells"] = m2

    # Mutant 3: Exact boundary & tie-breaking rows (exposes < vs <= and missing ORDER BY tie-breaks)
    m3 = _clone_tables_into_memory(tables)
    # Gather threshold-like REAL values from root/parent tables
    parent_reals: list[float] = []
    for rt in root_tables:
        for c_idx, c in enumerate(rt.columns):
            if "REAL" in c.col_type or "NUM" in c.col_type or "FLOAT" in c.col_type:
                for r in rt.rows:
                    if isinstance(r[c_idx], (int, float)):
                        parent_reals.append(float(r[c_idx]))
    boundary_val = parent_reals[0] if parent_reals else 100.0

    # Insert two rows into child entity -> leaf chain: one at exact boundary_val, one tying row[0]
    if fk_tables:
        leaf_tbl = fk_tables[-1]
        mid_tbl = fk_tables[0] if len(fk_tables) > 1 else None
        for tag, target_val in (("CMP-05-BOUND", boundary_val), ("CMP-00-TIE", None)):
            created_mid_pk: Any = None
            if mid_tbl is not None:
                m_pk = [c.name for c in mid_tbl.columns if c.is_pk][0]
                m_row = dict(zip((c.name for c in mid_tbl.columns), mid_tbl.rows[0]))
                created_mid_pk = _next_int_pk(m3, mid_tbl, m_pk)
                m_row[m_pk] = created_mid_pk
                fk_names = {fk.from_col for fk in mid_tbl.foreign_keys}
                for c in mid_tbl.columns:
                    if not c.is_pk and c.name not in fk_names and "TEXT" in c.col_type:
                        if str(m_row[c.name]).isupper() and len(str(m_row[c.name])) <= 8 and "-" not in str(m_row[c.name]):
                            continue
                        m_row[c.name] = tag
                _insert_row_dict(m3, mid_tbl, m_row)

            l_pk = [c.name for c in leaf_tbl.columns if c.is_pk][0]
            l_row = dict(zip((c.name for c in leaf_tbl.columns), leaf_tbl.rows[0]))
            l_row[l_pk] = _next_int_pk(m3, leaf_tbl, l_pk)
            if mid_tbl is not None and created_mid_pk is not None:
                for fk in leaf_tbl.foreign_keys:
                    if fk.ref_table == mid_tbl.name:
                        l_row[fk.from_col] = created_mid_pk
            if target_val is not None:
                for c in leaf_tbl.columns:
                    if not c.is_pk and ("REAL" in c.col_type or "FLOAT" in c.col_type or "NUM" in c.col_type):
                        l_row[c.name] = target_val
            _insert_row_dict(m3, leaf_tbl, l_row)
    m3.commit()
    mutants["mutant_3_tie_breaking_rows"] = m3

    # Mutant 4: Empty group strata / childless parent entities (exposes INNER vs LEFT JOIN)
    m4 = _clone_tables_into_memory(tables)
    referenced_tables = {fk.ref_table for t in tables for fk in t.foreign_keys}
    for t in tables:
        if t.name in referenced_tables and t.rows:
            pk_cols = [c.name for c in t.columns if c.is_pk]
            if len(pk_cols) == 1:
                pk = pk_cols[0]
                orphan_parent = dict(zip((c.name for c in t.columns), t.rows[0]))
                orphan_parent[pk] = _next_int_pk(m4, t, pk)
                fk_names = {fk.from_col for fk in t.foreign_keys}
                for c in t.columns:
                    if not c.is_pk and c.name not in fk_names and "TEXT" in c.col_type:
                        orphan_parent[c.name] = f"EMPTY_STRATA_{orphan_parent[pk]}"
                _insert_row_dict(m4, t, orphan_parent)
    m4.commit()
    mutants["mutant_4_empty_group_strata"] = m4

    # Mutant 5: Case and whitespace categorical variants (exposes case-fragile string filters)
    m5 = _clone_tables_into_memory(tables)
    case_parent_ids: dict[tuple[str, str], Any] = {}
    for t in fk_tables:
        pk_cols = [c.name for c in t.columns if c.is_pk]
        if len(pk_cols) == 1:
            pk = pk_cols[0]
            variant = dict(zip((c.name for c in t.columns), t.rows[0]))
            new_pk = _next_int_pk(m5, t, pk)
            variant[pk] = new_pk
            fk_names = {fk.from_col for fk in t.foreign_keys}
            for fk in t.foreign_keys:
                if (fk.ref_table, fk.ref_col) in case_parent_ids:
                    variant[fk.from_col] = case_parent_ids[(fk.ref_table, fk.ref_col)]
            for c in t.columns:
                if c.is_pk or c.name in fk_names:
                    continue
                if "TEXT" in c.col_type and isinstance(variant[c.name], str):
                    s_val = variant[c.name]
                    if "-" in s_val:
                        variant[c.name] = f"{s_val}-CASE"
                    else:
                        variant[c.name] = s_val.lower()
                elif "REAL" in c.col_type and isinstance(variant[c.name], (int, float)):
                    variant[c.name] = float(variant[c.name]) - 15.0
            _insert_row_dict(m5, t, variant)
            case_parent_ids[(t.name, pk)] = new_pk
    m5.commit()
    mutants["mutant_5_case_variants"] = m5

    if lock_readonly:
        for conn in mutants.values():
            conn.set_authorizer(_readonly_authorizer)

    return mutants


def evaluate_sql_against_mutants(
    candidate_sql: str,
    gold_sql: str,
    seed_conn: sqlite3.Connection,
    mutants: dict[str, sqlite3.Connection],
) -> MutantGateVerdict:
    """Compare candidate_sql against gold_sql on the clean seed DB and all 5 mutants via Layer-4 AST/bipartite gate."""
    try:
        gold_seed = run(seed_conn, gold_sql)
        cand_seed = run(seed_conn, candidate_sql)
    except (ExecutionLimitError, sqlite3.Error) as exc:
        return MutantGateVerdict(False, False, ("seed_execution_error",), str(exc))

    seed_err = compare_results(cand_seed, gold_seed)
    if seed_err is not None:
        return MutantGateVerdict(False, False, ("seed_db_mismatch",), seed_err)

    failing: list[str] = []
    for m_name, m_conn in mutants.items():
        try:
            gold_res = run(m_conn, gold_sql)
            cand_res = run(m_conn, candidate_sql)
        except (ExecutionLimitError, sqlite3.Error) as exc:
            return MutantGateVerdict(True, False, (m_name,), str(exc))
        if compare_results(cand_res, gold_res) is not None:
            failing.append(m_name)

    return MutantGateVerdict(
        passed_seed_db=True,
        passed_all_mutants=(len(failing) == 0),
        failing_mutants=tuple(failing),
        error_detail=None,
    )


def build_clean_lims_seed_db(*, lock_readonly: bool = False) -> sqlite3.Connection:
    """Create a clean LIMS assay database where all rows are 1:1:1, non-null, and uppercase."""
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE plates (
            plate_id INTEGER PRIMARY KEY,
            campaign TEXT NOT NULL,
            target_thresh REAL NOT NULL
        );
        CREATE TABLE samples (
            sample_id INTEGER PRIMARY KEY,
            plate_id INTEGER NOT NULL REFERENCES plates(plate_id),
            compound_code TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE readouts (
            readout_id INTEGER PRIMARY KEY,
            sample_id INTEGER NOT NULL REFERENCES samples(sample_id),
            signal_rfu REAL,
            qc_flag TEXT
        );
        INSERT INTO plates VALUES
            (1, 'KinaseA', 100.0),
            (2, 'KinaseA', 100.0),
            (3, 'ProteaseB', 100.0);
        INSERT INTO samples VALUES
            (10, 1, 'CMP-01', 'TEST'),
            (20, 2, 'CMP-02', 'TEST'),
            (30, 3, 'CMP-03', 'CONTROL');
        INSERT INTO readouts VALUES
            (100, 10, 145.0, 'PASS'),
            (200, 20, 82.0, 'PASS'),
            (300, 30, 210.0, 'PASS');
        """
    )
    conn.commit()
    if lock_readonly:
        conn.set_authorizer(_readonly_authorizer)
    return conn


def _build_24_sql_candidates() -> list[SqlBenchmarkCandidate]:
    """6 gold SQL queries + 18 subtle semantic-bug SQL queries that pass on the clean seed DB."""
    g1 = (
        "SELECT p.plate_id, COUNT(DISTINCT s.sample_id) AS n_samples "
        "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
        "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "GROUP BY p.plate_id ORDER BY p.plate_id"
    )
    g2 = (
        "SELECT p.campaign, COALESCE(AVG(r.signal_rfu), 0.0) AS mean_rfu "
        "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
        "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "GROUP BY p.campaign ORDER BY p.campaign"
    )
    g3 = (
        "SELECT s.compound_code, MAX(r.signal_rfu) AS peak_rfu "
        "FROM samples s JOIN plates p ON s.plate_id = p.plate_id "
        "JOIN readouts r ON s.sample_id = r.sample_id "
        "WHERE UPPER(TRIM(r.qc_flag)) = 'PASS' AND r.signal_rfu >= p.target_thresh "
        "GROUP BY s.compound_code ORDER BY peak_rfu DESC, s.compound_code ASC"
    )
    g4 = (
        "SELECT DISTINCT s.sample_id, s.compound_code "
        "FROM samples s LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "WHERE r.qc_flag IS NULL OR UPPER(r.qc_flag) != 'FAIL' "
        "ORDER BY s.sample_id"
    )
    g5 = (
        "SELECT s.compound_code, MAX(r.signal_rfu) AS best_rfu "
        "FROM samples s JOIN readouts r ON s.sample_id = r.sample_id "
        "WHERE UPPER(s.role) = 'TEST' AND r.signal_rfu IS NOT NULL "
        "GROUP BY s.compound_code ORDER BY best_rfu DESC, s.compound_code ASC LIMIT 2"
    )
    g6 = (
        "SELECT p.plate_id, "
        "COUNT(DISTINCT CASE WHEN r.signal_rfu >= 80.0 THEN s.compound_code END) AS n_qual "
        "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
        "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
        "GROUP BY p.plate_id ORDER BY p.plate_id"
    )

    return [
        # Task 1 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q01-GOLD", "plate_sample_counts", g1, g1, True, "gold"),
        SqlBenchmarkCandidate(
            "Q02-BUG-COUNT-NO-DISTINCT",
            "plate_sample_counts",
            "SELECT p.plate_id, COUNT(s.sample_id) AS n_samples "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g1,
            False,
            "count_vs_count_distinct",
        ),
        SqlBenchmarkCandidate(
            "Q03-BUG-INNER-JOIN",
            "plate_sample_counts",
            "SELECT p.plate_id, COUNT(DISTINCT s.sample_id) AS n_samples "
            "FROM plates p INNER JOIN samples s ON p.plate_id = s.plate_id "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g1,
            False,
            "inner_vs_left_join",
        ),
        SqlBenchmarkCandidate(
            "Q04-BUG-COUNT-STAR",
            "plate_sample_counts",
            "SELECT p.plate_id, COUNT(*) AS n_samples "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g1,
            False,
            "count_star_on_left_join",
        ),
        # Task 2 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q05-GOLD", "campaign_mean_rfu", g2, g2, True, "gold"),
        SqlBenchmarkCandidate(
            "Q06-BUG-SUM-DIV-COUNT-STAR",
            "campaign_mean_rfu",
            "SELECT p.campaign, COALESCE(SUM(r.signal_rfu) / COUNT(*), 0.0) AS mean_rfu "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.campaign ORDER BY p.campaign",
            g2,
            False,
            "avg_null_denominator_trap",
        ),
        SqlBenchmarkCandidate(
            "Q07-BUG-CAMPAIGN-INNER-JOIN",
            "campaign_mean_rfu",
            "SELECT p.campaign, AVG(r.signal_rfu) AS mean_rfu "
            "FROM plates p JOIN samples s ON p.plate_id = s.plate_id "
            "JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.campaign ORDER BY p.campaign",
            g2,
            False,
            "inner_vs_left_join",
        ),
        SqlBenchmarkCandidate(
            "Q08-BUG-AVG-COALESCE-ZERO",
            "campaign_mean_rfu",
            "SELECT p.campaign, AVG(COALESCE(r.signal_rfu, 0.0)) AS mean_rfu "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.campaign ORDER BY p.campaign",
            g2,
            False,
            "avg_coalesce_null_as_zero",
        ),
        # Task 3 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q09-GOLD", "active_hits_above_thresh", g3, g3, True, "gold"),
        SqlBenchmarkCandidate(
            "Q10-BUG-STRICT-GT-BOUNDARY",
            "active_hits_above_thresh",
            "SELECT s.compound_code, MAX(r.signal_rfu) AS peak_rfu "
            "FROM samples s JOIN plates p ON s.plate_id = p.plate_id "
            "JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE UPPER(TRIM(r.qc_flag)) = 'PASS' AND r.signal_rfu > p.target_thresh "
            "GROUP BY s.compound_code ORDER BY peak_rfu DESC, s.compound_code ASC",
            g3,
            False,
            "strict_gt_boundary_off_by_one",
        ),
        SqlBenchmarkCandidate(
            "Q11-BUG-CASE-SENSITIVE-QC",
            "active_hits_above_thresh",
            "SELECT s.compound_code, MAX(r.signal_rfu) AS peak_rfu "
            "FROM samples s JOIN plates p ON s.plate_id = p.plate_id "
            "JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE r.qc_flag = 'PASS' AND r.signal_rfu >= p.target_thresh "
            "GROUP BY s.compound_code ORDER BY peak_rfu DESC, s.compound_code ASC",
            g3,
            False,
            "case_sensitive_predicate",
        ),
        SqlBenchmarkCandidate(
            "Q12-BUG-MISSING-TIE-BREAKER",
            "active_hits_above_thresh",
            "SELECT s.compound_code, MAX(r.signal_rfu) AS peak_rfu "
            "FROM samples s JOIN plates p ON s.plate_id = p.plate_id "
            "JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE UPPER(TRIM(r.qc_flag)) = 'PASS' AND r.signal_rfu >= p.target_thresh "
            "GROUP BY s.compound_code ORDER BY peak_rfu DESC",
            g3,
            False,
            "tie_breaking_order_bug",
        ),
        # Task 4 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q13-GOLD", "non_failed_samples", g4, g4, True, "gold"),
        SqlBenchmarkCandidate(
            "Q14-BUG-NEQ-DROPS-NULL",
            "non_failed_samples",
            "SELECT DISTINCT s.sample_id, s.compound_code "
            "FROM samples s LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE r.qc_flag != 'FAIL' ORDER BY s.sample_id",
            g4,
            False,
            "three_valued_null_neq_trap",
        ),
        SqlBenchmarkCandidate(
            "Q15-BUG-MISSING-DISTINCT",
            "non_failed_samples",
            "SELECT s.sample_id, s.compound_code "
            "FROM samples s LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE r.qc_flag IS NULL OR UPPER(r.qc_flag) != 'FAIL' "
            "ORDER BY s.sample_id",
            g4,
            False,
            "missing_distinct_on_join",
        ),
        SqlBenchmarkCandidate(
            "Q16-BUG-INNER-JOIN-READOUTS",
            "non_failed_samples",
            "SELECT DISTINCT s.sample_id, s.compound_code "
            "FROM samples s INNER JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE r.qc_flag IS NULL OR UPPER(r.qc_flag) != 'FAIL' "
            "ORDER BY s.sample_id",
            g4,
            False,
            "inner_vs_left_join",
        ),
        # Task 5 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q17-GOLD", "top2_test_compounds", g5, g5, True, "gold"),
        SqlBenchmarkCandidate(
            "Q18-BUG-CASE-SENSITIVE-ROLE",
            "top2_test_compounds",
            "SELECT s.compound_code, MAX(r.signal_rfu) AS best_rfu "
            "FROM samples s JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE s.role = 'TEST' AND r.signal_rfu IS NOT NULL "
            "GROUP BY s.compound_code ORDER BY best_rfu DESC, s.compound_code ASC LIMIT 2",
            g5,
            False,
            "case_sensitive_predicate",
        ),
        SqlBenchmarkCandidate(
            "Q19-BUG-INVERTED-TIE-LIMIT",
            "top2_test_compounds",
            "SELECT s.compound_code, MAX(r.signal_rfu) AS best_rfu "
            "FROM samples s JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE UPPER(s.role) = 'TEST' AND r.signal_rfu IS NOT NULL "
            "GROUP BY s.compound_code ORDER BY best_rfu DESC, s.compound_code DESC LIMIT 2",
            g5,
            False,
            "tie_breaking_order_bug",
        ),
        SqlBenchmarkCandidate(
            "Q20-BUG-SUM-INSTEAD-OF-MAX",
            "top2_test_compounds",
            "SELECT s.compound_code, SUM(r.signal_rfu) AS best_rfu "
            "FROM samples s JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE UPPER(s.role) = 'TEST' AND r.signal_rfu IS NOT NULL "
            "GROUP BY s.compound_code ORDER BY best_rfu DESC, s.compound_code ASC LIMIT 2",
            g5,
            False,
            "sum_fanout_vs_max",
        ),
        # Task 6 (1 gold + 3 bugs)
        SqlBenchmarkCandidate("Q21-GOLD", "qualified_compounds_per_plate", g6, g6, True, "gold"),
        SqlBenchmarkCandidate(
            "Q22-BUG-CASE-COUNT-NO-DISTINCT",
            "qualified_compounds_per_plate",
            "SELECT p.plate_id, "
            "COUNT(CASE WHEN r.signal_rfu >= 80.0 THEN s.compound_code END) AS n_qual "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g6,
            False,
            "count_vs_count_distinct",
        ),
        SqlBenchmarkCandidate(
            "Q23-BUG-WHERE-KILLS-LEFT-JOIN",
            "qualified_compounds_per_plate",
            "SELECT p.plate_id, COUNT(DISTINCT s.compound_code) AS n_qual "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "WHERE r.signal_rfu >= 80.0 "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g6,
            False,
            "where_clause_nullifies_left_join",
        ),
        SqlBenchmarkCandidate(
            "Q24-BUG-NULL-TREATED-QUALIFIED",
            "qualified_compounds_per_plate",
            "SELECT p.plate_id, "
            "COUNT(DISTINCT CASE WHEN r.signal_rfu IS NULL OR r.signal_rfu >= 80.0 "
            "THEN s.compound_code END) AS n_qual "
            "FROM plates p LEFT JOIN samples s ON p.plate_id = s.plate_id "
            "LEFT JOIN readouts r ON s.sample_id = r.sample_id "
            "GROUP BY p.plate_id ORDER BY p.plate_id",
            g6,
            False,
            "null_measurement_misclassified",
        ),
    ]


def run_benchmark() -> dict[str, Any]:
    """Compare single_seed_db vs mutant_db_gate across 24 gold/buggy SQL candidates."""
    raw_seed = build_clean_lims_seed_db(lock_readonly=False)
    mutants = synthesize_five_sqlite_mutants(raw_seed, lock_readonly=True)
    raw_seed.set_authorizer(_readonly_authorizer)

    candidates = _build_24_sql_candidates()
    assert len(candidates) == 24

    gold_total = sum(1 for c in candidates if c.is_semantically_equivalent)
    buggy_total = sum(1 for c in candidates if not c.is_semantically_equivalent)

    seed_caught_bugs = 0
    seed_accepted_gold = 0
    mutant_caught_bugs = 0
    mutant_accepted_gold = 0
    catches_per_mutant: dict[str, int] = {m: 0 for m in mutants}

    try:
        for cand in candidates:
            verdict = evaluate_sql_against_mutants(
                cand.candidate_sql, cand.gold_sql, raw_seed, mutants
            )
            if cand.is_semantically_equivalent:
                if verdict.passed_seed_db:
                    seed_accepted_gold += 1
                if verdict.passed_seed_db and verdict.passed_all_mutants:
                    mutant_accepted_gold += 1
            else:
                if not verdict.passed_seed_db:
                    seed_caught_bugs += 1
                if not verdict.passed_all_mutants:
                    mutant_caught_bugs += 1
                for m_name in verdict.failing_mutants:
                    if m_name in catches_per_mutant:
                        catches_per_mutant[m_name] += 1
    finally:
        for m_conn in mutants.values():
            m_conn.close()
        raw_seed.close()

    return {
        "benchmark": "idea_13_mutant_sql_synthesizer",
        "num_candidates": len(candidates),
        "gold_candidates": gold_total,
        "buggy_candidates": buggy_total,
        "num_mutants_per_schema": len(mutants),
        "single_seed_db": {
            "semantic_bugs_caught": seed_caught_bugs,
            "semantic_bug_catch_rate": round(seed_caught_bugs / buggy_total, 4),
            "gold_accepted": seed_accepted_gold,
            "gold_acceptance_rate": round(seed_accepted_gold / gold_total, 4),
        },
        "mutant_db_gate": {
            "semantic_bugs_caught": mutant_caught_bugs,
            "semantic_bug_catch_rate": round(mutant_caught_bugs / buggy_total, 4),
            "gold_accepted": mutant_accepted_gold,
            "gold_acceptance_rate": round(mutant_accepted_gold / gold_total, 4),
            "catches_by_mutant": catches_per_mutant,
        },
    }


if __name__ == "__main__":
    import json as _json

    print(_json.dumps(run_benchmark(), indent=2))
