"""Strict layered gate for text-to-SQL candidates on a toy lab database.

Thin executable wrapper around `lab_verify.sql_gate` and `lab_verify.cli`
enforcing UTF-8 benchmark validation, gold query self-verification, multi-seed
counterexample checks, and non-zero exit codes on any regression.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Sequence

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lab_verify.cli import main as _cli_main  # noqa: E402
from lab_verify.sql_gate import (  # noqa: E402,F401
    EXPERIMENTS,
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
    open_readonly_db,
    rows_equal,
    run,
    run_query,
    validate_candidates_schema,
    verify_sql,
)


def main(argv: Sequence[str] | None = None) -> int:
    return _cli_main(argv, default_candidates=HERE / "candidates.json")


if __name__ == "__main__":
    raise SystemExit(main())
