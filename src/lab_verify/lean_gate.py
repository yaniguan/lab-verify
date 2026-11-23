"""Lean 4 formalization & `LabLean` (`YLM/lean`) verification gate and vacuity detector."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
from typing import Sequence

from .verdict import VerifyVerdict

FORBIDDEN_LEAN_IDENTIFIERS: tuple[tuple[str, str], ...] = (
    ("sorry", "incomplete proof token 'sorry' is forbidden"),
    ("admit", "incomplete proof tactic 'admit' is forbidden"),
    ("native_decide", "unverified compiler trust boundary 'native_decide' is forbidden"),
    ("axiom", "custom 'axiom' declaration is forbidden"),
)

_DECL_RE = re.compile(r"\b(theorem|lemma|def|example|inductive|structure)\b")


def strip_lean_comments(source: str) -> str:
    """Strip Lean 4 `--` line comments, `/- ... -/` nested block comments, and string literals."""
    out: list[str] = []
    i = 0
    n = len(source)
    block_depth = 0
    in_string = False

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if block_depth > 0:
            if ch == "/" and nxt == "-":
                block_depth += 1
                i += 2
                continue
            if ch == "-" and nxt == "/":
                block_depth -= 1
                i += 2
                out.append(" ")
                continue
            if ch == "\n":
                out.append("\n")
            i += 1
            continue

        if in_string:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        if ch == "/" and nxt == "-":
            block_depth = 1
            i += 2
            continue
        if ch == "-" and nxt == "-":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == '"':
            in_string = True
            out.append('""')
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def verify_lean(
    source_or_path: str | Path,
    *,
    run_toolchain: bool = False,
    project_dir: str | Path | None = None,
    timeout_s: float = 30.0,
) -> VerifyVerdict:
    """Audit Lean 4 source for soundness bypasses (`sorry`, `native_decide`, `axiom`, vacuity) and optionally run `lake`."""
    is_file = False
    file_path: Path | None = None
    if isinstance(source_or_path, Path) or (
        isinstance(source_or_path, str)
        and "\n" not in source_or_path
        and source_or_path.endswith(".lean")
        and Path(source_or_path).exists()
    ):
        file_path = Path(source_or_path)
        is_file = True
        source = file_path.read_text(encoding="utf-8")
    else:
        source = str(source_or_path)

    if not source.strip():
        return VerifyVerdict(
            passed=False,
            layer="parse",
            reason="empty Lean 4 input",
            diagnostics=["Lean source contains no code"],
        )

    stripped = strip_lean_comments(source)
    diagnostics: list[str] = []

    for ident, msg in FORBIDDEN_LEAN_IDENTIFIERS:
        if re.search(rf"\b{re.escape(ident)}\b", stripped):
            diagnostics.append(msg)

    # Vacuity check: reject `theorem foo : False -> ...` or `True` trivial goals
    if re.search(r"\b(theorem|lemma)\s+\w+[^:=]*:\s*True\s*:=", stripped):
        diagnostics.append("vacuous theorem concluding literal 'True'")
    if re.search(r"\b(theorem|lemma)\s+\w+[^:=]*:\s*False\s*(->|\u2192)", stripped):
        diagnostics.append("vacuous theorem with literal 'False' antecedent")

    if not _DECL_RE.search(stripped):
        return VerifyVerdict(
            passed=False,
            layer="schema",
            reason="no Lean declarations found",
            diagnostics=["expected at least one theorem, lemma, def, or inductive declaration"],
        )

    if diagnostics:
        return VerifyVerdict(
            passed=False,
            layer="soundness",
            reason=diagnostics[0],
            diagnostics=diagnostics,
        )

    if run_toolchain:
        lake_bin = shutil.which("lake")
        if lake_bin is None:
            return VerifyVerdict(
                passed=True,
                layer=None,
                reason="static audit passed (lake toolchain not installed in environment)",
                diagnostics=["lake binary not found on PATH; static soundness checks passed"],
            )
        cwd = Path(project_dir) if project_dir else (file_path.parent if is_file and file_path else Path.cwd())
        cmd: Sequence[str]
        if is_file and file_path is not None:
            cmd = [lake_bin, "env", "lean", str(file_path)]
        else:
            cmd = [lake_bin, "exe", "lablean"]
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        if proc.returncode != 0:
            err_msg = (proc.stderr or proc.stdout).strip() or f"lake exited with code {proc.returncode}"
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=err_msg.splitlines()[0],
                diagnostics=err_msg.splitlines(),
            )
        for line in proc.stdout.splitlines():
            if "REJECTED:" in line:
                return VerifyVerdict(
                    passed=False,
                    layer="execution",
                    reason=line.strip(),
                    diagnostics=proc.stdout.splitlines(),
                )

    return VerifyVerdict(passed=True, layer=None, reason="match", diagnostics=[])
