"""Lean 4 formalization & `LabLean` (`YLM/lean`) verification gate, compiler runner, and axiom auditor."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Sequence

from .verdict import VerifyVerdict

ALLOWED_LEAN_AXIOMS: frozenset[str] = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)

FORBIDDEN_LEAN_IDENTIFIERS: tuple[tuple[str, str], ...] = (
    ("sorry", "incomplete proof token 'sorry' is forbidden"),
    ("admit", "incomplete proof tactic 'admit' is forbidden"),
    ("native_decide", "unverified compiler trust boundary 'native_decide' is forbidden"),
    ("axiom", "custom 'axiom' declaration is forbidden"),
    ("unsafe", "unsafe declaration or cast 'unsafe' is forbidden"),
)

_STATIC_ONLY_EXTRA_IDENTIFIERS: tuple[tuple[str, str], ...] = (
    ("sorryAx", "incomplete proof axiom 'sorryAx' is forbidden"),
    ("admitGoal", "incomplete proof metaprogram 'admitGoal' is forbidden"),
)

_FORBIDDEN_DIRECTIVES: tuple[tuple[str, str], ...] = (
    (r"#exit\b", "early file termination directive '#exit' is forbidden"),
    (r"\bopaque\b", "uninterpreted 'opaque' declaration is forbidden"),
)

_DECL_RE = re.compile(r"\b(theorem|lemma|def|abbrev|example|inductive|structure)\b")
_IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z0-9_.']+)", flags=re.MULTILINE)
_CORE_IMPORT_PREFIXES = ("Init", "Std", "Lean")

_ATTR_BLOCK_RE = re.compile(r"@\[[^\]]*\]")
_SCOPE_LINE_RE = re.compile(
    r"^\s*(?:(noncomputable\s+)?section(?:\s+([A-Za-z_][A-Za-z0-9_'.]*))?"
    r"|namespace\s+([A-Za-z_][A-Za-z0-9_'.]*)"
    r"|end(?:\s+([A-Za-z_][A-Za-z0-9_'.]*))?)\s*$"
)
_NAMED_DECL_LINE_RE = re.compile(
    r"^\s*(?:(?:private|protected|noncomputable|partial|scoped|local)\s+)*"
    r"(theorem|lemma|def|abbrev)\s+([A-Za-z_][A-Za-z0-9_'.]*)"
)

_PRINT_AXIOMS_DEPENDS_RE = re.compile(
    r"^'([^']+)'\s+depends on axioms:\s*\[([^\]]*)\]\s*$"
)
_PRINT_AXIOMS_NONE_RE = re.compile(
    r"^'([^']+)'\s+does not depend on any axioms\s*$"
)


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


def extract_lean_declarations(source: str) -> list[str]:
    """Extract qualified `theorem`/`lemma`/`def`/`abbrev` names from Lean 4 source."""
    stripped = strip_lean_comments(source)
    cleaned = _ATTR_BLOCK_RE.sub(" ", stripped)
    scopes: list[tuple[str, list[str]]] = []
    decls: list[str] = []
    seen: set[str] = set()

    for raw_line in cleaned.splitlines():
        scope_m = _SCOPE_LINE_RE.match(raw_line)
        if scope_m is not None:
            sec_name = scope_m.group(2)
            ns_name = scope_m.group(3)
            end_name = scope_m.group(4)
            raw_stripped = raw_line.strip()
            if ns_name is not None:
                parts = [p for p in ns_name.split(".") if p]
                for p in parts:
                    scopes.append(("namespace", [p]))
                continue
            if raw_stripped.startswith(("section", "noncomputable section")):
                scopes.append(("section", [sec_name or ""]))
                continue
            if raw_stripped.startswith("end"):
                if end_name:
                    parts = [p for p in end_name.split(".") if p]
                    for _ in parts:
                        if scopes:
                            scopes.pop()
                elif scopes:
                    scopes.pop()
                continue

        decl_m = _NAMED_DECL_LINE_RE.match(raw_line)
        if decl_m is not None:
            raw_name = decl_m.group(2)
            if raw_name.startswith("_root_."):
                qual_name = raw_name[len("_root_.") :]
            else:
                ns_parts = [p for kind, parts in scopes if kind == "namespace" for p in parts]
                qual_name = ".".join([*ns_parts, raw_name]) if ns_parts else raw_name
            if qual_name and qual_name not in seen:
                seen.add(qual_name)
                decls.append(qual_name)

    return decls


def _has_non_core_imports(stripped_source: str) -> bool:
    for match in _IMPORT_RE.finditer(stripped_source):
        mod = match.group(1)
        if not mod.startswith(_CORE_IMPORT_PREFIXES):
            return True
    return False


def _find_enclosing_lake_project(file_path: Path) -> Path | None:
    for parent in (file_path.parent, *file_path.parents):
        if (parent / "lakefile.toml").is_file() or (parent / "lakefile.lean").is_file():
            return parent
    return None


def _audit_print_axioms_output(
    combined_output: str,
    expected_decls: Sequence[str],
) -> tuple[list[str], set[str]]:
    """Parse `#print axioms` lines and return `(violations, reported_decls)`."""
    axiom_violations: list[str] = []
    sorry_warnings: list[str] = []
    reported: set[str] = set()

    for raw_line in combined_output.splitlines():
        line = raw_line.strip()
        m_dep = _PRINT_AXIOMS_DEPENDS_RE.match(line)
        if m_dep is not None:
            decl_name = m_dep.group(1)
            reported.add(decl_name)
            axioms = [ax.strip() for ax in m_dep.group(2).split(",") if ax.strip()]
            disallowed = [ax for ax in axioms if ax not in ALLOWED_LEAN_AXIOMS]
            if disallowed:
                axiom_violations.append(
                    f"declaration '{decl_name}' depends on disallowed axiom(s): "
                    f"{', '.join(disallowed)} (allowed: {', '.join(sorted(ALLOWED_LEAN_AXIOMS))})"
                )
            continue

        m_none = _PRINT_AXIOMS_NONE_RE.match(line)
        if m_none is not None:
            reported.add(m_none.group(1))
            continue

        if "declaration uses 'sorry'" in line or "declaration uses `sorry`" in line:
            sorry_warnings.append(f"Lean compiler reported incomplete proof (`sorry`): {line}")

    violations = axiom_violations + sorry_warnings
    for decl in expected_decls:
        matched = any(
            rep == decl or rep.endswith(f".{decl}")
            for rep in reported
        )
        if not matched:
            violations.append(f"missing `#print axioms` verification output for declaration '{decl}'")

    return violations, reported


def run_lablean_protocol_checker(
    project_dir: str | Path,
    *,
    timeout_s: float = 30.0,
) -> VerifyVerdict:
    """Execute an external `lake exe lablean` protocol checker inside `project_dir` (separate from proof compilation)."""
    proj = Path(project_dir).resolve()
    if not proj.is_dir():
        return VerifyVerdict(
            passed=False,
            layer="execution",
            reason=f"LabLean project directory not found: {proj}",
            diagnostics=[str(proj)],
        )
    lake_bin = shutil.which("lake")
    if lake_bin is None:
        return VerifyVerdict(
            passed=False,
            layer="execution",
            reason="Lean toolchain ('lake') not found on PATH",
            diagnostics=["lake binary is required to run 'lake exe lablean'"],
        )
    try:
        proc = subprocess.run(
            [lake_bin, "exe", "lablean"],
            cwd=str(proj),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return VerifyVerdict(
            passed=False,
            layer="execution",
            reason=f"lake exe lablean timed out after {timeout_s:.1f}s",
            diagnostics=[f"timeout_s={timeout_s}"],
        )
    except OSError as exc:
        return VerifyVerdict(
            passed=False,
            layer="execution",
            reason=f"lake execution failed: {exc}",
            diagnostics=[str(exc)],
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


def verify_lean(
    source_or_path: str | Path,
    *,
    run_toolchain: bool | None = None,
    static_only: bool = False,
    project_dir: str | Path | None = None,
    run_leanchecker: bool = False,
    expected_decls: Sequence[str] | None = None,
    timeout_s: float = 60.0,
) -> VerifyVerdict:
    """Compile Lean 4 candidate source, verify `#print axioms` against `{propext, Classical.choice, Quot.sound}`, and optionally run `leanchecker`.

    Fails closed when `lean`/`lake` is missing unless `static_only=True` (or legacy `run_toolchain=False`) is explicitly passed.
    """
    effective_static_only = bool(static_only) or (run_toolchain is False)

    is_file = False
    file_path: Path | None = None
    if isinstance(source_or_path, Path):
        file_path = source_or_path.resolve()
        if not file_path.is_file():
            return VerifyVerdict(
                passed=False,
                layer="parse",
                reason=f"Lean file not found: {source_or_path}",
                diagnostics=[f"resolved path does not exist: {file_path}"],
            )
        is_file = True
        source = file_path.read_text(encoding="utf-8")
    elif (
        isinstance(source_or_path, str)
        and "\n" not in source_or_path
        and source_or_path.strip().endswith(".lean")
    ):
        cand_path = Path(source_or_path.strip())
        if cand_path.exists():
            file_path = cand_path.resolve()
            is_file = True
            source = file_path.read_text(encoding="utf-8")
        else:
            return VerifyVerdict(
                passed=False,
                layer="parse",
                reason=f"Lean file not found: {source_or_path}",
                diagnostics=[f"resolved path does not exist: {cand_path.resolve()}"],
            )
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

    for pattern, msg in _FORBIDDEN_DIRECTIVES:
        if re.search(pattern, stripped):
            diagnostics.append(msg)

    ident_checks = (
        FORBIDDEN_LEAN_IDENTIFIERS + _STATIC_ONLY_EXTRA_IDENTIFIERS
        if effective_static_only
        else FORBIDDEN_LEAN_IDENTIFIERS
    )
    for ident, msg in ident_checks:
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

    if effective_static_only:
        return VerifyVerdict(
            passed=True,
            layer=None,
            reason="static_only",
            diagnostics=["static soundness checks passed; Lean kernel was not invoked"],
        )

    decls = extract_lean_declarations(source)
    if expected_decls:
        seen_decls = set(decls)
        for req_decl in expected_decls:
            clean_req = req_decl.strip()
            if clean_req and clean_req not in seen_decls:
                if not any(d == clean_req or d.endswith(f".{clean_req}") for d in seen_decls):
                    decls.append(clean_req)
                    seen_decls.add(clean_req)

    resolved_proj: Path | None = None
    if project_dir is not None:
        resolved_proj = Path(project_dir).resolve()
        if not resolved_proj.is_dir():
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=f"Lean project_dir does not exist: {resolved_proj}",
                diagnostics=[str(resolved_proj)],
            )
    elif is_file and file_path is not None and _has_non_core_imports(stripped):
        resolved_proj = _find_enclosing_lake_project(file_path)

    needs_lake = resolved_proj is not None or _has_non_core_imports(stripped)

    lake_bin = shutil.which("lake")
    lean_bin = shutil.which("lean")
    checker_bin = shutil.which("leanchecker") if run_leanchecker else None

    if run_leanchecker and checker_bin is None:
        return VerifyVerdict(
            passed=False,
            layer="execution",
            reason="Lean kernel replay binary ('leanchecker') not found on PATH",
            diagnostics=["run_leanchecker=True requires 'leanchecker' on PATH"],
        )

    if resolved_proj is not None:
        if lake_bin is None:
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason="Lean toolchain ('lake') not found on PATH; pass static_only=True for static-only checks",
                diagnostics=["lake binary not found on PATH"],
            )
    else:
        if lean_bin is None:
            missing_tool = "lake/lean" if needs_lake else "lean"
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=f"Lean 4 compiler ('{missing_tool}') not found on PATH; pass static_only=True for static-only checks",
                diagnostics=[f"{missing_tool} binary not found on PATH"],
            )

    mod_name = "LabVerifyCandidate"
    axiom_trailer = (
        "\n\n-- lab-verify automated axiom audit\n"
        + "\n".join(f"#print axioms {decl}" for decl in decls)
        + "\n"
        if decls
        else "\n"
    )
    rendered_source = source.rstrip() + axiom_trailer

    with tempfile.TemporaryDirectory(prefix="lab_verify_lean_") as tmp_str:
        tmp_dir = Path(tmp_str).resolve()
        temp_lean = tmp_dir / f"{mod_name}.lean"
        temp_olean = tmp_dir / f"{mod_name}.olean"
        temp_lean.write_text(rendered_source, encoding="utf-8", newline="\n")

        cmd: Sequence[str]
        run_cwd: str
        if resolved_proj is not None:
            assert lake_bin is not None
            run_cwd = str(resolved_proj)
            if run_leanchecker:
                cmd = [
                    lake_bin,
                    "env",
                    "lean",
                    "-R",
                    str(tmp_dir),
                    "-o",
                    str(temp_olean),
                    str(temp_lean),
                ]
            else:
                cmd = [lake_bin, "env", "lean", str(temp_lean)]
        else:
            assert lean_bin is not None
            run_cwd = str(tmp_dir)
            if run_leanchecker:
                cmd = [
                    lean_bin,
                    "-R",
                    str(tmp_dir),
                    "-o",
                    str(temp_olean),
                    str(temp_lean),
                ]
            else:
                cmd = [lean_bin, str(temp_lean)]

        try:
            proc = subprocess.run(
                cmd,
                cwd=run_cwd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=f"Lean compilation timed out after {timeout_s:.1f}s",
                diagnostics=[f"timeout_s={timeout_s}"],
            )
        except OSError as exc:
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=f"Lean compiler execution failed: {exc}",
                diagnostics=[str(exc)],
            )

        combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
        if proc.returncode != 0:
            lines = combined.splitlines() if combined else [f"Lean exited with code {proc.returncode}"]
            return VerifyVerdict(
                passed=False,
                layer="execution",
                reason=lines[0],
                diagnostics=lines,
            )

        axiom_violations, _ = _audit_print_axioms_output(combined, decls)
        if axiom_violations:
            return VerifyVerdict(
                passed=False,
                layer="soundness",
                reason=axiom_violations[0],
                diagnostics=axiom_violations + (combined.splitlines() if combined else []),
            )

        if run_leanchecker:
            assert checker_bin is not None
            existing_lean_path = os.environ.get("LEAN_PATH", "").strip()
            merged_lean_path = (
                f"{tmp_dir}{os.pathsep}{existing_lean_path}"
                if existing_lean_path
                else str(tmp_dir)
            )
            checker_env = {**os.environ, "LEAN_PATH": merged_lean_path}
            checker_cmd: Sequence[str] = (
                [lake_bin, "env", checker_bin, mod_name]
                if (resolved_proj is not None and lake_bin is not None)
                else [checker_bin, mod_name]
            )
            try:
                chk_proc = subprocess.run(
                    checker_cmd,
                    cwd=run_cwd,
                    env=checker_env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return VerifyVerdict(
                    passed=False,
                    layer="execution",
                    reason=f"leanchecker timed out after {timeout_s:.1f}s",
                    diagnostics=[f"timeout_s={timeout_s}"],
                )
            except OSError as exc:
                return VerifyVerdict(
                    passed=False,
                    layer="execution",
                    reason=f"leanchecker execution failed: {exc}",
                    diagnostics=[str(exc)],
                )

            if chk_proc.returncode != 0:
                chk_err = (
                    (chk_proc.stderr or chk_proc.stdout).strip()
                    or f"leanchecker exited with code {chk_proc.returncode}"
                )
                return VerifyVerdict(
                    passed=False,
                    layer="soundness",
                    reason=f"leanchecker rejected module: {chk_err.splitlines()[0]}",
                    diagnostics=chk_err.splitlines(),
                )

    return VerifyVerdict(passed=True, layer=None, reason="match", diagnostics=[])
