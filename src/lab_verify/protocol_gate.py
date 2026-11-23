"""Machine-readable benchtop protocol verification gate compatible with `lab-rehearsal` & `twinstep`."""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .verdict import VerifyVerdict

_WELL_LOC_RE = re.compile(r"^(plate\d*:[A-H](?:1[0-2]|[1-9])|res:(?:1[0-2]|[1-9])|reservoir:[A-Za-z0-9_]+|trash:1|waste)$")


def _is_finite_pos(val: Any) -> bool:
    return not isinstance(val, bool) and isinstance(val, (int, float)) and math.isfinite(float(val)) and float(val) > 0


def verify_protocol(
    protocol_or_path: str | Path | Sequence[Mapping[str, Any]] | Mapping[str, Any],
    *,
    pip_min: float = 20.0,
    pip_max: float = 300.0,
    well_max: float = 300.0,
) -> VerifyVerdict:
    """Validate machine-readable liquid-handling protocols across schema, tip, and volume rules."""
    raw: Any
    if isinstance(protocol_or_path, Path) or (
        isinstance(protocol_or_path, str) and Path(protocol_or_path).exists()
    ):
        try:
            raw = json.loads(Path(protocol_or_path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return VerifyVerdict(False, "parse", f"invalid JSON: {exc.msg}", [str(exc)])
    elif isinstance(protocol_or_path, str):
        try:
            raw = json.loads(protocol_or_path)
        except json.JSONDecodeError as exc:
            return VerifyVerdict(False, "parse", f"invalid JSON: {exc.msg}", [str(exc)])
    else:
        raw = protocol_or_path

    if isinstance(raw, Mapping) and "steps" in raw:
        steps = raw["steps"]
    else:
        steps = raw

    if not isinstance(steps, list) or len(steps) == 0:
        return VerifyVerdict(
            passed=False,
            layer="schema",
            reason="protocol must be a non-empty list of step objects",
            diagnostics=["empty or non-list protocol"],
        )

    diagnostics: list[str] = []
    is_macro = isinstance(steps[0], Mapping) and "type" in steps[0]

    if is_macro:
        well_vols: dict[str, float] = {}
        for idx, step in enumerate(steps, 1):
            if not isinstance(step, Mapping):
                diagnostics.append(f"step {idx}: must be an object")
                continue
            stype = step.get("type")
            if stype == "transfer":
                src, dst, vol = step.get("source"), step.get("dest"), step.get("volume")
                if not isinstance(src, str) or not _WELL_LOC_RE.match(src):
                    diagnostics.append(f"step {idx}: invalid source {src!r}")
                if not isinstance(dst, str) or not _WELL_LOC_RE.match(dst):
                    diagnostics.append(f"step {idx}: invalid dest {dst!r}")
                if not _is_finite_pos(vol):
                    diagnostics.append(f"step {idx}: invalid volume {vol!r}")
                else:
                    v_ul = float(vol) * 1000.0 if step.get("unit") == "mL" else float(vol)
                    if not (pip_min - 1e-9 <= v_ul <= pip_max + 1e-9):
                        diagnostics.append(
                            f"step {idx}: volume {v_ul:g} uL outside pipette range {pip_min:g}-{pip_max:g} uL"
                        )
                    if isinstance(dst, str) and dst.startswith("plate"):
                        well_vols[dst] = round(well_vols.get(dst, 0.0) + v_ul, 9)
                        if well_vols[dst] > well_max + 1e-9:
                            diagnostics.append(
                                f"step {idx}: {dst} overfilled ({well_vols[dst]:g} uL > {well_max:g} uL)"
                            )
                    if isinstance(src, str) and src.startswith("plate"):
                        avail = well_vols.get(src, 0.0)
                        if v_ul > avail + 1e-9:
                            diagnostics.append(
                                f"step {idx}: aspirate {v_ul:g} uL from {src} holding {avail:g} uL"
                            )
                        well_vols[src] = max(0.0, round(avail - v_ul, 9))
            elif stype == "mix":
                well, vol, cycles = step.get("well"), step.get("volume"), step.get("cycles", 1)
                if not isinstance(well, str) or not _WELL_LOC_RE.match(well):
                    diagnostics.append(f"step {idx}: invalid well {well!r}")
                if not _is_finite_pos(vol):
                    diagnostics.append(f"step {idx}: invalid mix volume {vol!r}")
                if isinstance(cycles, bool) or not isinstance(cycles, int) or cycles < 1:
                    diagnostics.append(f"step {idx}: invalid mix cycles {cycles!r}")
            elif stype in ("incubate", "wash", "read"):
                continue
            else:
                diagnostics.append(f"step {idx}: unknown macro step type {stype!r}")
    else:
        tip = False
        in_pip = 0.0
        well_vols = {}
        for idx, step in enumerate(steps, 1):
            if not isinstance(step, Mapping):
                diagnostics.append(f"step {idx}: must be an object")
                continue
            op = step.get("op")
            if op == "pick_up_tip":
                if tip:
                    diagnostics.append(f"step {idx}: tip already attached")
                tip = True
                in_pip = 0.0
            elif op == "drop_tip":
                if not tip:
                    diagnostics.append(f"step {idx}: drop_tip without a tip")
                elif in_pip > 1e-9 and not step.get("allow_wet_drop", False):
                    diagnostics.append(f"step {idx}: drop_tip with {in_pip:g} uL undispensed liquid")
                tip = False
                in_pip = 0.0
            elif op in ("aspirate", "dispense", "mix"):
                loc, vol = step.get("loc"), step.get("vol")
                if not tip:
                    diagnostics.append(f"step {idx}: {op} without a tip")
                if not isinstance(loc, str) or not _WELL_LOC_RE.match(loc):
                    diagnostics.append(f"step {idx}: unknown location {loc!r}")
                if not _is_finite_pos(vol):
                    diagnostics.append(f"step {idx}: invalid volume {vol!r}")
                    continue
                fv = float(vol)
                if not (pip_min - 1e-9 <= fv <= pip_max + 1e-9):
                    diagnostics.append(
                        f"step {idx}: {fv:g} uL outside pipette range {pip_min:g}-{pip_max:g} uL"
                    )
                if op == "aspirate":
                    if in_pip + fv > pip_max + 1e-9:
                        diagnostics.append(f"step {idx}: barrel overflow ({in_pip + fv:g} uL > {pip_max:g} uL)")
                    in_pip = round(in_pip + fv, 9)
                elif op == "dispense":
                    if fv > in_pip + 1e-9:
                        diagnostics.append(f"step {idx}: dispense {fv:g} uL but pipette holds {in_pip:g} uL")
                    give = min(fv, in_pip)
                    in_pip = round(in_pip - give, 9)
                    if isinstance(loc, str) and loc.startswith("plate:"):
                        well_vols[loc] = round(well_vols.get(loc, 0.0) + give, 9)
                        if well_vols[loc] > well_max + 1e-9:
                            diagnostics.append(
                                f"step {idx}: {loc} would hold {well_vols[loc]:g} uL > {well_max:g} uL"
                            )
                elif op == "mix":
                    reps = step.get("reps", 1)
                    if isinstance(reps, bool) or not isinstance(reps, int) or not (1 <= reps <= 100):
                        diagnostics.append(f"step {idx}: invalid mix reps {reps!r}")
                    if in_pip + fv > pip_max + 1e-9:
                        diagnostics.append(f"step {idx}: barrel overflow ({in_pip + fv:g} uL > {pip_max:g} uL)")
            else:
                diagnostics.append(f"step {idx}: unknown op {op!r}")
        if tip:
            diagnostics.append(f"step {len(steps)}: tip still attached at end")

    if diagnostics:
        return VerifyVerdict(
            passed=False,
            layer="protocol_rules",
            reason=diagnostics[0],
            diagnostics=diagnostics,
        )
    return VerifyVerdict(passed=True, layer=None, reason="match", diagnostics=[])
