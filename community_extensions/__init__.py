"""Community-inspired L4 verification extensions for lab-verify (Ideas #12 and #13)."""

from __future__ import annotations

from community_extensions.lean_mcp_firewall import (
    CapabilityToken,
    FirewallDecision,
    LeanMcpFirewall,
    McpExecutionRequest,
    StatelessBearerGate,
    run_benchmark as run_firewall_benchmark,
)
from community_extensions.mutant_sql_synthesizer import (
    MutantGateVerdict,
    SqlBenchmarkCandidate,
    evaluate_sql_against_mutants,
    run_benchmark as run_mutant_sql_benchmark,
    synthesize_five_sqlite_mutants,
)

__all__ = [
    "CapabilityToken",
    "FirewallDecision",
    "LeanMcpFirewall",
    "McpExecutionRequest",
    "MutantGateVerdict",
    "SqlBenchmarkCandidate",
    "StatelessBearerGate",
    "evaluate_sql_against_mutants",
    "run_firewall_benchmark",
    "run_mutant_sql_benchmark",
    "synthesize_five_sqlite_mutants",
]
