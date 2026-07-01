"""
LangGraph Security Pipeline

Defines the agent graph with 5 sequential nodes:
  regex_prefilter → cve_scanner → llm_analyzer → self_reflection → gate_decision

Supports multi-language repos — Java (Maven), JavaScript/Node.js (npm),
Python (PyPI) — via the cve_scanner node's manifest detection.
"""

from langgraph.graph import StateGraph, END
from typing import TypedDict, List


from nodes import (
    regex_prefilter_node,
    cve_scanner_node,
    llm_analyzer_node,
    self_reflection_node,
    gate_decision_node
)


class SecurityScanState(TypedDict):
    # Input context
    scan_id: str
    pr_number: int
    repo_full_name: str
    head_sha: str
    pr_author: str
    pr_title: str
    diff_content: str

    # Full manifest contents — fetched by Spring Boot when detected in diff
    pom_xml_content: str              # Maven (Java)
    package_json_content: str         # npm (JavaScript/TypeScript)
    requirements_txt_content: str     # PyPI (Python)

    # Pipeline outputs (accumulate through nodes)
    prefilter_hits: List[dict]
    cve_findings: List[dict]
    raw_findings: List[dict]
    critiqued_findings: List[dict]
    final_findings: List[dict]

    # Decision
    gate_decision: str

    # Observability
    langsmith_run_id: str
    errors: List[str]


def build_security_graph():
    """
    Builds and compiles the LangGraph security analysis pipeline.

        [START]
           |
           v
      regex_prefilter     Fast pattern matching, language-agnostic
           |
           v
      cve_scanner         OSV lookup -- Maven, npm, or PyPI depending on diff
           |
           v
      llm_analyzer        Mistral Codestral -- language-aware semantic analysis
           |
           v
      self_reflection     Mistral critiques its own findings
           |
           v
      gate_decision       Applies thresholds, sets BLOCK/WARN/ALLOW
           |
           v
        [END]
    """
    builder = StateGraph(SecurityScanState)

    builder.add_node("regex_prefilter", regex_prefilter_node)
    builder.add_node("cve_scanner", cve_scanner_node)
    builder.add_node("llm_analyzer", llm_analyzer_node)
    builder.add_node("self_reflection", self_reflection_node)
    builder.add_node("gate_decision", gate_decision_node)

    builder.set_entry_point("regex_prefilter")
    builder.add_edge("regex_prefilter", "cve_scanner")
    builder.add_edge("cve_scanner", "llm_analyzer")
    builder.add_edge("llm_analyzer", "self_reflection")
    builder.add_edge("self_reflection", "gate_decision")
    builder.add_edge("gate_decision", END)

    return builder.compile()
