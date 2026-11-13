#!/usr/bin/env python3
"""
Logihertz SELinux Exporters
Module: exporters.py
Multi-format exporters for SELinux Posture Audit Reports, CIL Verification Summaries,
and AVC Denial Analysis. Formats: ANSI Box Table, Canonical JSON, OASIS SARIF v2.1.0.
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
"""

import json
from typing import Dict, List, Any, Optional
from selinux_auditor import PostureAuditReport
from cil_engine import CILPolicy, AVCSynthesisResult, NeverallowViolation

# ANSI Color Codes
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_MAGENTA = "\033[35m"
ANSI_CYAN = "\033[36m"


def render_audit_table(report: PostureAuditReport, use_color: bool = True) -> str:
    """Format PostureAuditReport as an ANSI box table."""
    b = ANSI_BOLD if use_color else ""
    r = ANSI_RESET if use_color else ""
    c_status = ANSI_GREEN if use_color else ""

    if report.score < 50:
        c_status = ANSI_RED if use_color else ""
    elif report.score < 80:
        c_status = ANSI_YELLOW if use_color else ""
    elif report.score < 100:
        c_status = ANSI_CYAN if use_color else ""

    lines = []
    lines.append(f"\n{b}========================================================================================{r}")
    lines.append(f"{b}          LOGIHERTZ EMBEDDED SELINUX MANDATORY ACCESS CONTROL AUDITOR                   {r}")
    lines.append(f"{b}========================================================================================{r}")
    lines.append(f"  Policy Manifest : {b}{report.policy_name}{r}")
    lines.append(f"  Audited At      : {report.audited_at}")
    lines.append(f"  Rules Evaluated : {report.total_rules} total ({report.passed_rules} passed, {report.failed_rules} failed)")
    lines.append(f"  Security Score  : {c_status}{report.score}/100 ({report.status}){r}")
    lines.append("----------------------------------------------------------------------------------------")

    if report.failed_rules == 0:
        c_pass = ANSI_GREEN if use_color else ""
        lines.append(f"\n  {c_pass}[PASS]{r} Zero security posture deficiencies detected! Embedded MAC policy is HARDENED.\n")
    else:
        lines.append(f"\n{b}FINDINGS ({len(report.findings)} detected):{r}\n")
        for f in report.findings:
            c_sev = ANSI_RED if use_color else ""
            if f.severity == "MEDIUM":
                c_sev = ANSI_YELLOW if use_color else ""
            elif f.severity == "LOW":
                c_sev = ANSI_CYAN if use_color else ""

            c_cyan = ANSI_CYAN if use_color else ""
            lines.append(f"  {c_sev}[{f.severity}]{r} {b}{f.rule_id}{r}: {f.title}")
            lines.append(f"      CWE         : {f.cwe} (Weight: -{f.weight} pts)")
            lines.append(f"      Description : {f.description}")
            lines.append(f"      Remediation : {c_cyan}{f.remediation}{r}\n")

    lines.append(f"{b}========================================================================================{r}\n")
    return "\n".join(lines)


def export_json(report: PostureAuditReport) -> str:
    """Export PostureAuditReport to Canonical JSON."""
    return json.dumps(report.to_dict(), indent=2)


def export_sarif(report: PostureAuditReport) -> str:
    """Export PostureAuditReport to OASIS SARIF v2.1.0."""
    rule_definitions = [
        {"id": "LH-SELINUX-001", "name": "SELinux Mode Permissive Or Runtime Develop", "desc": "SELinux disabled or runtime develop mode active."},
        {"id": "LH-SELINUX-002", "name": "Unconfined Process Domains Active", "desc": "Unconfined domains active on embedded appliance."},
        {"id": "LH-SELINUX-003", "name": "Memory W^X Protection Bypassed", "desc": "Executable heap, stack, or memory permitted."},
        {"id": "LH-SELINUX-004", "name": "Missing Neverallow Assertions For Kernel Integrity", "desc": "Policy lacks neverallow for sys_module, /dev/mem, or raw blocks."},
        {"id": "LH-SELINUX-005", "name": "Edge AI Inference Domain Network Isolation", "desc": "Edge AI inference domain has unauthorized network or CAN bus access."},
        {"id": "LH-SELINUX-006", "name": "Execute No Trans Permitted On Writable Mounts", "desc": "execute_no_trans permitted on tmpfs or missing strict entrypoints."},
        {"id": "LH-SELINUX-007", "name": "Cross-Domain ptrace Permitted", "desc": "Cross-domain ptrace or memory snooping allowed."},
        {"id": "LH-SELINUX-008", "name": "Unknown Kernel Objects Or Unlabeled Files", "desc": "handle_unknown not deny or unlabeled files present."},
        {"id": "LH-SELINUX-009", "name": "Runtime Policy Reload Modifiable", "desc": "Runtime policy reload or insmod not locked."},
        {"id": "LH-SELINUX-010", "name": "Excessive dontaudit Or Audit Disabled", "desc": "dontaudit rules active in production or audit logging disabled."}
    ]

    rules_array = []
    for rd in rule_definitions:
        rules_array.append({
            "id": rd["id"],
            "name": rd["name"],
            "shortDescription": {"text": rd["desc"]}
        })

    results_array = []
    for f in report.findings:
        level = "error"
        if f.severity == "MEDIUM":
            level = "warning"
        elif f.severity == "LOW":
            level = "note"

        results_array.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f"{f.description} {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.policy_name}
                    }
                }
            ]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-selinux",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-selinux-embedded-policy",
                        "rules": rules_array
                    }
                },
                "results": results_array
            }
        ]
    }
    return json.dumps(sarif_doc, indent=2)


def render_cil_summary(policy: CILPolicy, violations: List[NeverallowViolation], use_color: bool = True) -> str:
    """Format CIL policy metrics and neverallow verification proof as a table."""
    b = ANSI_BOLD if use_color else ""
    r = ANSI_RESET if use_color else ""
    c_green = ANSI_GREEN if use_color else ""
    c_red = ANSI_RED if use_color else ""

    lines = []
    lines.append(f"\n{b}========================================================================================{r}")
    lines.append(f"{b}                LOGIHERTZ SELINUX CIL REFERENCE POLICY COMPILER & VERIFIER              {r}")
    lines.append(f"{b}========================================================================================{r}")
    lines.append(f"  Source Modules     : {len(policy.source_files)} loaded")
    lines.append(f"  Declared Types     : {len(policy.types)}")
    lines.append(f"  Type Attributes    : {len(policy.attributes)}")
    lines.append(f"  Security Classes   : {len(policy.classes)}")
    lines.append(f"  Allow Rules        : {len(policy.allow_rules)}")
    lines.append(f"  Neverallow Rules   : {len(policy.neverallow_rules)}")
    lines.append(f"  Handle Unknown     : {policy.handle_unknown}")
    lines.append(f"  MLS Enforced       : {policy.mls}")
    lines.append(f"  Policy SHA-256     : {policy.policy_hash}")
    lines.append("----------------------------------------------------------------------------------------")

    if not violations:
        lines.append(f"  {b}Compile-Time Disjointness Proof:{r} {c_green}[PASSED]{r}")
        lines.append(f"  Formula: ∀ (s, t, c), P_allow(s, t, c) ∩ P_never(s, t, c) = ∅")
        lines.append(f"  Zero compile-time neverallow conflicts detected across active reference modules.")
    else:
        lines.append(f"  {b}Compile-Time Disjointness Proof:{r} {c_red}[FAILED - {len(violations)} VIOLATIONS DETECTED]{r}")
        lines.append("----------------------------------------------------------------------------------------")
        for idx, v in enumerate(violations, 1):
            lines.append(f"  [{idx}] Conflict on ({v.source} -> {v.target}) class '{v.tclass}':")
            lines.append(f"      Forbidden Permissions : {c_red}{' '.join(v.forbidden_perms)}{r}")
            lines.append(f"      Invariant Assertion   : {v.rule_src}")

    lines.append(f"{b}========================================================================================{r}\n")
    return "\n".join(lines)


def render_avc_summary(results: List[AVCSynthesisResult], use_color: bool = True) -> str:
    """Format AVC denial analysis and candidate CIL allow synthesis."""
    b = ANSI_BOLD if use_color else ""
    r = ANSI_RESET if use_color else ""
    c_green = ANSI_GREEN if use_color else ""
    c_red = ANSI_RED if use_color else ""

    lines = []
    lines.append(f"\n{b}========================================================================================{r}")
    lines.append(f"{b}              LOGIHERTZ AVC DENIAL-TO-CIL SYNTHESIZER & INTRUSION FILTER                {r}")
    lines.append(f"{b}========================================================================================{r}")
    lines.append(f"  AVC Events Parsed  : {len(results)}")
    safe_count = sum(1 for res in results if res.is_safe)
    blocked_count = sum(1 for res in results if not res.is_safe)
    lines.append(f"  Synthesis Outcome  : {c_green}{safe_count} Safe Allow Rules{r} | {c_red}{blocked_count} Blocked Invariant Violations{r}")
    lines.append("----------------------------------------------------------------------------------------\n")

    for idx, res in enumerate(results, 1):
        d = res.denial
        if res.is_safe:
            lines.append(f"  [{idx}] {c_green}[SAFE AVC DENIAL]{r} Comm: '{d.comm}' (PID: {d.pid})")
            lines.append(f"      Source Domain   : {d.sdomain}")
            lines.append(f"      Target Type     : {d.ttype} (Class: {d.tclass})")
            lines.append(f"      Synthesized CIL : {b}{res.proposed_cil}{r}\n")
        else:
            lines.append(f"  [{idx}] {c_red}[BLOCKED BY NEVERALLOW - INTRUSION SUSPECTED]{r} Comm: '{d.comm}' (PID: {d.pid})")
            lines.append(f"      Source Domain   : {d.sdomain}")
            lines.append(f"      Target Type     : {d.ttype} (Class: {d.tclass})")
            lines.append(f"      Denied Perms    : {' '.join(d.perms)}")
            lines.append(f"      Rejection Reason: {c_red}{res.reason}{r}\n")

    lines.append(f"{b}========================================================================================{r}\n")
    return "\n".join(lines)
