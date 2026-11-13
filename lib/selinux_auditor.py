#!/usr/bin/env python3
"""
Logihertz SELinux Posture Auditor
Module: selinux_auditor.py
10-Rule deterministic SELinux embedded MAC posture auditor (LH-SELINUX-001..010).
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional


class PostureFinding:
    def __init__(self, rule_id: str, title: str, severity: str, weight: int, cwe: str,
                 description: str, remediation: str):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.weight = weight
        self.cwe = cwe
        self.description = description
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "weight": self.weight,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation
        }


class PostureAuditReport:
    def __init__(self, policy_name: str):
        self.policy_name = policy_name
        self.audited_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.total_rules = 10
        self.passed_rules = 0
        self.failed_rules = 0
        self.score = 100
        self.status = "HARDENED"
        self.findings: List[PostureFinding] = []

    def add_passed(self):
        self.passed_rules += 1

    def add_failed(self, finding: PostureFinding):
        self.failed_rules += 1
        self.findings.append(finding)

    def finalize(self):
        total_deductions = sum(f.weight for f in self.findings)
        self.score = max(0, 100 - total_deductions)
        if self.score == 100:
            self.status = "HARDENED"
        elif self.score >= 80:
            self.status = "ACCEPTABLE"
        elif self.score >= 50:
            self.status = "DEGRADED"
        else:
            self.status = "NON-COMPLIANT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "lh-selinux",
            "version": "0.1.0",
            "policy_name": self.policy_name,
            "audited_at": self.audited_at,
            "score": self.score,
            "status": self.status,
            "total_rules": self.total_rules,
            "passed_rules": self.passed_rules,
            "failed_rules": self.failed_rules,
            "findings": [f.to_dict() for f in self.findings]
        }


def audit_selinux_manifest(config: Dict[str, Any]) -> PostureAuditReport:
    """Audit an appliance SELinux manifest dictionary against all 10 posture rules."""
    policy_name = config.get("policy_name", "default_selinux_policy")
    report = PostureAuditReport(policy_name)

    # Rule 1: LH-SELINUX-001 (CRITICAL, 25 pts, CWE-284)
    mode = str(config.get("selinux_mode", "")).lower()
    dev_mode = bool(config.get("security_selinux_develop", False))
    if mode != "enforcing" or dev_mode:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-001",
                title="SELinux Disabled, Permissive Mode, or Runtime Development Override Active",
                severity="CRITICAL",
                weight=25,
                cwe="CWE-284",
                description="SELinux is disabled or running in permissive mode, or kernel has CONFIG_SECURITY_SELINUX_DEVELOP=y allowing runtime 'setenforce 0' downgrade.",
                remediation="Set SELINUX=enforcing in /etc/selinux/config and compile production kernel without CONFIG_SECURITY_SELINUX_DEVELOP."
            )
        )
    else:
        report.add_passed()

    # Rule 2: LH-SELINUX-002 (CRITICAL, 25 pts, CWE-250)
    unconfined_enabled = bool(config.get("unconfined_domains_enabled", False))
    unconfined_count = int(config.get("unconfined_processes_count", 0))
    if unconfined_enabled or unconfined_count > 0:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-002",
                title="Unconfined Process Domains Active on Embedded Appliance",
                severity="CRITICAL",
                weight=25,
                cwe="CWE-250",
                description="Appliance operates with active unconfined subject domains (e.g. unconfined_t), completely bypassing Mandatory Access Control.",
                remediation="Eliminate unconfined_t; confine all daemons into discrete subject domains with least-privilege allow rules."
            )
        )
    else:
        report.add_passed()

    # Rule 3: LH-SELINUX-003 (CRITICAL, 25 pts, CWE-119)
    execmem = bool(config.get("allow_execmem", False))
    execstack = bool(config.get("allow_execstack", False))
    execheap = bool(config.get("allow_execheap", False))
    if execmem or execstack or execheap:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-003",
                title="Memory W^X Protection Bypassed (Executable Heap/Stack/Memory Allowed)",
                severity="CRITICAL",
                weight=25,
                cwe="CWE-119",
                description="SELinux booleans or allow rules permit execmem, execstack, or execheap, permitting dynamic shellcode injection or JIT exploitation.",
                remediation="Enforce strict W^X memory protection by disabling allow_execmem, allow_execstack, and allow_execheap across all domains."
            )
        )
    else:
        report.add_passed()

    # Rule 4: LH-SELINUX-004 (HIGH, 10 pts, CWE-269)
    neverallow_int = bool(config.get("neverallow_kernel_integrity", False))
    if not neverallow_int:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-004",
                title="Missing Compile-Time Neverallow Assertions for Kernel Integrity",
                severity="HIGH",
                weight=10,
                cwe="CWE-269",
                description="CIL policy lacks compile-time neverallow invariants blocking sys_module, sys_rawio, /dev/mem, or raw block device access.",
                remediation="Define explicit neverallow assertions for sys_module, sys_rawio, /dev/mem, and ota_block_device_t in 20_neverallow_assertions.cil."
            )
        )
    else:
        report.add_passed()

    # Rule 5: LH-SELINUX-005 (HIGH, 10 pts, CWE-285)
    ai_iso = bool(config.get("ai_infer_network_isolated", False))
    can_iso = bool(config.get("canbus_domain_isolated", False))
    if not ai_iso or not can_iso:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-005",
                title="Edge AI Inference Domain Missing Network and Bus Isolation",
                severity="HIGH",
                weight=10,
                cwe="CWE-285",
                description="Edge AI inference domain (lh_ai_infer_t) has network socket or CAN bus permissions, or CAN bus actuator domain has external network sockets.",
                remediation="Isolate lh_ai_infer_t from tcp_socket/can_socket; restrict lh_canbus_ctrl_t to real-time CAN bus and watchdog devices only."
            )
        )
    else:
        report.add_passed()

    # Rule 6: LH-SELINUX-006 (HIGH, 10 pts, CWE-276)
    tmp_exec = bool(config.get("allow_tmp_execute_no_trans", False))
    entry_trans = bool(config.get("strict_entrypoint_transitions", False))
    if tmp_exec or not entry_trans:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-006",
                title="Execute-No-Trans Permitted on Writable Mounts or Missing Strict Entrypoint Transitions",
                severity="HIGH",
                weight=10,
                cwe="CWE-276",
                description="execute_no_trans is permitted on writable /tmp, /var, or scratch mounts, or service processes lack explicit entrypoint typetransition rules.",
                remediation="Forbid execute_no_trans on tmpfs_t; enforce explicit typetransition rules for all service executables."
            )
        )
    else:
        report.add_passed()

    # Rule 7: LH-SELINUX-007 (HIGH, 10 pts, CWE-250)
    ptrace_denied = bool(config.get("deny_ptrace_enforced", False))
    if not ptrace_denied:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-007",
                title="Cross-Domain ptrace or Process Inspection Permitted",
                severity="HIGH",
                weight=10,
                cwe="CWE-250",
                description="Policy permits ptrace or cross-domain process inspection, allowing memory snooping and credential theft.",
                remediation="Assert (neverallow all_domains_attr all_domains_attr (process (ptrace))) and deny sys_ptrace capability across non-debug domains."
            )
        )
    else:
        report.add_passed()

    # Rule 8: LH-SELINUX-008 (MEDIUM, 4 pts, CWE-732)
    handle_unk = str(config.get("handle_unknown", "")).lower()
    unlabeled_files = int(config.get("unlabeled_t_files_count", 0))
    if handle_unk != "deny" or unlabeled_files > 0:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-008",
                title="Permissive Unknown Kernel Objects or Unlabeled Files Present on RootFS",
                severity="MEDIUM",
                weight=4,
                cwe="CWE-732",
                description="Policy specifies handleunknown allow/reject instead of deny, or unlabeled filesystem nodes (unlabeled_t) exist on the root filesystem.",
                remediation="Set (handleunknown deny) in base CIL policy; relabel root filesystem using canonical policy/file_contexts."
            )
        )
    else:
        report.add_passed()

    # Rule 9: LH-SELINUX-009 (MEDIUM, 4 pts, CWE-693)
    policyload = bool(config.get("secure_mode_policyload", False))
    insmod_lock = bool(config.get("secure_mode_insmod", False))
    if not policyload or not insmod_lock:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-009",
                title="Runtime Policy Reload or SELinux Booleans Modifiable",
                severity="MEDIUM",
                weight=4,
                cwe="CWE-693",
                description="Runtime policy reload or kernel module loading is not locked after initialization, exposing policy to in-memory tampering.",
                remediation="Lock policy reload via secure_mode_policyload=true; lock module loading via secure_mode_insmod=true."
            )
        )
    else:
        report.add_passed()

    # Rule 10: LH-SELINUX-010 (LOW, 1 pt, CWE-778)
    strip_dontaudit = bool(config.get("strip_dontaudit_in_production", False))
    audit_logging = bool(config.get("avc_audit_logging", False))
    if not strip_dontaudit or not audit_logging:
        report.add_failed(
            PostureFinding(
                rule_id="LH-SELINUX-010",
                title="Excessive dontaudit Masking Security Probes or Audit Logging Disabled",
                severity="LOW",
                weight=1,
                cwe="CWE-778",
                description="dontaudit rules remain enabled in production policy masking privilege escalation probes, or auditd kernel event logging is inactive.",
                remediation="Strip dontaudit rules in production embedded builds; ensure auditd daemon is active and capturing AVC denials."
            )
        )
    else:
        report.add_passed()

    report.finalize()
    return report
