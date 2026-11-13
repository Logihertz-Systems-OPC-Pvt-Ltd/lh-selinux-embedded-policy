#!/usr/bin/env python3
"""
Logihertz SELinux Comprehensive Verification Test Suite
tests/test_suite.py
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
"""

import sys
import os
import json
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
LIB_DIR = os.path.join(PROJECT_ROOT, "lib")
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

from cil_engine import (
    CILPolicy,
    CILError,
    CILSyntaxError,
    NeverallowViolation,
    tokenize_cil,
    parse_sexp,
    parse_avc_log,
    analyze_avc_log,
    check_file_contexts
)
from selinux_auditor import audit_selinux_manifest, PostureFinding
from exporters import (
    render_audit_table,
    export_json,
    export_sarif,
    render_cil_summary,
    render_avc_summary
)

TOTAL_ASSERTIONS = 0
PASSED_ASSERTIONS = 0
FAILED_ASSERTIONS = 0


def assert_true(condition: bool, message: str):
    global TOTAL_ASSERTIONS, PASSED_ASSERTIONS, FAILED_ASSERTIONS
    TOTAL_ASSERTIONS += 1
    if condition:
        PASSED_ASSERTIONS += 1
    else:
        FAILED_ASSERTIONS += 1
        sys.stderr.write(f"[-] ASSERTION FAILED: {message}\n")


# ------------------------------------------------------------------------------
# Test 1: S-Expression Tokenizer & AST Parser
# ------------------------------------------------------------------------------
def test_tokenizer_and_parser():
    # Basic tokenization
    t1 = tokenize_cil("(handleunknown deny)")
    assert_true(t1 == ['(', 'handleunknown', 'deny', ')'], "Basic tokenization")

    # Comments stripping
    t2 = tokenize_cil(";; Comment line\n(mls true) ; inline comment\n")
    assert_true(t2 == ['(', 'mls', 'true', ')'], "Comment stripping in tokenization")

    # AST parsing
    ast1 = parse_sexp(t1)
    assert_true(ast1 == [['handleunknown', 'deny']], "AST parsing simple statement")

    # Nested AST parsing
    tokens_nested = tokenize_cil("(allow src tgt (file (read write)))")
    ast_nested = parse_sexp(tokens_nested)
    assert_true(ast_nested == [['allow', 'src', 'tgt', ['file', ['read', 'write']]]], "Nested AST parsing")

    # Unbalanced open parenthesis
    try:
        parse_sexp(['(', 'allow', 's', 't'])
        assert_true(False, "Should raise CILSyntaxError on unclosed parenthesis")
    except CILSyntaxError:
        assert_true(True, "Catches unclosed parenthesis syntax error")

    # Unbalanced close parenthesis
    try:
        parse_sexp(['(', 'allow', ')', ')'])
        assert_true(False, "Should raise CILSyntaxError on extra close parenthesis")
    except CILSyntaxError:
        assert_true(True, "Catches extra close parenthesis syntax error")

    # Unexpected top-level token
    try:
        parse_sexp(['bare_token'])
        assert_true(False, "Should raise CILSyntaxError on bare top-level token")
    except CILSyntaxError:
        assert_true(True, "Catches bare token outside parenthesis")

    # Empty content
    assert_true(parse_sexp([]) == [], "Empty token list produces empty AST")
    assert_true(tokenize_cil("   \n;; Only comments\n") == [], "Whitespace and comments produce empty tokens")


# ------------------------------------------------------------------------------
# Test 2: Base Classes, Permissions & Configuration
# ------------------------------------------------------------------------------
def test_base_classes_and_types():
    policy = CILPolicy()
    base_cil = os.path.join(PROJECT_ROOT, "policy", "cil", "00_base_classes_and_types.cil")
    policy.add_cil_file(base_cil)
    policy.finalize()

    assert_true(policy.handle_unknown == "deny", "handleunknown is deny")
    assert_true(policy.mls is True, "mls is true")
    assert_true("process" in policy.classes, "Security class 'process' declared")
    assert_true("execmem" in policy.classes["process"], "Class process contains 'execmem'")
    assert_true("ptrace" in policy.classes["process"], "Class process contains 'ptrace'")
    assert_true("file" in policy.classes, "Security class 'file' declared")
    assert_true("can_socket" in policy.classes, "Security class 'can_socket' declared")
    assert_true("gpu_device_t" in policy.types, "Type 'gpu_device_t' declared")
    assert_true("ota_block_device_t" in policy.types, "Type 'ota_block_device_t' declared")
    assert_true("kernel_mem_device_t" in policy.types, "Type 'kernel_mem_device_t' declared")


# ------------------------------------------------------------------------------
# Test 3: Type Attributes & Attribute Set Resolution
# ------------------------------------------------------------------------------
def test_type_attributes():
    policy = CILPolicy()
    base_cil = os.path.join(PROJECT_ROOT, "policy", "cil", "00_base_classes_and_types.cil")
    domains_cil = os.path.join(PROJECT_ROOT, "policy", "cil", "10_robotics_ai_domains.cil")
    policy.add_cil_file(base_cil)
    policy.add_cil_file(domains_cil)
    policy.finalize()

    assert_true("all_domains_attr" in policy.attributes, "all_domains_attr declared")
    assert_true("non_init_domains_attr" in policy.attributes, "non_init_domains_attr declared")
    assert_true("non_ota_domains_attr" in policy.attributes, "non_ota_domains_attr declared")

    all_domains = policy.expand_types("all_domains_attr")
    assert_true("lh_init_t" in all_domains, "lh_init_t in all_domains_attr")
    assert_true("lh_ai_infer_t" in all_domains, "lh_ai_infer_t in all_domains_attr")
    assert_true("lh_canbus_ctrl_t" in all_domains, "lh_canbus_ctrl_t in all_domains_attr")
    assert_true("lh_sensor_ingest_t" in all_domains, "lh_sensor_ingest_t in all_domains_attr")
    assert_true("lh_ota_updater_t" in all_domains, "lh_ota_updater_t in all_domains_attr")

    non_init = policy.expand_types("non_init_domains_attr")
    assert_true("lh_init_t" not in non_init, "lh_init_t not in non_init_domains_attr")
    assert_true("lh_ai_infer_t" in non_init, "lh_ai_infer_t in non_init_domains_attr")

    non_ota = policy.expand_types("non_ota_domains_attr")
    assert_true("lh_ota_updater_t" not in non_ota, "lh_ota_updater_t not in non_ota_domains_attr")
    assert_true("lh_canbus_ctrl_t" in non_ota, "lh_canbus_ctrl_t in non_ota_domains_attr")


# ------------------------------------------------------------------------------
# Test 4: Baseline Reference Policy Invariant Proof (Zero Violations)
# ------------------------------------------------------------------------------
def test_baseline_policy_invariants():
    policy = CILPolicy()
    cil_dir = os.path.join(PROJECT_ROOT, "policy", "cil")
    for fname in sorted(os.listdir(cil_dir)):
        if fname.endswith(".cil"):
            policy.add_cil_file(os.path.join(cil_dir, fname))
    policy.finalize()

    assert_true(len(policy.types) >= 15, "Declared types >= 15")
    assert_true(len(policy.allow_rules) >= 15, "Allow rules >= 15")
    assert_true(len(policy.neverallow_rules) >= 5, "Neverallow rules >= 5")
    assert_true(len(policy.policy_hash) == 64, "Policy hash is 64 hex chars")

    # Evaluate neverallow disjointness proof on baseline reference policy
    violations = policy.verify_neverallows()
    assert_true(len(violations) == 0, "Baseline CIL reference policy has ZERO neverallow violations")

    # Verify domain transitions
    assert_true(len(policy.typetransitions) == 4, "Explicit typetransitions configured for 4 service domains")


# ------------------------------------------------------------------------------
# Test 5: Compile-Time Neverallow Violation Detection
# ------------------------------------------------------------------------------
def test_violating_module_detection():
    policy = CILPolicy()
    cil_dir = os.path.join(PROJECT_ROOT, "policy", "cil")
    for fname in sorted(os.listdir(cil_dir)):
        if fname.endswith(".cil"):
            policy.add_cil_file(os.path.join(cil_dir, fname))

    # Add intentionally violating module
    violating_cil = os.path.join(PROJECT_ROOT, "fixtures", "violating_module.cil")
    policy.add_cil_file(violating_cil)
    policy.finalize()

    violations = policy.verify_neverallows()
    assert_true(len(violations) >= 3, f"Violating module detected {len(violations)} >= 3 conflicts")

    # Check for execmem violation
    execmem_violations = [v for v in violations if "execmem" in v.forbidden_perms]
    assert_true(len(execmem_violations) > 0, "Catches execmem neverallow violation on lh_ai_infer_t")

    # Check for sys_module violation
    sys_module_violations = [v for v in violations if "sys_module" in v.forbidden_perms]
    assert_true(len(sys_module_violations) > 0, "Catches sys_module neverallow violation on lh_canbus_ctrl_t")

    # Check for raw block device write violation
    blk_write_violations = [v for v in violations if v.target == "ota_block_device_t" and "write" in v.forbidden_perms]
    assert_true(len(blk_write_violations) > 0, "Catches ota_block_device_t write neverallow violation")


# ------------------------------------------------------------------------------
# Test 6: AVC Denial Log Analyzer & Safe audit2cil Synthesis
# ------------------------------------------------------------------------------
def test_avc_analyzer():
    policy = CILPolicy()
    cil_dir = os.path.join(PROJECT_ROOT, "policy", "cil")
    for fname in sorted(os.listdir(cil_dir)):
        if fname.endswith(".cil"):
            policy.add_cil_file(os.path.join(cil_dir, fname))
    policy.finalize()

    log_path = os.path.join(PROJECT_ROOT, "fixtures", "sample_avc_denials.log")
    with open(log_path, 'r', encoding='utf-8') as f:
        log_text = f.read()

    denials = parse_avc_log(log_text)
    assert_true(len(denials) == 6, f"Parsed 6 AVC denials from log fixture, got {len(denials)}")

    results = analyze_avc_log(policy, log_text)
    assert_true(len(results) == 6, "Analyzed 6 AVC synthesis candidates")

    # Benign denial 1: sensor reading sensor_data_file_t
    assert_true(results[0].is_safe, "Benign sensor read is marked safe")
    assert_true("(allow lh_sensor_ingest_t sensor_data_file_t (file (read)))" in results[0].proposed_cil,
                "Synthesizes valid CIL allow rule for sensor read")

    # Malicious denial 2: AI requesting execmem
    assert_true(not results[1].is_safe, "execmem AVC denial is BLOCKED_BY_NEVERALLOW")
    assert_true("execmem" in results[1].reason, "Block reason identifies execmem invariant")

    # Malicious denial 3: CAN bus requesting sys_module
    assert_true(not results[2].is_safe, "sys_module AVC denial is BLOCKED_BY_NEVERALLOW")
    assert_true("sys_module" in results[2].reason, "Block reason identifies sys_module invariant")

    # Malicious denial 4: AI requesting write on ota_block_device_t
    assert_true(not results[3].is_safe, "OTA block write AVC denial is BLOCKED_BY_NEVERALLOW")
    assert_true("ota_block_device_t" in results[3].reason or "write" in results[3].reason,
                "Block reason identifies OTA block protection")

    # Malicious denial 5: sensor requesting ptrace on canbus
    assert_true(not results[4].is_safe, "ptrace AVC denial is BLOCKED_BY_NEVERALLOW")

    # Benign denial 6: CAN bus getattr on chr_file
    assert_true(results[5].is_safe, "canbus getattr on chr_file is marked safe")


# ------------------------------------------------------------------------------
# Test 7: file_contexts Validation
# ------------------------------------------------------------------------------
def test_file_contexts():
    policy = CILPolicy()
    cil_dir = os.path.join(PROJECT_ROOT, "policy", "cil")
    for fname in sorted(os.listdir(cil_dir)):
        if fname.endswith(".cil"):
            policy.add_cil_file(os.path.join(cil_dir, fname))
    policy.finalize()

    contexts_path = os.path.join(PROJECT_ROOT, "policy", "file_contexts")
    valid, errors, count = check_file_contexts(policy, contexts_path)
    assert_true(valid, f"policy/file_contexts is completely valid (errors: {errors})")
    assert_true(count >= 15, f"file_contexts has >= 15 valid rules (got {count})")
    assert_true(len(errors) == 0, "Zero errors in reference file_contexts")


# ------------------------------------------------------------------------------
# Test 8: 10 Individual Posture Auditor Rules
# ------------------------------------------------------------------------------
def test_auditor_rules():
    base_hardened = {
        "policy_name": "test_unit_policy",
        "selinux_mode": "enforcing",
        "security_selinux_develop": False,
        "unconfined_domains_enabled": False,
        "unconfined_processes_count": 0,
        "allow_execmem": False,
        "allow_execstack": False,
        "allow_execheap": False,
        "neverallow_kernel_integrity": True,
        "ai_infer_network_isolated": True,
        "canbus_domain_isolated": True,
        "allow_tmp_execute_no_trans": False,
        "strict_entrypoint_transitions": True,
        "deny_ptrace_enforced": True,
        "handle_unknown": "deny",
        "unlabeled_t_files_count": 0,
        "secure_mode_policyload": True,
        "secure_mode_insmod": True,
        "strip_dontaudit_in_production": True,
        "avc_audit_logging": True
    }

    # Rule 1: LH-SELINUX-001
    cfg = dict(base_hardened, selinux_mode="permissive")
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 75, "Rule 1 permissive mode deducts 25 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-001", "Rule 1 finding ID matches")

    # Rule 2: LH-SELINUX-002
    cfg = dict(base_hardened, unconfined_domains_enabled=True)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 75, "Rule 2 unconfined domains deducts 25 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-002", "Rule 2 finding ID matches")

    # Rule 3: LH-SELINUX-003
    cfg = dict(base_hardened, allow_execmem=True)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 75, "Rule 3 allow_execmem deducts 25 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-003", "Rule 3 finding ID matches")

    # Rule 4: LH-SELINUX-004
    cfg = dict(base_hardened, neverallow_kernel_integrity=False)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 90, "Rule 4 missing neverallow deducts 10 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-004", "Rule 4 finding ID matches")

    # Rule 5: LH-SELINUX-005
    cfg = dict(base_hardened, ai_infer_network_isolated=False)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 90, "Rule 5 AI network isolation deducts 10 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-005", "Rule 5 finding ID matches")

    # Rule 6: LH-SELINUX-006
    cfg = dict(base_hardened, allow_tmp_execute_no_trans=True)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 90, "Rule 6 tmp execute_no_trans deducts 10 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-006", "Rule 6 finding ID matches")

    # Rule 7: LH-SELINUX-007
    cfg = dict(base_hardened, deny_ptrace_enforced=False)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 90, "Rule 7 ptrace allowed deducts 10 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-007", "Rule 7 finding ID matches")

    # Rule 8: LH-SELINUX-008
    cfg = dict(base_hardened, handle_unknown="allow")
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 96, "Rule 8 handle_unknown allow deducts 4 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-008", "Rule 8 finding ID matches")

    # Rule 9: LH-SELINUX-009
    cfg = dict(base_hardened, secure_mode_policyload=False)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 96, "Rule 9 policyload unlocked deducts 4 pts")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-009", "Rule 9 finding ID matches")

    # Rule 10: LH-SELINUX-010
    cfg = dict(base_hardened, avc_audit_logging=False)
    rep = audit_selinux_manifest(cfg)
    assert_true(rep.score == 99, "Rule 10 audit logging disabled deducts 1 pt")
    assert_true(rep.findings[0].rule_id == "LH-SELINUX-010", "Rule 10 finding ID matches")


# ------------------------------------------------------------------------------
# Test 9: Full Policy Manifest Evaluations (Hardened vs Vulnerable)
# ------------------------------------------------------------------------------
def test_full_posture_evaluations():
    # Hardened Fixture
    hardened_path = os.path.join(PROJECT_ROOT, "fixtures", "hardened_selinux_policy.json")
    with open(hardened_path, 'r', encoding='utf-8') as f:
        hardened_cfg = json.load(f)
    rep_hardened = audit_selinux_manifest(hardened_cfg)
    assert_true(rep_hardened.score == 100, "Hardened policy scores 100/100")
    assert_true(rep_hardened.status == "HARDENED", "Hardened status is HARDENED")
    assert_true(rep_hardened.passed_rules == 10, "Hardened passes all 10 rules")
    assert_true(rep_hardened.failed_rules == 0, "Hardened has 0 failed rules")

    # Vulnerable Fixture
    vuln_path = os.path.join(PROJECT_ROOT, "fixtures", "vulnerable_selinux_policy.json")
    with open(vuln_path, 'r', encoding='utf-8') as f:
        vuln_cfg = json.load(f)
    rep_vuln = audit_selinux_manifest(vuln_cfg)
    assert_true(rep_vuln.score == 0, "Vulnerable policy scores 0/100")
    assert_true(rep_vuln.status == "NON-COMPLIANT", "Vulnerable status is NON-COMPLIANT")
    assert_true(rep_vuln.passed_rules == 0, "Vulnerable passes 0 rules")
    assert_true(rep_vuln.failed_rules == 10, "Vulnerable fails all 10 rules")
    assert_true(len(rep_vuln.findings) == 10, "Vulnerable produces 10 findings")

    # Partial score calculation: 1 CRITICAL + 1 HIGH = 100 - 35 = 65 -> DEGRADED
    cfg_degraded = dict(hardened_cfg, selinux_mode="permissive", ai_infer_network_isolated=False)
    rep_deg = audit_selinux_manifest(cfg_degraded)
    assert_true(rep_deg.score == 65, "1 CRITICAL + 1 HIGH = 65 pts")
    assert_true(rep_deg.status == "DEGRADED", "Score 65 is DEGRADED")

    # Partial score calculation: 1 MEDIUM + 1 LOW = 100 - 5 = 95 -> ACCEPTABLE
    cfg_acc = dict(hardened_cfg, handle_unknown="allow", avc_audit_logging=False)
    rep_acc = audit_selinux_manifest(cfg_acc)
    assert_true(rep_acc.score == 95, "1 MEDIUM + 1 LOW = 95 pts")
    assert_true(rep_acc.status == "ACCEPTABLE", "Score 95 is ACCEPTABLE")


# ------------------------------------------------------------------------------
# Test 10: Multi-Format Exporters
# ------------------------------------------------------------------------------
def test_exporters():
    hardened_path = os.path.join(PROJECT_ROOT, "fixtures", "hardened_selinux_policy.json")
    with open(hardened_path, 'r', encoding='utf-8') as f:
        hardened_cfg = json.load(f)
    rep_hardened = audit_selinux_manifest(hardened_cfg)

    vuln_path = os.path.join(PROJECT_ROOT, "fixtures", "vulnerable_selinux_policy.json")
    with open(vuln_path, 'r', encoding='utf-8') as f:
        vuln_cfg = json.load(f)
    rep_vuln = audit_selinux_manifest(vuln_cfg)

    # ANSI Table
    table_out = render_audit_table(rep_hardened, use_color=False)
    assert_true("100/100 (HARDENED)" in table_out, "Table contains 100/100 HARDENED")
    assert_true("Zero security posture deficiencies detected" in table_out, "Table shows zero deficiencies")

    # JSON export
    json_out = export_json(rep_vuln)
    parsed_json = json.loads(json_out)
    assert_true(parsed_json["score"] == 0, "Exported JSON has score 0")
    assert_true(parsed_json["status"] == "NON-COMPLIANT", "Exported JSON has status NON-COMPLIANT")
    assert_true(len(parsed_json["findings"]) == 10, "Exported JSON contains 10 findings")

    # SARIF export
    sarif_out = export_sarif(rep_vuln)
    parsed_sarif = json.loads(sarif_out)
    assert_true(parsed_sarif["version"] == "2.1.0", "SARIF version is 2.1.0")
    assert_true(len(parsed_sarif["runs"][0]["tool"]["driver"]["rules"]) == 10, "SARIF contains 10 rule definitions")
    assert_true(len(parsed_sarif["runs"][0]["results"]) == 10, "SARIF contains 10 results")


def main():
    print("==================================================================")
    print("      Logihertz SELinux Reference Policy & Auditor Test Suite     ")
    print("==================================================================\n")

    test_tokenizer_and_parser()
    test_base_classes_and_types()
    test_type_attributes()
    test_baseline_policy_invariants()
    test_violating_module_detection()
    test_avc_analyzer()
    test_file_contexts()
    test_auditor_rules()
    test_full_posture_evaluations()
    test_exporters()

    print("\n------------------------------------------------------------------")
    print(f"Summary: {TOTAL_ASSERTIONS} assertions run | {PASSED_ASSERTIONS} passed | {FAILED_ASSERTIONS} failed")
    print("------------------------------------------------------------------")

    return 0 if FAILED_ASSERTIONS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
