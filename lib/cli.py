#!/usr/bin/env python3
"""
Logihertz SELinux Reference Policy & Posture Auditor CLI
Module: cli.py
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
"""

import sys
import os
import argparse
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
LIB_DIR = SCRIPT_DIR
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

from cil_engine import (
    CILPolicy,
    CILError,
    CILSyntaxError,
    NeverallowViolation,
    analyze_avc_log,
    check_file_contexts
)
from selinux_auditor import audit_selinux_manifest
from exporters import (
    render_audit_table,
    export_json,
    export_sarif,
    render_cil_summary,
    render_avc_summary
)

VERSION = "0.1.0"
TOOL_NAME = "lh-selinux"
ORG_NAME = "Logihertz Systems (OPC) Private Limited"


def print_banner():
    print(f"Logihertz Embedded SELinux Policy & MAC Auditor ({TOOL_NAME} v{VERSION})")
    print(f"Copyright (C) 2026 {ORG_NAME}\n")


def cmd_scan(args) -> int:
    manifest_path = args.manifest
    if not os.path.isfile(manifest_path):
        sys.stderr.write(f"Error: Policy manifest not found: {manifest_path}\n")
        return 2

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse manifest JSON: {e}\n")
        return 2

    report = audit_selinux_manifest(config)
    use_color = sys.stdout.isatty() and not args.no_color

    if args.format == "json":
        output_text = export_json(report)
    elif args.format == "sarif":
        output_text = export_sarif(report)
    else:
        output_text = render_audit_table(report, use_color=use_color)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_text + "\n")
        except Exception as e:
            sys.stderr.write(f"Error: Failed to write output file: {e}\n")
            return 2
    else:
        print(output_text)

    return 0 if report.score == 100 else 1


def cmd_verify_cil(args) -> int:
    cil_dir = args.cil_dir
    if not os.path.isdir(cil_dir):
        sys.stderr.write(f"Error: CIL directory not found: {cil_dir}\n")
        return 2

    policy = CILPolicy()

    # Collect .cil files in sorted order
    cil_files = sorted([
        os.path.join(cil_dir, f)
        for f in os.listdir(cil_dir)
        if f.endswith('.cil')
    ])

    if not cil_files:
        sys.stderr.write(f"Error: No .cil files found in {cil_dir}\n")
        return 2

    if args.extra_cil:
        if not os.path.isfile(args.extra_cil):
            sys.stderr.write(f"Error: Extra CIL file not found: {args.extra_cil}\n")
            return 2
        cil_files.append(args.extra_cil)

    try:
        for cfp in cil_files:
            policy.add_cil_file(cfp)
        policy.finalize()
    except CILSyntaxError as e:
        sys.stderr.write(f"Syntax Error in CIL policy: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Error loading CIL policy: {e}\n")
        return 2

    violations = policy.verify_neverallows()
    use_color = sys.stdout.isatty() and not args.no_color
    print(render_cil_summary(policy, violations, use_color=use_color))

    return 0 if len(violations) == 0 else 1


def cmd_audit2cil(args) -> int:
    log_path = args.log_file
    if not os.path.isfile(log_path):
        sys.stderr.write(f"Error: Audit log file not found: {log_path}\n")
        return 2

    policy_dir = args.policy_dir
    if not os.path.isdir(policy_dir):
        sys.stderr.write(f"Error: Policy directory not found: {policy_dir}\n")
        return 2

    policy = CILPolicy()
    cil_files = sorted([
        os.path.join(policy_dir, f)
        for f in os.listdir(policy_dir)
        if f.endswith('.cil')
    ])

    try:
        for cfp in cil_files:
            policy.add_cil_file(cfp)
        policy.finalize()
    except Exception as e:
        sys.stderr.write(f"Error loading CIL policy: {e}\n")
        return 2

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log_text = f.read()
    except Exception as e:
        sys.stderr.write(f"Error reading audit log: {e}\n")
        return 2

    results = analyze_avc_log(policy, log_text)
    use_color = sys.stdout.isatty() and not args.no_color
    print(render_avc_summary(results, use_color=use_color))

    # If any denial was blocked by neverallow, signal potential intrusion (exit 1)
    has_blocked = any(not res.is_safe for res in results)
    return 1 if has_blocked else 0


def cmd_check_contexts(args) -> int:
    contexts_path = args.contexts_file
    if not os.path.isfile(contexts_path):
        sys.stderr.write(f"Error: file_contexts not found: {contexts_path}\n")
        return 2

    policy_dir = args.policy_dir
    policy = CILPolicy()

    if os.path.isdir(policy_dir):
        cil_files = sorted([
            os.path.join(policy_dir, f)
            for f in os.listdir(policy_dir)
            if f.endswith('.cil')
        ])
        for cfp in cil_files:
            try:
                policy.add_cil_file(cfp)
            except Exception:
                pass
        policy.finalize()

    valid, errors, valid_count = check_file_contexts(policy, contexts_path)

    if valid:
        print(f"[+] SUCCESS: {valid_count} file context labeling rules validated successfully.")
        print(f"    All regex patterns compiled and all object types exist in CIL policy.")
        return 0
    else:
        sys.stderr.write(f"[-] VALIDATION FAILED: {len(errors)} errors found in {contexts_path}:\n")
        for err in errors:
            sys.stderr.write(f"    - {err}\n")
        return 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in ("--version", "-v"):
        print(f"{TOOL_NAME} v{VERSION}")
        return 0

    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"Logihertz SELinux CIL Reference Policy & Posture Auditor ({TOOL_NAME} v{VERSION})",
        epilog=f"Copyright (C) 2026 {ORG_NAME}"
    )
    parser.add_argument("--version", "-v", action="version", version=f"{TOOL_NAME} v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Audit appliance SELinux policy manifest against 10 posture rules")
    p_scan.add_argument("manifest", help="Path to policy manifest JSON")
    p_scan.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="Output report format")
    p_scan.add_argument("--output", help="Write report to file")
    p_scan.add_argument("--no-color", action="store_true", help="Disable ANSI color codes")

    # verify-cil
    p_verify = subparsers.add_parser("verify-cil", help="Verify CIL S-expression syntax and evaluate neverallow disjointness proof")
    p_verify.add_argument("cil_dir", help="Directory containing .cil policy modules")
    p_verify.add_argument("--extra-cil", help="Optional additional CIL file to evaluate against baseline")
    p_verify.add_argument("--no-color", action="store_true", help="Disable ANSI color codes")

    # audit2cil
    p_audit = subparsers.add_parser("audit2cil", help="Analyze auditd AVC denials and synthesize safe CIL rules")
    p_audit.add_argument("log_file", help="Path to auditd AVC denial log")
    p_audit.add_argument("--policy-dir", default=os.path.join(PROJECT_ROOT, "policy", "cil"), help="Path to baseline CIL directory")
    p_audit.add_argument("--no-color", action="store_true", help="Disable ANSI color codes")

    # check-contexts
    p_check = subparsers.add_parser("check-contexts", help="Validate file_contexts regex patterns and security label types")
    p_check.add_argument("contexts_file", help="Path to file_contexts specification")
    p_check.add_argument("--policy-dir", default=os.path.join(PROJECT_ROOT, "policy", "cil"), help="Path to baseline CIL directory")

    if len(sys.argv) < 2:
        print_banner()
        parser.print_help()
        return 2

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "verify-cil":
        return cmd_verify_cil(args)
    elif args.command == "audit2cil":
        return cmd_audit2cil(args)
    elif args.command == "check-contexts":
        return cmd_check_contexts(args)
    else:
        print_banner()
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
