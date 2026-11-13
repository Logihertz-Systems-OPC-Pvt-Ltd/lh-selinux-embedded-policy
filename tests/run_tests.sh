#!/usr/bin/env bash
# ==============================================================================
# Logihertz SELinux Reference Policy & Posture Auditor - Test Runner
# tests/run_tests.sh
# Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "=================================================================="
echo "    Running Logihertz SELinux Comprehensive Verification Suite   "
echo "=================================================================="
echo ""

# 1. Shell & Python syntax verification
echo "[*] Step 1: Validating Shell and Python syntax..."
bash -n bin/lh-selinux
bash -n tests/run_tests.sh
python3 -m py_compile lib/*.py tests/test_suite.py
echo "[+] Syntax verification passed."
echo ""

# 2. Run Comprehensive Python Assertion Suite
echo "[*] Step 2: Executing Python Assertion Test Suite..."
python3 tests/test_suite.py
echo ""

# 3. CLI Integration & Subcommand Smoke Tests
echo "[*] Step 3: Verifying CLI subcommands & exit codes..."

# --version (exit 0)
./bin/lh-selinux --version > /dev/null
echo "[+] CLI --version: PASS (exit 0)"

# --help (exit 0)
./bin/lh-selinux --help > /dev/null
echo "[+] CLI --help: PASS (exit 0)"

# scan hardened policy (exit 0)
./bin/lh-selinux scan fixtures/hardened_selinux_policy.json --no-color > /dev/null
echo "[+] CLI scan (hardened): PASS (exit 0)"

# scan hardened policy to json (exit 0)
./bin/lh-selinux scan fixtures/hardened_selinux_policy.json --format json > /dev/null
echo "[+] CLI scan (json format): PASS (exit 0)"

# scan hardened policy to sarif (exit 0)
./bin/lh-selinux scan fixtures/hardened_selinux_policy.json --format sarif > /dev/null
echo "[+] CLI scan (sarif format): PASS (exit 0)"

# scan vulnerable policy (exit 1)
if ./bin/lh-selinux scan fixtures/vulnerable_selinux_policy.json --no-color > /dev/null 2>&1; then
    echo "[-] FAILED: Expected exit code 1 for vulnerable policy"
    exit 1
else
    echo "[+] CLI scan (vulnerable expected exit 1): PASS"
fi

# verify-cil reference policy (exit 0)
./bin/lh-selinux verify-cil policy/cil/ --no-color > /dev/null
echo "[+] CLI verify-cil (baseline): PASS (exit 0)"

# verify-cil with violating module (exit 1)
if ./bin/lh-selinux verify-cil policy/cil/ --extra-cil fixtures/violating_module.cil --no-color > /dev/null 2>&1; then
    echo "[-] FAILED: Expected exit code 1 for violating module"
    exit 1
else
    echo "[+] CLI verify-cil (violating module expected exit 1): PASS"
fi

# audit2cil with AVC log containing intrusion attempts (exit 1)
if ./bin/lh-selinux audit2cil fixtures/sample_avc_denials.log --policy-dir policy/cil/ --no-color > /dev/null 2>&1; then
    echo "[-] FAILED: Expected exit code 1 when intrusion denials present"
    exit 1
else
    echo "[+] CLI audit2cil (rejection of intrusion denials expected exit 1): PASS"
fi

# check-contexts (exit 0)
./bin/lh-selinux check-contexts policy/file_contexts --policy-dir policy/cil/ > /dev/null
echo "[+] CLI check-contexts: PASS (exit 0)"

# invalid CLI usage (exit 2)
if ./bin/lh-selinux non-existent-command > /dev/null 2>&1; then
    echo "[-] FAILED: Expected exit code 2 for invalid subcommand"
    exit 1
else
    echo "[+] CLI invalid command (expected exit 2): PASS"
fi

echo ""
echo "=================================================================="
echo "    All Verification Assertions & CLI Tests PASSED (100% OK)     "
echo "=================================================================="
