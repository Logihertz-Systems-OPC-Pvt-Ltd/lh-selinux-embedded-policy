# Contributing to lh-selinux-embedded-policy

Thank you for your interest in contributing to `lh-selinux-embedded-policy`, the embedded Linux SELinux CIL reference policy and MAC posture auditor.

## Core Governance & Policy Mandates

1. **Zero External Dependencies**:
   - Reference policy modules in `policy/cil/` must adhere strictly to valid SELinux Common Intermediate Language (CIL) syntax.
   - All parser, verifier, and auditor logic in `lib/` and `bin/` must use standard Python 3.10+ standard libraries and POSIX shell only.
   - Do not introduce dependencies on external package managers or non-standard tools.

2. **Strict Invariant Verification**:
   - Any new policy rule must not conflict with compile-time `neverallow` invariants defined in `policy/cil/20_neverallow_assertions.cil`.
   - Never allow W^X violations (`execmem`, `execstack`, `execheap`).
   - Never grant `sys_module` or `sys_rawio` outside of initialization bootstrap.
   - Never grant `ptrace` across security domains.

3. **Submitting Changes**:
   - Run the verification test suite before committing:
     ```bash
     bash tests/run_tests.sh
     ```
   - All tests must pass with zero failures.
   - Ensure `bash -n bin/lh-selinux tests/run_tests.sh` passes without errors.
   - Ensure Python syntax validation passes: `python3 -m py_compile lib/*.py`.
