# lh-selinux-embedded-policy (`lh-selinux`)

**Production-Grade, Zero-Dependency SELinux Common Intermediate Language (CIL) Reference Policy, Compile-Time `neverallow` Invariant Verifier, AVC Denial Analyzer, and 10-Rule Embedded MAC Posture Auditor**

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-selinux-embedded-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-selinux-embedded-policy/actions/workflows/ci.yml)
[![Standard](https://img.shields.io/badge/SELinux-CIL%20Reference%20Policy-blue.svg)](https://github.com/SELinuxProject/selinux)
[![Security Model](https://img.shields.io/badge/MAC-Type%20Enforcement%20%2B%20MLS-success.svg)](https://trustedcomputinggroup.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 1. Overview & Architectural Mission

`lh-selinux-embedded-policy` (`bin/lh-selinux`) provides a modular, production-grade **SELinux Common Intermediate Language (`.cil`) Reference Policy** tailored for sovereign edge AI appliances, autonomous robotics, UAV flight controllers, and embedded Linux platforms.

Operating with **100% zero external third-party dependencies** (portable POSIX shell + Python 3 standard library), this repository combines:

1. **Modular CIL Reference Policy (`policy/cil/`)**:
   - `00_base_classes_and_types.cil`: Declares security classes, access vectors, MLS/MCS `s0` ranges, and strict `(handleunknown deny)`.
   - `10_robotics_ai_domains.cil`: Implements least-privilege confined subject domains (`lh_init_t`, `lh_ai_infer_t`, `lh_canbus_ctrl_t`, `lh_sensor_ingest_t`, `lh_ota_updater_t`) with explicit executable entrypoints and typetransitions.
   - `20_neverallow_assertions.cil`: Enforces formal compile-time invariants (W^X memory protection, blocking `/dev/mem` and `sys_module`, OTA block device isolation, and cross-domain anti-debugging).
   - `policy/file_contexts`: Canonical filesystem security labeling rules.
2. **Compile-Time `neverallow` Disjointness Verifier**:
   - Recursive S-expression AST tokenizer and parser verifying balanced parentheses and valid class/permission sets.
   - Formal mathematical disjointness proof verifying that no allowed rule intersects any forbidden `neverallow` capability.
3. **Safe `audit2cil` AVC Denial Synthesizer**:
   - Analyzes kernel auditd AVC denial records, synthesizes minimal safe CIL `(allow ...)` rules for benign faults, and flags/rejects candidate rules that violate active `neverallow` invariants.
4. **10-Rule Mandatory Access Control Posture Auditor**:
   - Normative auditor evaluating appliance configuration manifests against rules `LH-SELINUX-001` through `LH-SELINUX-010`.
   - Exports results to ANSI box tables, Canonical JSON, and OASIS SARIF v2.1.0.

```
+----------------------------------------------------------------------------------------------------+
|                              LOGIHERTZ SELINUX CIL ARCHITECTURE                                    |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|    +-----------------------------+           +------------------------------+                      |
|    |  Modular CIL Source Policy  |           |  Canonical file_contexts     |                      |
|    |  00_base, 10_domains, 20_inv|           |  system_u:object_r:<type>:s0 |                      |
|    +--------------+--------------+           +--------------+---------------+                      |
|                   |                                         |                                      |
|                   v                                         v                                      |
|    +------------------------------------------------------------------------+                      |
|    |                  CIL S-Expression AST Parser & Resolver                |                      |
|    |             Tokenizes, parses AST, resolves typeattribute sets         |                      |
|    +------------------------------------+-----------------------------------+                      |
|                                         |                                                          |
|                    +--------------------+--------------------+                                     |
|                    |                                         |                                     |
|                    v                                         v                                     |
|    +--------------------------------+       +--------------------------------+                     |
|    |   Compile-Time Invariant Proof |       |   Safe audit2cil Synthesizer   |                     |
|    |   P_allow ∩ P_never == ∅       |       |   Kernel AVC Denial Analysis   |                     |
|    |   Neverallow Violation Engine  |       |   Intrusion Rejection Filter   |                     |
|    +----------------+---------------+       +----------------+---------------+                     |
|                     |                                        |                                     |
|                     v                                        v                                     |
|    +--------------------------------+       +--------------------------------+                     |
|    |   10-Rule Posture Auditor      |       |   Multi-Format Exporters       |                     |
|    |   LH-SELINUX-001..010          |       |   ANSI Table / JSON / SARIF    |                     |
|    +--------------------------------+       +--------------------------------+                     |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Mathematical Formalisms & Security Invariant Proofs

### 2.1. Access Vector Matrix Formulation
Let $\mathcal{S}$ be the set of subject domains, $\mathcal{T}$ be the set of target types, and $\mathcal{C}$ be the set of security classes. The access control function defines the permitted access vectors:
$$M: \mathcal{S} \times \mathcal{T} \times \mathcal{C} \longrightarrow \mathcal{P}(\mathcal{V}_c)$$
where $\mathcal{V}_c$ is the permission bitmask for security class $c \in \mathcal{C}$.

### 2.2. Compile-Time `neverallow` Disjointness Proof
Let $\mathcal{A}$ be the expanded set of allow rules and $\mathcal{N}$ be the set of invariant `neverallow` assertions after resolving type attributes and the `self` pseudo-target:
$$\mathcal{A} = \left\{ (s, t, c, P_{\text{allow}}) \mid s \in \mathcal{S}, \, t \in \mathcal{T}, \, c \in \mathcal{C}, \, P_{\text{allow}} \subseteq \mathcal{V}_c \right\}$$
$$\mathcal{N} = \left\{ (S_{\text{neg}}, T_{\text{neg}}, c, P_{\text{never}}) \mid S_{\text{neg}} \subseteq \mathcal{S}, \, T_{\text{neg}} \subseteq \mathcal{T}, \, c \in \mathcal{C}, \, P_{\text{never}} \subseteq \mathcal{V}_c \right\}$$

The reference policy is provably secure if and only if for all rules:
$$\forall s \in S_{\text{neg}}, \; \forall t \in T_{\text{neg}}: \quad P_{\text{allow}}(s, t, c) \cap P_{\text{never}}(s, t, c) = \varnothing$$

If any intersection $\Delta P = P_{\text{allow}} \cap P_{\text{never}} \neq \varnothing$ occurs, the compiler rejects the policy and issues a `NeverallowViolation`.

### 2.3. Domain Privilege Density ($\rho_{\text{priv}}$)
The privilege density of a domain $s \in \mathcal{S}$ measures access exposure:
$$\rho_{\text{priv}}(s) = \sum_{t \in \mathcal{T}, \, c \in \mathcal{C}} |P_{\text{allow}}(s, t, c)|$$

The edge AI domain (`lh_ai_infer_t`) enforces strict privilege isolation with $\rho_{\text{priv}}(\text{lh\_ai\_infer\_t}) \ll \rho_{\text{priv}}(\text{lh\_init\_t})$, completely precluding network and actuator access.

---

## 3. 10-Rule Embedded MAC Posture Audit Matrix

Evaluated via `lib/selinux_auditor.py`:

| Rule ID | Severity | Weight | CWE | Vulnerability Condition Checked | Deterministic Remediation |
|:---|:---:|:---:|:---:|:---|:---|
| **`LH-SELINUX-001`** | CRITICAL | 25 pts | CWE-284 | `selinux_mode != "enforcing"` \|\| `security_selinux_develop: true` | Set `SELINUX=enforcing` in `/etc/selinux/config`; compile production kernel without `CONFIG_SECURITY_SELINUX_DEVELOP`. |
| **`LH-SELINUX-002`** | CRITICAL | 25 pts | CWE-250 | `unconfined_domains_enabled: true` \|\| `unconfined_processes_count > 0` | Eliminate `unconfined_t`; confine all processes into discrete domains with least-privilege rules. |
| **`LH-SELINUX-003`** | CRITICAL | 25 pts | CWE-119 | `allow_execmem: true` \|\| `allow_execstack: true` \|\| `allow_execheap: true` | Enforce strict W^X memory protection by disabling executable heap, stack, and anonymous memory. |
| **`LH-SELINUX-004`** | HIGH | 10 pts | CWE-269 | `neverallow_kernel_integrity: false` | Assert compile-time neverallows for `sys_module`, `sys_rawio`, `/dev/mem`, and raw block storage. |
| **`LH-SELINUX-005`** | HIGH | 10 pts | CWE-285 | `ai_infer_network_isolated: false` \|\| `canbus_domain_isolated: false` | Isolate `lh_ai_infer_t` from external sockets; isolate `lh_canbus_ctrl_t` from WAN interfaces. |
| **`LH-SELINUX-006`** | HIGH | 10 pts | CWE-276 | `allow_tmp_execute_no_trans: true` \|\| `strict_entrypoint_transitions: false` | Deny `execute_no_trans` on writable mounts (`tmpfs_t`); enforce explicit typetransitions. |
| **`LH-SELINUX-007`** | HIGH | 10 pts | CWE-250 | `deny_ptrace_enforced: false` | Assert `(neverallow all_domains_attr all_domains_attr (process (ptrace)))` to prevent cross-domain debugging. |
| **`LH-SELINUX-008`** | MEDIUM | 4 pts | CWE-732 | `handle_unknown != "deny"` \|\| `unlabeled_t_files_count > 0` | Enforce `(handleunknown deny)`; relabel rootfs according to canonical `file_contexts`. |
| **`LH-SELINUX-009`** | MEDIUM | 4 pts | CWE-693 | `secure_mode_policyload: false` \|\| `secure_mode_insmod: false` | Lock runtime policy reload via `secure_mode_policyload=true` and kernel module loading. |
| **`LH-SELINUX-010`** | LOW | 1 pt | CWE-778 | `strip_dontaudit_in_production: false` \|\| `avc_audit_logging: false` | Strip `dontaudit` rules in production builds; verify `auditd` actively captures AVC denials. |

### Scoring & Posture Classification
$$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$
- **Score = 100**: `HARDENED` (Exit 0)
- **Score 80–99**: `ACCEPTABLE` (Exit 1)
- **Score 50–79**: `DEGRADED` (Exit 1)
- **Score 0–49**: `NON-COMPLIANT` (Exit 1)

---

## 4. CLI Reference & Usage

`bin/lh-selinux` provides a unified command-line interface:

### 4.1. Audit Appliance Posture (`scan`)
```bash
# Terminal table output with ANSI coloring
./bin/lh-selinux scan fixtures/hardened_selinux_policy.json

# Export to Canonical JSON
./bin/lh-selinux scan fixtures/hardened_selinux_policy.json --format json --output report.json

# Export to OASIS SARIF v2.1.0 for CI/CD scanners
./bin/lh-selinux scan fixtures/vulnerable_selinux_policy.json --format sarif --output report.sarif
```

### 4.2. Verify CIL Invariants (`verify-cil`)
```bash
# Verify reference policy baseline (passes compile-time neverallow disjointness proof)
./bin/lh-selinux verify-cil policy/cil/

# Test an additional module against baseline invariants (detects violations)
./bin/lh-selinux verify-cil policy/cil/ --extra-cil fixtures/violating_module.cil
```

### 4.3. Safe AVC Denial Synthesis (`audit2cil`)
```bash
# Analyze kernel auditd AVC denials against active neverallows
./bin/lh-selinux audit2cil fixtures/sample_avc_denials.log --policy-dir policy/cil/
```

### 4.4. Validate Filesystem Labeling Contexts (`check-contexts`)
```bash
# Validate regular expressions and check that all labeled types exist in CIL policy
./bin/lh-selinux check-contexts policy/file_contexts --policy-dir policy/cil/
```

---

## 5. Verification Suite

Execute the test suite (validating syntax, reference CIL parsing, invariant proofs, AVC synthesis, and posture auditing):

```bash
# Run 97 deterministic assertions and CLI smoke tests
bash tests/run_tests.sh
```

---

## 6. License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
