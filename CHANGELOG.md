# Changelog

All notable changes to `lh-selinux-embedded-policy` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Modular SELinux CIL Reference Policy**:
  - `policy/cil/00_base_classes_and_types.cil`: Core kernel object classes, access vectors, MLS/MCS s0 declarations, and `(handleunknown deny)`.
  - `policy/cil/10_robotics_ai_domains.cil`: Confined subject domains (`lh_init_t`, `lh_ai_infer_t`, `lh_canbus_ctrl_t`, `lh_sensor_ingest_t`, `lh_ota_updater_t`) with least-privilege device and IPC rules.
  - `policy/cil/20_neverallow_assertions.cil`: Compile-time `neverallow` invariants enforcing W^X, blocking `sys_module`/`sys_rawio`, protecting `/dev/mem` and `ota_block_device_t`, and prohibiting cross-domain `ptrace`.
  - `policy/file_contexts`: Canonical filesystem security labeling for edge appliances.
- **CIL S-Expression Engine (`lib/cil_engine.py`)**:
  - S-Expression recursive AST tokenizer and parser.
  - Compile-time `neverallow` disjointness proof engine ($\mathcal{A} \cap \mathcal{N} = \varnothing$).
  - Safe `audit2cil` AVC denial log analyzer with automated intrusion rejection against `neverallow` assertions.
  - `file_contexts` syntax validator and type declaration checker.
- **10-Rule Embedded MAC Posture Auditor (`lib/selinux_auditor.py`)**:
  - Normative evaluation of `LH-SELINUX-001` through `LH-SELINUX-010`.
  - Deterministic Logihertz Security Posture Score calculation ($S_{\text{posture}} \in [0, 100]$).
- **Multi-Format Exporters (`lib/exporters.py`)**:
  - ANSI Terminal Box Table formatter with colorized posture score banner.
  - Canonical JSON exporter.
  - OASIS SARIF v2.1.0 exporter for CI/CD integration.
- **Unified CLI (`bin/lh-selinux`)**:
  - Subcommands: `scan`, `verify-cil`, `audit2cil`, `check-contexts`, `--version`, `--help`.
- **Verification Suite (`tests/run_tests.sh`)**:
  - 85+ deterministic assertions validating policy syntax, neverallow violations, AVC analysis, posture rules, and CLI exit codes.
