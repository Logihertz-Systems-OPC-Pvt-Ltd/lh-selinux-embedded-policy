# Security Policy: lh-selinux-embedded-policy

## Threat Model & Embedded Mandatory Access Control (MAC) Guarantees

`lh-selinux-embedded-policy` provides a reference SELinux Common Intermediate Language (`.cil`) policy, compile-time `neverallow` invariant verifier, and 10-rule posture auditor for edge AI appliances and autonomous robotics.

The security model assumes the following operational threats:
1. **Malicious or Compromised Edge AI Payload**: An edge AI inference pipeline (e.g. executing untrusted vision models) might suffer an exploitation attempt. The `lh_ai_infer_t` domain strictly isolates inference from network sockets (`tcp_socket`, `udp_socket`), control buses (`can_socket`), and shell interpreters (`bin_t`).
2. **Actuator & CAN Bus Tampering**: Actuators and hardware controllers run under `lh_canbus_ctrl_t`, isolated from unconfined processes and external network interfaces.
3. **Kernel Memory & Root of Trust Tampering**: Direct hardware access to `/dev/mem`, `/dev/kmem`, raw storage partitions (`ota_block_device_t`), and dynamic kernel module loading (`sys_module`) is categorically blocked by compile-time `neverallow` assertions.
4. **Permissive Degradation or Unconfined Escape**: Disabling SELinux, running in permissive mode, or spawning unconfined processes violates the core MAC boundary.

## Reporting a Vulnerability

If you discover a vulnerability, policy bypass, or neverallow flaw in `lh-selinux-embedded-policy`:
1. **Email**: Send detailed vulnerability reports to `security@logihertz.com` with a copy to `ops@logihertz.com`.
2. **PGP / Sensitive Submissions**: Request our PGP key prior to transmitting exploit payloads or sensitive proofs.
3. **Response Timeline**:
   - Initial acknowledgement within 24 hours.
   - Comprehensive vulnerability assessment and remediation plan within 72 hours.
   - Patch publication within 7 business days.
4. **Coordinated Disclosure**: Please do not publish public disclosures until an official fix is tagged and distributed.
