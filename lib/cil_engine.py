#!/usr/bin/env python3
"""
Logihertz SELinux CIL Engine
Module: cil_engine.py
Zero-dependency Common Intermediate Language (CIL) S-expression parser,
neverallow disjointness verifier, AVC denial synthesizer, and file_contexts validator.
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited
"""

import os
import re
import hashlib
from typing import Dict, List, Set, Tuple, Optional, Any


class CILError(Exception):
    """Base exception for SELinux CIL errors."""
    pass


class CILSyntaxError(CILError):
    """Raised when S-expression syntax is invalid or parentheses unbalanced."""
    pass


class NeverallowViolation(CILError):
    """Raised when an allow rule violates a compile-time neverallow assertion."""
    def __init__(self, source: str, target: str, tclass: str, forbidden_perms: List[str], rule_src: str = ""):
        self.source = source
        self.target = target
        self.tclass = tclass
        self.forbidden_perms = forbidden_perms
        self.rule_src = rule_src
        super().__init__(
            f"Neverallow violation: (allow {source} {target} ({tclass} ({' '.join(forbidden_perms)}))) "
            f"conflicts with invariant assertion"
        )


def tokenize_cil(text: str) -> List[str]:
    """Tokenize CIL text into S-expression tokens, stripping comments."""
    tokens = []
    lines = text.splitlines()
    for line in lines:
        # Strip comments
        if ';' in line:
            line = line[:line.index(';')]
        line = line.strip()
        if not line:
            continue

        # Split on whitespace while preserving parentheses
        line = line.replace('(', ' ( ').replace(')', ' ) ')
        tokens.extend(line.split())
    return tokens


def parse_sexp(tokens: List[str]) -> List[Any]:
    """Parse token list into recursive S-expression AST."""
    stack: List[List[Any]] = [[]]

    for token in tokens:
        if token == '(':
            new_list: List[Any] = []
            stack[-1].append(new_list)
            stack.append(new_list)
        elif token == ')':
            if len(stack) <= 1:
                raise CILSyntaxError("Unbalanced parentheses: unexpected ')'")
            stack.pop()
        else:
            if len(stack) == 1:
                raise CILSyntaxError(f"Unexpected top-level token outside S-expression: {token}")
            stack[-1].append(token)

    if len(stack) != 1:
        raise CILSyntaxError("Unbalanced parentheses: missing closing ')'")

    return stack[0]


class RuleStatement:
    def __init__(self, kind: str, source: str, target: str, tclass: str, perms: Set[str], raw_text: str = ""):
        self.kind = kind  # 'allow' or 'neverallow'
        self.source = source
        self.target = target
        self.tclass = tclass
        self.perms = set(perms)
        self.raw_text = raw_text

    def __repr__(self):
        return f"({self.kind} {self.source} {self.target} ({self.tclass} ({' '.join(sorted(self.perms))})))"


class CILPolicy:
    """Represents a compiled/aggregated SELinux CIL reference policy."""

    def __init__(self):
        self.handle_unknown: str = "deny"
        self.mls: bool = True
        self.classes: Dict[str, Set[str]] = {}
        self.types: Set[str] = set()
        self.attributes: Dict[str, Set[str]] = {}
        self.roles: Set[str] = set()
        self.roletypes: Dict[str, Set[str]] = {}
        self.allow_rules: List[RuleStatement] = []
        self.neverallow_rules: List[RuleStatement] = []
        self.typetransitions: List[Tuple[str, str, str, str]] = []
        self.source_files: List[str] = []
        self.policy_hash: str = ""

    def add_cil_file(self, filepath: str) -> None:
        """Parse and ingest a single CIL policy file."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"CIL policy file not found: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        self.source_files.append(filepath)
        self.parse_cil_content(content)

    def parse_cil_content(self, content: str) -> None:
        """Parse raw CIL text and populate policy structures."""
        tokens = tokenize_cil(content)
        ast = parse_sexp(tokens)

        for stmt in ast:
            if not isinstance(stmt, list) or len(stmt) == 0:
                continue

            op = stmt[0]

            if op == 'handleunknown' and len(stmt) >= 2:
                self.handle_unknown = stmt[1]

            elif op == 'mls' and len(stmt) >= 2:
                self.mls = (stmt[1].lower() == 'true')

            elif op == 'class' and len(stmt) >= 3:
                cname = stmt[1]
                cperms = stmt[2] if isinstance(stmt[2], list) else stmt[2:]
                self.classes[cname] = set(cperms)

            elif op == 'type' and len(stmt) >= 2:
                self.types.add(stmt[1])

            elif op == 'typeattribute' and len(stmt) >= 2:
                if stmt[1] not in self.attributes:
                    self.attributes[stmt[1]] = set()

            elif op == 'typeattributeset' and len(stmt) >= 3:
                attr = stmt[1]
                val = stmt[2]
                members = val if isinstance(val, list) else stmt[2:]
                if attr not in self.attributes:
                    self.attributes[attr] = set()
                for m in members:
                    self.attributes[attr].add(m)

            elif op == 'role' and len(stmt) >= 2:
                self.roles.add(stmt[1])

            elif op == 'roletype' and len(stmt) >= 3:
                role = stmt[1]
                tt = stmt[2]
                if role not in self.roletypes:
                    self.roletypes[role] = set()
                self.roletypes[role].add(tt)

            elif op == 'typetransition' and len(stmt) >= 5:
                # (typetransition src target class default)
                self.typetransitions.append((stmt[1], stmt[2], stmt[3], stmt[4]))

            elif op in ('allow', 'neverallow') and len(stmt) >= 4:
                # (allow s t (c (p1 p2 ...)))
                src = stmt[1]
                tgt = stmt[2]
                class_perm = stmt[3]

                if isinstance(class_perm, list) and len(class_perm) >= 2:
                    tclass = class_perm[0]
                    perms_item = class_perm[1]
                    perms = set(perms_item if isinstance(perms_item, list) else class_perm[1:])
                else:
                    tclass = str(class_perm)
                    perms = set(stmt[4:]) if len(stmt) > 4 else set()

                rule = RuleStatement(op, src, tgt, tclass, perms)
                if op == 'allow':
                    self.allow_rules.append(rule)
                else:
                    self.neverallow_rules.append(rule)

    def finalize(self) -> None:
        """Compute checksum across loaded files and normalize attribute sets."""
        hasher = hashlib.sha256()
        for fp in sorted(self.source_files):
            try:
                with open(fp, 'rb') as f:
                    hasher.update(f.read())
            except Exception:
                pass
        self.policy_hash = hasher.hexdigest()

    def expand_types(self, identifier: str) -> Set[str]:
        """Resolve a type or typeattribute to its constituent atomic types."""
        if identifier in self.attributes:
            expanded = set()
            for item in self.attributes[identifier]:
                expanded.update(self.expand_types(item))
            return expanded
        return {identifier}

    def verify_neverallows(self) -> List[NeverallowViolation]:
        """
        Verify compile-time disjointness proof:
        For every (s, t, c): P_allow(s, t, c) ∩ P_never(s, t, c) == ∅.
        Returns a list of violations (empty list if policy is valid).
        """
        violations: List[NeverallowViolation] = []

        # Build flattened map of allowed permissions: (source_type, target_type, class) -> set of perms
        allowed_map: Dict[Tuple[str, str, str], Set[str]] = {}

        for rule in self.allow_rules:
            src_types = self.expand_types(rule.source)
            for s in src_types:
                # Handle 'self'
                tgt_types = {s} if rule.target == 'self' else self.expand_types(rule.target)
                for t in tgt_types:
                    key = (s, t, rule.tclass)
                    if key not in allowed_map:
                        allowed_map[key] = set()
                    allowed_map[key].update(rule.perms)

        # Cross check every neverallow assertion
        for n_rule in self.neverallow_rules:
            n_src_types = self.expand_types(n_rule.source)
            for s in n_src_types:
                n_tgt_types = {s} if n_rule.target == 'self' else self.expand_types(n_rule.target)
                for t in n_tgt_types:
                    key = (s, t, n_rule.tclass)
                    if key in allowed_map:
                        overlap = allowed_map[key] & n_rule.perms
                        if overlap:
                            violations.append(
                                NeverallowViolation(
                                    source=s,
                                    target=t,
                                    tclass=n_rule.tclass,
                                    forbidden_perms=sorted(list(overlap)),
                                    rule_src=f"{n_rule}"
                                )
                            )

        return violations


class AVCDenial:
    """Represents a parsed Linux kernel AVC denial audit event."""
    def __init__(self, scontext: str, tcontext: str, tclass: str, perms: List[str], comm: str = "", pid: str = ""):
        self.scontext = scontext
        self.tcontext = tcontext
        self.tclass = tclass
        self.perms = perms
        self.comm = comm
        self.pid = pid

        # Extract domain from context system_u:system_r:<s>:s0
        s_parts = scontext.split(':')
        self.sdomain = s_parts[2] if len(s_parts) >= 3 else scontext

        # Extract type from context system_u:object_r:<t>:s0
        t_parts = tcontext.split(':')
        self.ttype = t_parts[2] if len(t_parts) >= 3 else tcontext


class AVCSynthesisResult:
    def __init__(self, denial: AVCDenial, is_safe: bool, proposed_cil: str, reason: str = ""):
        self.denial = denial
        self.is_safe = is_safe
        self.proposed_cil = proposed_cil
        self.reason = reason


def parse_avc_log(log_text: str) -> List[AVCDenial]:
    """Parse auditd log text for AVC denial events."""
    denials = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line or 'avc:' not in line or 'denied' not in line:
            continue

        perms_m = re.search(r'avc:\s+denied\s+\{\s*([^\}]+)\s*\}', line)
        sctx_m = re.search(r'scontext=([^\s]+)', line)
        tctx_m = re.search(r'tcontext=([^\s]+)', line)
        tcls_m = re.search(r'tclass=([^\s]+)', line)
        pid_m = re.search(r'pid=(\d+)', line)
        comm_m = re.search(r'comm="([^"]+)"', line)

        if perms_m and sctx_m and tctx_m and tcls_m:
            perms = perms_m.group(1).split()
            scontext = sctx_m.group(1)
            tcontext = tctx_m.group(1)
            tclass = tcls_m.group(1)
            pid = pid_m.group(1) if pid_m else ""
            comm = comm_m.group(1) if comm_m else ""
            denials.append(AVCDenial(scontext, tcontext, tclass, perms, comm, pid))

    return denials


def analyze_avc_log(policy: CILPolicy, log_text: str) -> List[AVCSynthesisResult]:
    """
    Synthesize candidate CIL allow statements for AVC denials,
    rejecting any denial that conflicts with compile-time neverallows.
    """
    denials = parse_avc_log(log_text)
    results = []

    for d in denials:
        # Check against neverallows
        forbidden_found = False
        blocked_reasons = []

        candidate_perms = set(d.perms)

        for n_rule in policy.neverallow_rules:
            n_src = policy.expand_types(n_rule.source)
            if d.sdomain in n_src:
                n_tgt = {d.sdomain} if n_rule.target == 'self' else policy.expand_types(n_rule.target)
                if d.ttype in n_tgt and d.tclass == n_rule.tclass:
                    conflict = candidate_perms & n_rule.perms
                    if conflict:
                        forbidden_found = True
                        blocked_reasons.append(
                            f"Conflicts with neverallow assertion on {n_rule.tclass} ({' '.join(sorted(conflict))})"
                        )

        if forbidden_found:
            results.append(
                AVCSynthesisResult(
                    denial=d,
                    is_safe=False,
                    proposed_cil="",
                    reason="; ".join(blocked_reasons)
                )
            )
        else:
            perms_str = " ".join(sorted(d.perms))
            cil_stmt = f"(allow {d.sdomain} {d.ttype} ({d.tclass} ({perms_str})))"
            results.append(
                AVCSynthesisResult(
                    denial=d,
                    is_safe=True,
                    proposed_cil=cil_stmt,
                    reason="Safe: passes all neverallow invariant proofs"
                )
            )

    return results


def check_file_contexts(policy: CILPolicy, contexts_path: str) -> Tuple[bool, List[str], int]:
    """
    Validate policy/file_contexts:
    1. Valid regex patterns
    2. Context syntax 'system_u:object_r:<type>:s0'
    3. Referenced type must be declared in CIL policy
    """
    if not os.path.isfile(contexts_path):
        return False, [f"file_contexts file not found: {contexts_path}"], 0

    errors = []
    valid_lines = 0

    with open(contexts_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 2:
                errors.append(f"Line {idx}: Malformed entry (fewer than 2 columns): '{line}'")
                continue

            pattern = parts[0]
            context = parts[-1]

            # 1. Validate regex
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"Line {idx}: Invalid regular expression '{pattern}': {e}")
                continue

            # 2. Validate context format
            c_parts = context.split(':')
            if len(c_parts) != 4 or c_parts[0] != 'system_u' or c_parts[1] != 'object_r':
                errors.append(f"Line {idx}: Invalid security context '{context}', expected 'system_u:object_r:<type>:s0'")
                continue

            otype = c_parts[2]
            # 3. Check if type declared in CIL policy
            if policy.types and otype not in policy.types:
                errors.append(f"Line {idx}: Type '{otype}' is not declared in active CIL policy")
                continue

            valid_lines += 1

    return (len(errors) == 0), errors, valid_lines
