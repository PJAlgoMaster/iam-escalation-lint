"""IAM privilege-escalation linter - phase 1.

Walks a directory of exported AWS IAM policies, resolves Allow statements
(including the inverted NotAction and NotResource forms) and prints the
over-broad grants ranked by severity. Escalation primitives, the role trust
graph and drift tracking arrive in later phases.

Run:  python main.py [POLICY_DIR] [--top N]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

DEFAULT_POLICY_DIR = Path(__file__).resolve().parent / "policies"

# Services where a wildcard is a privilege problem and not just a data-access
# one: they control identity, keys or the audit trail itself.
SENSITIVE_SERVICES = frozenset(
    {
        "account",
        "access-analyzer",
        "cloudtrail",
        "iam",
        "identitystore",
        "kms",
        "organizations",
        "secretsmanager",
        "sso",
        "sso-directory",
        "sts",
    }
)

READ_PREFIXES = (
    "batchget",
    "check",
    "describe",
    "get",
    "head",
    "list",
    "lookup",
    "query",
    "search",
    "view",
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Statement:
    """One Allow statement, flattened into the fields the checks read."""

    role: str
    policy: str
    index: int
    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A single over-broad grant, ready to print."""

    severity: str
    role: str
    policy: str
    index: int
    reason: str
    statement: dict[str, Any]


@dataclass
class Scan:
    """Counts behind the report header."""

    files: int = 0
    statements: int = 0
    allows: int = 0


def _as_list(value: Any) -> tuple[str, ...]:
    """Normalise an IAM string-or-list field into a tuple of strings."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _service(action: str) -> str:
    """Return the service prefix of an IAM action, lowercased."""
    return action.split(":", 1)[0].lower()


def _is_read_only_wildcard(action: str) -> bool:
    """True for a wildcard whose verb part only covers read-style actions."""
    verb = action.split(":", 1)[-1].lower()
    return "*" in verb and verb.startswith(READ_PREFIXES)


def _documents(payload: Any, stem: str) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield ``(role, policy, document)`` triples from one parsed JSON file.

    Accepts a bare policy document, an export wrapping one under ``Document``
    (AWS-shaped ``get-role-policy`` output), or a list of either. The file name
    is the identity unless the export names a role explicitly.
    """
    if isinstance(payload, list):
        for entry in payload:
            yield from _documents(entry, stem)
        return
    if not isinstance(payload, dict):
        return
    document = payload.get("Document")
    if isinstance(document, dict):
        role = str(payload.get("RoleName") or stem)
        policy = str(payload.get("PolicyName") or payload.get("PolicyArn") or stem)
        yield role, policy, document
        return
    if "Statement" in payload:
        yield stem, stem, payload


def load_statements(directory: Path) -> tuple[list[Statement], Scan]:
    """Read every ``*.json`` policy under *directory*, recursively.

    Deny statements are counted but not returned: this phase reports over-broad
    Allow grants only.
    """
    scan = Scan()
    allows: list[Statement] = []
    for path in sorted(directory.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"skipped {path.name}: {exc}", file=sys.stderr)
            continue
        scan.files += 1
        for role, policy, document in _documents(payload, path.stem):
            statements = document.get("Statement") or []
            if isinstance(statements, dict):
                statements = [statements]
            for index, raw in enumerate(statements):
                if not isinstance(raw, dict):
                    continue
                scan.statements += 1
                if str(raw.get("Effect", "")).lower() != "allow":
                    continue
                scan.allows += 1
                allows.append(
                    Statement(
                        role=role,
                        policy=policy,
                        index=index,
                        effect="Allow",
                        actions=_as_list(raw.get("Action")),
                        not_actions=_as_list(raw.get("NotAction")),
                        resources=_as_list(raw.get("Resource")),
                        not_resources=_as_list(raw.get("NotResource")),
                        raw=raw,
                    )
                )
    return allows, scan


def _checks(statement: Statement) -> list[tuple[str, str]]:
    """Return every ``(severity, reason)`` an Allow statement trips."""
    found: list[tuple[str, str]] = []
    acts = statement.actions
    broad = any(action == "*" for action in acts)
    wild = [action for action in acts if action != "*" and "*" in action]
    named = [action for action in acts if "*" not in action]
    res_any = "*" in statement.resources

    if broad and res_any:
        found.append(("CRITICAL", 'Allow "*" on "*" - full administrator'))
    elif broad:
        found.append(
            ("HIGH", 'Allow "*" on a scoped resource - every action, no action filtering')
        )

    if statement.not_actions and statement.not_actions != ("*",):
        excluded = ", ".join(statement.not_actions)
        if res_any:
            found.append(
                ("CRITICAL", f'Allow NotAction on "*" - permits everything except {excluded}')
            )
        else:
            found.append(
                ("HIGH", f"Allow NotAction on a scoped resource - permits everything except {excluded}")
            )

    if statement.not_resources:
        excluded = ", ".join(statement.not_resources)
        found.append(("HIGH", f"Allow NotResource - permits every resource except {excluded}"))

    read_wild = [action for action in wild if _is_read_only_wildcard(action)]
    sensitive_wild = [
        action
        for action in wild
        if action not in read_wild and _service(action) in SENSITIVE_SERVICES
    ]
    other_wild = [
        action for action in wild if action not in read_wild and action not in sensitive_wild
    ]

    if read_wild:
        found.append(("LOW", f"Allow {', '.join(read_wild)} - read-only wildcard"))
    if sensitive_wild:
        services = ", ".join(sorted({_service(action) for action in sensitive_wild}))
        found.append(
            ("HIGH", f"Allow {', '.join(sensitive_wild)} - service-wide control of {services}")
        )
    if other_wild:
        where = '"*"' if res_any else "a scoped resource"
        severity = "HIGH" if res_any else "MEDIUM"
        found.append(
            (severity, f"Allow {', '.join(other_wild)} on {where} - service-wide control")
        )

    if named and not wild:
        services = sorted({_service(action) for action in named})
        sensitive = [service for service in services if service in SENSITIVE_SERVICES]
        if sensitive:
            where = '"*"' if res_any else "a scoped resource"
            found.append(
                (
                    "HIGH",
                    f"Allow {', '.join(named)} on {where} - named control of {', '.join(sensitive)}",
                )
            )
        elif res_any:
            found.append(
                ("MEDIUM", f'Allow {len(named)} named actions on "*" - no resource scoping')
            )

    return found


def analyze(statements: Sequence[Statement]) -> list[Finding]:
    """Rank every Allow statement by its most severe over-broad grant."""
    findings: list[Finding] = []
    for statement in statements:
        checks = _checks(statement)
        if not checks:
            continue
        severity, reason = min(checks, key=lambda check: SEVERITY_ORDER[check[0]])
        findings.append(
            Finding(
                severity=severity,
                role=statement.role,
                policy=statement.policy,
                index=statement.index,
                reason=reason,
                statement=statement.raw,
            )
        )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.role, f.policy, f.index))
    return findings


def render(findings: Sequence[Finding], scan: Scan, detail_limit: int) -> str:
    """Format the terminal report: ranked table, statement detail, totals."""
    lines = [
        "IAM PRIVILEGE ESCALATION LINT - phase 1 (wildcard and NotAction audit)",
        f"scanned {scan.files} policy files | {scan.statements} statements | {scan.allows} Allow",
        "",
    ]
    if not findings:
        lines.append("no over-broad Allow statements found")
        return "\n".join(lines)

    sev_w = max(len("SEV"), max(len(f.severity) for f in findings))
    role_w = max(len("ROLE"), max(len(f.role) for f in findings))
    pol_w = max(len("POLICY"), max(len(f.policy) for f in findings))
    idx_w = max(len("STMT"), max(len(str(f.index)) for f in findings))

    lines.append(
        f"{'SEV':<{sev_w}}  {'ROLE':<{role_w}}  {'POLICY':<{pol_w}}  "
        f"{'STMT':>{idx_w}}  WHY"
    )
    for finding in findings:
        lines.append(
            f"{finding.severity:<{sev_w}}  {finding.role:<{role_w}}  "
            f"{finding.policy:<{pol_w}}  {finding.index:>{idx_w}}  {finding.reason}"
        )

    detail = findings[:detail_limit]
    if detail:
        lines.append("")
        lines.append(f"--- statement detail (top {len(detail)}) ---")
        for finding in detail:
            lines.append(f"{finding.severity} {finding.role}/{finding.policy} [{finding.index}]")
            lines.append("  " + json.dumps(finding.statement))

    tally = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    summary = ", ".join(f"{count} {sev}" for sev, count in tally.items() if count)
    lines.append("")
    lines.append(f"{len(findings)} findings - {summary}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, scan the policy directory and print the report."""
    parser = argparse.ArgumentParser(
        description="Report over-broad Allow statements in exported AWS IAM policies."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=str(DEFAULT_POLICY_DIR),
        help="directory of exported IAM policy JSON files (default: bundled sample set)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="how many findings to expand with their raw statement (default: 10)",
    )
    args = parser.parse_args(argv)

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 2

    statements, scan = load_statements(directory)
    print(render(analyze(statements), scan, args.top))
    return 0