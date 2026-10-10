"""IAM privilege-escalation linter - phase 3.

Walks a directory of exported AWS IAM policies, resolves Allow statements
(including the inverted NotAction and NotResource forms), prints the over-broad
grants ranked by severity, flags the roles that hold a known one-step path to
administrator, then builds the role-to-role trust graph and searches it for the
shortest assume route from any role that is not admin-equivalent to one that is.

The sqlite baseline and the CI output formats arrive in phase 4 and phase 5.

Run:  python main.py [POLICY_DIR] [--top N]
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

DEFAULT_POLICY_DIR = Path(__file__).resolve().parent / "policies"

# Services where a wildcard is a privilege problem and not only a data-access
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

# Actions that write permissions onto a principal, or otherwise hand one
# identity the rights of another. Any of them alone is a step to administrator.
ESCALATION_PRIMITIVES: dict[str, str] = {
    "iam:CreatePolicyVersion": "rewrite a managed policy it can already see",
    "iam:SetDefaultPolicyVersion": "promote an older version of a policy",
    "iam:AttachUserPolicy": "attach an admin policy to a user it picks",
    "iam:AttachRolePolicy": "attach an admin policy to a role it picks",
    "iam:PutUserPolicy": "inline an admin policy onto a user it picks",
    "iam:PutRolePolicy": "inline an admin policy onto a role it picks",
    "iam:PutGroupPolicy": "inline an admin policy onto a group it picks",
    "iam:AddUserToGroup": "drop a user it controls into an admin group",
    "iam:CreateAccessKey": "mint access keys for another user",
    "iam:CreateLoginProfile": "set a console password on another user",
    "iam:UpdateLoginProfile": "reset another user's console password",
    "iam:UpdateAssumeRolePolicy": "rewrite a role's trust policy to trust itself",
    "sts:AssumeRole": "assume any role it can name",
}

# iam:PassRole is only half a finding. These actions take the passed role and
# run something as it, which turns the pass into code execution.
PASS_ROLE_CONSUMERS: dict[str, str] = {
    "lambda:CreateFunction": "run code as any role it can pass",
    "lambda:UpdateFunctionCode": "replace a function's code and run as its role",
    "lambda:UpdateFunctionConfiguration": "rebind a function to a role it can pass",
    "ec2:RunInstances": "launch an instance with a profile it can pass",
    "glue:CreateDevEndpoint": "run a notebook as any role it can pass",
    "glue:UpdateDevEndpoint": "rebind a dev endpoint to a role it can pass",
    "cloudformation:CreateStack": "run a stack with a service role it can pass",
    "codebuild:CreateProject": "run a build as any role it can pass",
    "codebuild:UpdateProject": "rebind a build project to a role it can pass",
    "ecs:RegisterTaskDefinition": "register a task definition with a role it can pass",
    "sagemaker:CreateNotebookInstance": "run a notebook as any role it can pass",
    "datapipeline:CreatePipeline": "run a pipeline as any role it can pass",
    "ssm:SendCommand": "run a command as any role it can pass",
    "batch:SubmitJob": "submit a job that runs as any role it can pass",
}


@dataclass
class Statement:
    """One statement, flattened into the fields the checks read."""

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
class Escalation:
    """A role-level path to administrator, assembled from one or more statements."""

    severity: str
    role: str
    reason: str
    actions: tuple[str, ...]


@dataclass
class Route:
    """Shortest assume route from a role that is not admin to one that is."""

    severity: str
    source: str
    target: str
    hops: tuple[str, ...]
    reason: str


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


def _role_name(arn_or_pattern: str) -> str | None:
    """Return the role name inside an IAM role ARN, or None for anything else.

    ``*`` is returned as-is: as a resource it means every role, as a principal
    it means any role in the account.
    """
    marker = ":role/"
    at = arn_or_pattern.find(marker)
    if at == -1:
        return "*" if arn_or_pattern == "*" else None
    return arn_or_pattern[at + len(marker) :]


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


def _principals(principal: Any) -> list[str]:
    """Return the role names a trust statement's ``Principal`` block names.

    ``*`` and an account root both collapse to ``*``: every role in the export
    may assume. Service principals are ignored, they are not roles.
    """
    if isinstance(principal, str):
        values = (principal,)
    elif isinstance(principal, (list, tuple)):
        values = tuple(str(item) for item in principal)
    elif isinstance(principal, dict):
        values = _as_list(principal.get("AWS"))
    else:
        return []

    names: list[str] = []
    for value in values:
        if value == "*" or value.endswith(":root"):
            names.append("*")
            continue
        name = _role_name(value)
        if name:
            names.append(name)
    return names


def _trusts(payload: Any, stem: str) -> Iterator[tuple[str, tuple[str, ...]]]:
    """Yield ``(role, principals)`` for every ``AssumeRolePolicyDocument`` found.

    Also reads a trust policy exported on its own, where the file name is the
    trusted role. A permission statement carries no ``Principal``, so it
    contributes nothing here.
    """
    if isinstance(payload, list):
        for entry in payload:
            yield from _trusts(entry, stem)
        return
    if not isinstance(payload, dict):
        return

    role = str(payload.get("RoleName") or stem)
    documents: list[dict[str, Any]] = []
    trust = payload.get("AssumeRolePolicyDocument") or payload.get("TrustPolicy")
    if isinstance(trust, dict):
        documents.append(trust)
    elif "Document" not in payload:
        documents.append(payload)

    principals: list[str] = []
    for document in documents:
        entries = document.get("Statement") or []
        if isinstance(entries, dict):
            entries = [entries]
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            if str(raw.get("Effect", "")).strip().capitalize() != "Allow":
                continue
            principals.extend(_principals(raw.get("Principal")))
    if principals:
        yield role, tuple(principals)


def load_statements(
    directory: Path,
) -> tuple[list[Statement], dict[str, tuple[str, ...]], Scan]:
    """Read every ``*.json`` policy under *directory*, recursively.

    Returns Deny statements as well as Allow ones. The wildcard checks skip
    Deny, but the escalation and reachability checks need it to know when a
    primitive or an assume has been taken back. Also returns each role's trust
    principals, keyed by the role that is trusted.
    """
    scan = Scan()
    statements: list[Statement] = []
    trusts: dict[str, list[str]] = {}

    for path in sorted(directory.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"skipped {path.name}: {exc}", file=sys.stderr)
            continue
        scan.files += 1
        for role, principals in _trusts(payload, path.stem):
            trusts.setdefault(role, []).extend(principals)
        for role, policy, document in _documents(payload, path.stem):
            entries = document.get("Statement") or []
            if isinstance(entries, dict):
                entries = [entries]
            for index, raw in enumerate(entries):
                if not isinstance(raw, dict):
                    continue
                scan.statements += 1
                effect = str(raw.get("Effect", "")).strip().capitalize()
                if effect == "Allow":
                    scan.allows += 1
                statements.append(
                    Statement(
                        role=role,
                        policy=policy,
                        index=index,
                        effect=effect,
                        actions=_as_list(raw.get("Action")),
                        not_actions=_as_list(raw.get("NotAction")),
                        resources=_as_list(raw.get("Resource")),
                        not_resources=_as_list(raw.get("NotResource")),
                        raw=raw,
                    )
                )

    trusted = {role: tuple(dict.fromkeys(names)) for role, names in trusts.items()}
    return statements, trusted, scan


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
                (
                    "HIGH",
                    f"Allow NotAction on a scoped resource - permits everything except {excluded}",
                )
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
        if statement.effect != "Allow":
            continue
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


def _by_role(statements: Sequence[Statement]) -> dict[str, list[Statement]]:
    """Group statements by the role that holds them."""
    grouped: dict[str, list[Statement]] = {}
    for statement in statements:
        grouped.setdefault(statement.role, []).append(statement)
    return grouped


def _names(statement: Statement, action: str) -> bool:
    """True when the statement's action list grants *action*, ignoring resources.

    The reachability checks apply their own resource test, so they need the
    action match on its own.
    """
    lowered = action.lower()
    if any(fnmatch.fnmatchcase(lowered, grant.lower()) for grant in statement.actions):
        return True
    if statement.not_actions:
        return not any(
            fnmatch.fnmatchcase(lowered, grant.lower()) for grant in statement.not_actions
        )
    return False


def _covers(statement: Statement, action: str) -> bool:
    """True when *statement*'s action list grants *action*.

    A bare ``"*"`` action, and a ``NotAction`` list, only count when the
    statement is account-wide: ``Action: "*"`` scoped to ``arn:aws:s3:::ops-*``
    can never call an IAM action, and counting it would be a false positive.
    """
    if not _names(statement, action):
        return False
    if "*" in statement.actions or statement.not_actions:
        return "*" in statement.resources
    return True


def _holds(statements: Sequence[Statement], action: str) -> bool:
    """True when the role is granted *action* and no Deny takes it back.

    Deny is treated as a blanket block on the actions it names. Conditions on
    the Deny are not evaluated, so a conditional Deny still reads as a block.
    """
    if not any(_covers(s, action) for s in statements if s.effect == "Allow"):
        return False
    return not any(_covers(s, action) for s in statements if s.effect == "Deny")


def _grants_role(statement: Statement, role: str) -> bool:
    """True when the statement's resource list reaches the named role's ARN.

    Resources are compared on the part after ``:role/``, so a policy written
    against a real account id matches a role name from any export.
    """
    lowered = role.lower()
    if any(
        fnmatch.fnmatchcase(lowered, tail.lower())
        for tail in (_role_name(resource) for resource in statement.resources)
        if tail is not None
    ):
        return True
    if statement.not_resources:
        excluded = [tail for tail in map(_role_name, statement.not_resources) if tail]
        return not any(fnmatch.fnmatchcase(lowered, tail.lower()) for tail in excluded)
    return False


def _can_assume(held: Sequence[Statement], role: str) -> bool:
    """True when the role holds ``sts:AssumeRole`` reaching *role*, with no Deny."""

    def grants(statement: Statement) -> bool:
        return _names(statement, "sts:AssumeRole") and _grants_role(statement, role)

    if not any(grants(s) for s in held if s.effect == "Allow"):
        return False
    return not any(grants(s) for s in held if s.effect == "Deny")


def _is_full_admin(statements: Sequence[Statement]) -> bool:
    """True when the role already holds ``Allow "*" on "*"``."""
    return any(
        s.effect == "Allow" and "*" in s.actions and "*" in s.resources for s in statements
    )


def _admin_reason(held: Sequence[Statement]) -> str:
    """Return how the role reaches administrator on its own, or an empty string.

    ``sts:AssumeRole`` is deliberately excluded: assuming a role is movement,
    not a destination, and the reachability pass is what follows it.
    """
    if _is_full_admin(held):
        return 'holds Allow "*" on "*"'
    if _holds(held, "iam:PassRole"):
        for action in PASS_ROLE_CONSUMERS:
            if _holds(held, action):
                return f"iam:PassRole into {action} - {PASS_ROLE_CONSUMERS[action]}"
    for action in ESCALATION_PRIMITIVES:
        if action != "sts:AssumeRole" and _holds(held, action):
            return f"{action} - {ESCALATION_PRIMITIVES[action]}"
    return ""


def find_escalations(statements: Sequence[Statement]) -> list[Escalation]:
    """Flag every role that holds a known one-step path to administrator."""
    found: list[Escalation] = []
    for role, held in sorted(_by_role(statements).items()):
        if _is_full_admin(held):
            continue

        if _holds(held, "iam:PassRole"):
            consumers = [action for action in PASS_ROLE_CONSUMERS if _holds(held, action)]
            if consumers:
                first = consumers[0]
                extra = f" (+{len(consumers) - 1} more)" if len(consumers) > 1 else ""
                found.append(
                    Escalation(
                        severity="CRITICAL",
                        role=role,
                        reason=(
                            f"iam:PassRole into {first}{extra} - {PASS_ROLE_CONSUMERS[first]}"
                        ),
                        actions=("iam:PassRole", *consumers),
                    )
                )

        primitives = [action for action in ESCALATION_PRIMITIVES if _holds(held, action)]
        if primitives:
            if len(primitives) == 1:
                reason = f"{primitives[0]} - {ESCALATION_PRIMITIVES[primitives[0]]}"
            else:
                shown = ", ".join(primitives[:3])
                more = f", +{len(primitives) - 3} more" if len(primitives) > 3 else ""
                reason = f"{shown}{more} - {len(primitives)} one-step paths to administrator"
            found.append(
                Escalation(severity="HIGH", role=role, reason=reason, actions=tuple(primitives))
            )

    found.sort(key=lambda e: (SEVERITY_ORDER[e.severity], e.role))
    return found


def _shortest_route(
    edges: dict[str, list[str]], source: str, targets: set[str]
) -> list[str] | None:
    """Breadth-first search for the shortest role chain from *source* to a target."""
    seen = {source}
    queue: deque[list[str]] = deque([[source]])
    while queue:
        chain = queue.popleft()
        for step in edges.get(chain[-1], ()):
            if step in seen:
                continue
            seen.add(step)
            if step in targets:
                return chain + [step]
            queue.append(chain + [step])
    return None


def find_paths(
    statements: Sequence[Statement], trusts: dict[str, tuple[str, ...]]
) -> list[Route]:
    """Find the shortest assume route from each non-admin role to an admin role.

    An edge ``A -> B`` exists when the trust policy attached to ``B`` names
    ``A`` as a principal and ``A`` holds ``sts:AssumeRole`` reaching ``B``.
    A route only counts when it ends on a role that reaches administrator on
    its own, so a lone ``sts:AssumeRole`` is movement, not a destination.
    """
    by_role = _by_role(statements)
    reasons = {role: _admin_reason(held) for role, held in by_role.items()}
    targets = {role for role, reason in reasons.items() if reason}
    edges = {
        role: [
            target
            for target in by_role
            if target != role
            and _can_assume(held, target)
            and _is_trusted_by(trusts.get(target, ()), role)
        ]
        for role, held in by_role.items()
    }

    routes: list[Route] = []
    for source in sorted(by_role):
        if source in targets:
            continue
        chain = _shortest_route(edges, source, targets)
        if chain is None:
            continue
        hops = len(chain) - 1
        severity = "CRITICAL" if hops == 1 else "HIGH" if hops == 2 else "MEDIUM"
        routes.append(
            Route(
                severity=severity,
                source=source,
                target=chain[-1],
                hops=tuple(chain),
                reason=reasons[chain[-1]],
            )
        )
    routes.sort(key=lambda route: (SEVERITY_ORDER[route.severity], route.source))
    return routes


def _is_trusted_by(principals: Sequence[str], role: str) -> bool:
    """True when a trust policy allows *role* to assume; ``*`` allows anyone."""
    return "*" in principals or role in principals


def _table(rows: Sequence[tuple[str, ...]], headers: Sequence[str]) -> list[str]:
    """Render a left-aligned column table with a header row."""
    widths = [
        max(len(headers[col]), *(len(row[col]) for row in rows)) for col in range(len(headers))
    ]
    lines = [
        "  ".join(
            header.ljust(width) if col == 0 else header.ljust(width)
            for col, (header, width) in enumerate(zip(headers, widths))
        )
    ]
    for row in rows:
        lines.append("  ".join(value.ljust(width) for value, width in zip(row, widths)))
    return lines


def render(
    findings: Sequence[Finding],
    escalations: Sequence[Escalation],
    routes: Sequence[Route],
    scan: Scan,
    detail_limit: int,
) -> str:
    """Format the terminal report: wildcard table, primitives, reachability, totals."""
    lines = [
        "IAM PRIVILEGE ESCALATION LINT - phase 3 "
        "(wildcard audit + escalation primitives + reachability)",
        f"scanned {scan.files} policy files | {scan.statements} statements | {scan.allows} Allow",
        "",
    ]

    if findings:
        rows = [
            (f.severity, f.role, f.policy, str(f.index), f.reason) for f in findings
        ]
        widths = [
            max(len("SEV"), max(len(row[0]) for row in rows)),
            max(len("ROLE"), max(len(row[1]) for row in rows)),
            max(len("POLICY"), max(len(row[2]) for row in rows)),
            max(len("STMT"), max(len(row[3]) for row in rows)),
        ]
        lines.append(
            f"{'SEV':<{widths[0]}}  {'ROLE':<{widths[1]}}  {'POLICY':<{widths[2]}}  "
            f"{'STMT':>{widths[3]}}  WHY"
        )
        for severity, role, policy, index, reason in rows:
            lines.append(
                f"{severity:<{widths[0]}}  {role:<{widths[1]}}  {policy:<{widths[2]}}  "
                f"{index:>{widths[3]}}  {reason}"
            )

        detail = findings[:detail_limit]
        if detail:
            lines.append("")
            lines.append(f"--- statement detail (top {len(detail)}) ---")
            for finding in detail:
                lines.append(
                    f"{finding.severity} {finding.role}/{finding.policy} [{finding.index}]"
                )
                lines.append("  " + json.dumps(finding.statement))
    else:
        lines.append("no over-broad Allow statements found")

    lines.append("")
    lines.append("--- escalation paths (role -> administrator) ---")
    if escalations:
        sev_w = max(len("SEV"), max(len(e.severity) for e in escalations))
        role_w = max(len("ROLE"), max(len(e.role) for e in escalations))
        lines.append(f"{'SEV':<{sev_w}}  {'ROLE':<{role_w}}  PATH")
        for escalation in escalations:
            lines.append(
                f"{escalation.severity:<{sev_w}}  {escalation.role:<{role_w}}  "
                f"{escalation.reason}"
            )
    else:
        lines.append("no role holds a known escalation primitive")

    lines.append("")
    lines.append("--- reachability (role -> role) ---")
    if routes:
        sev_w = max(len("SEV"), max(len(r.severity) for r in routes))
        src_w = max(len("FROM"), max(len(r.source) for r in routes))
        lines.append(f"{'SEV':<{sev_w}}  {'FROM':<{src_w}}  HOPS  PATH")
        for route in routes:
            chain = " -> ".join(route.hops)
            lines.append(
                f"{route.severity:<{sev_w}}  {route.source:<{src_w}}  "
                f"{len(route.hops) - 1:>4}  {chain} ({route.reason})"
            )
    else:
        lines.append("no role reaches an admin-equivalent role through assume")

    tally = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    summary = ", ".join(f"{count} {sev}" for sev, count in tally.items() if count)

    esc_tally = {sev: sum(1 for e in escalations if e.severity == sev) for sev in SEVERITY_ORDER}
    esc_summary = ", ".join(f"{count} {sev}" for sev, count in esc_tally.items() if count)

    route_tally = {sev: sum(1 for r in routes if r.severity == sev) for sev in SEVERITY_ORDER}
    route_summary = ", ".join(f"{count} {sev}" for sev, count in route_tally.items() if count)

    lines.append("")
    lines.append(f"{len(findings)} findings" + (f" - {summary}" if summary else ""))
    lines.append(
        f"{len(escalations)} escalation paths" + (f" - {esc_summary}" if esc_summary else "")
    )
    lines.append(
        f"{len(routes)} assume routes to administrator"
        + (f" - {route_summary}" if route_summary else "")
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, scan the policy directory and print the report."""
    parser = argparse.ArgumentParser(
        description=(
            "Report over-broad Allow statements, role-level privilege escalation "
            "paths and assume routes to administrator in exported AWS IAM policies."
        )
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

    statements, trusts, scan = load_statements(directory)
    report = render(
        analyze(statements),
        find_escalations(statements),
        find_paths(statements, trusts),
        scan,
        args.top,
    )
    print(report)
    return 0