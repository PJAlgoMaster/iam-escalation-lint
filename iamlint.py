"""IAM privilege-escalation linter.

Reads a directory of exported AWS IAM policies and reports three things:
over-broad Allow statements, the roles that hold a known one-step path to
administrator, and the shortest assume route from a role that is not
admin-equivalent to one that is.

Every row lands in a sqlite baseline, so the next run prints the drift instead
of the whole account, and the same run can emit JSON or SARIF and gate a build
through its exit code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

PHASE = "5"

BANNER = (
    f"IAM PRIVILEGE ESCALATION LINT - phase {PHASE} "
    "(wildcard audit + escalation primitives + reachability + baseline drift + CI output)"
)

DEFAULT_POLICY_DIR = Path(__file__).resolve().parent / "policies"
DEFAULT_BASELINE = Path(".iamlint-baseline.db")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
FAIL_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

SENSITIVE_SERVICES = ("iam", "sts", "kms")
READ_VERBS = ("Get", "List", "Describe", "Head", "View", "BatchGet", "Search", "Query", "Scan")

# Actions that run code as a role, once a role has been handed to them.
CONSUMER_ACTIONS = (
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
    "codepipeline:CreatePipeline",
    "datapipeline:CreatePipeline",
    "events:PutTargets",
    "sagemaker:CreateNotebookInstance",
    "batch:SubmitJob",
    "ecs:RegisterTaskDefinition",
    "ecs:RunTask",
    "codebuild:CreateProject",
    "codebuild:StartBuild",
)

# The identity-writing primitives, in report order. sts:AssumeRole is here
# because it moves, not because it lands - the graph says where it lands.
IDENTITY_PRIMITIVES = (
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "sts:AssumeRole",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
)

PRIMITIVE_REASONS = {
    "iam:CreatePolicyVersion": "point a role it can assume at AdministratorAccess",
    "iam:AttachRolePolicy": "attach AdministratorAccess to a role it can assume",
    "iam:UpdateAssumeRolePolicy": "rewrite a trust policy so it can assume the role",
    "iam:AddUserToGroup": "add itself to an administrator group",
    "sts:AssumeRole": "assume any role it can name",
    "iam:AttachUserPolicy": "attach AdministratorAccess to its own user",
    "iam:AttachGroupPolicy": "attach AdministratorAccess to a group it belongs to",
    "iam:PutRolePolicy": "write an inline admin policy onto a role it can assume",
    "iam:PutUserPolicy": "write an inline admin policy onto itself",
    "iam:PutGroupPolicy": "write an inline admin policy onto a group it belongs to",
    "iam:CreateAccessKey": "mint an access key for a more privileged user",
    "iam:CreateLoginProfile": "set a console password on a more privileged user",
    "iam:UpdateLoginProfile": "reset a more privileged user's console password",
}

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0"}
SARIF_RULES = [
    {
        "id": "IAM001",
        "name": "OverBroadAllow",
        "shortDescription": {"text": "Over-broad Allow statement"},
        "properties": {"tags": ["security"]},
    },
    {
        "id": "IAM002",
        "name": "EscalationPath",
        "shortDescription": {"text": "One-step privilege escalation path"},
        "properties": {"tags": ["security"]},
    },
    {
        "id": "IAM003",
        "name": "AssumeRoute",
        "shortDescription": {"text": "Assume route to an admin-equivalent role"},
        "properties": {"tags": ["security"]},
    },
]


@dataclass(frozen=True)
class Statement:
    """One Allow or Deny statement, flattened for the rules to read."""

    role: str
    policy: str
    index: int
    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    raw: dict[str, Any]
    file: str = ""


@dataclass(frozen=True)
class Finding:
    """One over-broad Allow statement."""

    severity: str
    role: str
    policy: str
    index: int
    reason: str
    statement: dict[str, Any]
    source_file: str = ""


@dataclass(frozen=True)
class Escalation:
    """One role holding a known one-step path to administrator."""

    severity: str
    role: str
    reason: str
    actions: tuple[str, ...]
    source_file: str = ""


@dataclass(frozen=True)
class Route:
    """One assume chain from a role to an admin-equivalent role."""

    severity: str
    source: str
    target: str
    hops: tuple[str, ...]
    reason: str
    source_file: str = ""


@dataclass(frozen=True)
class Scan:
    """What the walk over the policy directory counted."""

    files: int
    statements: int
    allows: int


@dataclass(frozen=True)
class Record:
    """One row as the baseline stores it."""

    kind: str
    ident: str
    severity: str
    fingerprint: str


@dataclass(frozen=True)
class Drift:
    """What changed since the last snapshot."""

    baseline: Path
    previous_run: str | None
    fixed: tuple[tuple[str, str, str], ...]
    unchanged: int


@dataclass(frozen=True)
class Report:
    """Everything this run produced, ready for one of the three renderers."""

    directory: str
    scan: Scan
    findings: tuple[Finding, ...]
    escalations: tuple[Escalation, ...]
    routes: tuple[Route, ...]
    total: tuple[int, int, int]
    drift: Drift
    fail_on: str
    breached: bool


# --- phase 1: the wildcard rules -------------------------------------------


def _scope(resources: tuple[str, ...]) -> str:
    """Name the resource a statement is scoped to, the way the report prints it."""
    return '"*"' if not resources or "*" in resources else resources[0]


def _joined(actions: Sequence[str]) -> str:
    """Join an action list the way the IAM console shows it."""
    return ", ".join(actions)


def _is_read_wildcard(action: str) -> bool:
    """True for a wildcard that can only read, like s3:Get* or s3:List*."""
    service, _, verb = action.partition(":")
    return bool(service) and verb.endswith("*") and verb.startswith(READ_VERBS)


def classify(statement: Statement) -> tuple[str, str] | None:
    """Rank one statement against the over-broad patterns, or return None.

    Deny statements are skipped, and so is ``NotAction: "*"``: it grants
    nothing at all.
    """
    if statement.effect != "Allow":
        return None

    actions = statement.actions
    resources = statement.resources

    if not actions:
        if not statement.not_actions or "*" in statement.not_actions:
            return None
        excluded = _joined(statement.not_actions)
        if "*" in resources:
            return "CRITICAL", f'Allow NotAction on "*" - permits everything except {excluded}'
        return (
            "HIGH",
            f"Allow NotAction on {_scope(resources)} - permits everything except {excluded}",
        )

    if "*" in actions:
        if "*" in resources:
            return "CRITICAL", 'Allow "*" on "*" - full administrator'
        return (
            "HIGH",
            f'Allow "*" on {_scope(resources)} - every action, '
            "including the ones AWS adds next quarter",
        )

    for action in actions:
        if not action.endswith(":*"):
            continue
        service = action.split(":")[0]
        if service in SENSITIVE_SERVICES:
            return "HIGH", f"Allow {action} on {_scope(resources)} - service-wide control of {service}"
        if "*" in resources:
            noun = "bucket" if service == "s3" else "resource"
            return "HIGH", f'Allow {action} on "*" - service-wide control of every {noun} in the account'
        return "MEDIUM", f"Allow {action} on {_scope(resources)} - service-wide, scoped to one resource"

    if statement.not_resources:
        return (
            "HIGH",
            f"Allow {_joined(actions)} except {_joined(statement.not_resources)} - "
            "every other resource is permitted",
        )

    if all(_is_read_wildcard(action) for action in actions):
        return "LOW", f"Allow {_joined(actions)} on {_scope(resources)} - read-only wildcard"

    for action in actions:
        service = action.split(":")[0]
        if service in SENSITIVE_SERVICES:
            return (
                "HIGH",
                f"Allow {_joined(actions)} on {_scope(resources)} - named control of {service}",
            )

    if "*" in resources:
        return "MEDIUM", f'Allow {_joined(actions)} on "*" - named actions with no resource scope'

    return None


def analyze(statements: Sequence[Statement]) -> list[Finding]:
    """Read one statement at a time and rank what is over-broad about it."""
    findings: list[Finding] = []
    for statement in statements:
        verdict = classify(statement)
        if verdict is None:
            continue
        severity, reason = verdict
        findings.append(
            Finding(
                severity=severity,
                role=statement.role,
                policy=statement.policy,
                index=statement.index,
                reason=reason,
                statement=statement.raw,
                source_file=statement.file,
            )
        )
    return sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.role, f.policy, f.index))


# --- what one role's statements add up to ----------------------------------


def _service_of(resource: str) -> str:
    """Pull the service out of an ARN, or return an empty string."""
    parts = resource.split(":")
    return parts[2] if len(parts) > 2 else ""


def _absorb(bucket: dict[str, Any], statement: Statement) -> None:
    """Fold one statement's actions into an allow or a deny bucket."""
    if statement.not_actions:
        if "*" in statement.not_actions:
            return
        bucket["any"] = True
        for action in statement.not_actions:
            if action.endswith(":*"):
                bucket["services"].add(action.split(":")[0])
            else:
                bucket["named"].add(action)
        return

    for action in statement.actions:
        if action == "*":
            if not statement.resources or "*" in statement.resources:
                bucket["any"] = True
            else:
                for resource in statement.resources:
                    service = _service_of(resource)
                    if service:
                        bucket["services"].add(service)
        elif action.endswith(":*"):
            bucket["services"].add(action.split(":")[0])
        else:
            bucket["named"].add(action)


def _permitter(statements: Sequence[Statement]):
    """Return a predicate answering whether these statements permit an action."""
    allow: dict[str, Any] = {"any": False, "services": set(), "named": set()}
    deny: dict[str, Any] = {"any": False, "services": set(), "named": set()}

    for statement in statements:
        if statement.effect == "Deny":
            if statement.not_resources:
                continue
            _absorb(deny, statement)
        elif statement.effect == "Allow":
            _absorb(allow, statement)

    def permits(action: str) -> bool:
        """True when the statements add up to a grant of the action."""
        service = action.split(":")[0]
        if deny["any"] or action in deny["named"] or service in deny["services"]:
            return False
        return allow["any"] or action in allow["named"] or service in allow["services"]

    return permits


def _holds_full_admin(statements: Sequence[Statement]) -> bool:
    """True when a statement is literally ``Allow "*" on "*"``."""
    return any(
        statement.effect == "Allow" and "*" in statement.actions and "*" in statement.resources
        for statement in statements
    )


def _group(statements: Sequence[Statement]) -> dict[str, list[Statement]]:
    """Group statements by the role that holds them, keeping file order."""
    grouped: dict[str, list[Statement]] = {}
    for statement in statements:
        grouped.setdefault(statement.role, []).append(statement)
    return grouped


# --- phase 2: the escalation engine ----------------------------------------


def find_escalations(statements: Sequence[Statement]) -> list[Escalation]:
    """Report the roles that reach administrator in one step.

    ``iam:PassRole`` with no consumer action is a risk, not a path, and a role
    already holding ``Allow "*" on "*"`` is not reported again here.
    """
    escalations: list[Escalation] = []
    for role, held in _group(statements).items():
        if _holds_full_admin(held):
            continue
        permits = _permitter(held)
        consumers = [action for action in CONSUMER_ACTIONS if permits(action)]
        if permits("iam:PassRole") and consumers:
            escalations.append(
                Escalation(
                    severity="CRITICAL",
                    role=role,
                    reason=f"iam:PassRole + {consumers[0]} - hand a role to it and run code as that role",
                    actions=("iam:PassRole", consumers[0]),
                    source_file=held[0].file,
                )
            )
            continue
        for action in IDENTITY_PRIMITIVES:
            if permits(action):
                escalations.append(
                    Escalation(
                        severity="HIGH",
                        role=role,
                        reason=f"{action} - {PRIMITIVE_REASONS[action]}",
                        actions=(action,),
                        source_file=held[0].file,
                    )
                )
                break
    return sorted(escalations, key=lambda e: (-SEVERITY_RANK.get(e.severity, 0), e.role))


# --- phase 3: the reachability graph ---------------------------------------


def _role_name(value: str) -> str:
    """Reduce a principal ARN or a bare name to the role name."""
    return value.split(":role/")[-1] if ":role/" in value else value


def _assume_targets(statements: Sequence[Statement]) -> set[str] | None:
    """Role names these statements may assume, or None when anything is assumable."""
    names: set[str] = set()
    for statement in statements:
        if statement.effect != "Allow":
            continue
        if not _permitter([statement])("sts:AssumeRole"):
            continue
        if statement.not_actions and not statement.resources:
            return None
        for resource in statement.resources or ("*",):
            if resource == "*":
                return None
            names.add(_role_name(resource))
    return names


def _can_assume(statements: Sequence[Statement], target: str) -> bool:
    """True when these statements let the role assume exactly that role."""
    if not _permitter(statements)("sts:AssumeRole"):
        return False
    targets = _assume_targets(statements)
    if targets is None:
        return True
    return any(target == name or (name.endswith("*") and target.startswith(name[:-1])) for name in targets)


def _trusts(principals: Sequence[str], role: str) -> bool:
    """True when the trust policy names this role, or names everyone."""
    return role in principals or "*" in principals


def _reaches_admin_alone(statements: Sequence[Statement]) -> bool:
    """True when the role does not need to move: it is already admin-equivalent.

    ``sts:AssumeRole`` on its own is movement, not a destination, so it does
    not count here.
    """
    if _holds_full_admin(statements):
        return True
    permits = _permitter(statements)
    if permits("iam:PassRole") and any(permits(action) for action in CONSUMER_ACTIONS):
        return True
    return any(permits(action) for action in IDENTITY_PRIMITIVES if action != "sts:AssumeRole")


def _admin_reason(statements: Sequence[Statement]) -> str:
    """Say why a route stops on this role."""
    if _holds_full_admin(statements):
        return 'holds Allow "*" on "*"'
    permits = _permitter(statements)
    for action in IDENTITY_PRIMITIVES:
        if action != "sts:AssumeRole" and permits(action):
            return f"holds {action}"
    return "reaches administrator on its own"


def _shortest_route(
    source: str,
    roles: Sequence[str],
    by_role: dict[str, list[Statement]],
    trusts: dict[str, tuple[str, ...]],
    destinations: set[str],
) -> list[str] | None:
    """Breadth-first walk to the nearest admin-equivalent role."""
    queue = deque([[source]])
    seen = {source}
    while queue:
        path = queue.popleft()
        held = by_role.get(path[-1], [])
        for target in roles:
            if target in seen:
                continue
            if not _trusts(trusts.get(target, ()), path[-1]):
                continue
            if not _can_assume(held, target):
                continue
            seen.add(target)
            extended = path + [target]
            if target in destinations:
                return extended
            queue.append(extended)
    return None


def find_paths(statements: Sequence[Statement], trusts: dict[str, tuple[str, ...]]) -> list[Route]:
    """Find the shortest assume route from every role that is not admin to one that is.

    An edge ``A -> B`` exists when the trust policy on ``B`` names ``A`` and
    ``A`` holds ``sts:AssumeRole`` reaching ``B``. A route only ends on a role
    that reaches administrator on its own, so a lone assume is never a
    destination.
    """
    by_role = _group(statements)
    roles = sorted(set(by_role) | set(trusts))
    destinations = {role for role, held in by_role.items() if _reaches_admin_alone(held)}

    routes: list[Route] = []
    for source in roles:
        if source in destinations:
            continue
        path = _shortest_route(source, roles, by_role, trusts, destinations)
        if path is None:
            continue
        hops = len(path) - 1
        routes.append(
            Route(
                severity="CRITICAL" if hops == 1 else ("HIGH" if hops == 2 else "MEDIUM"),
                source=source,
                target=path[-1],
                hops=tuple(path),
                reason=f"{path[-1]} {_admin_reason(by_role.get(path[-1], []))}",
                source_file=by_role[source][0].file,
            )
        )
    return sorted(routes, key=lambda r: (-SEVERITY_RANK.get(r.severity, 0), r.source))


# --- reading the policy directory ------------------------------------------


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Normalise an IAM field that may be absent, a string or a list."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(item for item in value if isinstance(item, str))


def _statements_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the statement dicts of a policy document, however it is shaped."""
    statements = document.get("Statement")
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [item for item in statements if isinstance(item, dict)]
    return []


def _statement(role: str, policy: str, index: int, raw: dict[str, Any], path: Path) -> Statement:
    """Flatten one raw statement into the shape the rules read."""
    return Statement(
        role=role,
        policy=policy,
        index=index,
        effect=str(raw.get("Effect", "Allow")),
        actions=_as_tuple(raw.get("Action")),
        not_actions=_as_tuple(raw.get("NotAction")),
        resources=_as_tuple(raw.get("Resource")),
        not_resources=_as_tuple(raw.get("NotResource")),
        raw=raw,
        file=str(path),
    )


def _principals(trust: dict[str, Any]) -> tuple[str, ...]:
    """Collect the principals a trust policy names, as role names."""
    names: list[str] = []
    for raw in _statements_of(trust):
        if str(raw.get("Effect", "Allow")) != "Allow":
            continue
        principal = raw.get("Principal")
        values: list[str] = []
        if isinstance(principal, str):
            values = [principal]
        elif isinstance(principal, dict):
            aws = principal.get("AWS")
            values = [aws] if isinstance(aws, str) else list(_as_tuple(aws))
        for value in values:
            name = _role_name(value)
            if name not in names:
                names.append(name)
    return tuple(names)


def _read_entry(
    entry: dict[str, Any],
    path: Path,
    statements: list[Statement],
    trusts: dict[str, tuple[str, ...]],
) -> None:
    """Read one export out of a file: the document and the trust policy."""
    role = str(entry.get("RoleName") or path.stem)
    trust = entry.get("AssumeRolePolicyDocument") or entry.get("TrustPolicy")
    if isinstance(trust, dict):
        trusts[role] = _principals(trust)

    document = entry.get("Document")
    if not isinstance(document, dict):
        document = entry
    if "Statement" not in document:
        return

    policy = str(entry.get("PolicyName") or path.stem)
    for index, raw in enumerate(_statements_of(document)):
        statements.append(_statement(role, policy, index, raw, path))


def load_statements(directory: Path) -> tuple[list[Statement], dict[str, tuple[str, ...]], Scan]:
    """Walk the directory: return the statements, the trust policies and the counts."""
    statements: list[Statement] = []
    trusts: dict[str, tuple[str, ...]] = {}
    files = 0
    for path in sorted(directory.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: {path} skipped: {exc}", file=sys.stderr)
            continue
        files += 1
        for entry in payload if isinstance(payload, list) else [payload]:
            if isinstance(entry, dict):
                _read_entry(entry, path, statements, trusts)
    scan = Scan(
        files=files,
        statements=len(statements),
        allows=sum(1 for statement in statements if statement.effect == "Allow"),
    )
    return statements, trusts, scan


# --- phase 4: the baseline -------------------------------------------------


def _fingerprint(kind: str, ident: str, severity: str, reason: str) -> str:
    """Hash a row's identity: kind, label, severity and reason together.

    Severity is part of it on purpose - a rule that starts calling a row
    critical reprints the row instead of passing it off as unchanged.
    """
    digest = hashlib.sha1(f"{kind}|{ident}|{severity}|{reason}".encode("utf-8"))
    return digest.hexdigest()[:16]


def _finding_record(finding: Finding) -> Record:
    """Reduce a finding to the row the baseline stores."""
    return Record(
        kind="finding",
        ident=f"{finding.role}/{finding.policy}[{finding.index}]",
        severity=finding.severity,
        fingerprint=_fingerprint(
            "finding", f"{finding.role}/{finding.policy}[{finding.index}]", finding.severity, finding.reason
        ),
    )


def _escalation_record(escalation: Escalation) -> Record:
    """Reduce an escalation path to the row the baseline stores."""
    return Record(
        kind="escalation",
        ident=escalation.role,
        severity=escalation.severity,
        fingerprint=_fingerprint("escalation", escalation.role, escalation.severity, escalation.reason),
    )


def _route_record(route: Route) -> Record:
    """Reduce an assume route to the row the baseline stores."""
    ident = f"{route.source} -> {route.target}"
    return Record(
        kind="route",
        ident=ident,
        severity=route.severity,
        fingerprint=_fingerprint("route", ident, route.severity, route.reason),
    )


def snapshot(
    findings: Sequence[Finding],
    escalations: Sequence[Escalation],
    routes: Sequence[Route],
) -> list[Record]:
    """Pack every row this run produced into the rows the baseline stores."""
    return [
        *(_finding_record(finding) for finding in findings),
        *(_escalation_record(escalation) for escalation in escalations),
        *(_route_record(route) for route in routes),
    ]


def compare(
    previous: dict[str, tuple[str, str, str]], records: Sequence[Record]
) -> tuple[list[Record], list[tuple[str, str, str]], int]:
    """Split this run's rows into new, fixed and unchanged against the snapshot."""
    current = {record.fingerprint for record in records}
    new = [record for record in records if record.fingerprint not in previous]
    fixed = [entry for fingerprint, entry in previous.items() if fingerprint not in current]
    return new, fixed, len(records) - len(new)


def save_baseline(path: Path, records: Sequence[Record], timestamp: str) -> None:
    """Replace the snapshot on disk with this run's rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS findings "
            "(fingerprint TEXT PRIMARY KEY, kind TEXT, ident TEXT, severity TEXT)"
        )
        connection.execute("CREATE TABLE IF NOT EXISTS meta (recorded_at TEXT)")
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM meta")
        connection.executemany(
            "INSERT INTO findings VALUES (?, ?, ?, ?)",
            [(record.fingerprint, record.kind, record.ident, record.severity) for record in records],
        )
        connection.execute("INSERT INTO meta VALUES (?)", (timestamp,))


def load_baseline(path: Path) -> tuple[dict[str, tuple[str, str, str]], str | None]:
    """Read the stored snapshot, or return an empty one when there is none."""
    if not path.exists():
        return {}, None
    try:
        with sqlite3.connect(path) as connection:
            rows = connection.execute(
                "SELECT fingerprint, kind, ident, severity FROM findings"
            ).fetchall()
            stamp = connection.execute("SELECT recorded_at FROM meta").fetchone()
    except sqlite3.Error:
        return {}, None
    loaded = {fingerprint: (kind, ident, severity) for fingerprint, kind, ident, severity in rows}
    return loaded, (stamp[0] if stamp else None)


def worst_severity(severities: Iterable[str]) -> str | None:
    """Return the worst severity present, or None when there is nothing to rank."""
    worst: str | None = None
    for severity in severities:
        if worst is None or SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(worst, 0):
            worst = severity
    return worst


def breaches(severities: Iterable[str], fail_on: str) -> bool:
    """True when any row sits at the ``--fail-on`` severity or worse."""
    if fail_on == "NONE":
        return False
    threshold = SEVERITY_RANK.get(fail_on, 0)
    return any(SEVERITY_RANK.get(severity, 0) >= threshold for severity in severities)


def _only_new(rows: Iterable[Any], record_of: Any, fresh: set[str]) -> list[Any]:
    """Keep the rows whose fingerprint this run recorded as new."""
    return [row for row in rows if record_of(row).fingerprint in fresh]


# --- phase 5: the output formats -------------------------------------------


def _finding_row(finding: Finding) -> dict[str, Any]:
    """Reduce an over-broad Allow statement to the fields the JSON output carries."""
    return {
        "severity": finding.severity,
        "role": finding.role,
        "policy": finding.policy,
        "index": finding.index,
        "file": finding.source_file,
        "reason": finding.reason,
        "statement": finding.statement,
    }


def _escalation_row(escalation: Escalation) -> dict[str, Any]:
    """Reduce an escalation path to the fields the JSON output carries."""
    return {
        "severity": escalation.severity,
        "role": escalation.role,
        "actions": list(escalation.actions),
        "file": escalation.source_file,
        "reason": escalation.reason,
    }


def _route_row(route: Route) -> dict[str, Any]:
    """Reduce an assume route to the fields the JSON output carries."""
    return {
        "severity": route.severity,
        "source": route.source,
        "target": route.target,
        "hops": len(route.hops) - 1,
        "path": list(route.hops),
        "file": route.source_file,
        "reason": route.reason,
    }


def _counts(severities: Iterable[str]) -> dict[str, int]:
    """Count rows per severity, worst first."""
    counts: dict[str, int] = {}
    for severity in severities:
        counts[severity] = counts.get(severity, 0) + 1
    return {severity: counts[severity] for severity in sorted(counts, key=lambda s: -SEVERITY_RANK.get(s, 0))}


def _section(rows: Sequence[Any], total: int) -> dict[str, Any]:
    """Summarise one table: what is new, what the run holds, and the spread."""
    return {"new": len(rows), "total": total, "by_severity": _counts(row.severity for row in rows)}


def _fixed_rows(drift: Drift) -> list[dict[str, str]]:
    """List the rows that were in the snapshot and are not in this run."""
    return [{"kind": kind, "severity": severity, "what": ident} for kind, ident, severity in drift.fixed]


def _suffix(severities: Iterable[str]) -> str:
    """Render the per-severity breakdown that trails a count line."""
    counts = _counts(severities)
    return " - " + ", ".join(f"{count} {severity}" for severity, count in counts.items()) if counts else ""


def render_json(report: Report) -> str:
    """Format the run as one JSON document: the new rows, the drift and the gate.

    Only the rows the report shows are listed - the new ones, or every row on a
    first run or after ``--reset``. ``counts`` covers the whole run.
    """
    document = {
        "tool": "iam-escalation-lint",
        "phase": PHASE,
        "directory": report.directory,
        "scan": {
            "files": report.scan.files,
            "statements": report.scan.statements,
            "allows": report.scan.allows,
        },
        "baseline": {
            "file": str(report.drift.baseline),
            "previous_run": report.drift.previous_run,
            "fixed": _fixed_rows(report.drift),
            "unchanged": report.drift.unchanged,
        },
        "counts": {
            "findings": _section(report.findings, report.total[0]),
            "escalations": _section(report.escalations, report.total[1]),
            "routes": _section(report.routes, report.total[2]),
        },
        "gate": {"fail_on": report.fail_on, "breached": report.breached},
        "findings": [_finding_row(finding) for finding in report.findings],
        "escalations": [_escalation_row(escalation) for escalation in report.escalations],
        "routes": [_route_row(route) for route in report.routes],
    }
    return json.dumps(document, indent=2)


def _sarif_result(
    rule_index: int,
    severity: str,
    location: str,
    fingerprint: str,
    message: str,
    properties: dict[str, str],
) -> dict[str, Any]:
    """Build one SARIF result.

    The baseline fingerprint rides along as the partial fingerprint, which is
    what lets a code-scanning upload update the alert it already has instead of
    opening a second one for the same row. A row with no source file gets no
    location rather than an empty one.
    """
    result: dict[str, Any] = {
        "ruleId": SARIF_RULES[rule_index]["id"],
        "ruleIndex": rule_index,
        "level": SARIF_LEVEL.get(severity, "warning"),
        "message": {"text": message},
        "partialFingerprints": {"iam-escalation-lint/v1": fingerprint},
        "properties": {
            **properties,
            "severity": severity,
            "security-severity": SECURITY_SEVERITY.get(severity, "5.0"),
        },
    }
    if location:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": location}}}]
    return result


def render_sarif(report: Report) -> str:
    """Format the run as SARIF 2.1.0 for a code-scanning upload.

    One rule per check family, the severity mapped to a code-scanning level, and
    the drift in the invocation properties: what this run reported, what went
    fixed, and whether the threshold was breached.
    """
    results = [
        *(
            _sarif_result(
                0,
                finding.severity,
                finding.source_file,
                _finding_record(finding).fingerprint,
                f"{finding.role}/{finding.policy} [{finding.index}]: {finding.reason}",
                {"role": finding.role, "policy": finding.policy},
            )
            for finding in report.findings
        ),
        *(
            _sarif_result(
                1,
                escalation.severity,
                escalation.source_file,
                _escalation_record(escalation).fingerprint,
                f"{escalation.role}: {escalation.reason}",
                {"role": escalation.role},
            )
            for escalation in report.escalations
        ),
        *(
            _sarif_result(
                2,
                route.severity,
                route.source_file,
                _route_record(route).fingerprint,
                f"{route.source} -> {route.target} in {len(route.hops) - 1} hop(s): {route.reason}",
                {"role": route.source, "target": route.target},
            )
            for route in report.routes
        ),
    ]
    run = {
        "tool": {
            "driver": {
                "name": "iam-escalation-lint",
                "version": f"phase-{PHASE}",
                "rules": list(SARIF_RULES),
            }
        },
        "invocations": [
            {
                "executionSuccessful": True,
                "properties": {
                    "baseline_file": str(report.drift.baseline),
                    "previous_run": report.drift.previous_run,
                    "fixed": _fixed_rows(report.drift),
                    "unchanged": report.drift.unchanged,
                    "fail_on": report.fail_on,
                    "breached": report.breached,
                },
            }
        ],
        "results": results,
    }
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)


def render(report: Report, detail_limit: int) -> str:
    """Format the terminal report: what is new, what was fixed, what stands.

    The three tables are already filtered to this run's new rows; on a first
    run that is every row, and the report reads exactly as it did before the
    baseline existed. A ``--fail-on`` other than NONE appends the gate verdict.
    """
    findings = report.findings
    escalations = report.escalations
    routes = report.routes
    scan = report.scan
    drift = report.drift
    fresh = drift.previous_run is not None
    recorded = len(findings) + len(escalations) + len(routes)

    lines = [
        BANNER,
        f"scanned {scan.files} policy files | {scan.statements} statements | {scan.allows} Allow",
    ]
    if fresh:
        lines.append(f"baseline {drift.baseline} | compared against {drift.previous_run}")
    else:
        lines.append(f"baseline {drift.baseline} initialised - {recorded} findings recorded")
    lines.append("")

    if findings:
        rows = [(f.severity, f.role, f.policy, str(f.index), f.reason) for f in findings]
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
                lines.append(f"{finding.severity} {finding.role}/{finding.policy} [{finding.index}]")
                lines.append("  " + json.dumps(finding.statement))
    else:
        lines.append(
            "no new over-broad Allow statements" if fresh else "no over-broad Allow statements found"
        )

    lines.append("")
    lines.append("--- escalation paths (role -> administrator) ---")
    if escalations:
        sev_w = max(len("SEV"), max(len(e.severity) for e in escalations))
        role_w = max(len("ROLE"), max(len(e.role) for e in escalations))
        lines.append(f"{'SEV':<{sev_w}}  {'ROLE':<{role_w}}  PATH")
        for escalation in escalations:
            lines.append(f"{escalation.severity:<{sev_w}}  {escalation.role:<{role_w}}  {escalation.reason}")
    else:
        lines.append(
            "no new escalation paths" if fresh else "no role holds a known escalation primitive"
        )

    lines.append("")
    lines.append("--- reachability (role -> role) ---")
    if routes:
        sev_w = max(len("SEV"), max(len(r.severity) for r in routes))
        src_w = max(len("FROM"), max(len(r.source) for r in routes))
        lines.append(f"{'SEV':<{sev_w}}  {'FROM':<{src_w}}  HOPS  PATH")
        for route in routes:
            lines.append(
                f"{route.severity:<{sev_w}}  {route.source:<{src_w}}  "
                f"{len(route.hops) - 1:>4}  {' -> '.join(route.hops)} ({route.reason})"
            )
    else:
        lines.append(
            "no new assume routes to administrator"
            if fresh
            else "no role reaches an admin-equivalent role through assume"
        )

    if drift.fixed:
        lines.append("")
        lines.append(f"--- fixed since {drift.previous_run} ---")
        sev_w = max(len("SEV"), max(len(severity) for _, _, severity in drift.fixed))
        kind_w = max(len("KIND"), max(len(kind) for kind, _, _ in drift.fixed))
        lines.append(f"{'SEV':<{sev_w}}  {'KIND':<{kind_w}}  WHAT")
        for kind, ident, severity in drift.fixed:
            lines.append(f"{severity:<{sev_w}}  {kind:<{kind_w}}  {ident}")

    lines.append("")
    if fresh and not recorded:
        lines.append(
            f"nothing new since {drift.previous_run} - {len(drift.fixed)} fixed, {drift.unchanged} unchanged"
        )
    else:
        mark = " new" if fresh else ""
        lines.append(f"{len(findings)}{mark} findings" + _suffix(f.severity for f in findings))
        lines.append(
            f"{len(escalations)}{mark} escalation paths" + _suffix(e.severity for e in escalations)
        )
        lines.append(
            f"{len(routes)}{mark} assume routes to administrator" + _suffix(r.severity for r in routes)
        )
        if fresh:
            lines.append(f"{len(drift.fixed)} fixed, {drift.unchanged} unchanged")
    if report.fail_on != "NONE":
        lines.append(
            f"gate: fail-on {report.fail_on} - "
            + ("breached, exiting 1" if report.breached else "no new row at or above it")
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, scan the policy directory, report and re-record the drift.

    Returns 1 when a row new to this run is at the ``--fail-on`` severity or
    worse, 2 when the policy directory is not a directory, and 0 otherwise. The
    json and sarif formats print their document on stdout and their one-line
    summary on stderr, so a redirect keeps the document clean.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Report over-broad Allow statements, role-level privilege escalation "
            "paths and assume routes to administrator in exported AWS IAM policies, "
            "compared against the last run."
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
        help="how many new findings to expand with their raw statement (default: 10)",
    )
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help=f"sqlite file holding the last run's findings (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="ignore the stored baseline and report every finding as new again",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        type=str.upper,
        choices=FAIL_LEVELS,
        default="NONE",
        help=(
            "exit 1 when a row new to this run is at this severity or worse "
            "(default: NONE, never fail)"
        ),
    )
    args = parser.parse_args(argv)

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 2

    baseline = Path(args.baseline)
    statements, trusts, scan = load_statements(directory)
    findings = analyze(statements)
    escalations = find_escalations(statements)
    routes = find_paths(statements, trusts)

    records = snapshot(findings, escalations, routes)
    previous, last_run = ({}, None) if args.reset else load_baseline(baseline)
    new_records, fixed, unchanged = compare(previous, records)
    fresh = {record.fingerprint for record in new_records}

    report = Report(
        directory=str(directory),
        scan=scan,
        findings=tuple(_only_new(findings, _finding_record, fresh)),
        escalations=tuple(_only_new(escalations, _escalation_record, fresh)),
        routes=tuple(_only_new(routes, _route_record, fresh)),
        total=(len(findings), len(escalations), len(routes)),
        drift=Drift(
            baseline=baseline,
            previous_run=last_run,
            fixed=tuple(fixed),
            unchanged=unchanged,
        ),
        fail_on=args.fail_on,
        breached=breaches((record.severity for record in new_records), args.fail_on),
    )

    if args.format == "text":
        print(render(report, args.top))
    else:
        print(render_json(report) if args.format == "json" else render_sarif(report))
        print(
            f"iamlint {args.format}: {len(new_records)} new rows, "
            f"worst {worst_severity(r.severity for r in new_records) or 'none'}, "
            f"fail-on {args.fail_on}",
            file=sys.stderr,
        )

    try:
        save_baseline(baseline, records, datetime.now().isoformat(timespec="seconds"))
    except sqlite3.Error as exc:
        print(f"warning: baseline not written: {exc}", file=sys.stderr)
    return 1 if report.breached else 0