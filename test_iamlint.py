"""Assert-based checks for the finding rules, the escalation engine and the
reachability graph.

Run: python test_iamlint.py
"""

from iamlint import Statement, analyze, find_escalations, find_paths


def stmt(
    effect: str = "Allow",
    actions: tuple[str, ...] = (),
    not_actions: tuple[str, ...] = (),
    resources: tuple[str, ...] = (),
    not_resources: tuple[str, ...] = (),
    role: str = "test-role",
) -> Statement:
    """Build a statement with only the fields the checks read."""
    return Statement(
        role=role,
        policy="test-policy",
        index=0,
        effect=effect,
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        not_resources=not_resources,
        raw={},
    )


CASES: list[tuple[str, Statement, str | None]] = [
    ("star on star is critical", stmt(actions=("*",), resources=("*",)), "CRITICAL"),
    (
        "star on a scoped resource is high",
        stmt(actions=("*",), resources=("arn:aws:s3:::a/*",)),
        "HIGH",
    ),
    (
        "NotAction with a wildcard resource is critical",
        stmt(not_actions=("iam:*",), resources=("*",)),
        "CRITICAL",
    ),
    (
        "NotAction on a scoped resource is high",
        stmt(not_actions=("iam:*",), resources=("arn:aws:s3:::a",)),
        "HIGH",
    ),
    ("NotAction star grants nothing", stmt(not_actions=("*",), resources=("*",)), None),
    (
        "iam wildcard on a scoped resource is high",
        stmt(actions=("iam:*",), resources=("arn:aws:s3:::a",)),
        "HIGH",
    ),
    ("service wildcard on all resources is high", stmt(actions=("s3:*",), resources=("*",)), "HIGH"),
    (
        "service wildcard on a scoped resource is medium",
        stmt(actions=("dynamodb:*",), resources=("arn:aws:dynamodb:x",)),
        "MEDIUM",
    ),
    (
        "read-only wildcards are low",
        stmt(actions=("s3:Get*", "s3:List*"), resources=("*",)),
        "LOW",
    ),
    (
        "named iam actions on all resources is high",
        stmt(actions=("iam:PassRole",), resources=("*",)),
        "HIGH",
    ),
    (
        "named non-sensitive actions on all resources is medium",
        stmt(actions=("ec2:StopInstances",), resources=("*",)),
        "MEDIUM",
    ),
    (
        "scoped read actions are clean",
        stmt(actions=("s3:GetObject",), resources=("arn:aws:s3:::a/*",)),
        None,
    ),
    ("Deny is ignored", stmt(effect="Deny", actions=("*",), resources=("*",)), None),
    (
        "NotResource is high",
        stmt(actions=("s3:PutObject",), not_resources=("arn:aws:s3:::locked/*",)),
        "HIGH",
    ),
]

ESCALATION_CASES: list[tuple[str, list[Statement], str | None]] = [
    (
        "CreatePolicyVersion is an escalation primitive",
        [stmt(actions=("iam:CreatePolicyVersion",), resources=("*",))],
        "HIGH",
    ),
    (
        "AssumeRole is an escalation primitive",
        [stmt(actions=("sts:AssumeRole",), resources=("*",))],
        "HIGH",
    ),
    (
        "PassRole plus CreateFunction is critical",
        [
            stmt(actions=("iam:PassRole",), resources=("arn:aws:iam::1:role/r",)),
            stmt(actions=("lambda:CreateFunction",), resources=("arn:aws:lambda:x",)),
        ],
        "CRITICAL",
    ),
    (
        "PassRole plus RunInstances is critical",
        [
            stmt(actions=("iam:PassRole",), resources=("*",)),
            stmt(actions=("ec2:RunInstances",), resources=("*",)),
        ],
        "CRITICAL",
    ),
    (
        "an iam wildcard covers the primitive it names",
        [stmt(actions=("iam:*",), resources=("arn:aws:iam::1:role/*",))],
        "HIGH",
    ),
    (
        "PassRole alone is not a path",
        [stmt(actions=("iam:PassRole",), resources=("*",))],
        None,
    ),
    (
        "CreateFunction alone is not a path",
        [stmt(actions=("lambda:CreateFunction",), resources=("arn:aws:lambda:x",))],
        None,
    ),
    (
        "a full admin role is not reported twice",
        [stmt(actions=("*",), resources=("*",))],
        None,
    ),
    (
        "star scoped to s3 cannot call iam",
        [stmt(actions=("*",), resources=("arn:aws:s3:::ops-*",))],
        None,
    ),
    (
        "NotAction that still permits sts is escalation",
        [stmt(not_actions=("iam:*", "organizations:*"), resources=("*",))],
        "HIGH",
    ),
    (
        "a Deny on the primitive takes it back",
        [
            stmt(actions=("iam:CreateAccessKey",), resources=("*",)),
            stmt(effect="Deny", actions=("iam:CreateAccessKey",), resources=("*",)),
        ],
        None,
    ),
    (
        "a Deny on PassRole clears the chain",
        [
            stmt(actions=("iam:PassRole",), resources=("*",)),
            stmt(actions=("lambda:CreateFunction",), resources=("arn:aws:lambda:x",)),
            stmt(effect="Deny", actions=("iam:PassRole",), resources=("*",)),
        ],
        None,
    ),
]

ADMIN = stmt(actions=("*",), resources=("*",), role="admin-role")

GRAPH_CASES: list[tuple[str, list[Statement], dict[str, tuple[str, ...]], str | None]] = [
    (
        "one assume hop into a full admin role is critical",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            ADMIN,
        ],
        {"admin-role": ("test-role",)},
        "CRITICAL",
    ),
    (
        "a two-hop chain is high",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/mid-role",)),
            stmt(
                actions=("sts:AssumeRole",),
                resources=("arn:aws:iam::1:role/admin-role",),
                role="mid-role",
            ),
            ADMIN,
        ],
        {"mid-role": ("test-role",), "admin-role": ("mid-role",)},
        "HIGH",
    ),
    (
        "a trust that names someone else leaves no edge",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            ADMIN,
        ],
        {"admin-role": ("another-role",)},
        None,
    ),
    (
        "trust without the assume permission is not a route",
        [stmt(actions=("s3:GetObject",), resources=("*",)), ADMIN],
        {"admin-role": ("test-role",)},
        None,
    ),
    (
        "a Deny on sts:AssumeRole removes the edge",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            stmt(effect="Deny", actions=("sts:AssumeRole",), resources=("*",)),
            ADMIN,
        ],
        {"admin-role": ("test-role",)},
        None,
    ),
    (
        "a role that only holds assume is a hop, not a destination",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/mid-role",)),
            stmt(actions=("sts:AssumeRole",), resources=("*",), role="mid-role"),
        ],
        {"mid-role": ("test-role",)},
        None,
    ),
    (
        "a wildcard principal in the trust policy still needs the assume grant",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            ADMIN,
        ],
        {"admin-role": ("*",)},
        "CRITICAL",
    ),
    (
        "a role that is already administrator is not a source",
        [
            stmt(actions=("iam:CreateAccessKey",), resources=("*",)),
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            ADMIN,
        ],
        {"admin-role": ("test-role",)},
        None,
    ),
    (
        "the shortest chain wins",
        [
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/mid-role",)),
            stmt(actions=("sts:AssumeRole",), resources=("arn:aws:iam::1:role/admin-role",)),
            stmt(
                actions=("sts:AssumeRole",),
                resources=("arn:aws:iam::1:role/admin-role",),
                role="mid-role",
            ),
            ADMIN,
        ],
        {"mid-role": ("test-role",), "admin-role": ("test-role", "mid-role")},
        "CRITICAL",
    ),
]


def main() -> int:
    """Run every case and report how many passed."""
    failures = 0

    for name, statement, expected in CASES:
        findings = analyze([statement])
        got = findings[0].severity if findings else None
        if got != expected:
            failures += 1
            print(f"FAIL {name}: expected {expected}, got {got}")

    for name, statements, expected in ESCALATION_CASES:
        paths = find_escalations(statements)
        got = paths[0].severity if paths else None
        if got != expected:
            failures += 1
            print(f"FAIL {name}: expected {expected}, got {got}")

    for name, statements, trusts, expected in GRAPH_CASES:
        routes = find_paths(statements, trusts)
        got = routes[0].severity if routes else None
        if got != expected:
            failures += 1
            print(f"FAIL {name}: expected {expected}, got {got}")

    total = len(CASES) + len(ESCALATION_CASES) + len(GRAPH_CASES)
    print(f"{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())