"""Assert-based checks for the finding rules and the escalation engine.

Run: python test_iamlint.py
"""

from iamlint import Statement, analyze, find_escalations


def stmt(
    effect: str = "Allow",
    actions: tuple[str, ...] = (),
    not_actions: tuple[str, ...] = (),
    resources: tuple[str, ...] = (),
    not_resources: tuple[str, ...] = (),
) -> Statement:
    """Build a statement with only the fields the checks read."""
    return Statement(
        role="test-role",
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

    total = len(CASES) + len(ESCALATION_CASES)
    print(f"{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())