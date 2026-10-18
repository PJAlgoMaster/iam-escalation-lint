# iam-escalation-lint

I exported our IAM policies to a folder and pointed this at it. It tells me which statements are too broad, and which roles can walk to administrator. Python 3, standard library only, no network, no API keys.

## Run

```
python main.py
```

It walks the sample policy directory that ships in the repo and prints findings ranked by severity. Then it writes `.iamlint-baseline.db`. On the next run it reports only what is new, fixed or unchanged since that snapshot, so the weekly re-read is a short diff instead of a full audit.

Phase 5 added SARIF and JSON output and a severity threshold, so the same command can fail a pull request.

## What it printed

```
scanned 12 policy files | 21 statements | 19 Allow
baseline .iamlint-baseline.db initialised - 21 findings recorded

SEV       ROLE              POLICY            STMT  WHY
CRITICAL  app-deploy        deploy-artifacts     0  Allow "*" on "*" - full administrator
CRITICAL  ci-runner         ci-runner            0  Allow NotAction on "*" - permits everything except iam:*, organizations:*
CRITICAL  ops-admin         admin-ops            0  Allow "*" on "*" - full administrator
HIGH      backup            backup               0  Allow kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey on "*" - named control of kms
HIGH      build-release     deploy-pipeline      1  Allow iam:PassRole on arn:aws:iam::111122223333:role/release-runner - named control of iam
HIGH      data-science      data-science         0  Allow s3:* on "*" - service-wide control of every bucket in the account
HIGH      data-science      data-science         1  Allow iam:PassRole, iam:GetRole, iam:ListRoles on "*" - named control of iam
HIGH      dev-readonly      read-only            1  Allow sts:AssumeRole on arn:aws:iam::111122223333:role/release-runner - named control of sts
HIGH      legacy-migration  legacy-migration     0  Allow s3:GetObject, s3:PutObject except arn:aws:s3:::locked-*/* - every other resource is permitted
HIGH      platform-admin    ops-bucket-full      0  Allow "*" on arn:aws:s3:::ops-* - every action, including the ones AWS adds next quarter
HIGH      release-runner    release-ops          0  Allow sts:AssumeRole on arn:aws:iam::111122223333:role/ops-admin - named control of sts
MEDIUM    analytics         analytics            0  Allow dynamodb:* on arn:aws:dynamodb:ap-south-1:111122223333:table/events - service-wide, scoped to one resource
MEDIUM    analytics         analytics            1  Allow ec2:TerminateInstances, ec2:StopInstances on "*" - named actions with no resource scope
MEDIUM    dev-readonly      read-only            0  Allow s3:GetObject, ec2:DescribeInstances on "*" - named actions with no resource scope
LOW       reporting         reporting            0  Allow s3:Get*, s3:List* on "*" - read-only wildcard

--- escalation paths (role -> administrator) ---
CRITICAL  build-release   iam:PassRole + lambda:CreateFunction - hand a role to it and run code as that role
CRITICAL  ci-runner       iam:PassRole + lambda:CreateFunction - hand a role to it and run code as that role
HIGH      dev-readonly    sts:AssumeRole - assume any role it can name
HIGH      release-runner  sts:AssumeRole - assume any role it can name

--- reachability (role -> role) ---
CRITICAL  release-runner     1  release-runner -> ops-admin (ops-admin holds Allow "*" on "*")
HIGH      dev-readonly       2  dev-readonly -> release-runner -> ops-admin (ops-admin holds Allow "*" on "*")

15 findings - 3 CRITICAL, 8 HIGH, 3 MEDIUM, 1 LOW
4 escalation paths - 2 CRITICAL, 2 HIGH
2 assume routes to administrator - 1 CRITICAL, 1 HIGH
```

Each finding also prints the raw statement JSON underneath, so I can paste the offending `Sid` straight into the ticket.

## Phases

1. Parse and wildcard report: walks the policy directory, resolves Allow with NotAction, prints ranked findings.
2. Escalation rule engine: the known primitives, including iam:PassRole into lambda:CreateFunction, iam:CreatePolicyVersion and sts:AssumeRole, flagged as role-level combinations.
3. Reachability graph: role-to-role trust and assume edges, shortest path from a low-privilege role to an admin-equivalent one.
4. Baseline and drift: findings in sqlite, so a re-run prints new, fixed and unchanged since the last snapshot.
5. CI output and exit codes: SARIF and JSON output, severity threshold, non-zero exit for the gate.

## In a real environment

I would run it in CI against the policy directory on every change, keep the baseline file in the repo, and fail the build on a new CRITICAL while reviewers look at the drift lines instead of the whole report.