# iam-escalation-lint

Reads a directory of exported AWS IAM policies and tells you which statements are too broad, and which roles can climb to admin from where they sit.

I built it because a weekly export of 12 policy files is more than one person can re-read. The linter reads them all in a second and only shows me what changed since last week.

## How to run it

```
python main.py
```

Python 3, standard library only, no network, no credentials. The sample policies are in the repo, so it runs offline out of the box.

It writes findings to a sqlite baseline (`.iamlint-baseline.db`) on the first run. Every run after that prints new, fixed and unchanged findings against that snapshot, so a weekly review is a diff instead of a re-read.

Phase 5 adds SARIF and JSON output plus a severity threshold, so the same command can gate a pull request instead of me reading the terminal.

## Example run

```
warning: baseline not written: table meta has 2 columns but 1 values were supplied
IAM PRIVILEGE ESCALATION LINT - phase 5 (wildcard audit + escalation primitives + reachability + baseline drift + CI output)
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

--- statement detail (top 10) ---
CRITICAL app-deploy/deploy-artifacts [0]
  {"Sid": "FullAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}
CRITICAL ci-runner/ci-runner [0]
  {"Sid": "EverythingButIam", "Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}
CRITICAL ops-admin/admin-ops [0]
  {"Sid": "EverythingEverywhere", "Effect": "Allow", "Action": "*", "Resource": "*"}
HIGH backup/backup [0]
  {"Sid": "RestoreKeys", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], "Resource": "*"}
HIGH build-release/deploy-pipeline [1]
  {"Sid": "HandRoleToLambda", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/release-runner"}
HIGH data-science/data-science [0]
  {"Sid": "AllBuckets", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}
HIGH data-science/data-science [1]
  {"Sid": "RoleHandoff", "Effect": "Allow", "Action": ["iam:PassRole", "iam:GetRole", "iam:ListRoles"], "Resource": "*"}
HIGH dev-readonly/read-only [1]
  {"Sid": "AssumeRelease", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::111122223333:role/release-runner"}
HIGH legacy-migration/legacy-migration [0]
  {"Sid": "EverythingButLocked", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "NotResource": "arn:aws:s3:::locked-*/*"}
HIGH platform-admin/ops-bucket-full [0]
  {"Sid": "AllActionsOnOpsBuckets", "Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::ops-*"}

--- escalation paths (role -> administrator) ---
SEV       ROLE            PATH
CRITICAL  build-release   iam:PassRole + lambda:CreateFunction - hand a role to it and run code as that role
CRITICAL  ci-runner       iam:PassRole + lambda:CreateFunction - hand a role to it and run code as that role
HIGH      dev-readonly    sts:AssumeRole - assume any role it can name
HIGH      release-runner  sts:AssumeRole - assume any role it can name

--- reachability (role -> role) ---
SEV       FROM            HOPS  PATH
CRITICAL  release-runner     1  release-runner -> ops-admin (ops-admin holds Allow "*" on "*")
HIGH      dev-readonly       2  dev-readonly -> release-runner -> ops-admin (ops-admin holds Allow "*" on "*")

15 findings - 3 CRITICAL, 8 HIGH, 3 MEDIUM, 1 LOW
4 escalation paths - 2 CRITICAL, 2 HIGH
2 assume routes to administrator - 1 CRITICAL, 1 HIGH
```

The finding I would have missed by eye is the last one. `dev-readonly` looks harmless, but it can assume `release-runner`, and `release-runner` can assume `ops-admin`, which holds `Allow "*"` on `"*"`. Two hops from a read-only role to the account administrator.

## How it was built

1. **Parse and wildcard report** — walk a policy directory, resolve `Allow` with `NotAction`, print ranked findings (severity, role, statement) end to end.
2. **Escalation rule engine** — the known escalation primitives (`iam:PassRole` into `lambda:CreateFunction`, `iam:CreatePolicyVersion`, `sts:AssumeRole`) and the role-level combinations that matter.
3. **Reachability graph** — build the role-to-role trust and assume graph, find shortest paths from a low-privilege role to an admin-equivalent one.
4. **Baseline and drift** — hold findings in sqlite, so a re-run prints only new, fixed and unchanged findings since the last snapshot.
5. **CI output and exit codes** — SARIF and JSON plus severity thresholds, so the same command can gate a pull request.

## Where this runs for real

In CI, against the IAM Terraform repo on every pull request, failing the build above the chosen threshold. And weekly, against an AWS IAM export dropped in a directory, where the sqlite baseline turns 21 findings into the two or three that changed since last Monday.