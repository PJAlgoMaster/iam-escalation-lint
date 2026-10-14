# iam-escalation-lint

I wrote this to read a directory of exported AWS IAM policies and tell me which statements are over-broad and which roles can actually reach administrator.
It runs offline, on the standard library, on Python 3.
No API keys, no network, no install step.

## Run it

```
python main.py
```

No arguments. It walks the policy directory that ships in the repo - 12 files, 21 statements, 19 Allow in the sample.
Every run records findings into a sqlite baseline and prints only what changed since the last one.

## What it does

It resolves `Allow` with `NotAction`, so a statement that permits "everything except `iam:*`" does not get read as narrow.
It ranks each statement CRITICAL / HIGH / MEDIUM / LOW by how much of the account it actually touches.
It flags the escalation primitives that matter: `iam:PassRole` into `lambda:CreateFunction`, `iam:CreatePolicyVersion`, `sts:AssumeRole`.
It builds the role-to-role trust and assume graph and reports the shortest path from a low-privilege role to one holding `Allow "*" on "*"`.
It stores findings in a sqlite baseline, so a re-run prints new, fixed and unchanged instead of the same wall of text.
Phase 5 added SARIF and JSON output plus a severity threshold, so the same command can gate a pull request.

## Example

`python main.py` on the sample policy set prints this:

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

The first line is real too: the meta row does not insert when the baseline is created. Findings and drift still record, so it is cosmetic, and it is the next thing I fix.

## Phases

1. Parse and wildcard report - walks the directory, resolves `Allow` with `NotAction`, prints ranked findings.
2. Escalation rule engine - the known escalation primitives and the role-level combinations that reach admin.
3. Reachability graph - role-to-role trust and assume edges, shortest path to an admin-equivalent role.
4. Baseline and drift - sqlite baseline, prints new, fixed and unchanged since the last snapshot.
5. CI output and exit codes - SARIF and JSON plus a severity threshold, so one command gates a pull request.

## In a real environment

I would run it in CI on every change to the IAM templates, with the severity threshold set so a CRITICAL finding fails the build, and the sqlite baseline committed so the pull request shows only what that change added.
The 2-hop path above is the kind of thing a weekly manual review misses: nothing in `dev-readonly` looks wrong by itself, it is the route through `release-runner` that matters.