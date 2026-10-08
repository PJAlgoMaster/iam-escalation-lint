# iam-escalation-lint

Reads a directory of exported AWS IAM policies and prints two things: the
over-broad Allow statements, ranked by severity, and the roles that hold a
known path to administrator.

## Run

    python main.py

No arguments, no network, no dependencies outside the Python 3 standard
library. It reads the sample policy set in `policies/` and prints a report.

Point it at a real export by passing the directory:

    python main.py ~/exports/iam-policies-2026-10-08

## What it finds

### Over-broad Allow statements

| Severity | Pattern | Why it matters |
|---|---|---|
| CRITICAL | `Action: "*"` with `Resource: "*"` | Full administrator. |
| CRITICAL | `NotAction` with `Resource: "*"` | Inverted logic: permits every action except the short excluded list. |
| HIGH | `Action: "*"` on a scoped resource | Every action, including the ones AWS adds next quarter. |
| HIGH | `iam:*`, `sts:*`, `kms:*` | Service-wide control of a privilege-bearing service. |
| HIGH | `s3:*` with `Resource: "*"` | Service-wide control of every bucket in the account. |
| HIGH | A named action on `*` under `iam`/`sts`/`kms` | Narrow action, no resource scope. `iam:PassRole` on `*` is an escalation primitive. |
| HIGH | `NotResource` on an Allow | Permits every resource except the excluded prefix. |
| MEDIUM | `dynamodb:*` on one table | Service-wide, but scoped to one resource. |
| MEDIUM | Named write actions on `*` | No resource scoping. |
| LOW | `s3:Get*`, `s3:List*` | Read-only wildcard. Tolerable, still worth knowing. |

Deny statements are counted and skipped here. `NotAction: "*"` grants nothing
and is skipped too.

### Escalation paths

A statement can look harmless on its own and still be the first step to
administrator. This second pass reads every statement a role holds together
and asks whether the role can reach admin in one step.

| Severity | Pattern | Why it matters |
|---|---|---|
| CRITICAL | `iam:PassRole` plus an action that runs code as a role | `lambda:CreateFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack` and nine more. Pass a role, run code as it. |
| HIGH | Any one identity-writing primitive | `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:AddUserToGroup`, `sts:AssumeRole` and eight more. |

Two things are deliberately *not* reported again in this section:

- `iam:PassRole` on its own. Without a consumer action to use the role it is
  a risk, not a path. Phase 1 already flags the statement.
- A role that already holds `Allow "*" on "*"`. The wildcard table says
  CRITICAL; listing all thirteen primitives under it is noise.

The match handles wildcards: `iam:*` covers `iam:CreatePolicyVersion`, and a
`NotAction` list is subtracted from what a statement grants. A `Deny` on the
same action takes the primitive back. An `Action: "*"` scoped to
`arn:aws:s3:::ops-*` can never call an IAM action and is not counted.

## Input format

Every `*.json` file under the directory is read, recursively. A file may be:

- a bare policy document (`{"Version": ..., "Statement": [...]}`), where the
  file name is the role name;
- an export that wraps a document
  (`{"RoleName": ..., "PolicyName": ..., "Document": {...}}`);
- a JSON list of either.

## Sample output

The bundled set is 11 policy files, 17 statements, 15 of them Allow:

    IAM PRIVILEGE ESCALATION LINT - phase 2 (wildcard audit + escalation primitives)
    scanned 11 policy files | 17 statements | 15 Allow

    SEV       ROLE              POLICY             STMT  WHY
    CRITICAL  app-deploy        deploy-artifacts      0  Allow "*" on "*" - full administrator
    CRITICAL  ci-runner         ci-runner             0  Allow NotAction on "*" - permits everything except iam:*, organizations:*
    HIGH      backup            backup                0  Allow kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey on "*" - named control of kms
    HIGH      build-release     deploy-pipeline       1  Allow iam:PassRole on a scoped resource - named control of iam
    HIGH      data-science      data-science          0  Allow s3:* on "*" - service-wide control
    HIGH      data-science      data-science          1  Allow iam:PassRole, iam:GetRole, iam:ListRoles on "*" - named control of iam
    HIGH      legacy-migration  legacy-migration      0  Allow NotResource - permits every resource except arn:aws:s3:::locked-*/*
    HIGH      platform-admin    ops-bucket-full       0  Allow "*" on a scoped resource - every action, no action filtering
    MEDIUM    analytics         analytics             0  Allow dynamodb:* on a scoped resource - service-wide control
    MEDIUM    analytics         analytics             1  Allow 2 named actions on "*" - no resource scoping
    LOW       reporting         reporting             0  Allow s3:Get*, s3:List* - read-only wildcard

    --- statement detail (top 10) ---
    CRITICAL app-deploy/deploy-artifacts [0]
      {"Sid": "FullAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}

    ...

    --- escalation paths (role -> administrator) ---
    SEV       ROLE          PATH
    CRITICAL  build-release  iam:PassRole into lambda:CreateFunction (+1 more) - run code as any role it can pass
    HIGH      ci-runner      sts:AssumeRole - assume any role it can name

    11 findings - 2 CRITICAL, 6 HIGH, 2 MEDIUM, 1 LOW
    2 escalation paths - 1 CRITICAL, 1 HIGH

`build-release` is the one to read twice. Phase 1 sees a single HIGH row for
`iam:PassRole`. Phase 2 sees that the same role can call `lambda:CreateFunction`,
so it can pass itself an admin role and run code as it. `data-science` holds
`iam:PassRole` too but no consumer action, so it is left alone.

`--top N` controls how many findings get their raw statement printed
underneath the table. Default is 10.

## Checks

    python test_iamlint.py

24 assert-based cases: 14 over the wildcard rules, 10 over the escalation
engine.

## Next phases

- Phase 3: role-to-role trust graph, shortest path from a low-privilege role
  to an admin-equivalent one.
- Phase 4: sqlite baseline, so a re-run prints only new, fixed and unchanged
  findings.
- Phase 5: SARIF and JSON output plus severity thresholds for CI.