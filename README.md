# iam-escalation-lint

Reads a directory of exported AWS IAM policies and prints three things: the
over-broad Allow statements, ranked by severity, the roles that hold a known
one-step path to administrator, and the shortest assume route from a role that
is not admin to one that is.

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

### Reachability

The first two passes read one role at a time. The third pass builds the graph
and walks it. An edge `A -> B` exists when the trust policy attached to `B`
names `A` as a principal *and* `A` holds `sts:AssumeRole` reaching `B`. A route
only ends on a role that reaches administrator on its own, so a lone
`sts:AssumeRole` is movement, not a destination. The search is breadth-first
over every role that is not admin-equivalent, and reports the shortest chain.

| Severity | Pattern |
|---|---|
| CRITICAL | One assume hop into an admin-equivalent role. |
| HIGH | Two hops. |
| MEDIUM | Three hops or more. |

This is where `sts:AssumeRole` stops being a generic HIGH row. Phase 2 cannot
say *where* an assume lands; the graph can, and it names the role.

## Input format

Every `*.json` file under the directory is read, recursively. A file may be:

- a bare policy document (`{"Version": ..., "Statement": [...]}`), where the
  file name is the role name;
- an export that wraps a document
  (`{"RoleName": ..., "PolicyName": ..., "Document": {...}}`);
- a JSON list of either;
- an export that also carries the role's trust policy under
  `AssumeRolePolicyDocument` (or `TrustPolicy`), which is what the
  reachability pass reads. A trust policy exported on its own works too: the
  file name is then the trusted role.

## Sample output

The bundled set is 12 policy files, 21 statements, 19 of them Allow:

    IAM PRIVILEGE ESCALATION LINT - phase 3 (wildcard audit + escalation primitives + reachability)
    scanned 12 policy files | 21 statements | 19 Allow

    SEV       ROLE              POLICY             STMT  WHY
    CRITICAL  app-deploy        deploy-artifacts      0  Allow "*" on "*" - full administrator
    CRITICAL  ci-runner         ci-runner             0  Allow NotAction on "*" - permits everything except iam:*, organizations:*
    CRITICAL  ops-admin         admin-ops             0  Allow "*" on "*" - full administrator
    HIGH      backup            backup                0  Allow kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey on "*" - named control of kms
    HIGH      build-release     deploy-pipeline       1  Allow iam:PassRole on a scoped resource - named control of iam
    HIGH      data-science      data-science          0  Allow s3:* on "*" - service-wide control
    HIGH      data-science      data-science          1  Allow iam:PassRole, iam:GetRole, iam:ListRoles on "*" - named control of iam
    HIGH      dev-readonly      read-only             1  Allow sts:AssumeRole on a scoped resource - named control of sts
    HIGH      legacy-migration  legacy-migration      0  Allow NotResource - permits every resource except arn:aws:s3:::locked-*/*
    HIGH      platform-admin    ops-bucket-full       0  Allow "*" on a scoped resource - every action, no action filtering
    HIGH      release-runner    release-ops           0  Allow sts:AssumeRole on a scoped resource - named control of sts
    MEDIUM    analytics         analytics             0  Allow dynamodb:* on a scoped resource - service-wide control
    MEDIUM    analytics         analytics             1  Allow 2 named actions on "*" - no resource scoping
    MEDIUM    dev-readonly      read-only             0  Allow 2 named actions on "*" - no resource scoping
    LOW       reporting         reporting             0  Allow s3:Get*, s3:List* - read-only wildcard

    --- statement detail (top 10) ---
    CRITICAL app-deploy/deploy-artifacts [0]
      {"Sid": "FullAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}

    ...

    --- escalation paths (role -> administrator) ---
    SEV       ROLE            PATH
    CRITICAL  build-release   iam:PassRole into lambda:CreateFunction (+1 more) - run code as any role it can pass
    HIGH      ci-runner       sts:AssumeRole - assume any role it can name
    HIGH      dev-readonly    sts:AssumeRole - assume any role it can name
    HIGH      release-runner  sts:AssumeRole - assume any role it can name

    --- reachability (role -> role) ---
    SEV       FROM            HOPS  PATH
    CRITICAL  release-runner     1  release-runner -> ops-admin (holds Allow "*" on "*")
    HIGH      ci-runner          2  ci-runner -> release-runner -> ops-admin (holds Allow "*" on "*")
    HIGH      dev-readonly       2  dev-readonly -> release-runner -> ops-admin (holds Allow "*" on "*")

    15 findings - 3 CRITICAL, 8 HIGH, 3 MEDIUM, 1 LOW
    4 escalation paths - 1 CRITICAL, 3 HIGH
    3 assume routes to administrator - 1 CRITICAL, 2 HIGH

`build-release` is the one to read twice. Phase 1 sees a single HIGH row for
`iam:PassRole`. Phase 2 sees that the same role can call `lambda:CreateFunction`,
so it can pass itself an admin role and run code as it. `data-science` holds
`iam:PassRole` too but no consumer action, so it is left alone.

`ci-runner` is the phase 3 row. Phase 2 only knew it could call
`sts:AssumeRole` somewhere. The graph now names the destination: `release-runner`
trusts it, and `ops-admin` trusts `release-runner`, so two hops separate a role
with no IAM actions at all from full administrator.

`--top N` controls how many findings get their raw statement printed
underneath the table. Default is 10.

## Checks

    python test_iamlint.py

35 assert-based cases: 14 over the wildcard rules, 12 over the escalation
engine, 9 over the reachability graph.

## Next phases

- Phase 4: sqlite baseline, so a re-run prints only new, fixed and unchanged
  findings.
- Phase 5: SARIF and JSON output plus severity thresholds for CI.