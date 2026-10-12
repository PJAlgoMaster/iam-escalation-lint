# iam-escalation-lint

Reads a directory of exported AWS IAM policies and prints three things: the
over-broad Allow statements, ranked by severity, the roles that hold a known
one-step path to administrator, and the shortest assume route from a role that
is not admin to one that is.

Every row also goes into a sqlite baseline, so the next run prints only what
changed: the new rows in full, the rows that have gone away as fixed, and a
count of what is unchanged.

## Run

    python main.py

No arguments, no network, no dependencies outside the Python 3 standard
library. It reads the sample policy set in `policies/`, prints a report and
records it in `.iamlint-baseline.db` in the working directory.

Point it at a real export by passing the directory:

    python main.py ~/exports/iam-policies-2026-10-08

| Flag | Effect |
|---|---|
| `--top N` | how many new findings get their raw statement printed (default 10) |
| `--baseline FILE` | where the snapshot lives (default `.iamlint-baseline.db`) |
| `--reset` | ignore the stored snapshot and report every finding as new again |

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
| CRITICAL | `iam:PassRole` plus an action that runs code as a role | `lambda:CreateFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack` and ten more. Pass a role, run code as it. |
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

## Baseline and drift

Each run writes every row it produced, findings and escalation paths and assume
routes alike, into a sqlite file with a fingerprint per row. The next run
compares against that snapshot and splits the results three ways:

- **new** - the row was not in the snapshot. Printed in full, in the usual
  tables, and the only rows `--top` expands.
- **fixed** - the snapshot held it and this run does not. Listed under a
  `fixed since <timestamp>` heading with its severity.
- **unchanged** - counted, not printed.

A row's identity is its kind, its label (role/policy/index for a finding, the
role for an escalation, `source -> target` for a route), its severity and its
reason. Severity is part of it on purpose: a rule that starts calling a row
critical reprints the row rather than passing it off as unchanged.

The baseline is a build artifact, not source. Delete it, or pass `--reset`, to
get a clean first run. It is safe to keep one per policy export: point
`--baseline` somewhere else when you switch accounts or directories.

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

First run. No baseline file yet, so every row is new and the report reads
exactly as it did before the baseline existed, plus one header line.

    IAM PRIVILEGE ESCALATION LINT - phase 4 (wildcard audit + escalation primitives + reachability + baseline drift)
    scanned 12 policy files | 21 statements | 19 Allow
    baseline .iamlint-baseline.db initialised - 22 findings recorded

    SEV       ROLE              POLICY             STMT  WHY
    CRITICAL  app-deploy        deploy-artifacts      0  Allow "*" on "*" - full administrator
    CRITICAL  ci-runner         ci-runner             0  Allow NotAction on "*" - permits everything except iam:*, organizations:*
    CRITICAL  ops-admin         admin-ops             0  Allow "*" on "*" - full administrator
    HIGH      backup            backup                0  Allow kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey on "*" - named control of kms
    ...

    15 findings - 3 CRITICAL, 8 HIGH, 3 MEDIUM, 1 LOW
    4 escalation paths - 1 CRITICAL, 3 HIGH
    3 assume routes to administrator - 1 CRITICAL, 2 HIGH

Second run, nothing on disk changed. The three passes still ran; none of them
found anything the snapshot did not already hold.

    IAM PRIVILEGE ESCALATION LINT - phase 4 (wildcard audit + escalation primitives + reachability + baseline drift)
    scanned 12 policy files | 21 statements | 19 Allow
    baseline .iamlint-baseline.db | compared against 2026-10-12T09:14:03

    no new over-broad Allow statements

    --- escalation paths (role -> administrator) ---
    no new escalation paths

    --- reachability (role -> role) ---
    no new assume routes to administrator

    nothing new since 2026-10-12T09:14:03 - 0 fixed, 22 unchanged

Now loosen `policies/build-release.json`: give `iam:PassRole` a `Resource` of
`"*"` and add `sts:AssumeRole` on the ops-admin role. The next run prints those
two rows, plus whatever the reachability pass now discovers through them, and
counts the other 22 rows as unchanged.

`build-release` is the one to read twice. Phase 1 sees a single HIGH row for
`iam:PassRole`. Phase 2 sees that the same role can call `lambda:CreateFunction`,
so it can pass itself an admin role and run code as it. `data-science` holds
`iam:PassRole` too but no consumer action, so it is left alone.

`ci-runner` is the phase 3 row. Phase 2 only knew it could call
`sts:AssumeRole` somewhere. The graph now names the destination: `release-runner`
trusts it, and `ops-admin` trusts `release-runner`, so two hops separate a role
with no IAM actions at all from full administrator.

## Checks

    python test_iamlint.py

42 assert-based cases: 14 over the wildcard rules, 12 over the escalation
engine, 9 over the reachability graph, 7 over the baseline (five drift
classifications and two sqlite round trips).

## Next phases

- Phase 5: SARIF and JSON output plus severity thresholds for CI.
