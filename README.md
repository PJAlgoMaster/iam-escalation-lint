# iam-escalation-lint

Reads a directory of exported AWS IAM policies and prints the over-broad
Allow statements, ranked by severity.

## Run

    python main.py

No arguments, no network, no dependencies outside the Python 3 standard
library. It reads the sample policy set in `policies/` and prints a report.

Point it at a real export by passing the directory:

    python main.py ~/exports/iam-policies-2026-10-08

## What it finds (phase 1)

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

Deny statements are counted and skipped. `NotAction: "*"` grants nothing and
is skipped too.

## Input format

Every `*.json` file under the directory is read, recursively. A file may be:

- a bare policy document (`{"Version": ..., "Statement": [...]}`), where the
  file name is the role name;
- an export that wraps a document
  (`{"RoleName": ..., "PolicyName": ..., "Document": {...}}`);
- a JSON list of either.

## Sample output

The bundled set is 10 policy files, 15 statements, 13 of them Allow:

    IAM PRIVILEGE ESCALATION LINT - phase 1 (wildcard and NotAction audit)
    scanned 10 policy files | 15 statements | 13 Allow

    SEV       ROLE              POLICY             STMT  WHY
    CRITICAL  app-deploy        deploy-artifacts      0  Allow "*" on "*" - full administrator
    CRITICAL  ci-runner         ci-runner             0  Allow NotAction on "*" - permits everything except iam:*, organizations:*
    HIGH      backup            backup                0  Allow kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey on "*" - named control of kms
    HIGH      data-science      data-science          0  Allow s3:* on "*" - service-wide control
    HIGH      data-science      data-science          1  Allow iam:PassRole, iam:GetRole, iam:ListRoles on "*" - named control of iam

    ...

    10 findings - 2 CRITICAL, 5 HIGH, 2 MEDIUM, 1 LOW

`--top N` controls how many findings get their raw statement printed
underneath the table. Default is 10.

## Checks

    python test_iamlint.py

14 assert-based cases over the finding rules, one per severity branch.

## Next phases

- Phase 2: escalation primitives (`iam:PassRole` into `lambda:CreateFunction`,
  `iam:CreatePolicyVersion`, `sts:AssumeRole`) and the role-level combinations.
- Phase 3: role-to-role trust graph, shortest path to an admin-equivalent role.
- Phase 4: sqlite baseline, so a re-run prints only new, fixed and unchanged
  findings.
- Phase 5: SARIF and JSON output plus severity thresholds for CI.