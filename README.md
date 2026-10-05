# IAM Privilege Escalation Linter

Reads a directory of exported AWS IAM policies and reports over-broad statements plus reachable privilege-escalation paths from any role to admin. Built for a one-person cloud security team that cannot re-read every finding each week.

## What it will do

Walks a policy directory, resolves Allow with NotAction, and prints ranked findings (severity, role, statement) end to end.

## How it is built

1. **Phase 1 - Parse and wildcard report** - Walks a policy directory, resolves Allow with NotAction, and prints ranked findings (severity, role, statement) end to end.
2. **Phase 2 - Escalation rule engine** - Adds the known escalation primitives (iam:PassRole into lambda:CreateFunction, iam:CreatePolicyVersion, sts:AssumeRole) and flags role-level combinations.
3. **Phase 3 - Reachability graph** - Builds the role-to-role trust and assume graph and finds shortest paths from a low-privilege role to an admin-equivalent one.
4. **Phase 4 - Baseline and drift** - Stores findings in a sqlite baseline so a re-run prints only new, fixed and unchanged findings since the last snapshot.
5. **Phase 5 - CI output and exit codes** - Adds SARIF and JSON output plus severity thresholds, so the same command can gate a pull request.

## Stack

python, stdlib, argparse, json, pathlib, sqlite, unittest

## Run it

```
python main.py
```

_Being built in public, one phase a day. The README grows with it._
