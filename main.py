"""Command-line entry point for the IAM privilege-escalation linter."""

import sys

from iamlint import main

if __name__ == "__main__":
    sys.exit(main())