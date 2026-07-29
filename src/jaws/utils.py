"""Shared utilities for JWT analysis."""

import sys
from typing import List, Optional
from .models import Finding, Severity


def print_finding(finding: Finding, use_color: bool = True) -> None:
    """Print a single finding with optional color."""
    color_map = {
        Severity.CRITICAL: "\033[91m",
        Severity.HIGH: "\033[93m",
        Severity.MEDIUM: "\033[94m",
        Severity.LOW: "\033[92m",
        Severity.INFO: "\033[90m",
    }
    reset = "\033[0m"

    prefix = color_map.get(finding.severity, "") if use_color else ""
    suffix = reset if use_color else ""

    print(f"{prefix}[{finding.severity.value}] {finding.title}{suffix}")
    print(f"  Detail: {finding.detail}")
    print(f"  Recommendation: {finding.recommendation}")
    if finding.field:
        print(f"  Field: {finding.field}")
    print()


def read_token_from_file(filepath: str) -> Optional[str]:
    """Read the first line of a file as the JWT token."""
    try:
        with open(filepath, 'r') as f:
            return f.readline().strip()
    except (IOError, OSError) as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return None


def load_wordlist(filepath: str):
    """Stream a wordlist file line by line."""
    try:
        with open(filepath, 'r') as f:
            for line in f:
                word = line.strip()
                if word:
                    yield word
    except (IOError, OSError) as e:
        print(f"Error reading wordlist: {e}", file=sys.stderr)
        return
