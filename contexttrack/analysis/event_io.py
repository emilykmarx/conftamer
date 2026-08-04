"""Shared helper for iterating through events in contexttrack's events jsonl file."""

import json
import sys
from collections.abc import Iterator
import itertools


def load_events(path: str) -> Iterator[dict]:
    """Yield one parsed JSON object per non-blank line of a JSON Lines file."""
    try:
        f = open(path)
    except FileNotFoundError:
        # Fail if no file
        sys.exit(f"File not found: {path}")

    with f:
        # Fail if file is empty
        first_line = f.readline()
        if not first_line:
            sys.exit(f"File empty: {path}")

        for lineno, line in enumerate(itertools.chain([first_line], f), 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                # Warn on malformed file
                print(f"WARNING: line {lineno}: {e}", file=sys.stderr)
