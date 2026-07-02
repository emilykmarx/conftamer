"""Shared helper for reading contexttrack's events.jsonl format.

Used by group_by_context.py, message_graph.py, and parse_events.py so the
three analysis scripts agree on how to read the file (blank lines skipped,
malformed lines warned about and skipped, missing file is a clean exit).
"""

import json
import sys
from collections.abc import Iterator


def load_events(path: str) -> Iterator[dict]:
    """Yield one parsed JSON object per non-blank line of a JSON Lines file."""
    try:
        f = open(path)
    except FileNotFoundError:
        sys.exit(f"File not found: {path}")
    with f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"WARNING: line {lineno}: {e}", file=sys.stderr)
