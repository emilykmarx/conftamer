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


def _response_site(ev: dict) -> str | None:
    """Which net/http layer logged a "Response received": "transport" (read loop,
    no api_id) or "client" (Client.do, with api_id). None for anything else.

    The transport read loop logs via conftamerLogResponseWire, so its recorded
    file is conftamer.go rather than transport.go.
    """
    if ev.get("kind") != "Response received":
        return None
    file = ev.get("file", "")
    if file.endswith(("/net/http/conftamer.go", "/net/http/transport.go")):
        return "transport"
    if file.endswith("/net/http/client.go"):
        return "client"
    return None


def dedup_responses(events: list[dict]) -> list[dict]:
    """Drop the transport-level "Response received" when Client.do also logged one.

    A request sent through http.Client is logged as received twice: once by the
    transport read loop and once by Client.do. Pair them by (pid, context_id,
    method, path, code), keeping the Client.do event since it carries api_id.
    Unpaired transport events (e.g., direct Transport.RoundTrip) are kept.
    """
    def key(ev: dict) -> tuple:
        msg = ev.get("message") or {}
        return (ev.get("pid"), (ev.get("context") or {}).get("context_id"),
                msg.get("req.Method"), msg.get("req.URL.Path"), msg.get("resp.StatusCode"))

    # The read loop logs before RoundTrip returns to Client.do, so each client
    # event claims the earliest unclaimed transport event with the same key.
    pending: dict[tuple, list[int]] = {}
    drop: set[int] = set()
    for i, ev in enumerate(events):
        site = _response_site(ev)
        if site == "transport":
            pending.setdefault(key(ev), []).append(i)
        elif site == "client" and pending.get(key(ev)):
            drop.add(pending[key(ev)].pop(0))
    return [ev for i, ev in enumerate(events) if i not in drop]
