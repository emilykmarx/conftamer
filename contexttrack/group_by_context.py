"""
Parse events.jsonl and print HTTP events grouped by root context address.

Usage:
    python3 group_by_context.py [events.jsonl]

The root context address is the address of the topmost context.Context in the
chain at the time each breakpoint fired.  Events sharing a root address were
(directly or indirectly) derived from the same context, so they belong to the
same logical request chain.
"""

import argparse
import json
import sys
from collections import defaultdict


# ── message identifier ───────────────────────────────────────────────────────
# A stable (kind, verb, path, code) tuple used for display and deduplication.

_KIND_LABEL = {
    "Request sent":      ">> req sent   ",
    "Request received":  "<< req recvd  ",
    "Response sent":     ">> resp sent  ",
    "Response received": "<< resp recvd ",
}

def _ident(event: dict) -> tuple:
    """Return (label, verb, path, code) for an event."""
    kind  = event.get("kind", "?")
    msg   = event.get("message") or {}
    label = _KIND_LABEL.get(kind, f"{kind:<14}")

    if kind == "Request sent":
        verb = msg.get("req.Method") or msg.get("r.Method", "?")
        path = msg.get("req.URL.Path") or msg.get("r.URL.Path", "/")
        code = ""

    elif kind == "Request received":
        verb = msg.get("req.Method") or msg.get("r.Method", "?")
        path = msg.get("req.URL.Path") or msg.get("r.URL.Path", "/")
        code = ""

    elif kind == "Response sent":
        # HTTP/1.x stores at w.req.*; HTTP/2 stores at w.rws.req.*
        verb = msg.get("w.req.Method") or msg.get("w.rws.req.Method", "?")
        path = msg.get("w.req.URL.Path") or msg.get("w.rws.req.URL.Path", "/")
        code = msg.get("code", "?")

    elif kind == "Response received":
        verb = msg.get("ireq.Method", "")
        path = msg.get("ireq.URL.Path", "")
        code = msg.get("resp.StatusCode", msg.get("resp.Status", "?"))

    else:
        verb = ""
        path = ""
        code = ""

    return (label, verb, path, code)


_KIND_LABEL_CLEAN = {
    ">> req sent   ":  "req sent",
    "<< req recvd  ":  "req recvd",
    ">> resp sent  ":  "resp sent",
    "<< resp recvd ":  "resp recvd",
}

def _ident_json(ident: tuple) -> str:
    label, verb, path, code = ident
    kind = _KIND_LABEL_CLEAN.get(label, label.strip())
    fields = {"kind": kind}
    if verb:
        fields["verb"] = verb
    if path:
        fields["endpoint"] = path
    if code:
        fields["code"] = code
    return json.dumps(fields, separators=(", ", ": "))


def _format_ident(ident: tuple) -> str:
    label, verb, path, code = ident
    parts = [label]
    if verb:
        parts.append(verb)
    if path:
        parts.append(path)
    if code:
        parts.append(code)
    return "  ".join(parts)


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Group events.jsonl entries by root context address"
    )
    parser.add_argument(
        "input", nargs="?", default="events.jsonl",
        help="Path to the JSON Lines file (default: events.jsonl)"
    )
    parser.add_argument(
        "--unknown", action="store_true",
        help="Include events where root_addr could not be determined (?)"
    )
    args = parser.parse_args()

    # ── load ──────────────────────────────────────────────────────────────────
    events = []
    try:
        with open(args.input) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"WARNING: line {lineno}: {e}", file=sys.stderr)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.input}")

    if not events:
        sys.exit("No events found.")

    # ── group by root_addr, preserving first-seen order ────────────────────
    group_order: dict[str, int] = {}
    groups: dict[str, list[tuple[int, dict]]] = defaultdict(list)

    for seq, ev in enumerate(events):
        ctx  = ev.get("context") or {}
        addr = ctx.get("root_addr", "?")

        if addr == "?" and not args.unknown:
            continue

        if addr not in group_order:
            group_order[addr] = seq
        groups[addr].append((seq, ev))

    if not groups:
        sys.exit("No groups to display (all events had unknown root_addr; "
                 "try --unknown).")

    # ── print ─────────────────────────────────────────────────────────────
    sorted_addrs = sorted(group_order, key=lambda a: group_order[a])

    print(f"{'═'*66}")
    print(f"  {len(sorted_addrs)} context group(s) from {len(events)} event(s)")
    print(f"{'═'*66}\n")

    for addr in sorted_addrs:
        items = groups[addr]
        seen: set[tuple] = set()
        lines = []
        for seq, ev in items:
            ident = _ident(ev)
            if ident in seen:
                continue
            seen.add(ident)
            lines.append(_format_ident(ident))

        unique = len(lines)
        total  = len(items)
        unique_str = f" ({unique} unique)" if unique != total else ""
        print(f"  root context: {addr}   ({total} event(s){unique_str})")
        print(f"{'─'*66}")

        for line in lines:
            print(f"  {line}")

        print()

    # ── global edge summary ───────────────────────────────────────────────
    # For each group, generate all ordered pairs (A, B) from the deduplicated
    # sequence (A appears before B).  Count how many distinct groups each pair
    # appears in.
    edge_counts: dict[tuple[tuple, tuple], int] = defaultdict(int)

    for addr in sorted_addrs:
        items = groups[addr]
        seen: set[tuple] = set()
        seq_idents: list[tuple] = []
        for _, ev in items:
            ident = _ident(ev)
            if ident not in seen:
                seen.add(ident)
                seq_idents.append(ident)

        for i in range(len(seq_idents)):
            for j in range(i + 1, len(seq_idents)):
                edge_counts[(seq_idents[i], seq_idents[j])] += 1

    print(f"{'═'*66}")
    print(f"  Co-occurrence pairs (edges, ordered by appearance in group)")
    print(f"{'═'*66}\n")

    if not edge_counts:
        print("  (no groups contain more than one unique message)\n")
    else:
        for (a, b), count in sorted(edge_counts.items(),
                                    key=lambda x: (-x[1], x[0])):
            freq = f"  # {count}x" if count > 1 else ""
            print(f"  ({_ident_json(a)}, {_ident_json(b)}){freq}")

    print()


if __name__ == "__main__":
    main()
