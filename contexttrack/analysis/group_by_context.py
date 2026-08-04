"""
Parse events.jsonl and print HTTP events grouped by context ID.

Usage:
    python3 group_by_context.py [events.jsonl]
"""

import argparse
import json
import sys
from collections import defaultdict

from event_io import load_events


# message identifier
# (kind, verb, path, code) tuple used for display and deduplication.
# TODO: add API_ID

_KIND_LABEL = {
    "Request sent":      ">> req sent   ",
    "Request received":  "<< req recvd  ",
    "Response sent":     ">> resp sent  ",
    "Response received": "<< resp recvd ",
}

def _ident(event: dict) -> tuple:
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
        # TODO these special cases are left over from delve approach; update to use
        # consistent logging format so we don't need this if/else logic.
        # HTTP/1.x stores at w.req.*; HTTP/2 stores at w.rws.req.*; the
        # promhttp handler-return fallback (no response-writer field to key
        # off) stores directly at req.*.
        verb = msg.get("w.req.Method") or msg.get("w.rws.req.Method") or msg.get("req.Method", "?")
        path = msg.get("w.req.URL.Path") or msg.get("w.rws.req.URL.Path") or msg.get("req.URL.Path", "/")
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
    """For end summary"""
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
    """For printing to terminal"""
    label, verb, path, code = ident
    parts = [label]
    if verb:
        parts.append(verb)
    if path:
        parts.append(path)
    if code:
        parts.append(code)
    return "  ".join(parts)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Group events.jsonl entries by context ID"
    )
    parser.add_argument(
        "input", nargs="?", default="events.jsonl",
        help="Path to the JSON Lines file (default: ./events.jsonl)"
    )
    parser.add_argument(
        "--unknown", action="store_true",
        help="Include events where context ID not found"
    )
    args = parser.parse_args()

    events = list(load_events(args.input))

    if not events:
        sys.exit("No events found.")

    # Preserve first-seen order
    group_order: dict[str, int] = {}
    groups: dict[str, list[tuple[int, dict]]] = defaultdict(list)

    for seq, ev in enumerate(events):
        ctx  = ev.get("context") or {}
        # TODO change this `root_addr` label
        addr = ctx.get("root_addr", "?")

        if addr == "?" and not args.unknown:
            continue

        if addr not in group_order:
            group_order[addr] = seq
        groups[addr].append((seq, ev))

    if not groups:
        sys.exit("No groups to display (all events had unknown root_addr; "
                 "try --unknown).")

    # Display
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

    # Summary
    # Deduplicate groups with identical message content
    total_sig_counts: dict[int, int] = defaultdict(int)   # all msgs (with dups)
    unique_sig_counts: dict[int, int] = defaultdict(int)  # unique msgs only

    seen_total_sigs: set = set()
    seen_unique_sigs: set = set()

    for addr in sorted_addrs:
        all_idents = tuple(sorted(_ident(ev) for _, ev in groups[addr]))
        unique_idents = frozenset(_ident(ev) for _, ev in groups[addr])

        if all_idents not in seen_total_sigs:
            seen_total_sigs.add(all_idents)
            total_sig_counts[len(all_idents)] += 1

        if unique_idents not in seen_unique_sigs:
            seen_unique_sigs.add(unique_idents)
            unique_sig_counts[len(unique_idents)] += 1

    print(f"{'═'*66}")
    print(f"  Group size summary — all messages (duplicates included)")
    print(f"  (groups with identical message sets counted once)")
    print(f"{'═'*66}\n")
    for size in sorted(total_sig_counts):
        print(f"  {size} message(s) = {total_sig_counts[size]} group(s)")
    print()

    print(f"{'═'*66}")
    print(f"  Group size summary — unique messages per group")
    print(f"  (groups with identical message sets counted once)")
    print(f"{'═'*66}\n")
    for size in sorted(unique_sig_counts):
        print(f"  {size} message(s) = {unique_sig_counts[size]} group(s)")
    print()

    # Summary of "kind-pair" (e.g., Request sent -> Response received) counts across all groups.
    kind_pair_counts: dict[tuple[str, str], int] = defaultdict(int)
    for addr in sorted_addrs:
        kinds_seen: list[str] = []
        seen_idents: set[tuple] = set()
        for _, ev in groups[addr]:
            ident = _ident(ev)
            if ident not in seen_idents:
                seen_idents.add(ident)
                kinds_seen.append(ev.get("kind", "?"))
        for a, b in zip(kinds_seen, kinds_seen[1:]):
            kind_pair_counts[(a, b)] += 1

    print(f"{'═'*66}")
    print(f"  Kind-pair summary (consecutive pairs)")
    print(f"{'═'*66}\n")
    if not kind_pair_counts:
        print("  (no groups contain more than one unique message)\n")
    else:
        for (ka, kb), count in sorted(kind_pair_counts.items(),
                                      key=lambda x: (-x[1], x[0])):
            print(f"  {ka} -> {kb}: {count}")
    print()

    # Unique groups with multiple linked messages.
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

        for a, b in zip(seq_idents, seq_idents[1:]):
            edge_counts[(a, b)] += 1

    print(f"{'═'*66}")
    print(f"  Co-occurrence pairs (consecutive only)")
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
