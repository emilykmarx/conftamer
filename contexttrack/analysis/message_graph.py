"""
Print message co-occurrence graph edges from events.jsonl.

Each node is a unique message (identified by the key-value pairs in the
"message" field).  There is an undirected edge between two messages if they
share a root context address in at least one event group.  Each unique edge
is printed once.

Run to svg: python3 contexttrack/analysis/message_graph.py --format dot | dot -Tsvg > graph.svg
"""

import argparse
import re
from collections import defaultdict
from pathlib import Path

from event_io import load_events


_PREFIXES = re.compile(r"^(req|ireq|r)\.")
_EXCLUDE_SUFFIXES = {"URL.RawQuery"}


def _normalize_key(k: str) -> str:
    return _PREFIXES.sub("req.", k)


def _msg_key(ev: dict) -> tuple:
    """Return a hashable, order-stable key for the message dict."""
    msg = ev.get("message", {})
    pairs = {}
    for k, v in msg.items():
        nk = _normalize_key(k)
        suffix = nk[len("req."):]
        if suffix in _EXCLUDE_SUFFIXES:
            continue
        pairs[nk] = v
    return tuple(sorted(pairs.items()))


def _msg_label(ev: dict) -> str:
    msg = ev.get("message", {})
    return "{" + ", ".join(f"{k}: {v}" for k, v in sorted(msg.items())
                           if _normalize_key(k)[len("req."):] not in _EXCLUDE_SUFFIXES) + "}"


def main() -> None:
    default_path = Path.home() / "conftamer" / "contexttrack" / "events" / "events.jsonl"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default=str(default_path),
                        help="Path to events.jsonl")
    parser.add_argument("--format", choices=["text", "dot"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--recv-sent", action="store_true",
                        help="Only draw edges from a received message to a later sent message")
    args = parser.parse_args()

    # root_addr -> list of (key, kind) in arrival order
    groups: dict[str, list] = defaultdict(list)
    # root_addr -> set of seen keys (for dedup within group)
    groups_seen: dict[str, set] = defaultdict(set)
    # message key -> one representative event (for labelling)
    msg_rep: dict[tuple, dict] = {}

    for ev in load_events(args.file):
        root = ev.get("context", {}).get("root_addr")
        if not root or "message" not in ev:
            continue
        key = _msg_key(ev)
        if key not in groups_seen[root]:
            groups_seen[root].add(key)
            groups[root].append((key, ev.get("kind", "")))
        if key not in msg_rep:
            msg_rep[key] = ev

    def _is_received(kind: str) -> bool:
        return "received" in kind.lower()

    def _is_sent(kind: str) -> bool:
        return "sent" in kind.lower()

    # Collect unique directed or undirected edges across all groups
    edges: set[frozenset] = set()
    for root, entries in groups.items():
        if args.recv_sent:
            for i, (ka, kinda) in enumerate(entries):
                if not _is_received(kinda):
                    continue
                for kb, kindb in entries[i + 1:]:
                    if _is_sent(kindb):
                        edges.add(frozenset([ka, kb]))
        else:
            keys = [k for k, _ in entries]
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    edges.add(frozenset([keys[i], keys[j]]))

    if not edges:
        print("(no edges found)")
        return

    # Assign short IDs to each message node
    all_keys = sorted({k for edge in edges for k in edge})
    node_id = {k: i for i, k in enumerate(all_keys)}

    if args.format == "dot":
        def _dot_label(ev: dict) -> str:
            kind = ev.get("kind", "?")
            msg = ev.get("message", {})
            fields = "\\n".join(f"{k}: {v}" for k, v in sorted(msg.items())
                                if _normalize_key(k)[len("req."):] not in _EXCLUDE_SUFFIXES)
            return f"{kind}\\n{fields}"

        print("graph messages {")
        print('  node [shape=box fontname="monospace" fontsize=10]')
        for k in all_keys:
            label = _dot_label(msg_rep[k]).replace('"', '\\"')
            print(f'  n{node_id[k]} [label="{label}"]')
        for edge in sorted(edges, key=lambda e: tuple(sorted(node_id[k] for k in e))):
            a, b = sorted(edge, key=lambda k: node_id[k])
            print(f"  n{node_id[a]} -- n{node_id[b]}")
        print("}")
    else:
        print("Nodes:")
        for k in all_keys:
            ev = msg_rep[k]
            kind = ev.get("kind", "?")
            print(f"  [{node_id[k]}] {kind}  {_msg_label(ev)}")

        print(f"\nEdges ({len(edges)}):")
        for edge in sorted(edges, key=lambda e: tuple(sorted(node_id[k] for k in e))):
            a, b = sorted(edge, key=lambda k: node_id[k])
            print(f"  [{node_id[a]}] -- [{node_id[b]}]")


if __name__ == "__main__":
    main()
