"""
Print message co-occurrence graph edges from events.jsonl.

Each node is a unique message (identified by the key-value pairs in the
"message" field).  There is a directed edge from a message to the message
that immediately follows it (in arrival order) within the same context
group.  Each unique edge is printed once.

Run to svg: python3 contexttrack/analysis/message_graph.py --format dot | dot -Tsvg > graph.svg
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

from event_io import load_events


_PREFIXES = re.compile(r"^(req|ireq|r)\.")
_ALWAYS_EXCLUDE_SUFFIXES = {"URL.RawQuery"}
_EXCLUDE_SUFFIXES = set(_ALWAYS_EXCLUDE_SUFFIXES)


def _normalize_key(k: str) -> str:
    return _PREFIXES.sub("req.", k)


def _new_key(ev: dict) -> tuple | None:
    """API-level node key for events carrying api_id (from the Go tracer's
    caller-identification: the org that owns the code invoking the HTTP
    library, found by backtracing past protocol-agnostic HTTP-layer frames).
    "Request sent" events key off (kind, api_id, method, path); "Response
    sent" events key off (kind, api_id, pattern) where pattern is the
    fully-qualified name of the handler frame that produced the response.
    request_id.host is deliberately excluded from the key — it's frequently
    an ephemeral test-server port that would fragment otherwise-identical
    nodes across runs.

    Returns None if this event doesn't carry the new fields, so the caller
    falls back to the legacy _msg_key() logic (older trace files, or
    "Request received"/"Response received" kinds, which this key doesn't
    cover).

    TODO: add API_ID to legacy _msg_key() logic; no need to support backwards-compatibility.
    """
    kind = ev.get("kind", "")
    api_id = ev.get("api_id")
    if not api_id:
        return None
    if kind == "Request sent":
        rid = ev.get("request_id") or {}
        if rid.get("method") and rid.get("path"):
            return (kind, api_id, rid["method"], rid["path"])
    elif kind == "Response sent":
        pattern = ev.get("pattern")
        if pattern:
            return (kind, api_id, pattern)
    return None


def _msg_key(ev: dict) -> tuple:
    """Return a hashable, order-stable key identifying this event's graph node."""
    new_key = _new_key(ev)
    if new_key is not None:
        return new_key
    msg = ev.get("message", {})
    pairs = {}
    for k, v in msg.items():
        nk = _normalize_key(k)
        suffix = nk[len("req."):]
        if suffix in _EXCLUDE_SUFFIXES:
            continue
        pairs[nk] = v
    return tuple(sorted(pairs.items()))


def _is_complete_response(ev: dict) -> bool:
    """A "response" event (sent or received) is only useful as a graph node if
    it identifies which request it belongs to. We capture some responses with
    only a status code and no request in their message.
    Those aren't worth a node at this point.
    TODO: change this behavior
    """`
    if "response" not in ev.get("kind", "").lower():
        return True
    if _new_key(ev) is not None:
        return True
    msg = ev.get("message", {})
    has_code = any("code" in k.lower() for k in msg)
    has_method = any(k.endswith("Method") for k in msg)
    has_path = any(k.endswith("URL.Path") for k in msg)
    return has_code and has_method and has_path


def _label_fields(ev: dict) -> list[tuple[str, str]]:
    kind = ev.get("kind", "")
    api_id = ev.get("api_id")
    if api_id and kind == "Request sent":
        rid = ev.get("request_id") or {}
        if rid.get("method") and rid.get("path"):
            return [("api_id", api_id), ("method", rid["method"]), ("path", rid["path"])]
    elif api_id and kind == "Response sent":
        pattern = ev.get("pattern")
        if pattern:
            return [("api_id", api_id), ("pattern", pattern)]
    msg = ev.get("message", {})
    return sorted((k, v) for k, v in msg.items()
                  if _normalize_key(k)[len("req."):] not in _EXCLUDE_SUFFIXES)


def _msg_label(ev: dict) -> str:
    return "{" + ", ".join(f"{k}: {v}" for k, v in _label_fields(ev)) + "}"


def main() -> None:
    default_path = Path.home() / "conftamer" / "contexttrack" / "events" / "events.jsonl"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default=str(default_path),
                        help="Path to events.jsonl")
    parser.add_argument("--format", choices=["text", "dot"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--recv-sent", action="store_true",
                        help="Only draw edges from a received message to a later sent message")
    parser.add_argument("--include-host", action="store_true",
                        help="Include URL.Host in node identity/labels (excluded by default, "
                             "since two otherwise-identical messages sent to different hosts "
                             "would otherwise be treated as distinct nodes)")
    args = parser.parse_args()

    global _EXCLUDE_SUFFIXES
    _EXCLUDE_SUFFIXES = set(_ALWAYS_EXCLUDE_SUFFIXES)
    if not args.include_host:
        _EXCLUDE_SUFFIXES.add("URL.Host")

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
        if not _is_complete_response(ev):
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

    # Collect unique directed edges across all groups
    edges: set[tuple] = set()
    for root, entries in groups.items():
        if args.recv_sent:
            for i, (ka, kinda) in enumerate(entries):
                if not _is_received(kinda):
                    continue
                for kb, kindb in entries[i + 1:]:
                    if _is_sent(kindb):
                        edges.add((ka, kb))
        else:
            keys = [k for k, _ in entries]
            for a, b in zip(keys, keys[1:]):
                edges.add((a, b))

    if not edges:
        print("(no edges found)")
        return

    # Assign short IDs to each message node.
    # Not strictly needed, but makes easier to sort.
    all_keys = sorted({k for edge in edges for k in edge}, key=repr)
    node_id = {k: i for i, k in enumerate(all_keys)}

    # Group nodes into connected components (treating edges as undirected)
    # to report cluster sizes.
    parent = {k: k for k in all_keys}

    def find(x: tuple) -> tuple:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: tuple, b: tuple) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for a, b in edges:
        union(a, b)

    clusters: dict[tuple, list] = defaultdict(list)
    for k in all_keys:
        clusters[find(k)].append(k)
    cluster_sizes = sorted((len(v) for v in clusters.values()), reverse=True)

    summary_lines = [
        f"Total unique nodes: {len(all_keys)}",
        f"Total unique edges: {len(edges)}",
        f"Clusters: {len(clusters)}",
        "Cluster sizes: " + ", ".join(str(s) for s in cluster_sizes),
    ]

    if args.format == "dot":
        def _dot_label(ev: dict) -> str:
            kind = ev.get("kind", "?")
            fields = "\\n".join(f"{k}: {v}" for k, v in _label_fields(ev))
            return f"{kind}\\n{fields}"

        print("digraph messages {")
        print('  node [shape=box fontname="monospace" fontsize=10]')
        for k in all_keys:
            label = _dot_label(msg_rep[k]).replace('"', '\\"')
            print(f'  n{node_id[k]} [label="{label}"]')
        for a, b in sorted(edges, key=lambda e: (node_id[e[0]], node_id[e[1]])):
            print(f"  n{node_id[a]} -> n{node_id[b]}")
        print("}")

        # Printed to stderr (not stdout) so piping into `dot` still works.
        print("\n".join(summary_lines), file=sys.stderr)
    else:
        print("Nodes:")
        for k in all_keys:
            ev = msg_rep[k]
            kind = ev.get("kind", "?")
            print(f"  [{node_id[k]}] {kind}  {_msg_label(ev)}")

        print(f"\nEdges ({len(edges)}):")
        for a, b in sorted(edges, key=lambda e: (node_id[e[0]], node_id[e[1]])):
            print(f"  [{node_id[a]}] -> [{node_id[b]}]")

        print("\nSummary:")
        for line in summary_lines:
            print(f"  {line}")


if __name__ == "__main__":
    main()
