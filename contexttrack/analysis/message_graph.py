"""
Print message co-occurrence graph edges from events.jsonl.

Each node is a unique message (identified by the key-value pairs in the
"message" field).  There is a directed edge from a message to the message
that immediately follows it (in arrival order) within the same context
group.  Each unique edge is printed once.

"Request routed" events supply the route pattern for received requests and
sent responses, when available.

Run to svg: python3 contexttrack/analysis/message_graph.py --format dot | dot -Tsvg > graph.svg
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from event_io import load_events


# message fields recorded for debugging but
# shouldn't go into node identity/labels
_EXCLUDE_KEYS = {"req.URL.RawQuery", "req.URL.Host"}


def _req_identity(ev: dict) -> tuple | None:
    """(method, path) of request event, or None."""
    msg = ev.get("message", {})
    method, path = msg.get("req.Method"), msg.get("req.URL.Path")
    return (method, path) if method and path else None


def _route_key(ev: dict) -> tuple | None:
    """(pid, context_id, method, path) — how a matched route pattern is tied to
    the request and response events it belongs to."""
    context_id = (ev.get("context") or {}).get("context_id")
    ident = _req_identity(ev)
    if not context_id or ident is None:
        return None
    return (ev.get("pid"), context_id, *ident)


def _full_pattern(orig_path: str, hop_path: str, last_pattern: str) -> str:
    """Recover the full routing pattern that matched on the URL that the client sent.
    This lets us deal with `StripPrefix`/path rewriting, which seems to be common.

    orig_path: original full request path
    hop_path: path as seen by the last mux that matched the request
    last_pattern: route pattern matched by the last mux
    """
    # Not sure if this is possible?
    if not orig_path.endswith(hop_path):
        raise AssertionError(f"orig_path={orig_path} hop_path={hop_path} pattern={last_pattern}")

    # No prefix stripping
    if hop_path == orig_path:
        return last_pattern
    # Prefixes removed before the last mux
    prefix = orig_path[:len(orig_path) - len(hop_path)]
    # Get the 'path' part of the pattern (after method+host, if any)
    slash = last_pattern.find("/")
    if slash < 0:
        # Go's parsePattern rejects a pattern with no `/` in it; this shouldn't happen
        raise AssertionError(f"pattern without '/': {pattern}")

    # method+host (if any) + prefixes stripped by prev muxes + last mux's pattern
    return last_pattern[:slash] + prefix + last_pattern[slash:]


def _stamp_routes(events: list[dict]) -> None:
    """Stamp every event with 'route_pattern', the route a ServeMux matched for
    it (see conftamerLogRouted in the Go patch).

    Note that "Request routed" events are logged after "Request received", so
    we need to pre-build this.

    One request can be routed by several muxes. We identify the full path by
    (1) finding the last "request routed" in the chain, and (2) taking the
    prefix of the original path up to that point.
    """
    # (pid, context_id, request) -> request's routed events, in order.
    # Keyed by the request as first seen.
    # Note: later muxes behind StripPrefix route on a shortened path, so
    # we can't key directly on the (original) request.
    # Match routes with: (1) exact match on pid, context_id, method, and (2)
    # path is a suffix of the last-seen path with that key.
    hops: dict[tuple, list[dict]] = {}
    # group -> requests seen in it, so a hop only scans its own context group
    # to find the right key.
    group_keys: dict[tuple, list[tuple]] = defaultdict(list)

    for ev in events:
        if ev.get("kind") != "Request routed":
            continue
        key = _route_key(ev)
        if key is None:
            print("Failed to parse route key for event:", ev, file=sys.stderr)
            continue
        path = ev["message"]["req.URL.Path"]
        for prev in group_keys[key[:2]]:
            latest = hops[prev][-1]["message"]["req.URL.Path"]
            if path != latest and latest.endswith(path):
                hops[prev].append(ev)
                break
        else:
            if key not in hops:
                hops[key] = []
                group_keys[key[:2]].append(key)
            hops[key].append(ev)

    routes: dict[tuple, str] = {}
    for key, chain in hops.items():
        first, last = chain[0], chain[-1]
        # First message: original complete request path
        # Last message path: request path as seen by last mux
        # Last message pattern: route pattern matched by last mux
        # Full pattern returned: original path up to and incl. last mux
        routes[key] = _full_pattern(
            first["message"]["req.URL.Path"],
            last["message"]["req.URL.Path"],
            last["message"]["pattern"],
        )

    for ev in events:
        if ev.get("kind") == "Request routed":
            continue
        key = _route_key(ev)
        if key is not None and key in routes:
            ev["route_pattern"] = routes[key]

def _attribute_response(ev: dict, group: tuple, open_requests: dict) -> None:
    """Attribute a "Response sent" event to the request it (likely) answers,
    copying that request's api_id into the response event.
    """
    ident = _req_identity(ev)
    if ident is None:
        return
    kind = ev.get("kind", "")
    if kind == "Request received":
        open_requests[(group, ident)] = ev
    elif kind == "Response sent":
        req = open_requests.get((group, ident))
        if req is None:
            return
        # Absent if caller identification failed for the request, e.g. it was
        # served by an http.ServeMux rather than an application handler.
        if req.get("api_id"):
            ev["api_id"] = req["api_id"]


def _new_key(ev: dict) -> tuple | None:
    """Node key.
    "Request" events: (kind, api_id, method, route pattern or path)
    "Response sent": (kind, api_id, method, route pattern or path, code)

    Prefer pattern over path (fall back to path if no 'route_pattern'), so that
    one wildcard route ('/items/{id}') is a single node rather than one node per
    concrete path.

    Returns None if this event doesn't carry the fields above, so the caller
    falls back to keying on the "message" fields ("Response received", or events
    with neither an api_id nor a matched route).
    """
    kind = ev.get("kind", "")
    api_id = ev.get("api_id")
    route = ev.get("route_pattern")
    if kind == "Request sent":
        if not api_id:
            return None
        rid = ev.get("request_id") or {}
        if rid.get("method") and rid.get("path"):
            return (kind, api_id, rid["method"], route or rid["path"])
    elif kind == "Request received":
        if api_id or route:
            msg = ev.get("message", {})
            return (kind, api_id, msg.get("req.Method"),
                    route or msg.get("req.URL.Path"))
    elif kind == "Response sent":
        if api_id or route:
            msg = ev.get("message", {})
            return (kind, api_id, msg.get("req.Method"),
                    route or msg.get("req.URL.Path"), msg.get("code"))
    return None


def _msg_key(ev: dict) -> tuple:
    """Return a hashable, order-stable key identifying this event's graph node."""
    new_key = _new_key(ev)
    if new_key is not None:
        return new_key
    msg = ev.get("message", {})
    pairs = {k: v for k, v in msg.items() if k not in _EXCLUDE_KEYS}
    key = tuple(sorted(pairs.items()))
    api_id = ev.get("api_id")
    return (api_id, key) if api_id else key


def _event_path(ev: dict) -> str | None:
    """Concrete URL path of this event, for counting what a pattern covers."""
    path = ev.get("message", {}).get("req.URL.Path")
    return path or (ev.get("request_id") or {}).get("path")


def _label_fields(ev: dict, n_paths: int | None = None) -> list[tuple[str, str]]:
    """Label fields for the node `ev` represents.

    When a route pattern matched, it is what the node is keyed on
    (the node stands for every path the pattern covers).
    `n_paths` = how many distinct paths landed on this node.
    """
    kind = ev.get("kind", "")
    api_id = ev.get("api_id")
    route = ev.get("route_pattern")
    paths = str(n_paths) if route and n_paths else None
    if api_id and kind == "Request sent":
        rid = ev.get("request_id") or {}
        if rid.get("method") and rid.get("path"):
            optional = [("api_id", api_id), ("pattern", route),
                        ("method", rid["method"]),
                        ("path", None if route else rid["path"]),
                        ("paths", paths)]
            return [(k, v) for k, v in optional if v]
    elif kind in ("Request received", "Response sent"):
        msg = ev.get("message", {})
        optional = [("api_id", api_id), ("pattern", route),
                    ("method", msg.get("req.Method")),
                    ("path", None if route else msg.get("req.URL.Path")),
                    ("code", msg.get("code")), ("paths", paths)]
        fields = [(k, v) for k, v in optional if v]
        if fields:
            return fields
    msg = ev.get("message", {})
    fields = sorted((k, v) for k, v in msg.items() if k not in _EXCLUDE_KEYS)
    if api_id:
        fields.append(("api_id", api_id))
    return fields


def _msg_label(ev: dict, n_paths: int | None = None) -> str:
    return "{" + ", ".join(f"{k}: {v}" for k, v in _label_fields(ev, n_paths)) + "}"


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

    # (pid, context_id) -> list of (key, kind) in arrival order
    groups: dict[tuple, list] = defaultdict(list)
    # context_id ((pid, context_id)) -> set of seen keys (for dedup within group)
    groups_seen: dict[tuple, set] = defaultdict(set)
    # message key -> one representative event (for labelling)
    msg_rep: dict[tuple, dict] = {}
    # message key -> distinct concrete paths keyed to it. >1 only for nodes
    # keyed on a route pattern, which covers every path that pattern matched.
    node_paths: dict[tuple, set[str]] = defaultdict(set)
    # (group, (method, path)) -> most recent "Request received" with that identity,
    # used to attribute each response back to the request it answers
    open_requests: dict[tuple, dict] = {}

    # Read in full so routes can be resolved before any event is keyed
    events = list(load_events(args.file))
    _stamp_routes(events)

    for ev in events:
        context_id = ev.get("context", {}).get("context_id")
        if not context_id or "message" not in ev:
            continue
        context_id = (ev.get("pid"), context_id)
        _attribute_response(ev, context_id, open_requests)
        # Routing metadata, not a message: contributes its pattern, not a node
        if ev.get("kind") == "Request routed":
            continue
        key = _msg_key(ev)
        if key not in groups_seen[context_id]:
            groups_seen[context_id].add(key)
            groups[context_id].append((key, ev.get("kind", "")))
        if key not in msg_rep:
            msg_rep[key] = ev
        path = _event_path(ev)
        if path:
            node_paths[key].add(path)

    def _is_received(kind: str) -> bool:
        return "received" in kind.lower()

    def _is_sent(kind: str) -> bool:
        return "sent" in kind.lower()

    # Collect unique directed edges across all groups
    edges: set[tuple] = set()
    for context_id, entries in groups.items():
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
        def _dot_label(ev: dict, n_paths: int) -> str:
            kind = ev.get("kind", "?")
            fields = "\\n".join(f"{k}: {v}" for k, v in _label_fields(ev, n_paths))
            return f"{kind}\\n{fields}"

        print("digraph messages {")
        print('  node [shape=box fontname="monospace" fontsize=10]')
        for k in all_keys:
            label = _dot_label(msg_rep[k], len(node_paths[k])).replace('"', '\\"')
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
            print(f"  [{node_id[k]}] {kind}  {_msg_label(ev, len(node_paths[k]))}")

        print(f"\nEdges ({len(edges)}):")
        for a, b in sorted(edges, key=lambda e: (node_id[e[0]], node_id[e[1]])):
            print(f"  [{node_id[a]}] -> [{node_id[b]}]")

        print("\nSummary:")
        for line in summary_lines:
            print(f"  {line}")


if __name__ == "__main__":
    main()
