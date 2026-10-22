"""
Write a CSV of how received requests are grouped into message types.

A received request's type (as in match_messages.py) is its route pattern when
a router matched one, else its path, so several concrete messages can share
one type. One row per (message, type):
  api_id, method, path: the message as received
  message_type:         the path or route pattern it was typed as
  count:                how many of this message were received
  truncated:            whether message_type differs from the path
  components:           which components received it

Sent requests are typed by their exact path, and responses by the request they
answer, so they are left out.

Run: python3 contexttrack/analysis/message_groups.py RUN_DIR -o groups.csv
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from event_io import load_events
from match_messages import _recvd_req_type, component, strip_pattern
from message_graph import _stamp_routes

FIELDS = ["api_id", "method", "path", "message_type", "count", "truncated", "components"]


def collect(path: Path, counts: Counter, components: dict) -> None:
    comp = component(path)
    events = list(load_events(str(path)))
    _stamp_routes(events)
    for ev in events:
        if ev.get("kind") != "Request received":
            continue
        api_id, method, _, typ = _recvd_req_type(ev)
        key = (api_id, method, (ev.get("message") or {}).get("req.URL.Path", ""), typ)
        counts[key] += 1
        components[key].add(comp)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+", type=Path,
                        help="events .jsonl files, or directories searched recursively")
    parser.add_argument("-o", "--output", help="CSV output path (default: stdout)")
    args = parser.parse_args()

    files = []
    for inp in args.inputs:
        if inp.is_dir():
            files += sorted(f for f in inp.rglob("*.jsonl") if f.stat().st_size)
        else:
            files.append(inp)
    if not files:
        sys.exit("No events files found.")

    counts: Counter = Counter()
    components: dict[tuple, set] = defaultdict(set)
    for f in files:
        collect(f, counts, components)

    rows = []
    for (api_id, method, path, typ), n in counts.items():
        # A ServeMux pattern may lead with method and host ("GET /metrics"), and
        # a Caddy one may name just this path (path=["/healthz"])
        truncated = typ not in (path, f'path=["{path}"]') and strip_pattern(typ) != path
        rows.append({"api_id": api_id, "method": method, "path": path, "message_type": typ,
                     "count": n, "truncated": truncated,
                     "components": ";".join(sorted(components[(api_id, method, path, typ)]))})
    rows.sort(key=lambda r: (r["api_id"], r["message_type"], r["method"], -r["count"], r["path"]))

    out = open(args.output, "w", newline="") if args.output else sys.stdout
    with out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    n_trunc = sum(r["truncated"] for r in rows)
    print(f"{len(rows)} message row(s), {n_trunc} truncated, "
          f"{len({(r['api_id'], r['method'], r['message_type']) for r in rows})} type(s)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
