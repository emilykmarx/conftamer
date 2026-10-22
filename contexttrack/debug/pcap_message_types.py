#!/usr/bin/env python3
"""Message type pairs from pcap_messages.py's ground truth, as a CSV shaped like
match_messages.py's, so the two can be compared row by row.

Types are as in match_messages.py, with the sender and receiver named by
workload instead of api_id (packets carry no api_id), and the receiver's path
being the concrete path (packets carry no route pattern):
  request:  sender (component, method, host, path) -> receiver (component, method, path)
  response: sender (component, code, request) -> receiver (component, code, request)
A response's sender is its request's receiver.

Every pair here happened on the wire, so status is "observed". snd_n and
rcv_n count the messages of each side's type, as in match_messages.py; n
counts the messages with exactly this pair.

Run: python3 contexttrack/debug/pcap_message_types.py RUN_DIR/truth.jsonl -o pcap-types.csv
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict

from pcap_messages import endpoint_name

FIELDS = ["message", "status",
          "snd_component", "snd_method", "snd_host", "snd_path", "snd_code", "snd_n",
          "rcv_component", "rcv_method", "rcv_host", "rcv_path", "rcv_code", "rcv_n",
          "n", "snd_components", "rcv_components", "protos"]


def instance(ep: dict) -> str:
    """The specific pod or process behind a component name."""
    return ep.get("pod") or ep.get("process") or f"{ep['ip']}:{ep['port']}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("truth", help="truth.jsonl from pcap_messages.py")
    parser.add_argument("-o", "--output", help="CSV output path (default: stdout)")
    args = parser.parse_args()

    messages = [json.loads(line) for line in open(args.truth)]
    by_id = {m["msg_id"]: m for m in messages}

    pairs = Counter()  # (message, sender type, receiver type) -> messages
    snd_n, rcv_n = Counter(), Counter()  # (message, type) -> messages
    instances = defaultdict(set)  # (message, side, type) -> pods/processes
    protos = defaultdict(set)
    for m in messages:
        src, dst = m["sent"]["src"], m["received"]["dst"]
        snd_c, rcv_c = endpoint_name(src), endpoint_name(dst)
        req = m if m["kind"] == "request" else by_id.get(m.get("request_msg_id"))
        method = (req or {}).get("method") or ""
        path = (req or {}).get("path") or ""
        host = (req or {}).get("host") or ""
        if m["kind"] == "request":
            s = (snd_c, method, host, path, "")
            r = (rcv_c, method, "", path, "")
        else:
            code = str(m.get("status") or "")
            if req is None:
                method, host, path = "", "", "(no request)"
            s = (snd_c, method, "", path, code)
            r = (rcv_c, method, host, path, code)
        key = (m["kind"], s, r)
        pairs[key] += 1
        snd_n[(m["kind"], s)] += 1
        rcv_n[(m["kind"], r)] += 1
        instances[(m["kind"], "snd", s)].add(instance(src))
        instances[(m["kind"], "rcv", r)].add(instance(dst))
        protos[key].add(m["proto"])

    rows = []
    for (kind, s, r), n in pairs.items():
        row = {"message": kind, "status": "observed", "n": n, "protos": ";".join(sorted(protos[(kind, s, r)]))}
        for prefix, t, counts in (("snd", s, snd_n), ("rcv", r, rcv_n)):
            component, method, host, path, code = t
            row |= {f"{prefix}_component": component, f"{prefix}_method": method, f"{prefix}_host": host,
                    f"{prefix}_path": path, f"{prefix}_code": code, f"{prefix}_n": counts[(kind, t)],
                    f"{prefix}_components": ";".join(sorted(instances[(kind, prefix, t)]))}
        rows.append(row)
    rows.sort(key=lambda row: (row["message"], -row["n"]))

    out = open(args.output, "w", newline="") if args.output else sys.stdout
    with out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    for kind in ("request", "response"):
        print(f"{kind:8s} {sum(1 for k in pairs if k[0] == kind)} type pair(s), "
              f"{sum(n for k, n in pairs.items() if k[0] == kind)} message(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
