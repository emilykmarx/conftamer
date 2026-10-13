"""
Match sender and receiver message types across events files, and write them as CSV.

Each message is reduced to a deduplicated type:
  Request sent:      (api_id, method, host, path)
  Request received:  (api_id, method, route pattern or path)
  Response sent:     (api_id, code, type of the received request it answers)
  Response received: (api_id, code, type of the sent request it answers)

Request types pair when api_id and method are equal and the paths are equal
("matched-exact") or the receiver's route pattern matches the sender's path
("matched-pattern"). For now, host is not used for matching.
Response types match when api_id and code are equal and the requests they
answer were paired. 
Types with no match get a row with the other side blank.

Run: python3 contexttrack/analysis/match_messages.py RUN_DIR -o types.csv
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from event_io import dedup_responses, load_events
from message_graph import _req_identity, _stamp_routes


# Type tuples. Requests: (api_id, method, host, path); host is "" for received.
# Responses: (api_id, code, request type).
def _sent_req_type(ev: dict) -> tuple:
    msg = ev.get("message", {})
    rid = ev.get("request_id") or {}
    return (ev.get("api_id", ""), rid.get("method") or msg.get("req.Method", ""),
            msg.get("req.URL.Host", ""), rid.get("path") or msg.get("req.URL.Path", ""))


def _recvd_req_type(ev: dict) -> tuple:
    msg = ev.get("message", {})
    return (ev.get("api_id", ""), msg.get("req.Method", ""), "",
            ev.get("route_pattern") or msg.get("req.URL.Path", ""))


_NO_REQ = ("", "", "", "")


def strip_pattern(pattern: str) -> str:
    """'GET host/path' -> '/path' (ServeMux patterns may lead with method and host)."""
    pattern = pattern.split(" ", 1)[-1]
    slash = pattern.find("/")
    return pattern[slash:] if slash >= 0 else pattern


def pattern_matches(pattern: str, path: str) -> bool:
    """Whether route `pattern` matches concrete `path`. Handles ServeMux
    {x}, {x...}, {$} and trailing-"/" subtrees, and httprouter :x and *x."""
    pat = strip_pattern(pattern)
    rx = re.escape(pat)
    rx = re.sub(r"\\\{[^}]*\\\.\\\.\\\.\\\}", ".*", rx)   # {x...}
    rx = re.sub(r"\\\{\\\$\\\}$", "", rx)                  # {$}
    rx = re.sub(r"\\\{[^}]*\\\}", "[^/]+", rx)             # {x}
    rx = re.sub(r":[A-Za-z_]\w*", "[^/]+", rx)             # :x
    rx = re.sub(r"\\\*[A-Za-z_]\w*$", ".*", rx)            # *x
    if pat.endswith("/") and not pattern.endswith("{$}"):
        rx += ".*"
    return re.fullmatch(rx, path) is not None


def component(path: Path) -> str:
    """'pods/<ns>_<pod>_<container>_<hash>.jsonl' -> container; else file stem."""
    parts = path.stem.split("_")
    if path.parent.name == "pods" and len(parts) == 4:
        return parts[2]
    return path.stem


class Side:
    """Types seen on one side (sent or received) of one message kind."""

    def __init__(self):
        self.n: Counter = Counter()
        self.components: dict[tuple, set] = defaultdict(set)
        self.paths: dict[tuple, set] = defaultdict(set)  # concrete paths per type

    def add(self, typ: tuple, comp: str, path: str | None = None) -> None:
        self.n[typ] += 1
        self.components[typ].add(comp)
        if path:
            self.paths[typ].add(path)


def collect(path: Path, sides: dict[str, Side]) -> None:
    """Add the types of every message in one events file to `sides`."""
    comp = component(path)
    events = dedup_responses(list(load_events(str(path))))
    _stamp_routes(events)

    # (pid, context_id) -> request events, to link each response to its request
    sent: dict[tuple, list] = defaultdict(list)
    recvd: dict[tuple, list] = defaultdict(list)

    for ev in events:
        kind = ev.get("kind")
        msg = ev.get("message") or {}
        group = (ev.get("pid"), (ev.get("context") or {}).get("context_id"))
        if kind == "Request sent":
            sent[group].append(ev)
            sides["snd_req"].add(_sent_req_type(ev), comp)
        elif kind == "Request received":
            recvd[group].append(ev)
            sides["rcv_req"].add(_recvd_req_type(ev), comp, msg.get("req.URL.Path"))
        elif kind == "Response sent":
            # Match on method and path, else the only request in the context:
            # handlers may rewrite the path before responding (e.g. Prometheus serveDebug)
            reqs = [r for r in recvd[group] if _req_identity(r) == _req_identity(ev)]
            if not reqs and len(recvd[group]) == 1:
                reqs = recvd[group]
            req = _recvd_req_type(reqs[-1]) if reqs else _NO_REQ
            sides["snd_resp"].add((req[0], msg.get("code", ""), req), comp)
        elif kind == "Response received":
            reqs = [r for r in sent[group] if _req_identity(r) == _req_identity(ev)]
            req = _sent_req_type(reqs[-1]) if reqs else _NO_REQ
            # Take api_id from the request, as for "Response sent": Client.do's
            # own api_id can name a wrapper (e.g. golang.org for parca), and
            # transport-only responses (direct RoundTrip) carry none
            api_id = req[0] or ev.get("api_id", "")
            sides["rcv_resp"].add((api_id, msg.get("resp.StatusCode", ""), req), comp)


def match_requests(snd: Side, rcv: Side) -> list[tuple]:
    """(status, sender type, receiver type) for every request type."""
    by_key = defaultdict(list)  # (api_id, method) -> receiver types
    for r in rcv.n:
        by_key[r[:2]].append(r)
    rows, matched = [], set()
    for s in snd.n:
        cands = by_key[s[:2]]
        exact = [r for r in cands if r[3] == s[3]]
        hits = exact or [r for r in cands if pattern_matches(r[3], s[3])]
        status = "matched-exact" if exact else "matched-pattern"
        for r in hits:
            rows.append((status, s, r))
            matched.add(r)
        if not hits:
            rows.append(("unmatched-sender", s, None))
    rows += [("unmatched-receiver", None, r) for r in rcv.n if r not in matched]
    return rows


def match_responses(snd: Side, rcv: Side, req_pairs: set[tuple]) -> list[tuple]:
    """Response types pair when api_id and code are equal and the requests they
    answer were paired. The response sender is the request receiver."""
    rows, matched = [], set()
    for s in snd.n:
        hits = [r for r in rcv.n
                if r[:2] == s[:2] and (r[2], s[2]) in req_pairs]
        for r in hits:
            status = "matched-exact" if r[2][3] == s[2][3] else "matched-pattern"
            rows.append((status, s, r))
            matched.add(r)
        if not hits:
            rows.append(("unmatched-sender", s, None))
    rows += [("unmatched-receiver", None, r) for r in rcv.n if r not in matched]
    return rows


FIELDS = ["message", "status",
          "snd_api_id", "snd_method", "snd_host", "snd_path", "snd_code", "snd_n",
          "rcv_api_id", "rcv_method", "rcv_host", "rcv_path", "rcv_code", "rcv_n",
          "snd_components", "rcv_components", "example_paths",
          "same_path_other_api_ids"]


def _side_fields(prefix: str, typ: tuple | None, side: Side, is_resp: bool) -> dict:
    if typ is None:
        return {}
    api_id, method, host, path = typ[2] if is_resp else typ
    if is_resp:
        api_id = typ[0]
    return {f"{prefix}_api_id": api_id, f"{prefix}_method": method,
            f"{prefix}_host": host, f"{prefix}_path": path,
            f"{prefix}_code": typ[1] if is_resp else "",
            f"{prefix}_n": side.n[typ],
            f"{prefix}_components": ";".join(sorted(side.components[typ]))}


def _other_api_ids(typ: tuple, others: Side, is_resp: bool) -> str:
    """api_ids the other side used for the same method and path, for unmatched types."""
    req = typ[2] if is_resp else typ
    ids = {(o[2] if is_resp else o)[0] for o in others.n
           if (o[2] if is_resp else o)[1::2] == req[1::2]}
    ids.discard(req[0])
    return ";".join(sorted(i or "(none)" for i in ids))


def build_rows(sides: dict[str, Side]) -> list[dict]:
    req_rows = match_requests(sides["snd_req"], sides["rcv_req"])
    req_pairs = {(s, r) for status, s, r in req_rows if status.startswith("matched")}
    resp_rows = match_responses(sides["snd_resp"], sides["rcv_resp"], req_pairs)

    out = []
    for message, rows, snd, rcv in (
            ("request", req_rows, sides["snd_req"], sides["rcv_req"]),
            # A response is sent by the request's receiver
            ("response", resp_rows, sides["snd_resp"], sides["rcv_resp"])):
        is_resp = message == "response"
        for status, s, r in rows:
            row = {"message": message, "status": status,
                   **_side_fields("snd", s, snd, is_resp),
                   **_side_fields("rcv", r, rcv, is_resp)}
            if message == "request" and status == "matched-pattern":
                row["example_paths"] = ";".join(sorted(rcv.paths[r])[:3])
            if status == "unmatched-sender":
                row["same_path_other_api_ids"] = _other_api_ids(s, rcv, is_resp)
            elif status == "unmatched-receiver":
                row["same_path_other_api_ids"] = _other_api_ids(r, snd, is_resp)
            out.append(row)
    out.sort(key=lambda row: (row["message"], row["status"],
                              -(row.get("snd_n") or 0), -(row.get("rcv_n") or 0)))
    return out


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

    sides = {k: Side() for k in ("snd_req", "rcv_req", "snd_resp", "rcv_resp")}
    for f in files:
        collect(f, sides)
    rows = build_rows(sides)

    out = open(args.output, "w", newline="") if args.output else sys.stdout
    with out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    counts = Counter((row["message"], row["status"]) for row in rows)
    for (message, status), n in sorted(counts.items()):
        print(f"{message:8s} {status:20s} {n} type row(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
