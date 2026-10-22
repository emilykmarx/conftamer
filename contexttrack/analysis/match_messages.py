"""
Match sender and receiver message types across events files, and write them as CSV.

Each message is reduced to a deduplicated type:
  Request sent:      (api_id, method, host, path)
  Request received:  (api_id, method, route pattern or path)
  Response sent:     (api_id, code, type of the received request it answers)
  Response received: (api_id, code, type of the sent request it answers)

Request types pair when api_id and method are equal and the paths are equal
("matched-exact") or the receiver's route pattern is one it received the
sender's path under ("matched-pattern").
Host is used for reference/debugging, not matching.
Response types pair when api_id and code are equal and the requests they
answer were paired.
Types with no match get a row with the other side blank.

Run: python3 contexttrack/analysis/match_messages.py RUN_DIR -o types.csv
With -o, also writes types.messages.jsonl: each client-side type's messages
(time, node, connection), for compare_message_types.py.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from event_io import dedup_responses, load_events
from message_graph import _req_identity, _stamp_routes


# The runtime's generic HTTP plumbing (conftamerHTTPLayerPackages in the patched
# net/http's conftamer.go): package -> also its subpackages
_RUNTIME_PLUMBING = {
    "net/http": False, "net/http/httputil": False, "golang.org/x/net/http2": False,
    "golang.org/x/oauth2": True, "golang.org/x/net/context/ctxhttp": True,
    "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp": True,
    "github.com/prometheus/common/route": True, "github.com/emicklei/go-restful": True,
    "github.com/gorilla/mux": True, "k8s.io/apiserver/pkg/server/mux": True,
    "github.com/grafana/grafana/pkg/web": True, "google.golang.org/grpc": True,
}
# Plumbing the runtime doesn't skip, so its "Request sent" events name it as
# their api_id: gRPC client interceptors (metrics, tracing). Skipped here using
# the event's call_chain. api_id it gets -> packages (and their subpackages).
_EXTRA_PLUMBING = {
    "github.com/grpc-ecosystem": ["github.com/grpc-ecosystem"],
    # otelhttp's gRPC twin; next out from grpc-ecosystem's interceptor in client-go/etcd's chain
    "go.opentelemetry.io": ["go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"],
}
_MULTI_TENANT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def _package(function: str) -> str:
    """As conftamerPackageName: 'a/b/c.(*T).F' -> 'a/b/c'."""
    name = function.split("[", 1)[0]
    end = max(name.rfind("/"), 0)
    dot = name.find(".", end)
    return name[:dot] if dot >= 0 else ""


def _api_id_of(pkg: str) -> str:
    """As conftamerApiID: 'github.com/prometheus/x' -> 'github.com/prometheus'."""
    segs = pkg.split("/", 2)
    if "." not in segs[0]:
        return pkg
    if len(segs) >= 2 and segs[0] in _MULTI_TENANT_HOSTS:
        return segs[0] + "/" + segs[1]
    return segs[0]


def _is_plumbing(pkg: str, extra: list[str]) -> bool:
    under = lambda p: pkg == p or pkg.startswith(p + "/")
    return (any(pkg == p or sub and pkg.startswith(p + "/") for p, sub in _RUNTIME_PLUMBING.items())
            or any(under(p) for p in extra))


def _api_id(ev: dict) -> str:
    """The event's api_id; for a "Request sent" naming extra plumbing, the first
    frame out of all plumbing in its call chain instead."""
    api_id = ev.get("api_id", "")
    chain = ev.get("call_chain")
    if api_id not in _EXTRA_PLUMBING or not chain:
        return api_id
    extra = [p for ps in _EXTRA_PLUMBING.values() for p in ps]
    for frame in chain:
        pkg = _package(frame.get("function", ""))
        if pkg and not _is_plumbing(pkg, extra):
            return _api_id_of(pkg)
    return api_id


# Type tuples. Requests: (api_id, method, host, path); host is "" for received.
# Responses: (api_id, code, request type).
def _sent_req_type(ev: dict) -> tuple:
    msg = ev.get("message", {})
    rid = ev.get("request_id") or {}
    return (_api_id(ev), rid.get("method") or msg.get("req.Method", ""),
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

def caddy_pattern_matches(pattern: str, path: str) -> bool | None:
    """Caddy patterns look different from other route patterns; must be parsed separately.
    Whether a Caddy route pattern (see caddy-route.patch: matchers as
    name=<JSON>, joined by " && " within a set and " || " between sets; "*"
    for none) matches `path`, or None if `pattern` isn't one. Only path
    matchers are checked: others (host, header...) can't be, as for host here."""
    if pattern == "*":
        return True
    if not re.match(r"[a-z_]+=", pattern):
        return None
    for matcher_set in pattern.split(" || "):
        ok = True
        for m in matcher_set.split(" && "):
            name, _, cfg = m.partition("=")
            if name != "path":
                continue
            try:
                globs = json.loads(cfg)
            except json.JSONDecodeError:
                globs = []
            # Caddy's path matcher: case-insensitive, "*" matches anything (incl. "/")
            ok = ok and any(re.fullmatch(".*".join(map(re.escape, g.split("*"))), path, re.I)
                            for g in globs)
        if ok:
            return True
    return False


def pattern_matches(pattern: str, path: str) -> bool:
    """Whether route `pattern` matches concrete `path`. Handles ServeMux
    {x}, {x...}, {$} and trailing-"/" subtrees, go-restful {x:*} and {x:regex},
    httprouter :x and *x, and Caddy's matcher patterns."""
    caddy = caddy_pattern_matches(pattern, path)
    if caddy is not None:
        return caddy
    pat = strip_pattern(pattern)
    # go-restful {x:*} (rest of the path) and {x:regex}, before escaping
    parts = re.split(r"(\{[^{}:]*:[^{}]*\})", pat)
    rx = ""
    for part in parts:
        m = re.fullmatch(r"\{[^{}:]*:([^{}]*)\}", part)
        if m:
            rx += ".*" if m.group(1).strip() == "*" else f"(?:{m.group(1)})"
        else:
            rx += re.escape(part)
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

    def __init__(self, name: str = "", keep_messages: bool = False):
        self.name = name
        self.ids: dict[tuple, int] = {}  # type -> its number, for the messages file
        # type -> its messages as (ts, node, local, remote): kept for the client
        # side (sent requests, received responses), whose types are specific to
        # one request, so a checker can tell when and where each could be seen
        self.keep_messages = keep_messages
        self.messages: dict[tuple, list] = defaultdict(list)
        self.n: Counter = Counter()
        self.components: dict[tuple, set] = defaultdict(set)
        self.paths: dict[tuple, set] = defaultdict(set)  # concrete paths per type
        self.first: dict[tuple, int] = {}  # earliest and latest event timestamp (ns) per type
        self.last: dict[tuple, int] = {}

    def add(self, typ: tuple, comp: str, path: str | None = None, ts: int | None = None,
            node: str = "", conn: dict | None = None) -> None:
        self.ids.setdefault(typ, len(self.ids))
        if self.keep_messages:
            conn = conn or {}
            self.messages[typ].append((ts, node, conn.get("local"), conn.get("remote")))
        self.n[typ] += 1
        self.components[typ].add(comp)
        if path:
            self.paths[typ].add(path)
        if ts is not None:
            self.first[typ] = min(ts, self.first.get(typ, ts))
            self.last[typ] = max(ts, self.last.get(typ, ts))


def collect(path: Path, sides: dict[str, Side]) -> None:
    """Add the types of every message in one events file to `sides`."""
    comp = component(path)
    # <node>/pods/<pod>.jsonl or <node>/<process>.jsonl, as deploy.sh collects them
    node = path.parent.parent.name if path.parent.name == "pods" else path.parent.name
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
            sides["snd_req"].add(_sent_req_type(ev), comp, ts=ev.get("ts"), node=node, conn=ev.get("conn"))
        elif kind == "Request received":
            recvd[group].append(ev)
            sides["rcv_req"].add(_recvd_req_type(ev), comp, msg.get("req.URL.Path"), ev.get("ts"))
        elif kind == "Response sent":
            # Match on method and path, else the only request in the context:
            # handlers may rewrite the path before responding (e.g. Prometheus serveDebug)
            reqs = [r for r in recvd[group] if _req_identity(r) == _req_identity(ev)]
            if not reqs and len(recvd[group]) == 1:
                reqs = recvd[group]
            req = _recvd_req_type(reqs[-1]) if reqs else _NO_REQ
            sides["snd_resp"].add((req[0], msg.get("code", ""), req), comp, ts=ev.get("ts"))
        elif kind == "Response received":
            reqs = [r for r in sent[group] if _req_identity(r) == _req_identity(ev)]
            req = _sent_req_type(reqs[-1]) if reqs else _NO_REQ
            # The connection is the request's: it's logged on the read loop, without one
            conn = reqs[-1].get("conn") if reqs else None
            # Take api_id from the request, as for "Response sent": Client.do's
            # own api_id can name a wrapper (e.g. golang.org for parca), and
            # transport-only responses (direct RoundTrip) carry none
            api_id = req[0] or ev.get("api_id", "")
            sides["rcv_resp"].add((api_id, msg.get("resp.StatusCode", ""), req), comp, ts=ev.get("ts"),
                                  node=node, conn=conn)


def match_requests(snd: Side, rcv: Side) -> list[tuple]:
    """(status, sender type, receiver type) for every request type."""
    by_key = defaultdict(list)  # (api_id, method) -> receiver types
    for r in rcv.n:
        by_key[r[:2]].append(r)
    rows, matched = [], set()
    for s in snd.n:
        cands = by_key[s[:2]]
        # A receiver can log the same request under its path and, when routed,
        # under its pattern (e.g. kube-apiserver's leases), so take both. A
        # pattern counts only if the receiver logged this path under it: a
        # catch-all (ServeMux "/", "/api/") matches every path, but receives few.
        hits = [("matched-exact", r) for r in cands if r[3] == s[3]]
        hits += [("matched-pattern", r) for r in cands if r[3] != s[3] and (
            s[3] in rcv.paths[r] if rcv.paths[r] else pattern_matches(r[3], s[3]))]
        for status, r in hits:
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
          "same_path_other_api_ids", "server_paths",
          "snd_first_ts", "snd_last_ts", "rcv_first_ts", "rcv_last_ts",
          "snd_type_id", "rcv_type_id"]


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
            f"{prefix}_first_ts": side.first.get(typ, ""),  # ns since the epoch
            f"{prefix}_last_ts": side.last.get(typ, ""),
            f"{prefix}_type_id": f"{side.name}#{side.ids[typ]}",  # in the messages file
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
            # Every concrete path the server logged its request type with, so a
            # checker can confirm a pattern as the matcher does (see match_requests)
            server_req = (s[2] if s else None) if is_resp else r
            if server_req is not None:
                row["server_paths"] = ";".join(sorted(sides["rcv_req"].paths[server_req]))
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

    sides = {k: Side(k, keep_messages=k in ("snd_req", "rcv_resp"))
             for k in ("snd_req", "rcv_req", "snd_resp", "rcv_resp")}
    for f in files:
        collect(f, sides)
    rows = build_rows(sides)

    out = open(args.output, "w", newline="") if args.output else sys.stdout
    with out:
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    # The client side's messages, per type: <output>.messages.jsonl
    if args.output:
        with open(Path(args.output).with_suffix(".messages.jsonl"), "w") as f:
            for side in (sides["snd_req"], sides["rcv_resp"]):
                for typ, msgs in side.messages.items():
                    f.write(json.dumps({"type_id": f"{side.name}#{side.ids[typ]}", "messages": msgs}) + "\n")

    counts = Counter((row["message"], row["status"]) for row in rows)
    for (message, status), n in sorted(counts.items()):
        print(f"{message:8s} {status:20s} {n} type row(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
