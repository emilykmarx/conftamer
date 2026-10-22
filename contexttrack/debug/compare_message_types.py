#!/usr/bin/env python3
"""Compare match_messages.py's type pairs (Go events) with pcap_message_types.py's (wire).

For each observed wire pair (sender component, receiver component, method, path[, code]):
did match_messages.py pair a sender type and receiver type
that cover it? And for each Go matched row: which of the component pairs it implies
were seen on the wire?

Usage: compare_message_types.py [--config RULES.json] GO.csv PCAP.csv RUN_DIR OUT.csv

RULES.json names endpoints that aren't instrumented pods (default:
kind_components.json beside this script, for a kind cluster):
  address_components  [[regex, component], ...]: an "ip:port" fully matching
                      regex is that component (e.g. a node's pod gateway -> kubelet)
  processes           {ss process name (truncated to 15 chars): container name}
                      for hostNetwork processes
  probe_paths         health-check paths; an unidentified node process
                      requesting one is probe_component

RUN_DIR layout:
  <node>/pods/<namespace>_<pod>_<container>_<x>.jsonl  events files (names name
                                     the pod's containers; none may contain "_")
  <node>/pcap/any.pcap*              the node's tcpdump -U capture (rotated files)
  truth.conns.jsonl                  pcap_messages.py's connections
GO.csv's messages, from match_messages.py, are read from GO.messages.jsonl beside it.
"""
import argparse
import csv
import fnmatch
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "analysis"))
from match_messages import pattern_matches as _pattern_matches


def pattern_matches(pattern: str, path: str) -> bool:
    """match_messages.py's matching, plus Caddy's matcher syntax (path=["glob", ...])."""
    if pattern.startswith("path=["):
        try:
            return any(fnmatch.fnmatchcase(path, g) for g in json.loads(pattern[len("path="):]))
        except json.JSONDecodeError:
            return False
    return _pattern_matches(pattern, path)

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("--config", default=Path(__file__).with_name("kind_components.json"))
ap.add_argument("go_csv")
ap.add_argument("pcap_csv")
ap.add_argument("run")
ap.add_argument("out_csv")
args = ap.parse_args()
go_csv, pcap_csv, run, out_csv = args.go_csv, args.pcap_csv, args.run, args.out_csv
with open(args.config) as fh:
    RULES = json.load(fh)
ADDRESS_COMPONENTS = [(re.compile(rx), comp) for rx, comp in RULES.get("address_components", [])]
PROCESS = RULES.get("processes", {})
PROBE_PATHS = set(RULES.get("probe_paths", []))
PROBE_COMPONENT = RULES.get("probe_component", "kubelet")

# pod (ns/name) -> container name, from the events files' names
pod_container = {}
for f in Path(run).glob("*/pods/*.jsonl"):
    parts = f.stem.split("_")
    if len(parts) == 4:
        pod_container[f"{parts[0]}/{parts[1]}"] = parts[2]

def go_component(instance: str) -> str:
    if "/" in instance:
        return pod_container.get(instance, f"(uninstrumented pod {instance})")
    for rx, comp in ADDRESS_COMPONENTS:
        if rx.fullmatch(instance):
            return comp
    if re.fullmatch(r"[\d.]+:\d+|\[.*\]:\d+", instance):
        return "(unknown node process)"
    return PROCESS.get(instance, instance)


def split(s):
    return [x for x in s.split(";") if x]


def first_packet_ns(pcap: Path) -> int | None:
    """A pcap's first packet time (ns since the epoch), from its first record header."""
    with open(pcap, "rb") as fh:
        head = fh.read(24 + 8)
    if len(head) < 32:
        return None
    for order in "<>":
        magic = struct.unpack(order + "I", head[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):  # microsecond, nanosecond pcap
            sec, frac = struct.unpack(order + "II", head[24:32])
            return sec * 10**9 + (frac if magic == 0xa1b23c4d else frac * 1000)
    return None


def capture_windows(run: str) -> dict[str, tuple[int, int]]:
    """node -> (start, end) of its capture, ns since the epoch: its first packet,
    and its last pcap file's last write (tcpdump -U writes each packet as it's
    captured, so that's its last packet)."""
    windows = {}
    for d in Path(run).glob("*/pcap"):
        files = sorted(d.glob("any.pcap*"))
        if not files or (start := first_packet_ns(d / "any.pcap")) is None:
            continue
        windows[d.parent.name] = (start, max(f.stat().st_mtime_ns for f in files))
    return windows


def wire_connections(run: str) -> dict[tuple, list[dict]]:
    """(client "ip:port", server "ip:port") -> the wire's connections between them,
    under any of the addresses either end was seen with (NAT)."""
    conns = defaultdict(list)
    path = Path(run) / "truth.conns.jsonl"
    if path.exists():
        for line in open(path):
            c = json.loads(line)
            for ci, cp in c["clients"]:
                for si, sp in c["servers"]:
                    conns[(f"{ci}:{cp}", f"{si}:{sp}")].append(c)
    return conns


def go_messages(go_csv: str) -> dict[str, list]:
    """type_id -> its client-side messages (ts, node, local, remote), from the
    messages file match_messages.py writes beside its CSV."""
    path = Path(go_csv).with_suffix(".messages.jsonl")
    if not path.exists():
        return {}
    return {d["type_id"]: d["messages"] for d in map(json.loads, open(path))}


WINDOWS = capture_windows(run)
WIRE_CONNS = wire_connections(run)
GO_MESSAGES = go_messages(go_csv)
# (node, local, remote) -> the connection's first use by any logged message
FIRST_USE = {}
for _msgs in GO_MESSAGES.values():
    for _ts, _node, _local, _remote in _msgs:
        if _ts is not None and _local and _remote:
            _k = (_node, _local, _remote)
            FIRST_USE[_k] = min(_ts, FIRST_USE.get(_k, _ts))
# Why a message can't be on the wire (by the client's view of it)
OUTSIDE = ("before capture", "after capture", "inside pod", "pre-capture connection")


def ip(addr: str) -> str:
    return addr.rsplit(":", 1)[0].strip("[]")


def where(ts, node, local, remote) -> str:
    """Why, or whether, the capture could have seen one message (its client's view)."""
    if node not in WINDOWS:
        return "no capture on node"
    start, end = WINDOWS[node]
    if ts is None or not local or not remote:
        return "connection unknown"
    if ts < start:
        return "before capture"
    if ts > end:
        return "after capture"
    conns = WIRE_CONNS.get((local, remote), [])
    if conns:
        # Opened before the capture: TLS can't be decrypted without its handshake
        # (HTTP/1 in the clear is still read from where the capture starts)
        if any(not c["syn"] and c["proto"] == "tls" for c in conns):
            return "pre-capture connection"
        return "captured connection"
    # Not in the wire's connections. pcap_messages.py records none it can't
    # identify, such as TLS picked up mid-stream (no ClientHello), so tell that
    # from the Go side: the connection was in use before the capture started
    if FIRST_USE.get((node, local, remote), ts) < start:
        return "pre-capture connection"
    # A pod's loopback or own IP stays in its network namespace, which the
    # capture (in the node's) can't see; a hostNetwork process's would be seen
    if ip(remote).startswith("127.") or ip(remote) in ("::1", ip(local)):
        return "inside pod"
    return "connection not on wire"


def message_note(row, message) -> str:
    """'; outside capture: 2 before capture, 6 after capture' when none of the row's
    messages could have been captured; else '; messages: ...'."""
    side = "snd" if message == "request" else "rcv"
    msgs = GO_MESSAGES.get(row.get(f"{side}_type_id", ""))
    if not msgs:
        return ""
    counts = Counter(where(*m) for m in msgs)
    detail = ", ".join(f"{n} {w}" for w, n in counts.most_common())
    return f"; outside capture: {detail}" if all(w in OUTSIDE for w in counts) else f"; messages: {detail}"

go = list(csv.DictReader(open(go_csv)))
wire = list(csv.DictReader(open(pcap_csv)))

# Wire pairs at component level: (message, snd comp, rcv comp, method, path, code) -> n
wpairs = Counter()
for r in wire:
    s = {go_component(i) for i in split(r["snd_components"])}
    probe = (r["snd_path"] or r["rcv_path"]) in PROBE_PATHS
    if s == {"(unknown node process)"} and probe and r["message"] == "request":
        s = {PROBE_COMPONENT}  # inferred: an unidentified node process probing health
    if r["message"] == "response" and probe and {go_component(i) for i in split(r["rcv_components"])} == {"(unknown node process)"}:
        r = dict(r, rcv_components=PROBE_COMPONENT)
    d = {go_component(i) for i in split(r["rcv_components"])}
    assert len(s) == 1 and len(d) == 1, r
    path = r["snd_path"]  # requests: sender's path; responses: the client's request path
    if r["message"] == "response":
        path = r["rcv_path"]
    wpairs[(r["message"], s.pop(), d.pop(), r["snd_method"] or r["rcv_method"], path,
            r["snd_code"] or "")] += int(r["n"])


def server_path_covers(row, server_path, path):
    """Whether the server's type (a path or route pattern) covers concrete `path`:
    as match_messages.py pairs, by the paths the server logged under it when it
    recorded them (a pattern alone can mislead: ServeMux's "/version/" serves
    "/version" too, by redirect or a mux registering both), else by the pattern."""
    if server_path == path:
        return True
    paths = row.get("server_paths")
    return path in split(paths) if paths else pattern_matches(server_path, path)


def go_side_covers(row, side, comp, method, path, code, message):
    if comp not in split(row[f"{side}_components"]) or row[f"{side}_method"] != method:
        return False
    if message == "response" and row[f"{side}_code"] != code:
        return False
    gp = row[f"{side}_path"]
    # Concrete path on the request sender's side (client), pattern or path on the server's
    concrete = (side == "snd") == (message == "request")
    return gp == path if concrete else server_path_covers(row, gp, path)


classes = Counter()  # (message, class) -> messages
detail = []
for (message, s, d, method, path, code), n in wpairs.items():
    def covers(row, side, comp):
        return go_side_covers(row, side, comp, method, path, code, message)
    rows = [r for r in go if r["message"] == message]
    matched = [r for r in rows if r["status"].startswith("matched") and covers(r, "snd", s) and covers(r, "rcv", d)]
    snd_rows = [r for r in rows if r.get("snd_api_id") is not None and covers(r, "snd", s)]
    rcv_rows = [r for r in rows if covers(r, "rcv", d)]
    if matched:
        cls = "matched by match_messages"
        note = matched[0]["status"]
    elif snd_rows and rcv_rows:
        cls = "both ends logged, not paired"
        sa = sorted({r["snd_api_id"] for r in snd_rows})
        ra = sorted({r["rcv_api_id"] for r in rcv_rows})
        note = "api_id differs" if not set(sa) & set(ra) else "same api_id"
        note += f": sender {';'.join(sa) or '(none)'} / receiver {';'.join(ra) or '(none)'}"
    elif snd_rows:
        cls = "receiver not logged"
        note = ""
    elif rcv_rows:
        cls = "sender not logged"
        note = ""
    else:
        cls = "neither end logged"
        note = ""
    classes[(message, cls)] += n
    detail.append({"source": "wire", "message": message, "class": cls, "n": n, "snd_component": s,
                   "rcv_component": d, "method": method, "path": path, "code": code, "note": note})

# Go matched rows: which implied component pairs were seen on the wire?
wire_index = defaultdict(list)
for (message, s, d, method, path, code), n in wpairs.items():
    wire_index[(message, s, d, method, code)].append((path, n))
go_rows = Counter()
for r in go:
    if not r["status"].startswith("matched"):
        continue
    message = r["message"]
    code = r["snd_code"] if message == "response" else ""
    client_path, server_path = (r["snd_path"], r["rcv_path"]) if message == "request" else (r["rcv_path"], r["snd_path"])
    implied = [(s, d) for s in split(r["snd_components"]) for d in split(r["rcv_components"])]
    seen = []
    for s, d in implied:
        hits = [n for p, n in wire_index.get((message, s, d, r["snd_method"], code), [])
                if p == client_path and server_path_covers(r, server_path, p)]
        if hits:
            seen.append((s, d, sum(hits)))
    cls = ("all implied pairs seen" if len(seen) == len(implied) else
           "some implied pairs seen" if seen else "no implied pair seen on the wire")
    go_rows[(message, cls)] += 1
    # Where the client's messages were (a request's sender, a response's
    # receiver: their types are specific to one request, the server's usually to
    # a route pattern spanning the whole run), for rows the wire doesn't confirm
    before = message_note(r, message) if cls != "all implied pairs seen" else ""
    detail.append({"source": "go", "message": message, "class": cls,
                   "n": int(r["snd_n"] or 0), "snd_component": r["snd_components"],
                   "rcv_component": r["rcv_components"], "method": r["snd_method"],
                   "path": f"{client_path} -> {server_path}", "code": code,
                   "note": f"{len(seen)}/{len(implied)} component pairs seen: " +
                           ";".join(f"{s}->{d}" for s, d, _ in seen) + before})

with open(out_csv, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["source", "message", "class", "n", "snd_component", "rcv_component",
                                      "method", "path", "code", "note"])
    w.writeheader()
    w.writerows(sorted(detail, key=lambda x: (x["source"], x["message"], x["class"], -x["n"])))

for message in ("request", "response"):
    total = sum(v for (m, _), v in classes.items() if m == message)
    print(f"wire {message}s: {total} messages in "
          f"{sum(1 for k in wpairs if k[0] == message)} component-level pairs")
    for (m, cls), v in sorted(classes.items(), key=lambda kv: -kv[1]):
        if m == message:
            print(f"  {v:7d} ({100 * v / total:4.1f}%)  {cls}")
for message in ("request", "response"):
    print(f"go matched {message} rows:")
    for (m, cls), v in sorted(go_rows.items(), key=lambda kv: -kv[1]):
        if m == message:
            print(f"  {v:7d}  {cls}")
