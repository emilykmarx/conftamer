#!/usr/bin/env python3
"""Deduplicated HTTP messages from per-node `tcpdump -i any` captures.

A message can be captured several times along its path: entering the host
from the sender's veth (before kube-proxy DNAT, so addressed to the Service
IP), leaving the sender's node on eth0, entering the receiver's node on eth0,
and leaving on the receiver's veth (after DNAT). This writes one record per
HTTP request or response, with the copy nearest its sender ("sent") and the
copy nearest its receiver ("received").

Each side also has `conn`: the connection as that end's socket saw it (local
and remote address, and the request's index on the connection or its HTTP/2
stream), which is what contexttrack events record. It comes from conntrack,
since a copy can be addressed differently from the socket: a hostNetwork
process's traffic is NATed before its first copy or after its last.

  1. Split each capture by interface, so tshark never sees two copies of a
     packet in one TCP stream.
  2. Classify each connection by its first payload (TLS, HTTP/1, h2c) and
     decode its server port as that.
  3. Decode HTTP with tshark, decrypting TLS with the CONFTAMER_KEYLOG files.
  4. Merge copies. A message's key is the raw seq + len and ack of the
     segment that completes it (NAT doesn't change them). Streams that share a
     message or a SYN/SYN-ACK ISN pair are one connection.
  5. Pick each message's sent and received copies by their place on the path
     (see path_rank), take each end's view from conntrack, and name endpoints
     from the cluster snapshots.

RUN_DIR (as written by prombench/conftamer/deploy.sh):
  <node>/pcap/any.pcap[N]                tcpdump -i any -y LINUX_SLL2 [-C]
  <node>/pcap/links.start.txt            `ip -o link` (interface names; eth0 = uplink)
  <node>/pcap/tcpdump.err               tcpdump's stderr (its dropped-packet count)
  <node>/pcap/conntrack.log             `conntrack -E -e NEW -p tcp -o timestamp`
  <node>/pcap/{listen.start.txt,ss.log}  ss output (hostNetwork processes)
  **/*.keys                              TLS key logs
  cluster/{services,pods,nodes,pods-watch}.json

Usage: pcap_messages.py RUN_DIR [-o truth.jsonl] [--report report.txt]
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LINKTYPE_LINUX_SLL2 = 276
DISSECTORS = {"tls": "tls", "http": "http", "h2c": "http2"}
PACKET_OUTGOING = 4  # SLL2 packet type of a packet the host sends on an interface
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ",
                b"OPTIONS ", b"CONNECT ", b"TRACE ")


@dataclass
class Capture:
    """One interface's packets on one node."""
    path: Path
    node_dir: str
    name: str  # node/interface

    @property
    def uplink(self) -> bool:
        return self.name.endswith("/eth0")


# 1. Split

def rotated_pcaps(pcap_dir: Path) -> list[Path]:
    """any.pcap, any.pcap1, ... (tcpdump -C) in order."""
    files = [p for p in pcap_dir.glob("any.pcap*") if re.fullmatch(r"any\.pcap\d*", p.name)]
    return sorted(files, key=lambda p: int(p.name[len("any.pcap"):] or 0))


def split_by_interface(node: str, pcaps: list[Path], outdir: Path) -> tuple[dict[int, Path], int]:
    """Write one pcap per SLL2 interface index. Returns the files and the packet count."""
    outs, paths, packets, ghdr = {}, {}, 0, None
    for pcap in pcaps:
        with open(pcap, "rb") as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                continue
            if hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            elif hdr[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            else:
                sys.exit(f"{pcap}: not a pcap file (pcapng isn't supported)")
            linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
            if linktype != LINKTYPE_LINUX_SLL2:
                sys.exit(f"{pcap}: link type {linktype}; capture with `tcpdump -i any -y LINUX_SLL2`")
            ghdr = ghdr or hdr
            while len(ph := f.read(16)) == 16:
                incl = struct.unpack(endian + "IIII", ph)[2]
                data = f.read(incl)
                if len(data) < incl:  # cut off when tcpdump was killed
                    break
                packets += 1
                ifindex = struct.unpack(">i", data[4:8])[0]
                if ifindex not in outs:
                    paths[ifindex] = outdir / f"{node}.if{ifindex}.pcap"
                    outs[ifindex] = open(paths[ifindex], "wb")
                    outs[ifindex].write(ghdr)
                outs[ifindex].write(ph + data)
    for out in outs.values():
        out.close()
    return paths, packets


def dropped_packets(tcpdump_err: Path) -> str:
    """The kernel-dropped count tcpdump prints at exit, or why there's none."""
    if not tcpdump_err.exists():
        return "unknown (no tcpdump.err)"
    m = re.search(r"(\d+) packets? dropped by kernel", tcpdump_err.read_text(errors="replace"))
    return m[1] if m else "unknown (tcpdump didn't exit cleanly)"


def interface_names(links: Path) -> dict[int, str]:
    """`ip -o link` output -> {ifindex: name}."""
    return {int(m[1]): m[2] for line in read_lines(links) if (m := re.match(r"(\d+): ([^:@]+)", line))}


# tshark

def tshark_ek(args: list[str]):
    """Yield each packet's {field: [values]} from `tshark -T ek` (streamed: output can be huge)."""
    cmd = ["tshark", "-n", "-T", "ek", *args]
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, text=True)
        for line in proc.stdout:
            if line.startswith('{"timestamp"'):
                yield json.loads(line)["layers"]
        if proc.wait() != 0:
            err.seek(0)
            sys.exit(f"tshark failed ({' '.join(cmd)}):\n{err.read().decode(errors='replace')}")


def fields(*names: str) -> list[str]:
    return [a for n in names for a in ("-e", n)]


def values(layers: dict, name: str) -> list:
    return layers.get(name.replace(".", "_")) or []


def first(layers: dict, name: str):
    v = values(layers, name)
    return v[0] if v else None


def addrs(layers: dict) -> tuple[tuple, tuple]:
    """((src ip, port), (dst ip, port))"""
    src = first(layers, "ip.src") or first(layers, "ipv6.src")
    dst = first(layers, "ip.dst") or first(layers, "ipv6.dst")
    return (src, int(first(layers, "tcp.srcport"))), (dst, int(first(layers, "tcp.dstport")))


ADDR_FIELDS = ("ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport")


# 2. Classify

@dataclass
class Stream:
    """One TCP connection at one capture point."""
    client: tuple | None = None  # (ip, port)
    server: tuple | None = None
    isn_c: int | None = None  # raw ISNs, from the SYN and SYN-ACK
    isn_s: int | None = None
    proto: str = "unknown"  # tls | http | h2c | other | unknown
    retransmissions: int = 0


def payload_class(payload_hex: str) -> tuple[str, str | None]:
    """(protocol, "client"/"server"/None for who sent it) from a payload's first bytes."""
    b = bytes.fromhex(payload_hex)
    if b.startswith(b"PRI * HTTP/2"):
        return "h2c", "client"
    if b.startswith(HTTP_METHODS):
        return "http", "client"
    if b.startswith(b"HTTP/1."):
        return "http", "server"
    if len(b) >= 6 and b[:2] == b"\x16\x03":  # handshake: ClientHello (1) or ServerHello (2)
        return "tls", {1: "client", 2: "server"}.get(b[5])
    if len(b) >= 3 and b[0] in (0x14, 0x15, 0x17) and b[1] == 0x03:  # mid-stream record
        return "tls", None
    return "other", None


def classify_streams(cap: Capture) -> dict[int, Stream]:
    streams: dict[int, Stream] = defaultdict(Stream)
    payloads = defaultdict(list)  # stream -> [(src, dst, first bytes)], one per direction
    for L in tshark_ek(["-r", str(cap.path),
                        "--disable-protocol", "http", "--disable-protocol", "http2", "--disable-protocol", "tls",
                        "-Y", "tcp.flags.syn==1 || (tcp.len>0 && tcp.seq==1) || tcp.analysis.retransmission",
                        *fields("tcp.stream", *ADDR_FIELDS, "tcp.flags.syn", "tcp.flags.ack", "tcp.seq_raw",
                                "tcp.payload", "tcp.analysis.retransmission")]):
        st = streams[int(first(L, "tcp.stream"))]
        src, dst = addrs(L)
        if first(L, "tcp.analysis.retransmission"):
            st.retransmissions += 1
        elif first(L, "tcp.flags.syn") == "True":
            if first(L, "tcp.flags.ack") == "True":
                st.server, st.client, st.isn_s = src, dst, int(first(L, "tcp.seq_raw"))
            else:
                st.client, st.server, st.isn_c = src, dst, int(first(L, "tcp.seq_raw"))
        elif payload := first(L, "tcp.payload"):
            payloads[int(first(L, "tcp.stream"))].append((src, dst, payload[:64]))
    for sid, ps in payloads.items():
        st = streams[sid]
        for src, dst, data in ps:
            proto, side = payload_class(data)
            if st.client is None and side:  # no SYN: the payload tells who's the client
                st.client, st.server = (src, dst) if side == "client" else (dst, src)
            if st.proto == "unknown" or src == st.client:  # the client's payload decides
                st.proto = proto
    return dict(streams)


def decode_as_args(streams) -> tuple[list[str], list[int]]:
    """tshark -d args giving each server port its majority protocol, and the ports with more than one."""
    votes = defaultdict(Counter)
    for st in streams:
        if st.server and st.proto in DISSECTORS:
            votes[st.server[1]][st.proto] += 1
    args = []
    for port, c in sorted(votes.items()):
        proto = c.most_common(1)[0][0]
        args += ["-d", f"tcp.port=={port},{DISSECTORS[proto]}"]
        if proto == "tls":  # HTTP/1 inside when there's no ALPN
            args += ["-d", f"tls.port=={port},http"]
    return args, [port for port, c in votes.items() if len(c) > 1]


# 3. Decode

@dataclass
class Observation:
    """One copy of a message."""
    cap: str
    stream: int
    frame: int
    t: float
    src: tuple
    dst: tuple
    outgoing: bool  # host -> interface; otherwise interface -> host
    kind: str  # request | response
    key: tuple
    method: str | None = None
    uri: str | None = None
    host: str | None = None
    status: int | None = None
    request_frame: int | None = None  # HTTP/1 response: its request's frame
    h2_stream: int | None = None
    flags: set = field(default_factory=set)

    @property
    def sk(self) -> tuple:
        return (self.cap, self.stream)


DECODE_FIELDS = ("frame.number", "frame.time_epoch", "sll.pkttype", "tcp.stream", *ADDR_FIELDS, "tcp.seq_raw", "tcp.ack_raw",
                 "tcp.len", "http.request.method", "http.request.uri", "http.host", "http.response.code",
                 "http.request_in", "http2.streamid", "http2.type", "http2.headers.method",
                 "http2.headers.path", "http2.headers.authority", "http2.headers.status")


def decode_messages(cap_id: str, cap: Capture, dargs: list[str], keylog: Path | None) -> list[Observation]:
    args = ["-r", str(cap.path), *dargs, "-Y", "http.request || http.response || http2.type==1"]
    if keylog:
        args += ["-o", f"tls.keylog_file:{keylog}"]
    obs = []
    for L in tshark_ek([*args, *fields(*DECODE_FIELDS)]):
        src, dst = addrs(L)
        segment = ((int(first(L, "tcp.seq_raw")) + int(first(L, "tcp.len"))) & 0xFFFFFFFF,
                   int(first(L, "tcp.ack_raw")))
        base = dict(cap=cap_id, stream=int(first(L, "tcp.stream")), frame=int(first(L, "frame.number")),
                    t=float(first(L, "frame.time_epoch")), src=src, dst=dst,
                    outgoing=int(first(L, "sll.pkttype")) == PACKET_OUTGOING)

        def new(kind, key, n, columns, **kw):
            """An observation, flagged if some of `columns` (one value per message) are short."""
            o = Observation(**base, kind=kind, key=(*segment, *key), **kw)
            if any(len(c) != n for c in columns):
                o.flags.add("unaligned_fields")
            obs.append(o)
            return o

        def at(column, i, n):
            return column[i] if len(column) == n else None

        # HTTP/1: a segment can complete several messages.
        methods, uris, hosts = (values(L, f) for f in ("http.request.method", "http.request.uri", "http.host"))
        for i, m in enumerate(methods):
            new("request", ("h1", i), len(methods), [uris], method=m,
                uri=at(uris, i, len(methods)), host=at(hosts, i, len(methods)))
        codes, req_in = values(L, "http.response.code"), values(L, "http.request_in")
        for i, c in enumerate(codes):
            new("response", ("h1", i), len(codes), [req_in], status=int(c),
                request_frame=int(r) if (r := at(req_in, i, len(codes))) else None)

        # HTTP/2: one message per HEADERS frame (type 1), except trailers (a
        # later HEADERS frame on the stream, e.g. gRPC's grpc-status). Pseudo-headers
        # line up with frames when there's one per HEADERS frame.
        sids = [int(s) for ty, s in zip(values(L, "http2.type"), values(L, "http2.streamid")) if ty == "1"]
        h2m, h2p, h2a, h2s = (values(L, f"http2.headers.{h}") for h in ("method", "path", "authority", "status"))
        n = len(sids)
        firsts = [i for i, sid in enumerate(sids) if sids.index(sid) == i]  # each stream's first here
        if h2m:
            for i, sid in enumerate(sids):
                new("request", ("h2", sid, i), n, [h2m, h2p], h2_stream=sid, method=at(h2m, i, n),
                    uri=at(h2p, i, n), host=at(h2a, i, n))
        elif len(h2s) == len(firsts) < n:
            # A response and its trailers in one segment: statuses go to each
            # stream's first HEADERS frame; the rest are trailers.
            for i, status in zip(firsts, h2s):
                new("response", ("h2", sids[i], i), 0, [], h2_stream=sids[i], status=int(status))
        else:
            # Unaligned (status unknown) when a segment mixes one stream's response
            # with another's trailers. build_messages drops trailers in later segments.
            for i, sid in enumerate(sids):
                new("response", ("h2", sid, i), n, [h2s], h2_stream=sid,
                    status=int(s) if (s := at(h2s, i, n)) else None)
    return obs


# 5. Endpoints

def read_lines(p: Path) -> list[str]:
    return p.read_text(errors="replace").splitlines() if p.exists() else []


def read_json(p: Path) -> list:
    return json.loads(p.read_text())["items"] if p.exists() else []


def parse_time(s: str | None) -> float | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None


def json_stream(path: Path):
    """Concatenated JSON values (`kubectl get --watch -o json`)."""
    if not path.exists():
        return
    text, dec, i = path.read_text(), json.JSONDecoder(), 0
    while (i := len(text) - len(text[i:].lstrip())) < len(text):
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:  # cut off when the watch was killed
            return
        yield obj


def ss_process(line: str) -> str | None:
    m = re.search(r'users:\(\("([^"]+)"', line)
    return m and m[1]


def ss_addr(s: str) -> tuple:
    host, port = s.rsplit(":", 1)
    host = host.strip("[]").split("%")[0].removeprefix("::ffff:")
    return host, int(port) if port.isdigit() else 0


def hostport(addr: tuple) -> str:
    """(ip, port) as Go's net.Addr.String() writes it."""
    ip, port = addr
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def workload(pod: str) -> str:
    """ns/name without its ReplicaSet/DaemonSet/StatefulSet suffix."""
    for pat in (r"-[a-z0-9]{6,10}-[a-z0-9]{5}$", r"-[a-z0-9]{5}$", r"-\d+$"):
        if (stripped := re.sub(pat, "", pod)) != pod:
            return stripped
    return pod


def endpoint_name(ep: dict) -> str:
    """A short name for an endpoint record: workload, node:process, or address."""
    if ep.get("pod"):
        return workload(ep["pod"])
    if ep.get("process"):
        return f"{ep['node']}:{ep['process']}"
    if ep.get("host_network"):
        return f"{ep['node']}:{ep['port']}"
    return f"{ep['ip']}:{ep['port']}"


class Cluster:
    """Names for addresses, from deploy.sh's snapshots (each optional)."""

    def __init__(self, run_dir: Path, node_dirs: list[str]):
        cdir = run_dir / "cluster"
        self.services = {}  # clusterIP -> ns/name
        self.pods = defaultdict(list)  # ip -> [(start, end, ns/name, node)]
        self.host_pods = {}  # (node ip, port) -> ns/name of a hostNetwork pod
        self.node_ips = {}  # ip -> node name
        self.dir_node = {d: d for d in node_dirs}  # capture dir -> node name
        self.listen = {}  # (node dir, port) -> process
        self.sockets = {}  # (node dir, local, peer) -> process
        # (node dir, client addr, server addr as one end saw them) ->
        # [(t, client's view, server's view)], each view as (client addr, server addr)
        self.conntrack = defaultdict(list)
        self.conntrack_entries = defaultdict(list)  # node dir -> [(t, client's view, server's view)]

        for svc in read_json(cdir / "services.json"):
            for ip in svc["spec"].get("clusterIPs") or [svc["spec"].get("clusterIP")]:
                if ip and ip != "None":
                    self.services[ip] = f"{svc['metadata']['namespace']}/{svc['metadata']['name']}"
        for n in read_json(cdir / "nodes.json"):
            name = n["metadata"]["name"]
            for a in n["status"].get("addresses", []):
                if a["type"] == "InternalIP":
                    self.node_ips[a["address"]] = name
            # kindnet gives the node the pod CIDR's first address on every veth; the
            # node's own traffic to pods (e.g. kubelet's probes) comes from it.
            spec = n.get("spec", {})
            for cidr in spec.get("podCIDRs") or ([spec["podCIDR"]] if spec.get("podCIDR") else []):
                self.node_ips[str(next(ipaddress.ip_network(cidr).hosts()))] = name
            for d in node_dirs:
                if name == d or name.endswith("-" + d):
                    self.dir_node[d] = name
        self.node_dir = {n: d for d, n in self.dir_node.items()}

        pods = {}  # uid -> latest object; the watch has pods deleted before `collect`
        for ev in json_stream(cdir / "pods-watch.json"):
            if ev.get("object", {}).get("kind") == "Pod":
                pods[ev["object"]["metadata"]["uid"]] = ev["object"]
        for p in read_json(cdir / "pods.json"):
            pods.setdefault(p["metadata"]["uid"], p)
        for p in pods.values():
            md, spec, status = p["metadata"], p["spec"], p.get("status", {})
            name = f"{md['namespace']}/{md['name']}"
            ips = [x["ip"] for x in status.get("podIPs") or []]
            if not ips and status.get("podIP"):
                ips = [status["podIP"]]
            if spec.get("hostNetwork"):
                for c in spec.get("containers", []):
                    for port in c.get("ports", []):
                        for ip in ips:
                            self.host_pods[(ip, port.get("hostPort") or port["containerPort"])] = name
                continue
            end = parse_time(md.get("deletionTimestamp"))
            if end is not None:
                end += spec.get("terminationGracePeriodSeconds", 30)
            for ip in ips:
                self.pods[ip].append((parse_time(md.get("creationTimestamp")) or 0, end, name, spec.get("nodeName")))

        for d in node_dirs:
            pdir = run_dir / d / "pcap"
            for line in read_lines(pdir / "listen.start.txt"):
                parts = line.split()
                if len(parts) >= 4 and (proc := ss_process(line)):
                    self.listen[(d, ss_addr(parts[3])[1])] = proc
            for line in read_lines(pdir / "ss.log"):
                parts = line.split()
                if len(parts) >= 5 and (proc := ss_process(line)):
                    self.sockets[(d, ss_addr(parts[3]), ss_addr(parts[4]))] = proc
            for line in read_lines(pdir / "conntrack.log"):
                # [ts] [NEW] tcp ... src= dst= sport= dport= (original) ... src= dst= sport= dport= (reply)
                ts = re.match(r"\[(\d+\.\d+)\]", line)
                tuples = re.findall(r"src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)", line)
                if not ts or len(tuples) < 2:
                    continue
                (osrc, odst, osp, odp), (rsrc, rdst, rsp, rdp) = tuples[:2]
                client_view = ((osrc, int(osp)), (odst, int(odp)))
                server_view = ((rdst, int(rdp)), (rsrc, int(rsp)))
                entry = (float(ts[1]), client_view, server_view)
                self.conntrack_entries[d].append(entry)
                for view in {client_view, server_view}:
                    self.conntrack[(d, *view)].append(entry)

    def hidden_nat(self) -> list[tuple]:
        """Connections NATed on the node of one of their ends' process (hostNetwork
        or loopback), so no copy shows that end's view: [(node dir, t, client's
        view, server's view)]. Covers connections without decoded HTTP, too."""
        hidden = []
        for d, entries in self.conntrack_entries.items():
            node = self.dir_node[d]
            local = {ip for ip, n in self.node_ips.items() if n == node}

            def on_node(ip):
                return ip in local or ipaddress.ip_address(ip).is_loopback
            for t, cv, sv in entries:
                if cv != sv and (on_node(cv[0][0]) or on_node(sv[1][0])):
                    hidden.append((d, t, cv, sv))
        return hidden

    def socket_views(self, node_dir: str, seen: tuple, t: float) -> tuple | None:
        """(client's view, server's view) of the connection whose (client, server)
        addresses were `seen` at node_dir around time t, from conntrack."""
        entries = [e for e in self.conntrack.get((node_dir, *seen), []) if e[0] <= t + 1]
        return max(entries)[1:] if entries else None

    def endpoint(self, addr: tuple, t: float, peer: tuple, capture_dir: str, server: bool) -> dict:
        """{ip, port} plus service, pod, or (hostNetwork) node and process.
        `server`: whether addr is the connection's server end (a listening socket)."""
        ip, port = addr
        ep = {"ip": ip, "port": port}
        if ip in self.services:
            return ep | {"service": self.services[ip]}
        live = [p for p in self.pods.get(ip, []) if p[0] <= t + 5 and (p[1] is None or t <= p[1])]
        if live:
            _, _, pod, node = max(live)  # the newest pod with this IP
            return ep | {"pod": pod, "node": node}
        if ipaddress.ip_address(ip).is_loopback:
            node, node_dir = self.dir_node[capture_dir], capture_dir
        elif ip in self.node_ips:
            node = self.node_ips[ip]
            node_dir = self.node_dir.get(node)
        else:
            return ep
        ep |= {"node": node, "host_network": True}
        if server:
            pod, proc = self.host_pods.get(addr), self.listen.get((node_dir, port))
        else:
            pod, proc = None, self.sockets.get((node_dir, addr, peer))
        if pod:
            ep["pod"] = pod
        if proc:
            ep["process"] = proc
        return ep


# 4. Merge

class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        while self.parent.setdefault(x, x) != x:
            x = self.parent[x] = self.parent[self.parent[x]]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def path_rank(o: Observation, cap: Capture) -> tuple:
    """Sort key for a message's copies, from its sender to its receiver:
    entering the host from the sender's veth (or lo), leaving the sender's node
    on eth0, entering the receiver's node on eth0, leaving on the receiver's
    veth (or lo). A hostNetwork sender or receiver has no veth copy, so its
    node's eth0 copy is the nearest. Time breaks ties (kind nodes share a clock)."""
    if cap.uplink:
        return (1 if o.outgoing else 2, o.t)
    return (3 if o.outgoing else 0, o.t)


def build_messages(streams: dict[tuple, Stream], observations: list[Observation],
                   captures: dict[str, Capture], cluster: Cluster) -> tuple[list[dict], list[dict]]:
    """(messages, connections)"""
    by_key = defaultdict(list)
    for o in observations:
        by_key[o.key].append(o)
    uf = UnionFind()
    for obs in by_key.values():
        for o in obs[1:]:
            uf.union(o.sk, obs[0].sk)
    by_isn = {}
    for sk, st in streams.items():
        if st.isn_c is not None and st.isn_s is not None:
            uf.union(sk, by_isn.setdefault((st.isn_c, st.isn_s), sk))

    # Connections, numbered by their first message
    keyed = sorted(by_key.values(), key=lambda obs: min(o.t for o in obs))
    # An HTTP/2 stream has one response: later HEADERS frames are its trailers.
    responded = set()

    def first_response(obs):
        if obs[0].kind != "response" or obs[0].h2_stream is None:
            return True
        stream = (uf.find(obs[0].sk), obs[0].h2_stream)
        if stream in responded:
            return False
        responded.add(stream)
        return True
    keyed = [obs for obs in keyed if first_response(obs)]
    groups = defaultdict(list)
    for obs in keyed:
        groups[uf.find(obs[0].sk)]
    for sk in streams:
        groups[uf.find(sk)].append(sk)
    conns = {}
    for n, (g, sks) in enumerate(groups.items()):
        sts = [streams[sk] for sk in sks]
        conns[g] = {
            "conn_id": f"c{n}",
            "proto": Counter(st.proto for st in sts).most_common(1)[0][0],
            "clients": sorted({st.client for st in sts if st.client}),
            "servers": sorted({st.server for st in sts if st.server}),
            "syn": any(st.isn_c is not None for st in sts),
            "isn_pairs": len({(st.isn_c, st.isn_s) for st in sts if st.isn_c is not None and st.isn_s is not None}),
            "streams": sorted(f"{captures[sk[0]].name}#{sk[1]}" for sk in sks),
            "n_messages": 0,
        }

    # Message IDs, so responses can name their request
    request_id = {}  # (capture, frame) of a request copy -> msg_id
    h2_request_id = {}  # (connection, HTTP/2 stream) -> msg_id
    for n, obs in enumerate(keyed):
        if obs[0].kind == "request":
            for o in obs:
                request_id.setdefault((o.cap, o.frame), f"m{n}")
            if obs[0].h2_stream is not None:
                h2_request_id.setdefault((uf.find(obs[0].sk), obs[0].h2_stream), f"m{n}")

    # HTTP/1 requests' index on their connection, as events record it. Unknown
    # without the connection's start.
    index = {}  # msg_id -> index
    per_conn = Counter()
    for n, obs in enumerate(keyed):
        g = uf.find(obs[0].sk)
        if obs[0].kind == "request" and obs[0].h2_stream is None and conns[g]["syn"]:
            index[f"m{n}"] = per_conn[g]
            per_conn[g] += 1

    messages = []
    for n, obs in enumerate(keyed):
        o0, g = obs[0], uf.find(obs[0].sk)
        conn = conns[g]
        conn["n_messages"] += 1
        flags = set().union(*(o.flags for o in obs))

        def agree(attr):
            vals = {getattr(o, attr) for o in obs} - {None}
            if len(vals) > 1:
                flags.add("field_mismatch")
            return min(vals, key=str) if vals else None

        kind = agree("kind")
        by_path = sorted(obs, key=lambda o: path_rank(o, captures[o.cap]))
        sent, received = by_path[0], by_path[-1]
        if not conn["syn"]:
            flags.add("no_syn")
        if len(obs) == 1:
            flags.add("single_observation")  # sent and received are the same copy

        req_id = None
        if kind == "response":
            if o0.h2_stream is not None:
                req_id = h2_request_id.get((g, o0.h2_stream))
            else:
                req_id = next((r for o in obs if (r := request_id.get((o.cap, o.request_frame)))), None)

        # (client, server) addresses as each end's socket saw them: from conntrack on
        # the node of the copy nearest that end, or else as that copy was addressed.
        def view(o, end):
            seen = (o.src, o.dst) if kind == "request" else (o.dst, o.src)
            views = cluster.socket_views(captures[o.cap].node_dir, seen, o.t)
            return (views[end], "conntrack") if views else (seen, "capture")

        near_client, near_server = (sent, received) if kind == "request" else (received, sent)
        views = {"client": view(near_client, 0), "server": view(near_server, 1)}

        def side(o, sender: bool) -> dict:
            """A copy's capture point and time, and the connection and endpoints as
            the sender's (or receiver's) socket saw them."""
            end = "client" if (kind == "request") == sender else "server"
            (client, server), source = views[end]
            local, remote = (client, server) if end == "client" else (server, client)
            src, dst = (local, remote) if sender else (remote, local)
            if (src, dst) != (o.src, o.dst):
                flags.add("socket_view_differs_from_copy")
            cdir = captures[o.cap].node_dir
            return {
                "at": captures[o.cap].name, "t": o.t,
                "conn": {"local": hostport(local), "remote": hostport(remote),
                         "index": index.get(f"m{n}" if kind == "request" else req_id),
                         "h2_stream": o0.h2_stream, "source": source},
                "src": cluster.endpoint(src, o.t, dst, cdir, server=src == server),
                "dst": cluster.endpoint(dst, o.t, src, cdir, server=dst == server),
            }

        rec = {
            "msg_id": f"m{n}",
            "conn_id": conn["conn_id"],
            "kind": kind,
            "proto": ("tls-" if conn["proto"] == "tls" else "") + ("http1" if o0.h2_stream is None else "h2"),
            "sent": side(sent, sender=True),
            "received": side(received, sender=False),
        }
        if kind == "request":
            uri = agree("uri")
            path, _, query = (uri or "").partition("?")
            rec |= {"method": agree("method"), "path": path if uri is not None else None,
                    "query": query or None, "host": agree("host")}
        else:
            rec |= {"status": agree("status"), "request_msg_id": req_id}
            if req_id is None:
                flags.add("no_request")
        rec |= {"h2_stream": o0.h2_stream, "observations": sorted(captures[o.cap].name for o in obs),
                "flags": sorted(flags)}
        messages.append(rec)

    for c in conns.values():
        if c["proto"] == "tls" and c["n_messages"] == 0:
            c["flags"] = ["tls_no_http"]
    return messages, list(conns.values())


# Report

def write_report(out, messages, conns, packets, drops, streams, captures, conflicts, cluster):
    def p(*a):
        print(*a, file=out)

    def counts(c):
        return ", ".join(f"{k}={v}" for k, v in c) or "none"

    reqs = [m for m in messages if m["kind"] == "request"]
    p(f"messages: {len(messages)} ({len(reqs)} requests, {len(messages) - len(reqs)} responses)")
    p("by proto: " + counts(Counter(m["proto"] for m in messages).most_common()))
    p("observations per message: " + counts(sorted(Counter(len(m["observations"]) for m in messages).items())))
    p("message flags: " + counts(Counter(f for m in messages for f in m["flags"]).most_common()))
    p()
    p(f"connections: {len(conns)}")
    p("by proto: " + counts(Counter(c["proto"] for c in conns).most_common()))
    p(f"without SYN (opened before the capture): {sum(not c['syn'] for c in conns)}")
    p(f"several ISN pairs in one connection (key collision?): {sum(c['isn_pairs'] > 1 for c in conns)}")
    no_http = [c for c in conns if c.get("flags")]
    p(f"TLS with no decoded HTTP (no keys, or idle): {len(no_http)}")
    for c in no_http[:20]:
        p(f"  {c['conn_id']} {c['clients']} -> {c['servers']} syn={c['syn']}")
    other = Counter(s[1] for c in conns if c["proto"] in ("other", "unknown") for s in c["servers"])
    p("non-HTTP connections by server port: " + counts(other.most_common()))
    if conflicts:
        p("server ports with conflicting protocols: " + ", ".join(map(str, conflicts)))
    p()
    p("packets per node: " + counts(sorted(packets.items())))
    # A dropped packet can lose a message, and shifts the index of every later
    # request on its connection.
    p("packets dropped by the kernel (should be 0): " + counts(sorted(drops.items())))
    retrans = Counter()
    for (cap, _), st in streams.items():
        retrans[captures[cap].name] += st.retransmissions
    p("retransmissions per interface (~0 expected; more means duplicate copies): " +
      counts((k, v) for k, v in retrans.most_common() if v))
    p()

    # Can events be matched by five-tuple? Only where each end's copy is addressed
    # as its socket saw it.
    p("socket views from: " + counts(Counter(
        f"{side}={m[side]['conn']['source']}" for m in messages for side in ("sent", "received")).most_common()))
    differs = [m for m in messages if "socket_view_differs_from_copy" in m["flags"]]
    p(f"messages whose sent or received copy is addressed differently from its socket: {len(differs)}")
    for (kind, src, dst), n in Counter(
            (m["kind"], endpoint_name(m["sent"]["src"]), endpoint_name(m["received"]["dst"])) for m in differs).most_common(20):
        p(f"  {n:7d}  {kind}: {src} -> {dst}")
    p(f"NATed messages (sender's and receiver's views differ): "
      f"{sum(m['sent']['conn']['remote'] != m['received']['conn']['local'] or m['sent']['conn']['local'] != m['received']['conn']['remote'] for m in messages)}")
    hidden = cluster.hidden_nat()
    p(f"connections NATed out of the capture's sight (an end's process is on the NATing node): {len(hidden)}")
    for (d, cs, cd, ss_), n in Counter(
            (d, endpoint_name(cluster.endpoint(cv[0], t, cv[1], d, server=False)),
             endpoint_name(cluster.endpoint(cv[1], t, cv[0], d, server=True)),
             endpoint_name(cluster.endpoint(sv[1], t, sv[0], d, server=True))) for d, t, cv, sv in hidden).most_common(20):
        p(f"  {n:7d}  on {d}: {cs} -> {cd} (server sees {ss_})")
    p(f"HTTP/1 requests without an index (connection opened before the capture): "
      f"{sum(m['sent']['conn']['index'] is None and m['proto'].endswith('http1') for m in reqs)}")
    p()

    c = Counter((endpoint_name(m["sent"]["src"]), endpoint_name(m["received"]["dst"]), m["method"], m["path"]) for m in reqs)
    p(f"requests by (sender, receiver, method, path): {len(c)} distinct")
    for (cl, sv, meth, path), n in c.most_common(100):
        p(f"  {n:7d}  {cl} -> {sv}  {meth} {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="$CONFTAMER_DIR of a prombench run")
    parser.add_argument("-o", "--output", type=Path, help="messages JSONL (default: RUN_DIR/truth.jsonl)")
    parser.add_argument("--connections", type=Path, help="connections JSONL (default: RUN_DIR/truth.conns.jsonl)")
    parser.add_argument("--report", type=Path, help="text report (default: RUN_DIR/truth.report.txt)")
    parser.add_argument("--work", type=Path, help="keep the per-interface pcaps here (default: a temp dir in RUN_DIR)")
    parser.add_argument("-j", "--jobs", type=int, default=min(4, os.cpu_count() or 1),
                        help="parallel tshark runs; each can use GBs (default: %(default)s)")
    args = parser.parse_args()

    run = args.run_dir
    node_dirs = sorted(d.name for d in run.iterdir() if rotated_pcaps(d / "pcap"))
    if not node_dirs:
        sys.exit(f"no <node>/pcap/any.pcap under {run}")
    if not shutil.which("tshark"):
        sys.exit("tshark not found")
    work = args.work or Path(tempfile.mkdtemp(prefix="pcap-split-", dir=run))
    work.mkdir(parents=True, exist_ok=True)

    keylog = None
    if keys := sorted(p for p in run.rglob("*.keys") if p.is_file()):
        keylog = work / "all.keys"
        keylog.write_bytes(b"".join(k.read_bytes() for k in keys))

    captures, packets = {}, {}
    drops = {d: dropped_packets(run / d / "pcap" / "tcpdump.err") for d in node_dirs}
    for d in node_dirs:
        paths, packets[d] = split_by_interface(d, rotated_pcaps(run / d / "pcap"), work)
        names = interface_names(run / d / "pcap" / "links.start.txt")
        for ifindex, path in paths.items():
            captures[f"{d}.if{ifindex}"] = Capture(path, d, f"{d}/{names.get(ifindex, f'if{ifindex}')}")
        print(f"{d}: {packets[d]} packets, {len(paths)} interfaces", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        streams = {(cid, sid): st
                   for cid, sts in zip(captures, pool.map(classify_streams, captures.values()))
                   for sid, st in sts.items()}
        # One port table for every capture: some only see a connection mid-stream.
        dargs, conflicts = decode_as_args(streams.values())
        print(f"classified {len(streams)} streams", file=sys.stderr)
        observations = [o for obs in pool.map(lambda cid: decode_messages(cid, captures[cid], dargs, keylog),
                                              captures) for o in obs]
    print(f"decoded {len(observations)} observations", file=sys.stderr)
    for o in observations:
        streams.setdefault(o.sk, Stream())  # e.g. no SYN and no payload starting at seq 1

    cluster = Cluster(run, node_dirs)
    messages, conns = build_messages(streams, observations, captures, cluster)

    out = args.output or run / "truth.jsonl"
    out.write_text("".join(json.dumps(m) + "\n" for m in messages))
    (args.connections or run / "truth.conns.jsonl").write_text("".join(json.dumps(c) + "\n" for c in conns))
    with open(args.report or run / "truth.report.txt", "w") as f:
        write_report(f, messages, conns, packets, drops, streams, captures, conflicts, cluster)
    print(f"wrote {len(messages)} messages to {out}", file=sys.stderr)

    if not args.work:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
