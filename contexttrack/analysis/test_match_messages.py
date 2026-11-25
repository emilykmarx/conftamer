"""Tests for match_messages' request matching (match_requests).

Run from this directory: python3 -m unittest test_match_messages
"""

import unittest

from match_messages import Side, match_requests, pattern_matches

API_ID = "example.com/hello"


def sides(client_path, server_pattern, server_paths):
    """A client that sent GET client_path, and a server that received GET requests under server_pattern, logging
    the concrete paths server_paths (none: it logged no path under the pattern)"""
    snd, rcv = Side("snd_req"), Side("rcv_req")
    snd.add((API_ID, "GET", "hello-server:8080", client_path), "client")
    for p in server_paths or [None]:
        rcv.add((API_ID, "GET", "", server_pattern), "server", path=p)
    return snd, rcv


def statuses(rows):
    return sorted(status for status, _, _ in rows)


class HelloAcrossRuns(unittest.TestCase):
    """A message whose path has an ID (e.g. a UUID), handled under a route pattern. When the client's and the
    server's events come from the same run, the server logs the client's path, and they pair. When they come from
    separate runs (e.g. the client's from a testbed, the server's from its own integration tests), each run has its
    own ID: the client sent /hello/123, the server received /hello/456 under its pattern. They are the same message
    type, and pair: the pattern decides, not the paths the server logged under it (match_requests)."""

    def test_same_run_pairs(self):
        # (the control: the server logged the client's path)
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", ["/hello/123"]))),
                         ["matched-pattern"])

    def test_no_logged_paths_pairs(self):
        # (with no path logged under the pattern, match_requests falls back to the pattern itself)
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", []))), ["matched-pattern"])

    def test_separate_runs_pair(self):
        self.assertTrue(pattern_matches("/hello/{id}", "/hello/123"))
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", ["/hello/456"]))),
                         ["matched-pattern"])

    # (a bare `*` at the end: pattern_matches)
    def test_separate_runs_pair_star_pattern(self):
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/*", ["/hello/456"]))),
                         ["matched-pattern"])


    def test_separate_runs_pair_k8s(self):
        # The same, on a real route: Prometheus in prombench lists pods in a namespace its concrete config names
        # (Kubernetes service discovery); kube-apiserver in its own integration tests
        # (test/integration/replicationcontroller/replicationcontroller_test.go: a namespace
        # "test-spec-replicas-change", then c.CoreV1().Pods(ns.Name).List) logs that route's path under its go-restful
        # pattern
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("k8s.io", "GET", "kubernetes.default.svc:443",
                 "/api/v1/namespaces/ccfg-alerting-alertmanagers-kubernetes-sd-configs-namespaces-names/pods"),
                "prometheus")
        rcv.add(("k8s.io", "GET", "", "/api/v1/namespaces/{namespace}/pods"), "kube-apiserver",
                path="/api/v1/namespaces/test-spec-replicas-change/pods")
        self.assertEqual(statuses(match_requests(snd, rcv)), ["matched-pattern"])


class RoutedLikeARouter(unittest.TestCase):
    """Without the logged paths to go by, a path pairs with the patterns a router would route it to"""

    def test_subtree_yields_to_exact(self):
        # kube-apiserver logs its discovery request GET /api under the prefix "/api/", and GET /api/v1/pods under its
        # path: GET /api/v1/pods pairs with the latter only
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("k8s.io", "GET", "10.96.0.1:443", "/api/v1/pods"), "client")
        rcv.add(("k8s.io", "GET", "", "/api/"), "server", path="/api")
        rcv.add(("k8s.io", "GET", "", "/api/v1/pods"), "server", path="/api/v1/pods")
        rows = match_requests(snd, rcv)
        self.assertEqual([(st, r[3]) for st, _, r in rows if st.startswith("matched")],
                         [("matched-exact", "/api/v1/pods")])

    def test_most_specific_pattern(self):
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add((API_ID, "GET", "hello-server:8080", "/hello/123"), "client")
        rcv.add((API_ID, "GET", "", "/hello/"), "server", path="/hello/other")
        rcv.add((API_ID, "GET", "", "/hello/{id}"), "server", path="/hello/456")
        rows = match_requests(snd, rcv)
        self.assertEqual([r[3] for st, _, r in rows if st.startswith("matched")], ["/hello/{id}"])

    def test_trailing_slash_optional(self):
        # (kube-apiserver logs GET /version under "/version/")
        self.assertEqual(statuses(match_requests(*sides("/version", "/version/", ["/version"]))), ["matched-pattern"])



class Loopback(unittest.TestCase):
    """match_requests' loopback_within: a rule about one component's own messages only"""

    def test_loopback_pairs_across_components(self):
        # kube-apiserver reaches etcd over loopback (host network on one node), but whether two components share a
        # network namespace depends on the testbed: a loopback request pairs by type
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("go.etcd.io", "POST", "127.0.0.1:2379", "/etcdserverpb.KV/Range"), "kube-apiserver")
        rcv.add(("go.etcd.io", "POST", "", "/etcdserverpb.KV/Range"), "etcd", path="/etcdserverpb.KV/Range")
        self.assertEqual(statuses(match_requests(snd, rcv, loopback_within=True)), ["matched-exact"])

    def test_proxy_not_paired_with_itself(self):
        # a proxy's forwarded request has the api_id and route of the request it received: it doesn't pair with it
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("github.com/caddyserver", "GET", "grafana.default.svc:3000", "/grafana/api/search"), "caddy")
        rcv.add(("github.com/caddyserver", "GET", "", 'path=["/grafana/*"]'), "caddy", path="/grafana/api/search")
        self.assertEqual(statuses(match_requests(snd, rcv, loopback_within=True)),
                         ["unmatched-receiver", "unmatched-sender"])


if __name__ == "__main__":
    unittest.main()
