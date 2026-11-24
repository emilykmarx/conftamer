"""Tests for match_messages' request matching (match_requests).

Run from this directory: python3 -m unittest test_match_messages
"""

import unittest

from match_messages import Side, build_rows, match_requests, pattern_matches

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
        # literal route: GET /api/v1/pods pairs with the latter only
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("k8s.io", "GET", "10.96.0.1:443", "/api/v1/pods"), "client")
        for t, p in ((("k8s.io", "GET", "", "/api/"), "/api"), (("k8s.io", "GET", "", "/api/v1/pods"), "/api/v1/pods")):
            rcv.add(t, "server", path=p)
            rcv.routed.add(t)  # (a literal route: go-restful's /api/v1/pods)
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



def rows_of(sides):
    return sorted((r["message"], r["status"], r.get("snd_path", ""), r.get("rcv_path", "")) for r in build_rows(sides))


class NeverRouted(unittest.TestCase):
    """A received request logged under its concrete path (never routed: e.g. kube-apiserver rejects it with 401 or
    403 before routing it) is folded into the receiver's own pattern for that path (fold_unrouted), so the pairs don't
    depend on whether the client's and the receiver's events came from one run"""

    PATH = "/api/v1/namespaces/ccfg-alerting-alertmanagers-kubernetes-sd-configs-namespaces-names/pods"

    def sides(self, receiver_types):
        sides = {k: Side(k) for k in ("snd_req", "rcv_req", "snd_resp", "rcv_resp")}
        sent = ("k8s.io", "GET", "kubernetes.default.svc:443", self.PATH)
        sides["snd_req"].add(sent, "prometheus")
        sides["rcv_resp"].add(("k8s.io", "403", sent), "prometheus")
        for typ, path, routed in receiver_types:
            sides["rcv_req"].add(typ, "kube-apiserver", path=path)
            if routed:
                sides["rcv_req"].routed.add(typ)
        rejected = receiver_types[0][0]
        sides["snd_resp"].add(("k8s.io", "403", rejected), "kube-apiserver")
        return sides

    def test_folded_into_pattern(self):
        # (prombench: kube-apiserver rejected Prometheus' requests, logged under the concrete path, and routed others'
        # under the pattern) => one pair, with the pattern, and the 403 pairs through it
        routed = ("k8s.io", "GET", "", "/api/v1/namespaces/{namespace}/pods")
        sides = self.sides([(("k8s.io", "GET", "", self.PATH), self.PATH, False),
                            (routed, "/api/v1/namespaces/default/pods", True)])
        self.assertEqual(rows_of(sides), [("request", "matched-pattern", self.PATH, routed[3]),
                                          ("response", "matched-pattern", routed[3], self.PATH)])
        self.assertEqual(rows_of(sides), [("request", "matched-pattern", self.PATH, routed[3]),
                                          ("response", "matched-pattern", routed[3], self.PATH)])  # (again: no change)

    def test_flagged_when_unfoldable(self):
        # (no pattern of the receiver's matches the path: the exact pair stays, flagged)
        sides = self.sides([(("k8s.io", "GET", "", self.PATH), self.PATH, False)])
        self.assertEqual(rows_of(sides), [("request", "matched-exact-unrouted", self.PATH, self.PATH),
                                          ("response", "matched-exact-unrouted", self.PATH, self.PATH)])

    def test_exact_route_wins(self):
        # (a literal route is more specific than any pattern: one pair)
        snd, rcv = Side("snd_req"), Side("rcv_req")
        snd.add(("k8s.io", "GET", "10.96.0.1:443", "/api/v1/pods"), "client")
        for t in (("k8s.io", "GET", "", "/api/v1/pods"), ("k8s.io", "GET", "", "/api/v1/{resource}")):
            rcv.add(t, "kube-apiserver", path="/api/v1/pods")
            rcv.routed.add(t)
        self.assertEqual([(st, r[3]) for st, _, r in match_requests(snd, rcv) if st.startswith("matched")],
                         [("matched-exact", "/api/v1/pods")])


if __name__ == "__main__":
    unittest.main()
