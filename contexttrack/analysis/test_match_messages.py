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
    type, but match_requests only pairs a path with a pattern when the server logged that very path under it (so
    that a catch-all pattern, e.g. ServeMux "/", doesn't pair with everything), so they don't pair."""

    def test_same_run_pairs(self):
        # (the control: the server logged the client's path)
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", ["/hello/123"]))),
                         ["matched-pattern"])

    def test_no_logged_paths_pairs(self):
        # (with no path logged under the pattern, match_requests falls back to the pattern itself)
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", []))), ["matched-pattern"])

    # (fails: separate runs' IDs differ, and the logged paths, not the pattern, decide)
    def test_separate_runs_pair(self):
        self.assertTrue(pattern_matches("/hello/{id}", "/hello/123"))
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/{id}", ["/hello/456"]))),
                         ["matched-pattern"])

    # (fails: as above, and pattern_matches doesn't handle a bare `*` segment either: only *name, {x...}, ...)
    def test_separate_runs_pair_star_pattern(self):
        self.assertEqual(statuses(match_requests(*sides("/hello/123", "/hello/*", ["/hello/456"]))),
                         ["matched-pattern"])


if __name__ == "__main__":
    unittest.main()
