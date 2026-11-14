"""End-to-end and unit tests for the cachepoison detector.

Covers the nine acceptance rules: eight fixture cases with exactly six
risks, the fixed cache-key format, and the per-case evidence requirements.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cachepoison.detector import analyze_cases
from cachepoison.key import build_cache_key, compute_cache_key
from cachepoison.normalize import normalize_path, normalize_query, path_split_risk
from cachepoison.policy import proxy_headers_in_key, public_with_set_cookie
from cachepoison.report import build_report
from cachepoison.vary import missing_vary_entries, parse_vary

CASES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "demo", "cases.json")


def load_results():
    with open(CASES_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return analyze_cases(data["cases"], data.get("config"))


def evidence_text(entry):
    return "\n".join(entry["evidence"])


class FixtureCaseTests(unittest.TestCase):
    """The eight demo cases must produce exactly the expected verdicts."""

    @classmethod
    def setUpClass(cls):
        cls.results = load_results()
        cls.by_id = {entry["case_id"]: entry for entry in cls.results}

    def test_eight_cases_six_risks(self):
        self.assertEqual(len(self.results), 8)
        risks = [e for e in self.results if e["verdict"] == "risk"]
        safe = [e for e in self.results if e["verdict"] == "safe"]
        self.assertEqual(len(risks), 6)
        self.assertEqual(len(safe), 2)
        self.assertEqual(
            {e["case_id"] for e in safe},
            {"normal-with-vary", "query-string-ignored"},
        )
        self.assertEqual(
            {e["case_id"] for e in risks},
            {"host-target-mismatch", "dot-segment-path", "forwarded-host-in-key",
             "missing-vary-origin", "public-with-set-cookie", "trailing-slash-split"},
        )

    def test_normal_with_vary_is_safe(self):
        entry = self.by_id["normal-with-vary"]
        self.assertEqual(entry["verdict"], "safe")
        self.assertEqual(entry["risk_types"], [])

    def test_host_mismatch_reports_both_values(self):
        entry = self.by_id["host-target-mismatch"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("host_mismatch", entry["risk_types"])
        text = evidence_text(entry)
        self.assertIn("victim.example.com", text)        # request Host header
        self.assertIn("cdn-attacker.example.net", text)  # absolute-form target host
        # The key's host segment must come from the request Host header.
        self.assertEqual(entry["cache_key"].split("|")[0], "victim.example.com")

    def test_dot_segment_path_normalized(self):
        entry = self.by_id["dot-segment-path"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("path_normalization_split", entry["risk_types"])
        text = evidence_text(entry)
        self.assertIn("/a/b/../c", text)                 # original path reported
        self.assertEqual(entry["cache_key"].split("|")[1], "/a/c")
        self.assertIn(entry["cache_key"], text)          # normalized key reported

    def test_forwarded_host_in_key_is_risk(self):
        entry = self.by_id["forwarded-host-in-key"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("trusted_proxy_header_in_key", entry["risk_types"])
        self.assertIn("X-Forwarded-Host", evidence_text(entry))
        self.assertTrue(entry["cache_key"].endswith("|x-forwarded-host"))

    def test_missing_vary_names_origin(self):
        entry = self.by_id["missing-vary-origin"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("missing_vary", entry["risk_types"])
        self.assertIn("Origin", evidence_text(entry))

    def test_public_with_set_cookie_conflict(self):
        entry = self.by_id["public-with-set-cookie"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("public_with_set_cookie", entry["risk_types"])
        text = evidence_text(entry)
        self.assertIn("Cache-Control: public", text)
        self.assertIn("Set-Cookie", text)

    def test_query_string_ignored_is_safe(self):
        entry = self.by_id["query-string-ignored"]
        self.assertEqual(entry["verdict"], "safe")
        # Query segment (third field) is empty when the mode is "ignore".
        self.assertEqual(entry["cache_key"].split("|")[2], "")

    def test_trailing_slash_split_reports_both_keys(self):
        entry = self.by_id["trailing-slash-split"]
        self.assertEqual(entry["verdict"], "risk")
        self.assertIn("path_normalization_split", entry["risk_types"])
        text = evidence_text(entry)
        key_with_slash = "api.example.com|/api/v1/items/||"
        key_without_slash = "api.example.com|/api/v1/items||"
        self.assertIn(key_with_slash, text)
        self.assertIn(key_without_slash, text)
        # The two keys differ only by the trailing slash.
        self.assertEqual(key_with_slash.replace("/|", "|"), key_without_slash)
        self.assertEqual(entry["cache_key"], key_without_slash)

    def test_report_entries_have_required_fields(self):
        for entry in self.results:
            for field in ("case_id", "verdict", "evidence", "cache_key"):
                self.assertIn(field, entry)
            self.assertIn(entry["verdict"], ("risk", "safe"))
            self.assertIsInstance(entry["evidence"], list)
            self.assertIsInstance(entry["cache_key"], str)

    def test_summary_distribution(self):
        report = build_report(self.results)
        summary = report["summary"]
        self.assertEqual(summary["cases"], 8)
        self.assertEqual(summary["risks"], 6)
        distribution = summary["risk_type_distribution"]
        self.assertEqual(distribution["path_normalization_split"], 2)
        self.assertEqual(distribution["host_mismatch"], 1)
        self.assertEqual(distribution["trusted_proxy_header_in_key"], 1)
        self.assertEqual(distribution["missing_vary"], 1)
        self.assertEqual(distribution["public_with_set_cookie"], 1)


class NormalizationTests(unittest.TestCase):
    """Normalization rules must hold for arbitrary inputs, not just fixtures."""

    def test_dot_segments(self):
        self.assertEqual(normalize_path("/a/b/../c"), "/a/c")
        self.assertEqual(normalize_path("/a/./b"), "/a/b")
        self.assertEqual(normalize_path("/a/../../b"), "/b")

    def test_percent_encoded_slash(self):
        self.assertEqual(normalize_path("/a%2fb"), "/a/b")
        self.assertEqual(normalize_path("/x%2Fy%2fz"), "/x/y/z")

    def test_duplicate_slashes(self):
        self.assertEqual(normalize_path("//a///b//c"), "/a/b/c")

    def test_case_and_trailing_slash(self):
        self.assertEqual(normalize_path("/API/V1/Items/"), "/api/v1/items")
        self.assertEqual(normalize_path("/"), "/")
        self.assertEqual(normalize_path(""), "/")

    def test_already_normalized_is_stable(self):
        self.assertFalse(path_split_risk("/api/v1/items"))
        self.assertTrue(path_split_risk("/api/v1/items/"))
        self.assertTrue(path_split_risk("/a/b/../c"))

    def test_query_modes(self):
        query = "b=2&a=1&c=3"
        self.assertEqual(normalize_query(query, mode="all"), query)
        self.assertEqual(normalize_query(query, mode="ignore"), "")
        self.assertEqual(normalize_query(query, mode="params", params=["c", "a"]),
                         "a=1&c=3")

    def test_query_mode_params_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            normalize_query("a=1", mode="bogus")


class CacheKeyTests(unittest.TestCase):
    def test_key_format(self):
        key = compute_cache_key("example.com", "/a/b", "x=1", ["B-Header", "a-header"])
        self.assertEqual(key, "example.com|/a/b|x=1|a-header,b-header")

    def test_build_cache_key_normalizes(self):
        key = build_cache_key("example.com", "/A//b/../c/", "q=1&utm=2", [],
                              query_mode="params", query_params=["q"])
        self.assertEqual(key, "example.com|/a/c|q=1|")


class VaryAndPolicyTests(unittest.TestCase):
    def test_parse_vary(self):
        self.assertEqual(parse_vary("Origin, Accept-Encoding"),
                         {"origin", "accept-encoding"})
        self.assertEqual(parse_vary(None), set())

    def test_missing_vary_entries(self):
        self.assertEqual(missing_vary_entries("Accept-Encoding", ["Origin"]), ["Origin"])
        self.assertEqual(missing_vary_entries("Origin", ["Origin"]), [])
        self.assertEqual(missing_vary_entries("*", ["Origin"]), [])
        self.assertEqual(missing_vary_entries(None, ["Origin"]), ["Origin"])

    def test_proxy_headers_in_key(self):
        self.assertEqual(proxy_headers_in_key(["X-Forwarded-Host", "Accept"]),
                         ["X-Forwarded-Host"])
        self.assertEqual(proxy_headers_in_key(["Accept"]), [])

    def test_public_with_set_cookie(self):
        self.assertTrue(public_with_set_cookie(
            {"Cache-Control": "public, max-age=60", "Set-Cookie": "sid=1"}))
        self.assertFalse(public_with_set_cookie(
            {"Cache-Control": "private", "Set-Cookie": "sid=1"}))
        self.assertFalse(public_with_set_cookie({"Cache-Control": "public"}))


if __name__ == "__main__":
    unittest.main()
