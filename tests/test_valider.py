import csv
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from valider.exporters import export_results
from valider.cli import _load_urls, _parser
from valider._native import (
    DomainPolicy,
    classify_http_status,
    is_retryable_http_status,
)
from valider.validator import URLResult, URLValidator, _Response


PUBLIC_IP = "93.184.216.34"


class NativePolicyTests(unittest.TestCase):
    def test_domain_matching_and_redirect_state_are_bounded(self):
        policy = DomainPolicy(["example.com"], 1)
        policy.begin()
        self.assertTrue(policy.is_allowed("example.com"))
        self.assertTrue(policy.is_allowed("api.example.com"))
        self.assertFalse(policy.is_allowed("not-example.com"))
        self.assertTrue(policy.visit_url("https://example.com/"))
        self.assertFalse(policy.visit_url("https://example.com/"))
        self.assertTrue(policy.follow_redirect())
        self.assertFalse(policy.follow_redirect())

        policy.begin()
        self.assertTrue(policy.visit_url("https://example.com/"))
        self.assertTrue(policy.follow_redirect())

    def test_native_policy_rejects_noncanonical_domains(self):
        with self.assertRaisesRegex(ValueError, "canonical lowercase ASCII"):
            DomainPolicy(["Example.com"], 1)

    def test_rust_status_classifier_returns_technical_categories(self):
        self.assertEqual(classify_http_status(200), "success")
        self.assertEqual(classify_http_status(302), "redirection")
        self.assertEqual(classify_http_status(404), "client_error")
        self.assertEqual(classify_http_status(503), "server_error")
        self.assertEqual(classify_http_status(99), "invalid")
        self.assertTrue(is_retryable_http_status(429))
        self.assertTrue(is_retryable_http_status(503))
        self.assertFalse(is_retryable_http_status(404))


class CLITests(unittest.TestCase):
    def test_parser_accepts_domain_and_positional_url(self):
        args = _parser().parse_args(
            ["--allow-domain", "championat.com", "https://www.championat.com/user/pdr"]
        )
        self.assertEqual(args.allow_domain, ["championat.com"])
        self.assertEqual(_load_urls(args), ["https://www.championat.com/user/pdr"])

    def test_missing_url_explains_positional_and_file_usage(self):
        args = _parser().parse_args(["--allow-domain", "championat.com"])
        with self.assertRaisesRegex(ValueError, "No URL provided.*--input FILE"):
            _load_urls(args)

    def test_input_reads_urls_from_a_local_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "links.txt"
            path.write_text(
                "# authorized test URLs\nhttps://championat.com/a\n\nhttps://championat.com/b\n",
                encoding="utf-8",
            )
            args = _parser().parse_args(
                ["--allow-domain", "championat.com", "--input", str(path)]
            )
            self.assertEqual(
                _load_urls(args),
                ["https://championat.com/a", "https://championat.com/b"],
            )

    def test_input_url_is_rejected_with_positional_usage_hint(self):
        args = _parser().parse_args(
            ["--allow-domain", "championat.com", "--input", "https://championat.com/user/pdr"]
        )
        with self.assertRaisesRegex(ValueError, "--input expects a local text-file path"):
            _load_urls(args)

    def test_misspelled_allow_domain_option_suggests_correct_option(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            _parser().parse_args(["--allow-dommain", "championat.com", "https://championat.com"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("did you mean --allow-domain?", stderr.getvalue())

    def test_url_passed_as_allow_domain_is_rejected_as_wrong_argument(self):
        with self.assertRaisesRegex(ValueError, "--allow-domain expects a domain name only"):
            URLValidator(["https://www.championat.com/user/pdr"])


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.resolved = []
        self.requests = []

        def resolver(host, port):
            self.resolved.append((host, port))
            return [PUBLIC_IP]

        def requester(url, host, port, scheme, ip, timeout):
            self.requests.append(url)
            return _Response(200, {"content-type": "text/html"}, b"<title>Service status</title>")

        self.validator = URLValidator(
            ["example.com"],
            resolver=resolver,
            requester=requester,
            sleeper=lambda seconds: None,
        )

    def test_malformed_url_is_rejected_without_dns_or_http(self):
        result = self.validator.validate("https://example.com:bad/")
        self.assertEqual(result.outcome, "erro")
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.requests, [])

    def test_allowlist_is_checked_before_dns_or_http(self):
        result = self.validator.validate("https://not-example.com/")
        self.assertEqual(result.outcome, "bloqueado")
        self.assertIn("allowlist", result.error)
        self.assertEqual(self.resolved, [])
        self.assertEqual(self.requests, [])

    def test_redirect_outside_allowlist_is_blocked_before_following(self):
        self.validator._requester = lambda *args: _Response(
            302, {"location": "https://outside.test/private"}, b""
        )
        result = self.validator.validate("https://example.com/")
        self.assertEqual(result.outcome, "bloqueado")
        self.assertIn("outside.test", result.error)
        self.assertEqual(self.resolved, [("example.com", 443)])
        self.assertEqual(len(self.requests), 0)

    def test_redirect_to_private_dns_result_is_blocked_before_second_request(self):
        def resolver(host, port):
            self.resolved.append((host, port))
            return ["127.0.0.1"] if host == "internal.example.com" else [PUBLIC_IP]

        def requester(url, host, port, scheme, ip, timeout):
            self.requests.append(url)
            return _Response(
                302 if len(self.requests) == 1 else 200,
                {"location": "https://internal.example.com/"} if len(self.requests) == 1 else {},
                b"",
            )

        self.validator._resolver = resolver
        self.validator._requester = requester
        result = self.validator.validate("https://example.com/")
        self.assertEqual(result.outcome, "bloqueado")
        self.assertIn("não global", result.error)
        self.assertEqual(len(self.requests), 1)

    def test_mixed_public_and_private_dns_answers_are_blocked(self):
        self.validator._resolver = lambda host, port: [PUBLIC_IP, "10.0.0.8"]
        result = self.validator.validate("https://example.com/")
        self.assertEqual(result.outcome, "bloqueado")
        self.assertEqual(self.requests, [])

    def test_public_html_is_reported_as_technical_data(self):
        result = self.validator.validate("https://example.com/")
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(result.http_status_class, "success")
        self.assertFalse(result.http_retryable_hint)
        self.assertEqual(result.title, "Service status")
        self.assertIn("INCONCLUSIVO", result.conclusion)

    def test_redirect_cycle_is_blocked_by_native_chain_state(self):
        def redirect_to_same_url(url, *args):
            self.requests.append(url)
            return _Response(302, {"location": "https://example.com/"}, b"")

        self.validator._requester = redirect_to_same_url
        result = self.validator.validate("https://example.com/")
        self.assertEqual(result.outcome, "erro")
        self.assertIn("Ciclo de redirecionamento", result.error)
        self.assertEqual(len(self.requests), 1)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.result = URLResult(
            url="https://example.com/",
            outcome="ok",
            http_status=200,
            dns_ips=["93.184.216.34"],
            title="Service status",
        )
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_json_export(self):
        path = Path(self.directory.name) / "results.json"
        export_results([self.result], str(path), "json")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))[0]["http_status"], 200)

    def test_txt_export(self):
        path = Path(self.directory.name) / "results.txt"
        export_results([self.result], str(path), "txt")
        text = path.read_text(encoding="utf-8")
        self.assertIn("Estado técnico: ok", text)
        self.assertIn("INCONCLUSIVO", text)

    def test_csv_export(self):
        path = Path(self.directory.name) / "results.csv"
        export_results([self.result], str(path), "csv")
        with path.open(encoding="utf-8", newline="") as stream:
            row = next(csv.DictReader(stream))
        self.assertEqual(row["dns_ips"], "93.184.216.34")
        self.assertEqual(row["http_status"], "200")


if __name__ == "__main__":
    unittest.main()
