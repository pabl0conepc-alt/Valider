import csv
import json
import tempfile
import unittest
from pathlib import Path

from valider.exporters import export_results
from valider.validator import URLResult, URLValidator, _Response


PUBLIC_IP = "93.184.216.34"


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
        self.assertEqual(result.title, "Service status")
        self.assertIn("INCONCLUSIVO", result.conclusion)


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
