from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import urlsplit

from rich.console import Console
from rich.table import Table

from . import __version__
from .exporters import export_results
from .validator import MAX_URLS, URLResult, URLValidator

console = Console(markup=False)


class _ArgumentParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        tokens = list(sys.argv[1:] if args is None else args)
        if "--allow-dommain" in tokens:
            self.error("unrecognized argument '--allow-dommain'; did you mean --allow-domain?")
        return super().parse_args(tokens, namespace)

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="valider",
        description=(
            "Technical URL diagnostics for authorized domains. "
            "Does not determine whether profiles or accounts exist. "
            "Pass URLs as positional arguments; --input takes a text-file path."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--allow-domain",
        action="append",
        required=True,
        metavar="DOMAIN",
        help="authorized domain name only (repeatable; includes subdomains)",
    )
    parser.add_argument("urls", nargs="*", help="HTTP/HTTPS URLs to check")
    parser.add_argument("-i", "--input", metavar="FILE", help="UTF-8 text file containing one URL per line")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout from 1 to 30 seconds (default: 10)")
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="maximum redirects per URL (default: 5; maximum: 10)",
    )
    parser.add_argument("--format", choices=("json", "txt", "csv"), help="export format")
    parser.add_argument("-o", "--output", metavar="FILE", help="output file")
    return parser


def _load_urls(arguments: argparse.Namespace) -> list[str]:
    urls = list(arguments.urls)
    if arguments.input:
        input_location = urlsplit(arguments.input)
        if input_location.scheme.lower() in ("http", "https") and input_location.netloc:
            raise ValueError(
                "--input expects a local text-file path, not a URL. "
                "Pass the URL after the options, or save URLs in a file and use --input FILE."
            )
        try:
            lines = Path(arguments.input).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"Cannot read input file {arguments.input!r}: {exc}") from exc
        urls.extend(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    if not urls:
        raise ValueError("No URL provided. Add a URL after the options or use --input FILE.")
    if len(urls) > MAX_URLS:
        raise ValueError(f"Maximum of {MAX_URLS} URLs per run exceeded.")
    return urls


def _render(results: list[URLResult]) -> None:
    table = Table(title="Valider — technical diagnostics")
    for column in ("URL", "Outcome", "HTTP", "Final URL", "DNS", "TLS", "Title"):
        table.add_column(column, overflow="fold")
    for item in results:
        table.add_row(
            item.url,
            item.outcome,
            str(item.http_status) if item.http_status is not None else "N/A",
            item.final_url or "N/A",
            ", ".join(item.dns_ips) or "N/A",
            item.tls_version or "N/A",
            item.title or "N/A",
        )
        if item.error:
            console.print(f"{item.url}: {item.error}", style="yellow", markup=False)
    console.print(table)
    console.print("Profile/account existence: INCONCLUSIVE.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if bool(arguments.format) != bool(arguments.output):
        parser.error("--format and --output must be used together.")
    try:
        validator = URLValidator(
            arguments.allow_domain,
            timeout=arguments.timeout,
            max_redirects=arguments.max_redirects,
        )
        urls = _load_urls(arguments)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    results = [validator.validate(url) for url in urls]
    if arguments.format:
        export_results(results, arguments.output, arguments.format)
    else:
        _render(results)
    return 0 if all(item.outcome == "ok" for item in results) else 1
