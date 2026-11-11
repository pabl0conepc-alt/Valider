from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.table import Table

from . import __version__
from .exporters import export_results
from .validator import MAX_URLS, URLResult, URLValidator

console = Console(markup=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="valider",
        description=(
            "Diagnóstico técnico de URLs em domínios autorizados. "
            "Não determina a existência de perfis ou contas."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--allow-domain",
        action="append",
        required=True,
        metavar="DOMINIO",
        help="domínio autorizado (pode ser repetido; inclui subdomínios)",
    )
    parser.add_argument("urls", nargs="*", help="URLs HTTP/HTTPS para verificar")
    parser.add_argument("-i", "--input", help="arquivo UTF-8 com uma URL por linha")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout de 1 a 30 segundos (padrão: 10)")
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="máximo de redirecionamentos por URL (padrão: 5; máximo: 10)",
    )
    parser.add_argument("--format", choices=("json", "txt", "csv"), help="formato de exportação")
    parser.add_argument("-o", "--output", help="caminho do arquivo de exportação")
    return parser


def _load_urls(arguments: argparse.Namespace) -> list[str]:
    urls = list(arguments.urls)
    if arguments.input:
        try:
            lines = Path(arguments.input).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"Não foi possível ler o arquivo de entrada: {exc}") from exc
        urls.extend(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    if not urls:
        raise ValueError("Informe ao menos uma URL ou use --input.")
    if len(urls) > MAX_URLS:
        raise ValueError(f"Limite de {MAX_URLS} URLs por execução excedido.")
    return urls


def _render(results: list[URLResult]) -> None:
    table = Table(title="Valider — diagnóstico técnico")
    for column in ("URL", "Estado", "HTTP", "URL final", "DNS", "TLS", "Título"):
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
    console.print("Conclusão sobre existência de perfis/contas: INCONCLUSIVO.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if bool(arguments.format) != bool(arguments.output):
        parser.error("--format e --output devem ser usados juntos.")
    try:
        urls = _load_urls(arguments)
        validator = URLValidator(
            arguments.allow_domain,
            timeout=arguments.timeout,
            max_redirects=arguments.max_redirects,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    results = [validator.validate(url) for url in urls]
    if arguments.format:
        export_results(results, arguments.output, arguments.format)
    else:
        _render(results)
    return 0 if all(item.outcome == "ok" for item in results) else 1
