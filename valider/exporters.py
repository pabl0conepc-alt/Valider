import csv
import json
from pathlib import Path
from typing import Iterable

from .validator import URLResult

_FIELDS = [
    "url",
    "outcome",
    "http_status",
    "http_status_class",
    "http_retryable_hint",
    "final_url",
    "redirects",
    "dns_ips",
    "tls_version",
    "tls_expires",
    "title",
    "description",
    "error",
    "conclusion",
]


def export_results(results: Iterable[URLResult], output: str, fmt: str) -> None:
    rows = [result.to_dict() for result in results]
    destination = Path(output)
    if fmt == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2) + "\n"
        destination.write_text(content, encoding="utf-8")
    elif fmt == "txt":
        lines = []
        for row in rows:
            lines.extend(
                [
                    f"URL: {row['url']}",
                    f"Estado técnico: {row['outcome']}",
                    f"HTTP: {row['http_status'] if row['http_status'] is not None else 'N/A'}",
                    f"HTTP class: {row['http_status_class'] or 'N/A'}",
                    f"Retryability hint: {row['http_retryable_hint']}",
                    f"URL final: {row['final_url'] or 'N/A'}",
                    f"Redirecionamentos: {row['redirects']}",
                    f"DNS: {', '.join(row['dns_ips']) or 'N/A'}",
                    f"TLS: {row['tls_version'] or 'N/A'}",
                    f"Expiração TLS: {row['tls_expires'] or 'N/A'}",
                    f"Título: {row['title'] or 'N/A'}",
                    f"Descrição: {row['description'] or 'N/A'}",
                    f"Erro: {row['error'] or 'N/A'}",
                    f"Conclusão: {row['conclusion']}",
                    "",
                ]
            )
        destination.write_text("\n".join(lines), encoding="utf-8")
    elif fmt == "csv":
        with destination.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=_FIELDS)
            writer.writeheader()
            for row in rows:
                row["dns_ips"] = ";".join(row["dns_ips"])
                writer.writerow(row)
    else:
        raise ValueError(f"Formato de exportação inválido: {fmt}")
