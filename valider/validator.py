from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Callable, Iterable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from ._native import DomainPolicy, classify_http_status, is_retryable_http_status

MAX_BODY_BYTES = 1_048_576
MAX_URLS = 1_000
MAX_REDIRECTS = 10
MIN_REQUEST_INTERVAL = 1.0
MAX_TIMEOUT = 30.0
INCONCLUSIVE = "INCONCLUSIVO: existência de perfis não verificada."
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass
class URLResult:
    url: str
    outcome: str
    http_status: Optional[int] = None
    http_status_class: Optional[str] = None
    http_retryable_hint: Optional[bool] = None
    final_url: Optional[str] = None
    redirects: int = 0
    dns_ips: list[str] = field(default_factory=list)
    tls_version: Optional[str] = None
    tls_expires: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    error: Optional[str] = None
    conclusion: str = INCONCLUSIVE

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Response:
    status: int
    headers: dict[str, str]
    body: bytes
    tls_version: Optional[str] = None
    tls_expires: Optional[str] = None


class _PageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: Optional[str] = None
        self.description: Optional[str] = None
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "meta":
            values = {key.lower(): value for key, value in attrs if value is not None}
            if values.get("name", "").lower() == "description":
                self.description = values.get("content", "").strip()[:300]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title:
            self.title = " ".join("".join(self._title_parts).split())[:300]
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def _normalize_domain(domain: str) -> str:
    value = domain.strip()
    if "://" in value or "/" in value:
        raise ValueError(
            f"--allow-domain expects a domain name only, not a URL ({domain!r}). "
            "Pass the URL separately after the options."
        )
    try:
        candidate = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid authorized domain: {domain!r}") from exc
    if not candidate or len(candidate) > 253:
        raise ValueError(f"Invalid authorized domain: {domain!r}")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("The allowlist accepts domain names, not IP addresses.")
    if any(not _DNS_LABEL.fullmatch(label) for label in candidate.split(".")):
        raise ValueError(f"Invalid authorized domain: {domain!r}")
    return candidate


def _parse_url(value: str) -> tuple[str, str, int, str]:
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError("URL vazia ou contendo espaços/caracteres de controle.")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"URL malformada: {exc}") from exc
    if scheme not in ("http", "https") or not parts.netloc or not host:
        raise ValueError("Somente URLs absolutas HTTP ou HTTPS são aceitas.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credenciais embutidas na URL não são aceitas.")
    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Nome de host inválido.") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("URLs com endereço IP literal não são aceitas.")
    if not host or any(not _DNS_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("Nome de host inválido.")
    expected_port = 443 if scheme == "https" else 80
    if port not in (None, expected_port):
        raise ValueError("Somente as portas padrão HTTP (80) e HTTPS (443) são aceitas.")
    path = parts.path or "/"
    clean_url = urlunsplit((scheme, host, path, parts.query, ""))
    return clean_url, host, expected_port, scheme


def _resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise ValueError("O domínio não resolveu para nenhum endereço.")
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, port: int, pinned_ip: str, timeout: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _request_once(url: str, host: str, port: int, scheme: str, pinned_ip: str, timeout: float) -> _Response:
    parts = urlsplit(url)
    target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host, port, pinned_ip, timeout, ssl.create_default_context()
        )
    else:
        connection = _PinnedHTTPConnection(host, port, pinned_ip, timeout)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "User-Agent": "Valider/1.0",
                "Connection": "close",
                "Accept-Encoding": "identity",
            },
        )
        response = connection.getresponse()
        tls_version = None
        tls_expires = None
        if scheme == "https" and connection.sock is not None:
            tls_version = connection.sock.version()
            cert = connection.sock.getpeercert()
            expiry = cert.get("notAfter")
            if expiry:
                tls_expires = parsedate_to_datetime(expiry).isoformat()
        body = response.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
        return _Response(
            status=response.status,
            headers={key.lower(): value for key, value in response.getheaders()},
            body=body,
            tls_version=tls_version,
            tls_expires=tls_expires,
        )
    finally:
        connection.close()


class URLValidator:
    def __init__(
        self,
        allowed_domains: Iterable[str],
        timeout: float = 10.0,
        max_redirects: int = 5,
        resolver: Callable[[str, int], list[str]] = _resolve,
        requester: Callable[[str, str, int, str, str, float], _Response] = _request_once,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        domains = [_normalize_domain(domain) for domain in allowed_domains]
        if not domains:
            raise ValueError("Provide at least one authorized domain.")
        if not 1 <= timeout <= MAX_TIMEOUT:
            raise ValueError("Timeout must be between 1 and 30 seconds.")
        if not 0 <= max_redirects <= MAX_REDIRECTS:
            raise ValueError(f"Redirect limit must be between 0 and {MAX_REDIRECTS}.")
        self.allowed_domains = tuple(dict.fromkeys(domains))
        self.timeout = float(timeout)
        self.max_redirects = max_redirects
        self._policy = DomainPolicy(self.allowed_domains, max_redirects)
        self._resolver = resolver
        self._requester = requester
        self._clock = clock
        self._sleeper = sleeper
        self._last_request_at: Optional[float] = None

    def _wait_for_rate_limit(self) -> None:
        now = self._clock()
        if self._last_request_at is not None:
            remaining = MIN_REQUEST_INTERVAL - (now - self._last_request_at)
            if remaining > 0:
                self._sleeper(remaining)
        self._last_request_at = self._clock()

    def _resolve_public(self, host: str, port: int) -> list[str]:
        addresses = self._resolver(host, port)
        if not addresses:
            raise ValueError("O domínio não resolveu para nenhum endereço.")
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address.split("%", 1)[0])
            except ValueError as exc:
                raise PermissionError("DNS retornou um endereço IP inválido; destino bloqueado.") from exc
            if not parsed.is_global:
                raise PermissionError(f"Destino não global bloqueado: {address}")
        return addresses

    def validate(self, value: str) -> URLResult:
        result = URLResult(url=value, outcome="erro")
        try:
            self._policy.begin()
            current, host, port, scheme = _parse_url(value)
            if not self._policy.is_allowed(host):
                raise PermissionError(f"Domínio fora da allowlist: {host}")
            while True:
                if not self._policy.visit_url(current):
                    raise ValueError("Ciclo de redirecionamento detectado.")
                current, host, port, scheme = _parse_url(current)
                if not self._policy.is_allowed(host):
                    raise PermissionError(f"Redirecionamento fora da allowlist: {host}")
                addresses = self._resolve_public(host, port)
                result.dns_ips = addresses
                self._wait_for_rate_limit()
                response = self._requester(current, host, port, scheme, addresses[0], self.timeout)
                result.http_status = response.status
                result.http_status_class = classify_http_status(response.status)
                result.http_retryable_hint = is_retryable_http_status(response.status)
                result.final_url = current
                result.tls_version = response.tls_version or result.tls_version
                result.tls_expires = response.tls_expires or result.tls_expires
                location = response.headers.get("location")
                if response.status not in (301, 302, 303, 307, 308) or not location:
                    self._parse_metadata(result, response)
                    result.outcome = "ok"
                    return result
                if not self._policy.follow_redirect():
                    raise ValueError("Limite de redirecionamentos excedido.")
                next_url = urljoin(current, location)
                parsed_next, next_host, _, _ = _parse_url(next_url)
                if not self._policy.is_allowed(next_host):
                    raise PermissionError(f"Redirecionamento fora da allowlist: {next_host}")
                current = parsed_next
                result.redirects += 1
        except PermissionError as exc:
            result.outcome = "bloqueado"
            result.error = str(exc)
        except (ValueError, UnicodeError) as exc:
            result.outcome = "erro"
            result.error = str(exc)
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            result.outcome = "erro"
            result.error = f"Falha de rede: {exc}"
        return result

    @staticmethod
    def _parse_metadata(result: URLResult, response: _Response) -> None:
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type and not response.body.lstrip().lower().startswith(
            (b"<!doctype html", b"<html")
        ):
            return
        parser = _PageMetadataParser()
        try:
            parser.feed(response.body.decode("utf-8", errors="replace"))
        except (ValueError, AssertionError):
            return
        result.title = parser.title
        result.description = parser.description
