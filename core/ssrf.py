"""URL normalization and strict SSRF protection utilities.

Enforces:
- Allowed schemes strictly limited to ``http`` and ``https``.
- Safe RFC 3986 URL normalization (lowercased scheme/host, IDNA, dot-segment
  resolution, default port removal, fragment removal, credential rejection).
- DNS resolution validation ensuring EVERY resolved IP address is globally
  routable (blocking loopback, private ranges, link-local / AWS metadata
  ``169.254.169.254``, CGNAT, multicast, reserved, unspecified, and obfuscated
  numeric IP literals).

This module has zero dependency on ``apify``.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

# Resolver signature matching socket.getaddrinfo(host, port, type=...) or simplified mocks.
# Each entry in the returned sequence may be a standard 5-tuple from socket.getaddrinfo
# ``(family, type, proto, canonname, sockaddr)`` where ``sockaddr[0]`` is the IP string,
# OR a plain IP address string (for concise unit-test mocks).
AddrInfoItem = tuple[Any, Any, Any, Any, tuple[Any, ...]] | str
SyncResolver = Callable[[str, int], Sequence[AddrInfoItem]]
AsyncResolver = Callable[[str, int], Awaitable[Sequence[AddrInfoItem]]]
Resolver = SyncResolver | AsyncResolver

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$")
_BARE_PORT_RE = re.compile(r"^\d{1,5}(?:[/?#].*)?$")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")

_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


class SSRFBlockedError(ValueError):
    """Raised when a URL is rejected by SSRF or URL-safety checks."""


class DNSResolutionError(OSError):
    """Raised when DNS resolution fails for an otherwise valid hostname."""


class ValidatedTarget(BaseModel):
    """Result of normalizing and SSRF-validating a target URL."""

    model_config = ConfigDict(frozen=True)

    normalized_url: str
    scheme: Literal["http", "https"]
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


def is_ip_globally_routable(ip_str: str) -> bool:
    """Return True iff *ip_str* represents a globally routable unicast IP."""
    cleaned = ip_str.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]

    # Reject scoped / zone-ID IPv6 addresses (e.g. fe80::1%eth0)
    if not cleaned or "%" in cleaned:
        return False

    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address):
        # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 vs ::ffff:8.8.8.8)
        if addr.ipv4_mapped is not None:
            return _is_plain_global_unicast(addr.ipv4_mapped)

        # Reject NAT64 translation prefixes that can embed arbitrary IPv4 targets
        if addr in _NAT64_WELL_KNOWN or addr in _NAT64_LOCAL_USE:
            return False

        # Belt-and-suspenders check for 6to4 / Teredo transition addresses
        if addr.sixtofour is not None and not _is_plain_global_unicast(addr.sixtofour):
            return False
        if addr.teredo is not None:
            server_ip, client_ip = addr.teredo
            if not (
                _is_plain_global_unicast(server_ip)
                and _is_plain_global_unicast(client_ip)
            ):
                return False

    return _is_plain_global_unicast(addr)


def _is_plain_global_unicast(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return bool(
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def _parse_int_part(part: str) -> int | None:
    """Parse a BSD inet_aton integer component (decimal, 0x hex, or 0 octal)."""
    if not part:
        return None
    lower = part.lower()
    try:
        if lower.startswith("0x"):
            if len(lower) <= 2 or not all(c in "0123456789abcdef" for c in lower[2:]):
                return None
            return int(lower, 16)
        if len(lower) > 1 and lower.startswith("0"):
            if not all(c in "01234567" for c in lower):
                return None
            return int(lower, 8)
        if not lower.isdigit():
            return None
        return int(lower, 10)
    except ValueError:
        return None


def _try_parse_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse standard IPv4/IPv6 literals as well as obfuscated BSD IPv4 forms.

    Handles forms such as ``127.1``, ``2130706433``, ``0x7f000001``, and
    ``0177.0.0.1`` so they cannot bypass literal IP filtering.
    """
    cleaned = hostname.strip()
    if not cleaned:
        return None

    # Standard IPv4 / IPv6
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass

    # Obfuscated BSD inet_aton IPv4 forms (1 to 4 dot-separated numeric parts)
    parts = cleaned.split(".")
    if 1 <= len(parts) <= 4:
        parsed_parts = [_parse_int_part(p) for p in parts]
        if all(v is not None for v in parsed_parts):
            nums = [v for v in parsed_parts if v is not None]
            if len(nums) == 1 and 0 <= nums[0] <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(nums[0])
            if len(nums) == 2 and nums[0] <= 0xFF and nums[1] <= 0xFFFFFF:
                return ipaddress.IPv4Address((nums[0] << 24) | nums[1])
            if len(nums) == 3 and nums[0] <= 0xFF and nums[1] <= 0xFF and nums[2] <= 0xFFFF:
                return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | nums[2])
            if len(nums) == 4 and all(0 <= n <= 0xFF for n in nums):
                return ipaddress.IPv4Address(
                    (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
                )

    return None


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.`` and ``..`` segments according to RFC 3986 Section 5.2.4."""
    if not path:
        return "/"

    input_buf = path
    output: list[str] = []

    while input_buf:
        if input_buf.startswith("../"):
            input_buf = input_buf[3:]
        elif input_buf.startswith("./"):
            input_buf = input_buf[2:]
        elif input_buf.startswith("/./"):
            input_buf = "/" + input_buf[3:]
        elif input_buf == "/.":
            input_buf = "/"
        elif input_buf.startswith("/../"):
            input_buf = "/" + input_buf[4:]
            if output:
                output.pop()
        elif input_buf == "/..":
            input_buf = "/"
            if output:
                output.pop()
        elif input_buf in (".", ".."):
            input_buf = ""
        else:
            if input_buf.startswith("/"):
                next_slash = input_buf.find("/", 1)
            else:
                next_slash = input_buf.find("/")
            if next_slash == -1:
                output.append(input_buf)
                input_buf = ""
            else:
                output.append(input_buf[:next_slash])
                input_buf = input_buf[next_slash:]

    normalized = "".join(output)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _prepare_candidate_url(raw_url: str, *, allow_bare_host: bool) -> str:
    candidate = raw_url.strip()
    if not candidate:
        raise SSRFBlockedError("URL must not be empty.")

    if _CONTROL_OR_SPACE_RE.search(candidate):
        raise SSRFBlockedError("URL contains whitespace or control characters.")

    if candidate.startswith("//"):
        raise SSRFBlockedError("Scheme-relative URLs are not allowed.")

    match = _SCHEME_RE.match(candidate)
    if match:
        scheme_candidate = match.group(1).lower()
        remainder = match.group(2)
        if remainder.startswith("//"):
            if scheme_candidate not in _ALLOWED_SCHEMES:
                raise SSRFBlockedError(
                    f"Disallowed URL scheme '{scheme_candidate}'. Only http/https are allowed."
                )
            return candidate

        # Distinguish bare host:port (e.g. "example.com:8443/path") from
        # non-hierarchical schemes (e.g. "javascript:alert(1)", "file:/etc/passwd").
        if (
            allow_bare_host
            and scheme_candidate not in _ALLOWED_SCHEMES
            and ("." in scheme_candidate or scheme_candidate == "localhost")
            and _BARE_PORT_RE.match(remainder)
        ):
            return f"https://{candidate}"

        raise SSRFBlockedError(
            f"Disallowed or malformed URL scheme '{scheme_candidate}'."
        )

    if not allow_bare_host:
        raise SSRFBlockedError("URL must include an explicit http:// or https:// scheme.")

    return f"https://{candidate}"


def normalize_url(raw_url: str, *, allow_bare_host: bool = False) -> str:
    """Normalize and structurally validate an HTTP(S) URL.

    When *allow_bare_host* is ``True`` (intended for user ``startUrls`` input),
    bare hostnames like ``example.com`` are automatically prefixed with
    ``https://`` while explicit non-HTTP(S) schemes remain blocked.
    """
    if not isinstance(raw_url, str):
        raise SSRFBlockedError("URL must be a string.")

    candidate = _prepare_candidate_url(raw_url, allow_bare_host=allow_bare_host)

    # Guard against backslash authority confusion (e.g. https://good.com\@127.0.0.1)
    scheme_sep = candidate.find("://")
    after_scheme = candidate[scheme_sep + 3 :]
    authority_end = len(after_scheme)
    for sep in ("/", "?", "#"):
        idx = after_scheme.find(sep)
        if idx != -1 and idx < authority_end:
            authority_end = idx
    raw_authority = after_scheme[:authority_end]
    if "\\" in raw_authority:
        raise SSRFBlockedError("Backslash is not allowed in URL authority.")

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Disallowed URL scheme '{scheme}'.")

    if parsed.username is not None or parsed.password is not None:
        raise SSRFBlockedError("Credentials (userinfo) in URL are not allowed.")

    raw_host = parsed.hostname
    if not raw_host:
        raise SSRFBlockedError("URL must include a valid hostname.")

    # Reject IPv6 zone identifiers inside host brackets
    if "%" in raw_host:
        raise SSRFBlockedError("Scoped IPv6 zone identifiers are not allowed.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise SSRFBlockedError(f"Invalid port in URL: {exc}") from exc

    if port is not None and not (1 <= port <= 65535):
        raise SSRFBlockedError(f"Port {port} is out of valid range (1-65535).")

    # Normalize hostname (strip FQDN trailing dot, lowercase, IDNA punycode)
    host_clean = raw_host.rstrip(".").lower()
    if not host_clean:
        raise SSRFBlockedError("URL hostname is empty.")

    ip_literal = _try_parse_ip_literal(host_clean)
    if ip_literal is not None:
        canonical_host = str(ip_literal)
        netloc_host = f"[{canonical_host}]" if isinstance(ip_literal, ipaddress.IPv6Address) else canonical_host
    else:
        try:
            canonical_host = host_clean.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise SSRFBlockedError(f"Invalid internationalized hostname: {exc}") from exc
        if not canonical_host or ".." in canonical_host:
            raise SSRFBlockedError("URL hostname contains invalid empty labels.")
        netloc_host = canonical_host

    default_port = _DEFAULT_PORTS[scheme]
    if port is not None and port != default_port:
        netloc = f"{netloc_host}:{port}"
    else:
        netloc = netloc_host

    normalized_path = _remove_dot_segments(parsed.path)
    query = parsed.query

    return urlunsplit((scheme, netloc, normalized_path, query, ""))


def extract_host(url: str) -> str:
    """Return the normalized lowercase hostname from an HTTP(S) URL."""
    normalized = normalize_url(url)
    host = urlsplit(normalized).hostname
    if not host:
        raise SSRFBlockedError("URL has no hostname.")
    return host.lower()


def is_same_host(url_a: str, url_b: str) -> bool:
    """Return True if two HTTP(S) URLs share the exact same normalized host."""
    return extract_host(url_a) == extract_host(url_b)


def _check_blocked_hostname(hostname: str) -> None:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise SSRFBlockedError(f"Blocked loopback hostname '{hostname}'.")


def _extract_ips_from_addrinfo(
    hostname: str, addrinfo: Sequence[AddrInfoItem]
) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for entry in addrinfo:
        if isinstance(entry, str):
            ip_str = entry
        else:
            sockaddr = entry[4]
            ip_str = str(sockaddr[0])
        seen.setdefault(ip_str, None)

    ips = tuple(seen.keys())
    if not ips:
        raise SSRFBlockedError(f"DNS resolution returned no IP addresses for '{hostname}'.")

    for ip_str in ips:
        if not is_ip_globally_routable(ip_str):
            raise SSRFBlockedError(
                f"Blocked non-global IP '{ip_str}' resolved for host '{hostname}'."
            )

    return ips


def _prepare_target_parts(
    url: str, *, allow_bare_host: bool
) -> tuple[str, Literal["http", "https"], str, int]:
    normalized = normalize_url(url, allow_bare_host=allow_bare_host)
    parsed = urlsplit(normalized)
    scheme: Literal["http", "https"] = "https" if parsed.scheme == "https" else "http"
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL must include a valid hostname.")
    port = parsed.port or _DEFAULT_PORTS[scheme]
    _check_blocked_hostname(hostname)
    return normalized, scheme, hostname, port


def validate_url(
    url: str,
    *,
    allow_bare_host: bool = False,
    resolver: SyncResolver | None = None,
) -> ValidatedTarget:
    """Synchronously normalize and SSRF-validate *url* including DNS resolution.

    Every IP returned by DNS must pass :func:`is_ip_globally_routable`.
    """
    normalized, scheme, hostname, port = _prepare_target_parts(
        url, allow_bare_host=allow_bare_host
    )

    ip_literal = _try_parse_ip_literal(hostname)
    if ip_literal is not None:
        ip_str = str(ip_literal)
        if not is_ip_globally_routable(ip_str):
            raise SSRFBlockedError(f"Blocked non-global IP literal '{ip_str}'.")
        return ValidatedTarget(
            normalized_url=normalized,
            scheme=scheme,
            hostname=ip_str,
            port=port,
            resolved_ips=(ip_str,),
        )

    try:
        if resolver is not None:
            addrinfo = resolver(hostname, port)
        else:
            addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DNSResolutionError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    ips = _extract_ips_from_addrinfo(hostname, addrinfo)
    return ValidatedTarget(
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=ips,
    )


async def validate_url_async(
    url: str,
    *,
    allow_bare_host: bool = False,
    resolver: Resolver | None = None,
) -> ValidatedTarget:
    """Asynchronously normalize and SSRF-validate *url* including DNS resolution.

    Supports both async resolvers and synchronous mock resolvers for testing.
    """
    normalized, scheme, hostname, port = _prepare_target_parts(
        url, allow_bare_host=allow_bare_host
    )

    ip_literal = _try_parse_ip_literal(hostname)
    if ip_literal is not None:
        ip_str = str(ip_literal)
        if not is_ip_globally_routable(ip_str):
            raise SSRFBlockedError(f"Blocked non-global IP literal '{ip_str}'.")
        return ValidatedTarget(
            normalized_url=normalized,
            scheme=scheme,
            hostname=ip_str,
            port=port,
            resolved_ips=(ip_str,),
        )

    try:
        if resolver is not None:
            result = resolver(hostname, port)
            addrinfo = await result if inspect.isawaitable(result) else result
        else:
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DNSResolutionError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    ips = _extract_ips_from_addrinfo(hostname, addrinfo)
    return ValidatedTarget(
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=ips,
    )
