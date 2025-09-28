

import contextlib
import ipaddress
import logging
import socket
import ssl

import httpx

logger = logging.getLogger(__name__)


class URLRejectedError(ValueError):
    ...


def default_socket_options() -> list[tuple]:
    '''
    cross platform socket options for TCP connections

    Returns
    -------
    list[SockOpt]
    '''
    opts = []

    if hasattr(socket, "TCP_NODELAY"):
        opts.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))

    if hasattr(socket, "SO_KEEPALIVE"):
        opts.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))

    if hasattr(socket, "TCP_KEEPIDLE"):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60))

    if hasattr(socket, "TCP_KEEPINTVL"):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10))

    if hasattr(socket, "TCP_KEEPCNT"):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5))

    if hasattr(socket, "TCP_USER_TIMEOUT"):
        opts.append(
            (socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000))  # 30s

    return opts


TLS_1_3_CIPHERS = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]
TLS_1_2_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
]


def browser_like_ssl_context() -> ssl.SSLContext:
    '''
    creates a "browser-like" SSL context for secure HTTP connections
    for the reconoscope http client to allow TLS 1.2 and 1.3 connections
    using modern cipher suites and proper hostname verification.

    - attempts to negotiate http 2 and fallsback http 1.1
    - hostname verification is enabled

    Returns
    -------
    ssl.SSLContext
    '''
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    with contextlib.suppress(NotImplementedError):
        ctx.set_alpn_protocols(["h2", "http/1.1"])

    ctx.options |= ssl.OP_NO_COMPRESSION

    set_ciphersuites = getattr(ctx, "set_ciphersuites", None)
    if callable(set_ciphersuites):
        # for tls 1.3
        with contextlib.suppress(ssl.SSLError):
            set_ciphersuites(":".join(TLS_1_3_CIPHERS))

    # for tls 1.2
    ctx.set_ciphers(":".join(TLS_1_2_CIPHERS))

    if hasattr(ctx, "set_ecdh_curve"):
        try:
            ctx.set_ecdh_curve("X25519")
        except ssl.SSLError:
            with contextlib.suppress(ssl.SSLError):
                ctx.set_ecdh_curve("prime256v1")  

    return ctx


def host_is_private_literal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def normalize_idna_host(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def normalize_client_url(newurl: str) -> httpx.URL:
    url = httpx.URL(newurl)

    if url.scheme == "http":
        url = url.copy_with(scheme="https")

    if url.scheme != "https":
        raise URLRejectedError(f"Rejected unsupported URL scheme: {url.scheme}")

    if not url.host:
        return url

    if host_is_private_literal(url.host):
        raise URLRejectedError(f"Rejected private/invalid host: {url.host}")

    return url.copy_with(host=normalize_idna_host(url.host))


class HttpTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        *,
        http2: bool = True,
        trust_env: bool = False,
        retries: int = 1
    ) -> None:
        self._inner: httpx.AsyncHTTPTransport = httpx.AsyncHTTPTransport(
            http2=http2,
            socket_options=default_socket_options(),
            verify=browser_like_ssl_context(),
            trust_env=trust_env,
            retries=retries
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.url = normalize_client_url(str(request.url))
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
