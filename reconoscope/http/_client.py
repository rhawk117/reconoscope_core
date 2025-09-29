import random
import ssl
import socket
import ipaddress
import contextlib
import dataclasses as dc
import logging
from types import MappingProxyType
from typing import Literal

import httpx


logger = logging.getLogger(__name__)


Browsers = Literal['chrome', 'firefox']
Devices = Literal['windows', 'mac', 'linux', 'android', 'ios']

class URLRejectedError(ValueError):
    '''
    Raised when a URL is rejected by the client URL normalizer.

    Parent: ValueError
    '''


def _base_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=15,
    )


def _base_timeouts() -> httpx.Timeout:
    return httpx.Timeout(
        connect=5.0,
        read=5.0,
        write=5.0,
        pool=5.0,
    )


def _default_headers() -> dict[str, str]:
    return {
        'Cache-Control': 'max-age=0',
        'Accept-Language': 'en-US,en;q=0.9',
    }

class UserAgent:
    Spec = MappingProxyType({
        "chrome_windows": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ),
        "chrome_mac": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ),
        "chrome_linux": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ),
        "chrome_android": (
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36"
        ),
        "chrome_ios": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/118.0.0.0 Mobile/15E148 Safari/604.1"
        ),
        "firefox_windows": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
            "Gecko/20100101 Firefox/118.0"
        ),
        "firefox_mac": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) "
            "Gecko/20100101 Firefox/118.0"
        ),
        "firefox_linux": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
            "Gecko/20100101 Firefox/118.0"
        ),
        "firefox_android": (
            "Mozilla/5.0 (Mobile; rv:109.0) Gecko/118.0 Firefox/118.0"
        ),
        "firefox_ios": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 "
            "Mobile/15E148 Safari/605.1.15"
        ),
    })

    @classmethod
    def get_header(
        cls,
        browser: Browsers = 'chrome',
        device: Devices = 'windows'
    ) -> str:
        '''
        Get a User-Agent string for the specified browser and device.

        Parameters
        ----------
        browser : Browsers, optional
            The browser to use, by default 'chrome'
        device : Devices, optional
            The device to use (device may not be the best term),
            by default 'windows'

        Returns
        -------
        str
            _description_
        '''
        key = f"{browser}_{device}"
        return cls.Spec.get(key, cls.Spec[key])

    @classmethod
    def randomize(cls) -> str:
        return random.choice(list(cls.Spec.values()))



def get_socket_options() -> list[tuple]:
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
        with contextlib.suppress(ssl.SSLError):
            set_ciphersuites(":".join(TLS_1_3_CIPHERS))

    ctx.set_ciphers(":".join(TLS_1_2_CIPHERS))

    if hasattr(ctx, "set_ecdh_curve"):
        try:
            ctx.set_ecdh_curve("X25519")
        except ssl.SSLError:
            with contextlib.suppress(ssl.SSLError):
                ctx.set_ecdh_curve("prime256v1")

    return ctx


def host_is_private_literal(host: str) -> bool:
    '''
    Check if the given host is a private, loopback, link-local,

    Parameters
    ----------
    host : str

    Returns
    -------
    bool
    '''
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def normalize_idna_host(host: str) -> str:
    '''
    Normalize a hostname to its IDNA ASCII representation.

    Parameters
    ----------
    host : str

    Returns
    -------
    str
    '''
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def verify_http_url(newurl: str) -> httpx.URL:
    '''
    Verifies and normalizes a URL to ensure it uses HTTPS and has a
    valid host (primarily for when whatsmyusername URL lists)

    Parameters
    ----------
    newurl : str

    Returns
    -------
    httpx.URL

    Raises
    ------
    URLRejectedError
        If the URL scheme is not HTTP/S or if the host is a private/invalid literal.
    '''
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


class ReconoscopeTransport(httpx.AsyncBaseTransport):
    '''
    A custom HTTP transport for httpx that uses a browser-like SSL context
    and custom socket options (for TCP keepalive and performance tuning).
    '''
    def __init__(
        self,
        *,
        http2: bool = True,
        trust_env: bool = False,
        retries: int = 1
    ) -> None:
        self._inner: httpx.AsyncHTTPTransport = httpx.AsyncHTTPTransport(
            http2=http2,
            socket_options=get_socket_options(),
            verify=browser_like_ssl_context(),
            trust_env=trust_env,
            retries=retries
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.url = verify_http_url(str(request.url))
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()

async def user_agent_middleware(request: httpx.Request) -> None:
    request.headers['User-Agent'] = UserAgent.randomize()
    logger.debug(f'Sending request: {request.method} {request.url}')


@dc.dataclass(slots=True)
class ClientConfig:
    '''
    Configuration options for the Reconoscope HTTP client.
    Good defaults are provided for most use cases.
    '''
    timeout: httpx.Timeout = dc.field(default_factory=_base_timeouts)
    limits: httpx.Limits = dc.field(default_factory=_base_limits)
    http2: bool = True
    follow_redirects: bool = True
    trust_env: bool = False
    http2: bool = True
    retries: int = 3
    randomize_user_agent: bool = True




class ReconoscopeClient(httpx.AsyncClient):
    '''
    Thin wrapper around httpx.AsyncClient with
    sensible defaults for Reconoscope use cases
    and custom middleware/hooks.
    '''

    def __init__(
        self,
        base_url: str | None = None,
        *,
        auth: httpx.Auth | None = None,
        headers: dict[str, str] | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        self._config: ClientConfig = config or ClientConfig()

        transport = ReconoscopeTransport(
            http2=self._config.http2,
            trust_env=self._config.trust_env,
            retries=self._config.retries,
        )

        all_headers = _default_headers()
        if headers:
            all_headers.update(headers)

        super().__init__(
            base_url=base_url or '',
            transport=transport,
            auth=auth,
            limits=self._config.limits,
            timeout=self._config.timeout,
            headers=all_headers,
            follow_redirects=self._config.follow_redirects,
        )

        if self._config.randomize_user_agent:
            self.event_hooks['request'] = [user_agent_middleware]
