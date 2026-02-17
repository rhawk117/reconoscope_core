from collections.abc import Sequence
import contextlib
import dataclasses as dc
import ipaddress
import logging
import random
import socket
import ssl
from types import MappingProxyType
from typing import Literal, NamedTuple, Self
from reconoscope.http import constants
import httpx

logger = logging.getLogger(__name__)


Browsers = Literal['chrome', 'firefox']
Devices = Literal['windows', 'mac', 'linux', 'android', 'ios']


class URLRejectedError(ValueError):
    """
    Raised when a URL is rejected by the client URL normalizer.

    Parent: ValueError
    """


def _base_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=15,
    )


def _base_timeouts() -> httpx.Timeout:
    return httpx.Timeout(
        connect=constants.DEFAULT_TIMEOUT,
        read=constants.DEFAULT_TIMEOUT,
        write=constants.DEFAULT_TIMEOUT,
        pool=constants.DEFAULT_TIMEOUT,
    )


def _default_headers() -> dict[str, str]:
    return {
        'Cache-Control': 'max-age=0',
        'Accept-Language': 'en-US,en;q=0.9',
    }


class UserAgent:
    Spec =

    @classmethod
    def get_header(cls, browser: Browsers = 'chrome', device: Devices = 'windows') -> str:
        """
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
        """
        key = f'{browser}_{device}'
        return cls.Spec.get(key, cls.Spec[key])

    @classmethod
    def randomize(cls) -> str:
        return random.choice(list(cls.Spec.values()))


def get_socket_options() -> list[tuple]:
    opts = []

    if hasattr(socket, 'TCP_NODELAY'):
        opts.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))

    if hasattr(socket, 'SO_KEEPALIVE'):
        opts.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))

    if hasattr(socket, 'TCP_KEEPIDLE'):
        opts.append(constants.MAGIC_TCP_KEEPIDLE)

    if hasattr(socket, 'TCP_KEEPINTVL'):
        opts.append(constants.MAGIC_TCP_KEEPINTVL)

    if hasattr(socket, 'TCP_KEEPCNT'):
        opts.append(constants.MAGIC_TCP_KEEPCNT)

    return opts


class TLSCipherSuite(NamedTuple):
    v1_3_ciphers: tuple[str, ...]
    v1_2_ciphers: tuple[str, ...]

    @classmethod
    def default(cls) -> Self:
        return cls(
            v1_3_ciphers=(
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
            ),
            v1_2_ciphers=(
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
            )
        )
@dc.dataclass(slots=True)
class SSLContextOptions:
    tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    tls_max_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED
    check_hostname: bool = True
    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    tls_ciphers: TLSCipherSuite = dc.field(default_factory=TLSCipherSuite.default)
    ecdh_curve: str = 'X25519'
    options: Sequence[ssl.Options] | None = None




def browser_like_ssl_context() -> ssl.SSLContext:
    """
    creates a "browser-like" SSL context for secure HTTP connections
    for the reconoscope http client to allow TLS 1.2 and 1.3 connections
    using modern cipher suites and proper hostname verification.

    - attempts to negotiate http 2 and fallsback http 1.1
    - hostname verification is enabled

    Returns
    -------
    ssl.SSLContext
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    with contextlib.suppress(NotImplementedError):
        ctx.set_alpn_protocols(['h2', 'http/1.1'])

    ctx.options |= ssl.OP_NO_COMPRESSION

    set_ciphersuites = getattr(ctx, 'set_ciphersuites', None)
    if callable(set_ciphersuites):
        with contextlib.suppress(ssl.SSLError):
            set_ciphersuites(':'.join(constants.TLS_1_3_CIPHERS))

    ctx.set_ciphers(':'.join(constants.TLS_1_2_CIPHERS))

    if hasattr(ctx, 'set_ecdh_curve'):
        try:
            ctx.set_ecdh_curve('X25519')
        except ssl.SSLError:
            with contextlib.suppress(ssl.SSLError):
                ctx.set_ecdh_curve('prime256v1')

    return ctx





def normalize_idna_host(host: str) -> str:
    """
    Normalize a hostname to its IDNA ASCII representation.


    Returns
    -------
    str
    """
    try:
        return host.encode('idna').decode('ascii')
    except UnicodeError:
        return host




def verify_http_url(newurl: str) -> httpx.URL:
    """
    Verifies and normalizes a URL to ensure it uses HTTPS and has a
    valid host (primarily for when whatsmyusername URL lists)


    Raises
    ------
    URLRejectedError
        If the URL scheme is not HTTP/S or if the host is a private/invalid literal.
    """
    url = httpx.URL(newurl)

    if url.scheme == 'http':
        url = url.copy_with(scheme='https')

    if url.scheme != 'https':
        raise URLRejectedError(f'Rejected unsupported URL scheme: {url.scheme}')

    if not url.host:
        return url

    if host_is_private_literal(url.host):
        raise URLRejectedError(f'Rejected private/invalid host: {url.host}')

    return url





async def user_agent_middleware(request: httpx.Request) -> None:
    request.headers['User-Agent'] = UserAgent.randomize()
    logger.debug(f'Sending request: {request.method} {request.url}')


@dc.dataclass(slots=True)
class ClientOptions:
    """
    Configuration options for the Reconoscope HTTP client.
    Good defaults are provided for most use cases.
    """

    http2: bool = True
    follow_redirects: bool = True
    trust_env: bool = False
    retries: int = 3
    randomize_user_agent: bool = True
    max_connections: int = 100
    max_keepalive_connections: int  =20
    keepalive_expiry: int = 15
    connect_timeout: int = 5
    read_timeout: int = 5
    write_timeout: int = 5
    pool_timeout: int = 5
    auth: httpx.Auth | None = None
    headers: httpx.Headers | dict[str, str] = dc.field(default_factory=_default_headers)

    @property
    def httpx_timeouts(self) -> httpx.Timeout:
        return httpx.Timeout(
            read=self.read_timeout,
            write=self.write_timeout,
            connect=self.connect_timeout,
            pool=self.pool_timeout
        )

    @property
    def httpx_limits(self) -> httpx.Limits:
        return httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive_connections,
            keepalive_expiry=self.keepalive_expiry,
        )





class ReconoscopeClient(httpx.AsyncClient):
    """
    Thin wrapper around httpx.AsyncClient with
    sensible defaults for Reconoscope use cases
    and custom middleware/hooks.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        config: ClientOptions | None = None,
    ) -> None:
        self._config: ClientOptions = config or ClientOptions()

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
