from __future__ import annotations

import dataclasses as dc
import ipaddress
import logging
import random
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import TYPE_CHECKING, Self, TypedDict

import httpx

from aiointel.core.exception import AioIntelError

if TYPE_CHECKING:
    import ssl



logger = logging.getLogger(__name__)


class URLPolicyError(AioIntelError):
    """Base error for URL policy violations."""


type CertTypes = str | tuple[str, str] | tuple[str, str, str]
type SocketOptions = tuple[int, int, int]

RequestHook = Callable[[httpx.Request], Awaitable[None]]
ResponseHook = Callable[[httpx.Response], Awaitable[None]]


class HTTPLimits(TypedDict, total=False):
    """
    User-facing limits config that maps cleanly into httpx.Limits.

    All fields are optional; defaults are applied in-place.
    """
    max_connections: int
    max_keepalive_connections: int
    keepalive_expiry: int


class HTTPTimeouts(TypedDict, total=False):
    """
    User-facing timeouts config that maps cleanly into httpx.Timeout.

    All fields are optional; defaults are applied in-place and all
    default to 10 seconds
    """
    connect: int
    read: int
    write: int
    pool: int


def _set_httpx_defaults(limits: HTTPLimits, timeouts: HTTPTimeouts) -> None:
    """
    In-place defaulting for httpx limits and timeouts.

    Keeps public config simple while ensuring sane defaults when users
    provide partial dictionaries.
    """
    limits.setdefault('keepalive_expiry', 15)
    limits.setdefault('max_connections', 50)
    limits.setdefault('max_keepalive_connections', 20)

    timeouts.setdefault('connect', 10)
    timeouts.setdefault('read', 10)
    timeouts.setdefault('write', 10)
    timeouts.setdefault('pool', 10)


def _default_headers() -> dict[str, str]:
    """
    Default headers for generic HTTP requests.

    User-Agent is intentionally omitted; it is handled by the random
    UA request hook.
    """
    return {
        'Cache-Control': 'max-age=0',
        'Accept-Language': 'en-US,en;q=0.9',
    }


def make_socket_options(*, enable_tcp_keepalive: bool = True) -> list[SocketOptions]:
    """
    Cross-platform socket options for TCP connections.

    Parameters
    ----------
    enable_tcp_keepalive : bool, optional
        Whether to enable TCP keepalive tuning when supported by the platform.

    Returns
    -------
    list[SocketOptions]
        List of (level, optname, value) tuples.
    """
    opts: list[SocketOptions] = []

    if hasattr(socket, 'TCP_NODELAY'):
        opts.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))

    if not enable_tcp_keepalive:
        return opts

    if hasattr(socket, 'SO_KEEPALIVE'):
        opts.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))

    if hasattr(socket, 'TCP_KEEPIDLE'):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60))

    if hasattr(socket, 'TCP_KEEPINTVL'):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10))

    if hasattr(socket, 'TCP_KEEPCNT'):
        opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5))

    return opts


def is_host_private_literal(host: str | None) -> bool:
    """
    Check if the given host string is a private / non-public IP literal.

    Non-IP hostnames or None return False.

    Parameters
    ----------
    host : str | None

    Returns
    -------
    bool
    """
    if host is None:
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


@dc.dataclass(slots=True)
class URLPolicy:
    """
    URL normalization and safety policy for the HTTP client.

    Attributes
    ----------
    force_https : bool
        If True, plain HTTP URLs will be rewritten to HTTPS during normalization.
    reject_private_hosts : bool
        If True, URLs whose host is a private / loopback / link-local IP literal
        will be rejected.
    allow_url_schemes : set[str]
        Additional allowed URL schemes beyond "http" and "https".
    """

    force_https: bool = True
    reject_private_hosts: bool = True
    allow_url_schemes: set[str] = dc.field(default_factory=set)

    def check_url_scheme(self, url_scheme: str) -> bool:
        """
        Returns True if the URL scheme is allowed under this policy.
        """
        scheme = url_scheme.lower()
        if scheme in ('http', 'https'):
            return True
        return scheme in self.allow_url_schemes

    def get_url_error(self, url: str | httpx.URL) -> str | None:
        """
        Validate the URL against this policy.

        Parameters
        ----------
        url : str | httpx.URL

        Returns
        -------
        str | None
            An error message if the URL is rejected, otherwise None.
        """
        if isinstance(url, str):
            url = httpx.URL(url)

        scheme = url.scheme.lower()

        if not self.check_url_scheme(scheme):
            allowed_extra = ', '.join(sorted(self.allow_url_schemes)) or 'none'
            return (
                f'URL scheme {scheme!r} is not allowed. '
                f"Allowed schemes: 'http', 'https', extra: {allowed_extra}"
            )

        if self.reject_private_hosts and is_host_private_literal(url.host):
            return (
                f'URL was rejected because host {url.host!r} is private or non-public'
            )

        return None

    def normalize_url(self, url: httpx.URL) -> httpx.URL:
        """
        Normalize a URL according to this policy.

        Currently this only enforces the force_https behavior.
        """
        if url.scheme == 'http' and self.force_https:
            return url.copy_with(scheme='https')
        return url


class SecureAsyncTransport(httpx.AsyncBaseTransport):
    """
    A custom HTTP transport for httpx that:

    - Enforces a configurable URL policy (schemes, private hosts)
    - Supports custom socket options (TCP_NODELAY, TCP keepalive, etc.)
    - Accepts a ssl.SSLContext / verify flag / cert tuple, and other standard
      httpx.AsyncHTTPTransport options.

    Intended as the low-level transport for higher-level aiointel clients.
    """

    def __init__(
        self,
        *,
        url_policy: URLPolicy | None = None,
        verify: ssl.SSLContext | bool = True,
        cert: CertTypes | None = None,
        trust_env: bool = True,
        http2: bool = True,
        proxy: httpx.URL | str | httpx.Proxy | None = None,
        uds: str | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options: Iterable[SocketOptions] | None = None,
        enable_tcp_keepalive: bool = True,
    ) -> None:
        self.url_policy = url_policy or URLPolicy()

        if socket_options is None:
            socket_options = make_socket_options(
                enable_tcp_keepalive=enable_tcp_keepalive
            )

        self._inner = httpx.AsyncHTTPTransport(
            verify=verify,
            cert=cert,
            trust_env=trust_env,
            http2=http2,
            proxy=proxy,
            uds=uds,
            local_address=local_address,
            retries=retries,
            socket_options=list(socket_options),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Validate and normalize the request URL, then forward to the wrapped transport.
        """
        error = self.url_policy.get_url_error(request.url)
        if error is not None:
            logger.debug('Rejected URL %s: %s', request.url, error)
            raise httpx.RequestError(error, request=request)

        normalized_url = self.url_policy.normalize_url(request.url)
        if normalized_url is not request.url:
            request.url = normalized_url

        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


@dc.dataclass(slots=True)
class ClientConfig:
    """
    Configuration options for the aiointel HTTP client.

    This stays httpx-adjacent: it configures timeouts, limits, TLS,
    connection behavior, and basic headers. Higher-level concerns like
    URL policy and hooks live in AioIntelClient.
    """

    # Core IO config
    timeouts: HTTPTimeouts = dc.field(default_factory=HTTPTimeouts)
    limits: HTTPLimits = dc.field(default_factory=HTTPLimits)

    verify: ssl.SSLContext | bool = True
    cert: CertTypes | None = None
    trust_env: bool = True
    http2: bool = True
    proxy: httpx.URL | str | httpx.Proxy | None = None
    uds: str | None = None
    local_address: str | None = None
    retries: int = 0
    enable_tcp_keepalive: bool = True

    headers: dict[str, str] | None = None
    follow_redirects: bool = True

    def __post_init__(self) -> None:
        _set_httpx_defaults(self.limits, self.timeouts)

        if self.headers is None:
            self.headers = _default_headers()

    def build_limits(self) -> httpx.Limits:
        """
        Build an httpx.Limits instance from this config.
        """
        return httpx.Limits(
            max_connections=self.limits['max_connections'],
            max_keepalive_connections=self.limits['max_keepalive_connections'],
            keepalive_expiry=self.limits['keepalive_expiry'],
        )

    def build_timeout(self) -> httpx.Timeout:
        """
        Build an httpx.Timeout instance from this config.
        """
        return httpx.Timeout(
            connect=self.timeouts['connect'],
            read=self.timeouts['read'],
            write=self.timeouts['write'],
            pool=self.timeouts['pool'],
        )


# A tiny pool of realistic browser UA strings. You can expand this or make it configurable later.
_BROWSER_USER_AGENTS: list[str] = [
    # Chrome (Windows)
    (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/123.0.0.0 Safari/537.36'
    ),
    # Firefox (Windows)
    (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) '
        'Gecko/20100101 Firefox/124.0'
    ),
    # Chrome (macOS)
    (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/123.0.0.0 Safari/537.36'
    ),
    # Safari (macOS)
    (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) '
        'AppleWebKit/605.1.15 (KHTML, like Gecko) '
        'Version/16.4 Safari/605.1.15'
    ),
]


async def _random_user_agent_request_hook(request: httpx.Request) -> None:
    """
    Default on-request hook that randomizes the User-Agent header.

    - Does nothing if a User-Agent is already set.
    - Otherwise chooses a UA string from a small browser UA pool.
    - If the `user_agents` library is installed, the UA string is at least
      parsed (for sanity), but we don't really need the parsed result.
    """
    # Honor an explicit User-Agent from the user.
    for key in request.headers.keys():
        if key.lower() == 'user-agent':
            return

    ua = random.choice(_BROWSER_USER_AGENTS)

    if _parse_ua is not None:
        try:
            _ = _parse_ua(ua)
        except Exception:  # pragma: no cover - extremely unlikely
            logger.debug('Failed to parse UA with user_agents, using raw UA string')

    request.headers['User-Agent'] = ua


class AioIntelClient:
    """
    High-level aiointel HTTP client wrapper.

    Responsibilities:
    - Owns a configured httpx.AsyncClient.
    - Applies URLPolicy via SecureAsyncTransport (unless a custom transport is supplied).
    - Adds a default on-request hook to randomize User-Agent (optional).
    - Allows user-supplied on-request and on-response hooks.

    Notes
    -----
    If a custom transport is provided *and* a URLPolicy is also given,
    URLPolicy cannot be enforced, and a warning will be logged.
    """

    def __init__(
        self,
        *,
        config: ClientConfig | None = None,
        url_policy: URLPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        on_request: RequestHook | None = None,
        on_response: ResponseHook | None = None,
        randomize_user_agent: bool = True,
    ) -> None:
        self._config = config or ClientConfig()

        # Transport selection:
        if transport is not None:
            if url_policy is not None:
                logger.warning(
                    'A custom transport was provided along with a URLPolicy; '
                    'URL safety cannot be enforced through SecureAsyncTransport. '
                    'The custom transport will be used, and url_policy is ignored.'
                )
            self._transport = transport
        else:
            self._transport = SecureAsyncTransport(
                url_policy=url_policy,
                verify=self._config.verify,
                cert=self._config.cert,
                trust_env=self._config.trust_env,
                http2=self._config.http2,
                proxy=self._config.proxy,
                uds=self._config.uds,
                local_address=self._config.local_address,
                retries=self._config.retries,
                enable_tcp_keepalive=self._config.enable_tcp_keepalive,
            )

        # Event hooks
        request_hooks: list[Callable[[httpx.Request], Awaitable[None]]] = []
        response_hooks: list[Callable[[httpx.Response], Awaitable[None]]] = []

        if randomize_user_agent:
            request_hooks.append(_random_user_agent_request_hook)

        if on_request is not None:
            request_hooks.append(on_request)

        if on_response is not None:
            response_hooks.append(on_response)

        event_hooks: dict[str, list[Callable]] = {}
        if request_hooks:
            event_hooks['request'] = request_hooks
        if response_hooks:
            event_hooks['response'] = response_hooks

        self._client = httpx.AsyncClient(
            timeout=self._config.build_timeout(),
            limits=self._config.build_limits(),
            headers=self._config.headers,
            follow_redirects=self._config.follow_redirects,
            transport=self._transport,
            event_hooks=event_hooks or None,
        )

    @property
    def client(self) -> httpx.AsyncClient:
        """Expose the underlying httpx.AsyncClient (read-only)."""
        return self._client

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # Convenience passthrough methods

    async def request(
        self, method: str, url: str | httpx.URL, **kwargs
    ) -> httpx.Response:
        """
        Low-level request interface.

        Parameters
        ----------
        method : str
            HTTP method, e.g. "GET", "POST".
        url : str | httpx.URL
            Target URL.
        kwargs :
            Additional keyword arguments passed to httpx.AsyncClient.request.

        Returns
        -------
        httpx.Response
        """
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: str | httpx.URL, **kwargs) -> httpx.Response:
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str | httpx.URL, **kwargs) -> httpx.Response:
        return await self.request('POST', url, **kwargs)
