from __future__ import annotations

import dataclasses as dc
import ipaddress
import logging
import socket
import warnings
from typing import TYPE_CHECKING, Self

import httpx
import ua_generator

from aiointel.http._types import (
    CertTypes,
    ClientHooks,
    HTTPLimits,
    HTTPTimeouts,
    RequestHook,
    ResponseHook,
    SocketOptions,
    URLPolicy,
)

if TYPE_CHECKING:
    import ssl
    from collections.abc import Awaitable, Callable, Iterable

    from ua_generator.data import T_BROWSERS, T_DEVICES, T_PLATFORMS

    from aiointel.http._types import UAGenOptions, UALibType


logger = logging.getLogger(__name__)




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


def verify_url_scheme(
    url_policy: URLPolicy,
    url_scheme: str
) -> bool:
    scheme = url_scheme.lower()
    if scheme in ('http', 'https'):
        return True
    return scheme in url_policy.allow_url_schemes

def get_url_policy_violation(url: str | httpx.URL, policy: URLPolicy) -> str | None:
    if isinstance(url, str):
        url = httpx.URL(url)

    scheme = url.scheme.lower()

    if not verify_url_scheme(policy, scheme):
        allowed_extra = ', '.join(sorted(policy.allow_url_schemes)) or 'none'
        return (
            f'URL scheme {scheme!r} is not allowed. '
            f"Allowed schemes: 'http', 'https', extra: {allowed_extra}"
        )

    if policy.reject_private_hosts and is_host_private_literal(url.host):
        return (
            f'URL was rejected because host {url.host} is private or non-public'
        )

    return None


@dc.dataclass(slots=True)
class UserAgentRandomizer:
    browser: UALibType[T_BROWSERS] | None = None
    platform: UALibType[T_PLATFORMS] | None = None
    device: UALibType[T_DEVICES] | None = None
    options: UAGenOptions | None = None

    async def __call__(self, request: httpx.Request) -> None:
        header_value = self.generate()
        request.headers.update({'User-Agent': header_value})

    def generate(self) -> str:
        return ua_generator.generate(
            browser=self.browser,
            platform=self.platform,
            device=self.device,
            options=self.options,
        ).text



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
        if violation := get_url_policy_violation(request.url, self.url_policy):
            logger.debug('Rejected URL %s: %s', request.url, violation)
            raise httpx.RequestError(violation, request=request)

        if self.url_policy.force_https and request.url.scheme == 'http':
            request.url = request.url.copy_with(scheme='https')

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

    headers: httpx.Headers |
    follow_redirects: bool = True
    auth: httpx.Auth | None = None
    params: httpx.QueryParams | None = None

    def __post_init__(self) -> None:
        _set_httpx_defaults(self.limits, self.timeouts)

        if self.headers is None:
            self.headers = _default_headers()

    def get_limits(self) -> httpx.Limits:
        return httpx.Limits(**self.limits)

    def get_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(**self.timeouts)


def create_httpx_client(
    *,
    config: ClientConfig | None = None,
    url_policy: URLPolicy | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    hooks: ClientHooks | None = None,
    randomize_user_agent: bool = True,
) -> httpx.AsyncClient:
    if transport is not None and url_policy:
        warnings.warn(
            'A custom transport was provided along with a URLPolicy; '
            'URL safety cannot be enforced automatically with custom transports '
            'and is done via the class:``SecureAsyncTransport`` so urls are rejected '
            'before an HTTP connection is ever established by your operating system.'
            'The custom transport will be used, and url_policy is ignored.',
            category=UserWarning,
            stacklevel=2
        )

    config = config or ClientConfig()
    if transport is None:
        transport = SecureAsyncTransport(
            url_policy=url_policy,
            verify=config.verify,
            cert=config.cert,
            trust_env=config.trust_env,
            http2=config.http2,
            proxy=config.proxy,
            uds=config.uds,
            local_address=config.local_address,
            retries=config.retries,
            enable_tcp_keepalive=config.enable_tcp_keepalive,
        )

    hooks = hooks or ClientHooks()
    if randomize_user_agent:
        hooks.add_request_hook(UserAgentRandomizer())

    return httpx.AsyncClient(
        timeout=config.get_timeout(),
        limits=config.get_limits(),
        auth=config.auth,
        follow_redirects=config.follow_redirects,
        transport=transport,
        event_hooks=hooks.to_events()
    )








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
