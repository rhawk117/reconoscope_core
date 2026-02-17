from __future__ import annotations

import dataclasses as dc
import ipaddress
from ssl import SSLContext
from typing import TYPE_CHECKING, Any, Literal

import httpx

from reconoscope.http.errors import TransportConfigurationError, URLRejectedError
from reconoscope.http.ssl import SSLContextOptions, build_ssl_context

if TYPE_CHECKING:
    from reconoscope.http.sockets import SocketOptions




type CertTypes = str | tuple[str, str] | tuple[str, str, str]
type VerifyTypes = bool | str | SSLContext | None
type HTTPVersionMode = Literal['http1', 'http2', 'both']



@dc.dataclass(slots=True)
class TransportOptions:
    """
    options for constructing an httpx transport without doing interpretive tls.

    - httpx remains the source of truth for `cert=`.
    - ssl options are only used to build/tune a context passed via `verify=SSLContext`
      (or you pass verify yourself and leave ssl_options unset).

    Note
    ----------
    you still can hurt yourself by setting trust_env=True in hostile
    environments, but that's your problem but it's made explicit.
    """

    http: HTTPVersionMode = 'both'
    trust_env: bool = True

    retries: int = 1

    cert: CertTypes | None = None
    uds: str | None = None

    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry: float = 15.0

    local_address: str | None = None

    verify: VerifyTypes = None
    ssl_options: SSLContextOptions | None = None

    socket_options: SocketOptions | None = None

    @property
    def httpx_limits(self) -> httpx.Limits:
        return httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive_connections,
            keepalive_expiry=self.keepalive_expiry,
        )

    def resolve_http_versions(self) -> tuple[bool, bool]:
        if self.http == 'http1':
            return True, False

        if self.http == 'http2':
            return False, True

        return True, True

    def resolve_verify(self) -> VerifyTypes:
        """
        resolve verify in a way that avoids ambiguity.

        - if ssl_options is set, we produce a context and pass it as verify
        - if verify is already provided, ssl_options must be None
        """
        if self.ssl_options is None:
            return self.verify

        if self.verify is not None:
            raise TransportConfigurationError(
                'conflicting tls configuration: ssl_options is set but '
                'verify is also provided. use ssl_options or verify, not both.'
            )

        return build_ssl_context(self.ssl_options)

    def resolved_socket_options(self) -> list[tuple[int, int, int]] | None:
        """
        resolve socket options for httpcore.

        returns
        -------
        list[tuple[int, int, int]] | None
            socket option tuples, or none if not configured.
        """
        if self.socket_options is None:
            return None
        return self.socket_options.to_httpcore_options()

def get_httpx_transport_kwargs(options: TransportOptions) -> dict[str, Any]:
    """
    prodcues the key word arguments for the httpx transport using the options
    """
    http1, http2 = options.resolve_http_versions()
    verify_value = options.resolve_verify()
    socket_option_tuples = options.resolved_socket_options()

    transport_kwargs: dict[str, Any] = {
        'http1': http1,
        'http2': http2,
        'trust_env': options.trust_env,
        'verify': verify_value,
        'cert': options.cert,
        'limits': options.httpx_limits,
        'uds': options.uds,
        'local_address': options.local_address,
        'socket_options': socket_option_tuples,
    }

    return {
        key: value for key, value in transport_kwargs.items() if value is not None
    }

def create_httpx_transport(options: TransportOptions) -> httpx.AsyncHTTPTransport:
    """
    create the inner httpx async transport.
    """
    transport_kwargs: dict[str, Any] = get_httpx_transport_kwargs(options)
    return httpx.AsyncHTTPTransport(**transport_kwargs)

def _default_allowed_schemes() -> set[str]:
    return {'http', 'https'}

def host_is_private_literal(host: str) -> bool:
    """
    Check if the given host is a private, loopback, link-local,

    Returns
    -------
    bool
    """
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
    upgrade_to_https: bool = True
    allowed_schemes: set[str] = dc.field(default_factory=_default_allowed_schemes)
    private_literal_okay: bool = False
    relative_allowed: bool = True

    def _normalize_url(self, url: str) -> httpx.URL:
        """
        normalize url scheme based on policy.
        """
        norm = httpx.URL(url)
        if self.upgrade_to_https and norm.scheme == 'http':
            return norm.copy_with(scheme='https')
        return norm


    def enforce(self, str_url: str) -> httpx.URL:
        url = self._normalize_url(str_url)

        if url.scheme not in self.allowed_schemes:
            raise URLRejectedError(f'Rejected unsupported URL scheme: {url.scheme}')

        if not url.host and not self.relative_allowed:
            raise URLRejectedError('rejected url with no host (relative or malformed url)')


        if not self.private_literal_okay and host_is_private_literal(url.host):
            raise URLRejectedError(f'Rejected private/invalid host: {url.host}')

        return url




class BaseReconoscopeTransport(httpx.BaseTransport): ...



class DefaultAsyncTransport(BaseReconoscopeTransport):
    """
    an ergonomic wrapper around an inner httpx async transport.

    this exists because you want:
    - one place to enforce "no ambiguous config"
    - a stable surface for reconoscope behaviors later (telemetry, stricter url handling, etc.)
    - to avoid forking httpx just to keep your api tidy
    """

    def __init__(self, options: TransportOptions) -> None:
        self.options = options
        self.inner = create_httpx_transport(options)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


class URLSafeAsyncTransport(BaseReconoscopeTransport): ...
