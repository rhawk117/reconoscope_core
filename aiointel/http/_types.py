from __future__ import annotations

import typing
from collections.abc import Awaitable, Callable

import httpx
import msgspec
from ua_generator.data.version import VersionRange
from ua_generator.options import Options


@typing.runtime_checkable
class ClientMiddleware(typing.Protocol):

    async def on_request(self, request: httpx.Request) -> None: ...

    async def on_response(self, request: httpx.Response) -> None: ...



CertTypes = str | tuple[str, str] | tuple[str, str, str]
SocketOptions = tuple[int, int, int]

RequestHook = Callable[[httpx.Request], Awaitable[None]]
ResponseHook = Callable[[httpx.Response], Awaitable[None]]

# for users so they don't need to know the
# inner workings for a internal package
UAGenVersionRange = VersionRange
UAGenOptions = Options


type UALibType[T] = T | tuple | list


class HTTPLimits(typing.TypedDict, total=False):
    """
    User-facing limits config that maps cleanly into httpx.Limits.

    All fields are optional; defaults are applied in-place.
    """
    max_connections: int
    max_keepalive_connections: int
    keepalive_expiry: int


class HTTPTimeouts(typing.TypedDict, total=False):
    """
    User-facing timeouts config that maps cleanly into httpx.Timeout.

    All fields are optional; defaults are applied in-place and all
    default to 10 seconds
    """
    connect: int
    read: int
    write: int
    pool: int

class URLPolicy(msgspec.Struct):
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
    allow_url_schemes: set[str] = msgspec.field(default_factory=set)


class ClientHooks(msgspec.Struct):
    """
    A convience object for creating and adding middleware,
    and to fully support implementations of class:``ClientMiddleware``
    """
    _on_request: list[RequestHook] = msgspec.field(default_factory=list)
    _on_response: list[ResponseHook] = msgspec.field(default_factory=list)

    def add_request_hook(self, *hooks: RequestHook) -> None:
        self._on_request.append(*hooks)

    def add_response_hooks(self, *hooks: ResponseHook) -> None:
        self._on_response.append(*hooks)

    def mount_middleware(self, middleware: ClientMiddleware) -> None:
        self._on_request.append(middleware.on_request)
        self._on_response.append(middleware.on_response)

    def add_middleware(self, *middlewares: ClientMiddleware) -> None:
        for mw in middlewares:
            self.mount_middleware(mw)

    def to_events(self) -> dict:
        return {
            'request': self._on_request.copy(),
            'response': self._on_response.copy()
        }
