
import dataclasses as dc
from contextlib import asynccontextmanager

import httpx

from reconoscope.http.transport import HttpTransport


def _base_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=15,
    )


def _base_timeouts() -> httpx.Timeout:
    return httpx.Timeout(
        connect=5.0,
        read=10.0,
        write=10.0,
        pool=5.0,
    )


@dc.dataclass(slots=True)
class HttpOptions:
    timeout: httpx.Timeout = dc.field(default_factory=_base_timeouts)
    limits: httpx.Limits = dc.field(default_factory=_base_limits)
    http2: bool = True
    follow_redirects: bool = True
    trust_env: bool = False
    http2: bool = True
    retries: int = 3


class HttpClientPool:
    __slots__ = (
        '_transport',
        '_options',
        '_headers',
    )

    def __init__(self, options: HttpOptions | None = None) -> None:
        self._options: HttpOptions = options or HttpOptions()
        self._transport = HttpTransport(
            http2=self._options.http2,
            trust_env=self._options.trust_env,
        )
        self._headers = {
            'Cache-Control': 'max-age=0',
            'Accept-Language': 'en-US,en;q=0.9',
        }

    def create_client(
        self,
        base_url: str = '',
        headers: dict[str, str] | None = None
    ) -> httpx.AsyncClient:
        all_headers = self._headers.copy()
        if headers:
            all_headers.update(headers)

        return httpx.AsyncClient(
            base_url=base_url,
            transport=self._transport,
            limits=self._options.limits,
            timeout=self._options.timeout,
            headers=all_headers,
        )

    @asynccontextmanager
    async def client(
        self,
        base_url: str = '',
        headers: dict[str, str] | None = None,
    ):
        all_headers = self._headers.copy()
        if headers:
            all_headers.update(headers)

        async with self.create_client(base_url, headers) as client:
            yield client

    async def aclose(self) -> None:
        await self._transport.aclose()
