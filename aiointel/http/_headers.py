from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import ua_generator

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ua_generator.data import T_BROWSERS, T_DEVICES, T_PLATFORMS

    from aiointel.http._types import UAGenOptions, UALibType


@dataclass(slots=True)
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


class BrowserHeaders(httpx.Headers):
    """
    A headers object with browser-like defaults, built on top of class:``httpx.Headers``

    Defaults are modeled loosely after a modern desktop browser for
    typical HTML page navigation. You can customize common fields such
    as *User-Agent, Accept-Language, Origin, and Referer*, and layer
    additional headers on top.

    Example
    -------
    >>> headers = BrowserHeaders(user_agent='MyCustomUA/1.0')
    >>> headers['User-Agent']
    'MyCustomUA/1.0'
    """

    def __init__(
        self,
        *,
        user_agent: str | None = None,
        accept_language: str | None = None,
        origin: str | None = None,
        referer: str | None = None,
        extra: Mapping[str, str] | None = None,
        include_sec_fetch: bool = True,
    ) -> None:
        headers: dict[str, str] = {
            'Accept': (
                'text/html,application/xhtml+xml,application/xml;q=0.9,'
                'image/avif,image/webp,*/*;q=0.8'
            ),
            'Accept-Language': accept_language or 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
        }

        if include_sec_fetch:
            headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
            })

        if origin is not None:
            headers['Origin'] = origin

        if referer is not None:
            headers['Referer'] = referer

        if user_agent is not None:
            headers['User-Agent'] = user_agent

        if extra:
            headers.update(extra)

        super().__init__(headers)

    @classmethod
    def from_user_agent(
        cls,
        user_agent: str,
        *,
        accept_language: str | None = None,
        origin: str | None = None,
        referer: str | None = None,
        extra: Mapping[str, str] | None = None,
        include_sec_fetch: bool = True,
    ) -> BrowserHeaders:
        """
        Convenience constructor when you already have a UA string.
        """
        return cls(
            user_agent=user_agent,
            accept_language=accept_language,
            origin=origin,
            referer=referer,
            extra=extra,
            include_sec_fetch=include_sec_fetch,
        )

    @classmethod
    def minimal(
        cls,
        *,
        user_agent: str | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> BrowserHeaders:
        """
        A more minimal header set suitable for APIs or non-HTML requests.

        This omits Sec-Fetch-* and Upgrade-Insecure-Requests, and uses
        a simpler Accept header.
        """
        headers: dict[str, str] = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }

        if user_agent is not None:
            headers['User-Agent'] = user_agent

        if extra:
            headers.update(extra)

        return cls(
            user_agent=headers.pop('User-Agent', None),
            accept_language=headers.pop('Accept-Language', None),
            extra=headers,
            include_sec_fetch=False,
        )

    def with_overrides(self, **overrides: str) -> BrowserHeaders:
        """
        Return a new BrowserHeaders instance with the given header overrides.

        This is useful when you want to tweak a couple of headers from an
        existing base instance without mutating it.
        """
        base = dict(self.items())
        base.update(overrides)
        return BrowserHeaders(extra=base)
