'''
simple retry policy for http requests for reconoscope

Raises
------
NoAttemptsLeftError
    _raised from previous exception when all attempts are exhausted_
'''

import asyncio
import functools
import random
from collections.abc import Awaitable, Callable
from typing import ParamSpec, TypeVar

import httpcore
import httpx

P = ParamSpec("P")
R = TypeVar("R")


class NoAttemptsLeftError(Exception):
    ...


class retry_policy:

    _HTTPX_ERRORS = (
        ConnectionError,
        asyncio.TimeoutError,
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.NetworkError,
        httpcore.ConnectError,
    )

    def __init__(
        self,
        *,
        attempts: int = 3,
        delay: float = 0.25,
        jitter: float = 0.1,
    ) -> None:
        '''
        Parameters
        ----------
        attempts : int, optional
            The maximum number of attempts, by default 3
        delay : float, optional
            The base delay between attempts, by default 0.25
        jitter : float, optional
            The jitter factor to apply to the delay, by default 0.1
        '''
        self.attempts: int = attempts
        self.delay: float = delay
        self.jitter: float = jitter

    def get_timeout(self, attempt_no: int) -> float:
        base = self.delay * attempt_no

        if self.jitter:
            j = base * self.jitter
            base += random.uniform(-j, j)

        return max(0.0, base)

    async def call_with_retries(
        self,
        func: Callable[P, Awaitable[R]],
        *args,
        **kwargs
    ) -> R:
        last_exc: BaseException | None = None
        for attempt_no in range(1, self.attempts + 1):
            try:
                return await func(*args, **kwargs)
            except self._HTTPX_ERRORS as exc:
                if attempt_no == self.attempts:
                    raise NoAttemptsLeftError(
                        f"Failed after {self.attempts} attempts: {exc}"
                    ) from exc
                last_exc = exc
                await asyncio.sleep(self.get_timeout(attempt_no))
            except Exception:
                raise

        raise NoAttemptsLeftError(
            f"Failed after {self.attempts} attempts: {last_exc}"
        ) from last_exc

    def __call__(
        self,
        func: Callable[P, Awaitable[R]],
        *args,
        **kwargs
    ) -> Callable[P, Awaitable[R]]:

        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return await self.call_with_retries(func, *args, **kwargs)

        return wrapper
