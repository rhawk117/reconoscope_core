


from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from reconoscope._http import HttpClientPool





class HTTPClient:
    base_url: str = ''
    headers: dict[str, str] = {}

    def __init__(self, pool: 'HttpClientPool') -> None:
        self._client = pool.create_client(
            base_url=self.base_url,
            headers=self.headers,
        )


    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()
