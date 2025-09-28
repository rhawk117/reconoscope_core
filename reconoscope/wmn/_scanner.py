import asyncio
import json
import logging
from typing import NamedTuple, Self

import httpx
import os
from reconoscope import http
from reconoscope.wmn._collection import (
    WMNCollection,
    WMNRuleSet,
    create_wmn_collection,
    load_wmn_json_schema,
    fetch_wmn_collection
)
from reconoscope.wmn._schema import WhatsMyNameSite, WMNMethods
from concurrent.futures import ProcessPoolExecutor
import dataclasses as dc

logger = logging.getLogger(__name__)


@dc.dataclass(slots=True)
class WMNRequest:
    '''
    A request to send built from a WhatsMyNameSite and account name.
    '''
    method: WMNMethods
    url: str
    headers: dict[str, str] = dc.field(default_factory=dict)
    json_payload: dict | None = None
    content_bytes: bytes | None = None

    def get_http_stream(self, client: httpx.AsyncClient):
        '''
        Creates a httpx request stream using the instance

        Parameters
        ----------
        client : httpx.AsyncClient

        Returns
        -------
        The async httpx response stream.
        '''
        if self.method == 'GET':
            return client.stream(
                method=self.method,
                url=self.url,
                headers=self.headers,
            )

        if self.json_payload is not None:
            return client.stream(
                method=self.method,
                url=self.url,
                headers=self.headers,
                json=self.json_payload,
            )

        return client.stream(
            method=self.method,
            url=self.url,
            headers=self.headers,
            content=self.content_bytes,
        )

    def load_body(self, body_string: str) -> None:
        '''
        Load the body string into the request parts.

        Parameters
        ----------
        body_string : str
            The body string to load.
        '''
        if not body_string:
            return

        try:
            self.json_payload = json.loads(body_string)
        except json.JSONDecodeError:
            self.content_bytes = body_string.encode('utf-8')

    @classmethod
    def from_site(cls, site: WhatsMyNameSite, account: str) -> Self:
        '''
        Create a WMNRequestParts from a WhatsMyNameSite and account name.

        Parameters
        ----------
        site : WhatsMyNameSite
        account : str

        Returns
        -------
        WMNRequestParts
        '''
        method = site.method
        url = site.get_url(account)
        headers = site.options.headers.copy()

        parts = cls(
            method=method,
            url=url,
            headers=headers,
        )

        if method == 'GET':
            return parts

        body_string = site.get_body(account) or ''

        if not site.is_content_type_json:
            parts.content_bytes = body_string.encode('utf-8')
            return parts

        parts.load_body(body_string)
        return parts


def _encode_nullable(s: str | None) -> bytes:
    return s.encode('utf-8') if s else b''


class _WMNStreamReader:
    _MB_IN_BYTES: int = 1_048_576

    def __init__(
        self,
        response: httpx.Response,
        *,
        must_contain: str | None,
        must_not_contain: str | None,
        chunk_size: int = 16_384,
    ) -> None:
        self._response = response
        self._must_contain = must_contain
        self._must_not_contain = must_not_contain
        self._chunk_size = chunk_size

        self._seen_positive_identifier = False
        self._seen_negative_identifier = False

        self._pos_identifier: bytes = _encode_nullable(must_contain)
        self._negative_identifier: bytes = _encode_nullable(must_not_contain)

        self._need_positive = bool(self._pos_identifier)
        self._need_negative = bool(self._negative_identifier)

        overlap_boundary = max(
            len(self._pos_identifier),
            len(self._negative_identifier),
            1,
        )
        self._overlap_boundary = overlap_boundary - 1
        self._tail = b''

    async def check_stream(self, max_size_mb: int = 10) -> bool:
        """
        Streams a httpx.response and check for the presence of certain strings
        in a very memory efficient manner.

        Technical Details
        -----------------
        This function reads the response body in chunks, checking each chunk
        for the presence of the specified strings. It handles cases where the
        strings may span across chunk boundaries by maintaining a tail of bytes
        from the end of the previous chunk.

        - Seen Positive Identifier: A flag that indicates whether the positive
        identifier has been found in the stream or the sites `m_string`

        - Seen Negative Identifier: A flag that indicates whether the negative
        identifier has been found in the stream or the sites `e_string`


        Parameters
        ----------
        max_size_mb : int, optional
            The maximum size to read from the response in megabytes,
            by default 10.

        Returns
        -------
        tuple[bool, bool]
            _(seen_positive_identifier, seen_negative_identifier)_
        """
        total_read = 0
        max_bytes = max_size_mb * self._MB_IN_BYTES
        async for chunk in self._response.aiter_bytes(chunk_size=self._chunk_size):
            total_read += len(chunk)
            if total_read > max_bytes:
                break

            buffer = self._tail + chunk
            if self._need_positive and self._pos_identifier in buffer:
                self._seen_positive_identifier = True

            if self._need_negative and self._negative_identifier in buffer:
                self._seen_negative_identifier = True

            if self._need_negative and self._seen_negative_identifier:
                await self._response.aclose()
                return False

            if self._need_positive and self._seen_positive_identifier and not self._need_negative:
                await self._response.aclose()
                return True

            self._tail = buffer[-self._overlap_boundary:] if self._overlap_boundary > 0 else b''

        saw_positive = self._need_positive and self._seen_positive_identifier
        saw_negative = self._need_negative and self._seen_negative_identifier
        return saw_positive and not saw_negative


class WMNResult(NamedTuple):
    site: str
    url: str
    status_code: int
    success: bool


@http.retry_policy(
    attempts=3,
    delay=0.5,
    jitter=0.2,
)
async def check_wmn_site(
    site: WhatsMyNameSite,
    client: http.ReconoscopeClient,
    username: str,
) -> WMNResult:

    invalid_status = site.options.m_code
    expect_status = site.entry.e_code

    reject_if_saw = site.entry.m_string
    success_if_saw = site.entry.e_string

    request = WMNRequest.from_site(site, username)
    logger.debug(f'Checking {site.entry.cat} site: {site.entry.name}')

    async with request.get_http_stream(client) as response:
        status = response.status_code

        if invalid_status and status == invalid_status:
            await response.aclose()
            return WMNResult(
                site=site.entry.name,
                url=request.url,
                status_code=status,
                success=False,
            )

        if status != expect_status:
            await response.aclose()
            return WMNResult(
                site=site.entry.name,
                url=request.url,
                status_code=status,
                success=False,
            )

        reader = _WMNStreamReader(
            response,
            must_contain=success_if_saw,
            must_not_contain=reject_if_saw,
        )

        try:
            success = await reader.check_stream()
        except (
            httpx.ReadTimeout,
            httpx.TransportError
        ):
            await response.aclose()
            logger.warning(f'Timeout or transport error reading {site.entry.name} response')
            return WMNResult(
                site=site.entry.name,
                url=request.url,
                status_code=status,
                success=False,
            )

    return WMNResult(
        site=site.entry.name,
        url=request.url,
        status_code=status,
        success=success,
    )


async def _async_wmn_worker_process(
    config: http.ClientConfig,
    chunk: list[WhatsMyNameSite],
    username: str,
    concurrency_per_process: int,
    headers: dict[str, str],
) -> list[WMNResult]:
    '''
    The async worker for a single process in the `UsernameScanner`
    uses a semaphore to limit concurrency.

    Parameters
    ----------
    config : http.ClientConfig
    chunk : list[WhatsMyNameSite]
    username : str
    concurrency_per_process : int

    Returns
    -------
    list[WMNResult]
    '''
    async with http.ReconoscopeClient(config=config, headers=headers) as client:
        semaphore = asyncio.Semaphore(concurrency_per_process)
        results: list[WMNResult] = []

        async def run_one(site: WhatsMyNameSite) -> None:
            try:
                async with semaphore:
                    result = await check_wmn_site(
                        site=site,
                        client=client,
                        username=username,
                    )
                    results.append(result)
            except Exception as exc:
                logger.error(f'Error fetching site {site.entry.name}: {exc}')

        tasks = [asyncio.create_task(run_one(site)) for site in chunk]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return results


def _wmn_worker_sync(
    client_config: http.ClientConfig,
    chunk: list[WhatsMyNameSite],
    username: str,
    concurrency_per_process: int,
    headers: dict[str, str],
) -> list[WMNResult]:
    return asyncio.run(
        _async_wmn_worker_process(
            config=client_config,
            chunk=chunk,
            username=username,
            concurrency_per_process=concurrency_per_process,
            headers=headers,
        )
    )



def _get_proc_count(chunk_size: int) -> int:
    return max(1, os.cpu_count() or 1) * chunk_size // 100

def filter_for_success(results: list[WMNResult]) -> list[WMNResult]:
    return [res for res in results if res.success]

class UsernameScanner:
    _WMN_DEFAULT_URL = (
        'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
    )

    def __init__(
        self,
        *,
        client_config: http.ClientConfig | None = None,
        chunk_size: int = 100,
        concurrency_per_process: int = 50,
        headers: dict[str, str] | None = None,
    ) -> None:
        '''
        Parameters
        ----------
        http_options : HttpOptions | None, optional
            The HTTP options to use, by default None
        chunk_size : int, optional
            The number of sites to process per worker process, by default 100
        concurrency_per_process : int, optional
            The number of concurrent requests per worker process, by default 50
        headers : dict[str, str] | None, optional
            Additional headers to include in requests, by default None
        '''
        self.client_config = client_config or http.ClientConfig()
        self.chunk_size = max(2, chunk_size)
        self.concurrency_per_process = max(2, concurrency_per_process)
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            **(headers or {}),
        }

    async def get_collection(
        self,
        *,
        ruleset: WMNRuleSet | None = None,
        wmn_json_file_path: str | None = None,
        wmn_json_url: str | None = None,
    ) -> WMNCollection:
        '''
        Loads or fetches the WhatsMyName collection.
        If no parameters are provided, it fetches the latest schema from the
        default URL `_WMN_DEFAULT_URL`.

        Parameters
        ----------
        ruleset : WMNRuleSet | None, optional
            _description_, by default None
        wmn_json_file_path : str | None, optional
            _description_, by default None
        wmn_json_url : str | None, optional
            _description_, by default None

        Returns
        -------
        WMNCollection
            _description_
        '''
        if wmn_json_file_path:
            schema = load_wmn_json_schema(wmn_json_file_path)
            return create_wmn_collection(schema, ruleset)

        wmn_json_url = wmn_json_url or self._WMN_DEFAULT_URL
        async with httpx.AsyncClient(timeout=15) as client:
            collection = await fetch_wmn_collection(
                client,
                url=wmn_json_url,
                rule_set=ruleset,
            )

        return collection

    async def check_username(
        self,
        username: str,
        *,
        collection: WMNCollection | None = None,
        success_only: bool = True
    ) -> list[WMNResult]:
        '''
        Scan for a username across the WhatsMyName collection.

        Parameters
        ----------
        username : str
            The username to scan for.
        collection : WMNCollection | None, optional
            The existing whats my name collection to use, by default None
            If None, a new collection will be created by fetching the latest schema
        success_only : bool, optional
            Whether to return only successful results, by default True

        Returns
        -------
        list[WMNResult]
        '''
        collection = collection or await self.get_collection()
        event_loop = asyncio.get_running_loop()

        proccesses = _get_proc_count(self.chunk_size)
        logger.info(f'Starting scan for "{username}" on {len(collection.sites)} sites using {proccesses} processes')

        with ProcessPoolExecutor(max_workers=proccesses) as pool:
            proccesses = []
            for chunk in collection.chunkate(chunk_size=self.chunk_size):
                proc = event_loop.run_in_executor(
                    pool,
                    _wmn_worker_sync,
                    self.client_config,
                    chunk,
                    username,
                    self.concurrency_per_process,
                    self.headers,
                )
                proccesses.append(proc)

            all_results: list[WMNResult] = []
            for proc in asyncio.as_completed(proccesses):
                try:
                    results = await proc
                    all_results.extend(results)
                except Exception as exc:
                    logger.error(f'Error in worker process: {exc}')

        if success_only:
            return list(filter(
                lambda res: res.success,
                all_results
            ))

        return all_results