
import asyncio
import json
import logging
from pathlib import Path
from typing import NamedTuple

import httpx
from reconoscope._http import retry_policy, HttpClientPool, HttpOptions, get_random_user_agent
from reconoscope.wmn._collection import WMNCollection, WMNRuleSet, WhatsMyNameSchema, create_wmn_collection
from reconoscope.wmn._schema import WhatsMyNameSite
from reconoscope.wmn._utils import get_request_parts, stream_contains
from concurrent.futures import ProcessPoolExecutor
logger = logging.getLogger(__name__)

_WMN_DEFAULT_URL = (
    'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
)


@retry_policy(attempts=3)
async def fetch_wmn_schema(client: httpx.AsyncClient, url: str | None = None) -> WhatsMyNameSchema:
    """
    Fetch the WhatsMyName JSON schema from a URL.

    Parameters
    ----------
    url : str | None, optional
        The URL to fetch the schema from, by default None
        (uses the default WMN URL)
    client : httpx.AsyncClient
        The HTTPX client to use for the request.

    Returns
    -------
    WhatsMyNameSchema
        The fetched schema.

    Raises
    ------
    httpx.HTTPError
        If the request fails.
    ValueError
        If the response is not valid JSON or does not conform to the schema.
    """
    logger.debug(f'Fetching WhatsMyName JSON from {url}')
    url = url or _WMN_DEFAULT_URL

    response = await client.get(url, timeout=15)
    response.raise_for_status()

    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError('Response JSON is not an object')
        return data  # type: ignore
    except Exception as exc:
        raise ValueError(
            f'Failed to parse WhatsMyName JSON: {exc}') from exc


def load_wmn_json_schema(pathname: str) -> WhatsMyNameSchema:
    """
    Load the WhatsMyName JSON schema from a local file.

    Parameters
    ----------
    pathname : str
        The path to the local JSON file.

    Returns
    -------
    WhatsMyNameSchema
        The loaded schema.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file is not valid JSON or does not conform to the schema.
    """

    json_string = Path(pathname).read_text(pathname)

    logger.debug(f'Loading WhatsMyName JSON from {pathname}')
    try:
        return json.loads(json_string)
    except Exception as exc:
        raise ValueError(f'Failed to load WhatsMyName JSON: {exc}') from exc


async def fetch_wmn_collection(
    client: httpx.AsyncClient,
    *,
    url: str = _WMN_DEFAULT_URL,
    rule_set: WMNRuleSet | None = None,
) -> WMNCollection:
    """
    Fetch and build a WMNCollection from a URL.

    Parameters
    ----------
    client : httpx.AsyncClient
        The HTTPX client to use for the request.
    url : str, optional
        The URL to fetch the schema from, by default _WMN_DEFAULT_URL
    rule_set : WMNRuleSet | None, optional
        An optional rule set to filter sites, by default None

    Returns
    -------
    WMNCollection
        The fetched collection.

    Raises
    ------
    httpx.HTTPError
        If the request fails.
    ValueError
        If the response is not valid JSON or does not conform to the schema.
    """
    schema = await fetch_wmn_schema(client, url)
    return create_wmn_collection(schema, rule_set)

class WMNResult(NamedTuple):
    site: str
    url: str
    status_code: int
    success: bool


@retry_policy(
    attempts=3,
    delay=0.5,
    jitter=0.2,
)
async def check_wmn_site(
    site: WhatsMyNameSite,
    client: httpx.AsyncClient,
    username: str,
) -> WMNResult:

    invalid_status = site.options.m_code
    expect_status = site.entry.e_code

    reject_if_saw = site.entry.m_string
    success_if_saw = site.entry.e_string

    request_template = get_request_parts(
        site=site,
        account=username,
    )
    logger.debug(f'Checking {site.entry.cat} site: {site.entry.name}')

    async with request_template.stream(client) as response:
        status = response.status_code

        if invalid_status and status == invalid_status:
            await response.aclose()
            return WMNResult(
                site=site.entry.name,
                url=request_template.url,
                status_code=status,
                success=False,
            )

        if status != expect_status:
            await response.aclose()
            return WMNResult(
                site=site.entry.name,
                url=request_template.url,
                status_code=status,
                success=False,
            )

        try:
            saw_success, saw_reject = await stream_contains(
                response,
                must_contain=success_if_saw,
                must_not_contain=reject_if_saw,
            )
        except (
            httpx.ReadTimeout,
            httpx.TransportError
        ):
            await response.aclose()
            logger.warning(f'Timeout or transport error reading {site.entry.name} response')
            return WMNResult(
                site=site.entry.name,
                url=request_template.url,
                status_code=status,
                success=False,
            )

    return WMNResult(
        site=site.entry.name,
        url=request_template.url,
        status_code=status,
        success=saw_success and not saw_reject,
    )


async def wmn_worker_proc(
    client: httpx.AsyncClient,
    chunk: list[WhatsMyNameSite],
    username: str,
    concurrency_per_process: int,
) -> list[WMNResult]:
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


def wmn_process(
    pool_options: HttpOptions,
    chunk: list[WhatsMyNameSite],
    username: str,
    concurrency_per_process: int,
    headers: dict[str, str],
) -> list[WMNResult]:
    pool = HttpClientPool(options=pool_options)
    client = pool.create_client(headers={
        **headers,
        'User-Agent': get_random_user_agent(),
    })
    try:
        return asyncio.run(
            wmn_worker_proc(
                client=client,
                chunk=chunk,
                username=username,
                concurrency_per_process=concurrency_per_process,
            )
        )
    finally:
        asyncio.run(pool.aclose())
        if not client.is_closed:
            asyncio.run(client.aclose())



def get_proc_count(chunk_size: int) -> int:
    import os
    return max(1, os.cpu_count() or 1) * chunk_size // 100


class UsernameScanner:
    def __init__(
        self,
        *,
        http_options: HttpOptions | None = None,
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
        self.http_options = http_options or HttpOptions()
        self.chunk_size = max(2, chunk_size)
        self.concurrency_per_process = max(2, concurrency_per_process)
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            **(headers or {}),
        }

    async def create_wmn_collection(
        self,
        *,
        ruleset: WMNRuleSet | None = None,
        wmn_json_file_path: str | None = None,
        wmn_json_url: str | None = None,
    ) -> WMNCollection:
        if wmn_json_file_path:
            schema = load_wmn_json_schema(wmn_json_file_path)
            return create_wmn_collection(schema, ruleset)

        async with httpx.AsyncClient(timeout=15) as client:
            schema = await fetch_wmn_schema(client, wmn_json_url)

        return create_wmn_collection(schema, ruleset)


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
        collection = collection or await self.create_wmn_collection()
        event_loop = asyncio.get_running_loop()

        proccesses = get_proc_count(self.chunk_size)
        logger.info(f'Starting scan for "{username}" on {len(collection.sites)} sites using {proccesses} processes')

        with ProcessPoolExecutor(max_workers=proccesses) as pool:
            proccesses = []
            for chunk in collection.chunkate(chunk_size=self.chunk_size):
                proc = event_loop.run_in_executor(
                    pool,
                    wmn_process,
                    self.http_options,
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
            all_results = [res for res in all_results if res.success]

        return all_results