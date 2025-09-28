# WORK IN PROGRESS
from __future__ import annotations
import asyncio
import pprint
import httpx
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Literal, NamedTuple, Self
from bs4 import BeautifulSoup, ResultSet, Tag
from urllib.parse import urljoin
from reconoscope.js_state import json_utils


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


_WINDOW_EXPRESSIONS: list[str] = [
    r'window\.(__\w+__)\s*=\s*({[^<]*?});',
    r'window\.(\w+State)\s*=\s*({[^<]*?});',
    r'window\.(\w+Data)\s*=\s*({[^<]*?});',
    r'(\w+)\s*=\s*({(?:[^{}]|{[^}]*})*})\s*;',
]
_COMMON_SELECTORS: list[str] = [
    'script#__NEXT_DATA__',
    'script#__NUXT_DATA__',
]
_PAGE_DATA_URL_PATTERNS: list[str] = [
    r'href="(/_next/data/[^"]+\.json)"',
    r'href="([^"]*?\.pageContext\.json)"',
    r'"url":\s*"([^"]+\.json)"',
    r'fetch\(["\']([^"\']+\.json)["\']',
]

@dataclass(slots=True)
class ParserOptions:
    window_regexes: list[re.Pattern]
    hydration_selectors: list[str]
    page_data_url_patterns: list[re.Pattern]

    @classmethod
    def create(
        cls,
        *,
        window_regexes: list[str] | None = None,
        hydration_selectors: list[str] | None = None,
        page_data_url_patterns: list[str] | None = None
    ) -> Self:
        global _WINDOW_EXPRESSIONS, _COMMON_SELECTORS, _PAGE_DATA_URL_PATTERNS
        window_regexes = window_regexes or []
        hydration_selectors = hydration_selectors or []
        page_data_url_patterns = page_data_url_patterns or []

        window_regexes.extend(_WINDOW_EXPRESSIONS)
        window_pat = [
            re.compile(pattern, re.MULTILINE | re.DOTALL)
            for pattern in window_regexes
        ]
        page_data_url_patterns.extend(_PAGE_DATA_URL_PATTERNS)
        page_data_pats = [
            re.compile(pattern)
            for pattern in page_data_url_patterns
        ]
        hydration_selectors.extend(_COMMON_SELECTORS)
        return cls(
            window_regexes=window_pat,
            hydration_selectors=hydration_selectors,
            page_data_url_patterns=page_data_pats
        )

@dataclass(slots=True)
class ScriptDetails:
    tag_id: str | None
    tag_type: str | None
    content_length: int
    parse_success: bool
    parse_error: str | None
    data_keys: set[str] = field(default_factory=set)


@dataclass(slots=True)
class JavascriptPageState:
    '''
    Represents the extracted JavaScript state from a web page.
    Attributes
    ----------
    url : str
        The URL of the page that was analyzed.
    ok : bool
        Indicates if the page was successfully fetched and parsed.
    json_script_blobs : dict[str, dict[str, Any]]
        A dictionary mapping script tags with JSON content (like LD+JSON or application/json)
        to their parsed data.
    hydration : dict[str, Any]
        A dictionary of hydration state blobs extracted from the page
        including window variables and known selectors for frontend
        frameworks.
    page_data_urls : list[str]
        A list of discovered JSON endpoint URLs from the page.
    scripts : list[ScriptDetails]
        A list of details about each of the script tags found on the page.
    inline_json : dict[str, Any]
        A dictionary of inline JSON variables extracted from the
        returned HTML.
    total_scripts : int
        The total number of script tags found on the page.
    '''
    url: str
    ok: bool
    json_script_blobs: dict[str, dict[str, Any]]
    hydration: dict[str, Any]
    page_data_urls: list[str]
    scripts: list[ScriptDetails] = field(default_factory=list)
    inline_json: dict[str, Any] = field(default_factory=dict)
    total_scripts: int = 0

def is_dunder(var_name: str) -> bool:
    return var_name.startswith('__') and var_name.endswith('__')


def iter_matches(expressions: list[re.Pattern], text: str):
    for pattern in expressions:
        for match in pattern.finditer(text):
            yield match.groups()


def get_script_tag_details(script_tag: Tag) -> ScriptDetails:
    tag_id = script_tag.get('id')
    tag_type = script_tag.get('type')
    content = script_tag.string or script_tag.get_text() or ""

    preview = re.sub(r'\s+', ' ', content.strip())[:100]
    if len(content) > 100:
        preview += "..."

    details = ScriptDetails(
        tag_id=str(tag_id),
        tag_type=str(tag_type),
        content_length=len(content),
        parse_success=False,
        parse_error=None
    )

    if not json_utils.is_json_like(content, str(tag_type)):
        return details

    parsed_data, error = json_utils.try_loads(content)
    if parsed_data:
        details.parse_success = True
        details.data_keys = json_utils.flatten_dict(parsed_data)
    else:
        details.parse_error = error

    return details

class _WindowJSON(NamedTuple):
    var_name: str
    json: dict | list
    variable_type: Literal['hydration', 'inline']



def iter_window_blobs(window_regexes: list[re.Pattern], text: str):
    for pattern in window_regexes:
        for match in pattern.finditer(text):
            var_name, json_blob = match
            parsed_data, error = json_utils.try_loads(json_blob)
            if not parsed_data:
                logger.debug('Could not parse window.%s: %s', var_name, error)
                continue
            variable_type = 'hydration' if is_dunder(var_name) else 'inline'
            yield _WindowJSON(
                var_name,
                parsed_data,
                variable_type
            )

def collect_page_data_urls(page_data_url_patterns: list[re.Pattern], text: str, base_url: str) -> list[str]:
    urls = []
    for pattern in page_data_url_patterns:
        matches = pattern.findall(text)
        for match in matches:
            absolute_url = urljoin(base_url, match)
            urls.append(absolute_url)
    return list(dict.fromkeys(urls))


def parse_json_script(tags: ResultSet[Tag], type_: str) -> dict[str, dict]:
    results = {}
    for i, script in enumerate(tags):
        content = script.string or script.get_text() or ""

        script_id: str = script.get('id') or f'{type_}-JSON[{i}]' # type: ignore

        parsed_data, error = json_utils.try_loads(content)
        if parsed_data:
            results[script_id] = parsed_data

    return results

async def get_text(client: httpx.AsyncClient, url: str) -> str:
    try:
        r = await client.get(url)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        raise

class JavascriptParser:
    def __init__(
        self,
        client: httpx.AsyncClient,
        options: ParserOptions | None = None,
    ) -> None:
        self.options = options or ParserOptions.create()
        self.client = client

    async def check_url(self, url: str) -> JavascriptPageState:
        text = await get_text(self.client, url)
        soup = BeautifulSoup(text, "html.parser")
        all_scripts = soup.find_all('script')

        ld_json = parse_json_script(
            soup.select('script[type="application/ld+json"]'),
            'LD'
        )
        json_scripts = parse_json_script(
            soup.select('script[type="application/json"]'),
            'application'
        )
        hydration: dict[str, Any] = {}
        for selector in self.options.hydration_selectors:
            id, content = json_utils.get_hydrated_json(soup, selector=selector)
            hydration[id] = content

        inline_patterns = {}
        for window_json in iter_window_blobs(self.options.window_regexes, text):
            if window_json.variable_type == 'hydration':
                hydration[window_json.var_name] = window_json.json
            else:
                inline_patterns[window_json.var_name] = window_json.json

        page_data_urls = collect_page_data_urls(
            self.options.page_data_url_patterns,
            text,
            url
        )
        script_details = [
            get_script_tag_details(script)
            for script in all_scripts
        ]
        total_scripts = len(all_scripts)
        return JavascriptPageState(
            url=url,
            ok=True,
            json_script_blobs={
                'ld': ld_json,
                'application': json_scripts
            },
            hydration=hydration,
            page_data_urls=page_data_urls,
            scripts=script_details,
            inline_json=inline_patterns,
            total_scripts=total_scripts
        )



def render_js_page_state(state: JavascriptPageState) -> str:
    lines = [
        f'URL: {state.url}',
        f'Status: {"OK" if state.ok else "Failed"}',
        f'Total Scripts: {state.total_scripts}',
        '',
        '--- JSON Script Blobs ---',
    ]
    for script_type, blobs in state.json_script_blobs.items():
        lines.append(f'  {script_type}: {len(blobs)} blobs')
        for blob_id, data in blobs.items():
            keys = ', '.join(sorted(json_utils.flatten_dict(data)))
            lines.append(f'    - {blob_id}: {len(keys.split(", "))} keys ({keys})')

    lines.append('')
    lines.append('--- Hydration State ---')
    for var_name, data in state.hydration.items():
        keys = ', '.join(sorted(json_utils.flatten_dict(data)))
        lines.append(f'  - {var_name}: {len(keys.split(", "))} keys ({keys})')

        format = pprint.pformat(data, indent=4, width=80)
        input('Press enter to see hydration data preview')
        print(format)



    lines.append('')
    lines.append('--- Inline JSON Patterns ---')
    for var_name, data in state.inline_json.items():
        keys = ', '.join(sorted(json_utils.flatten_dict(data)))
        lines.append(f'  - {var_name}: {len(keys.split(", "))} keys ({keys})')
        fmt = pprint.pformat(data, indent=4, width=80)
        input('Press enter to see inline JSON data preview')
        print(fmt)

    lines.append('')
    lines.append('--- Page Data URLs ---')
    for url in state.page_data_urls:
        lines.append(f'  - {url}')

    lines.append('')
    lines.append('--- Script Tag Details ---')
    for detail in state.scripts:
        status = 'Parsed' if detail.parse_success else f'Error: {detail.parse_error}'
        keys = ', '.join(sorted(detail.data_keys)) if detail.data_keys else 'N/A'
        lines.append(
            f'  ID: {detail.tag_id or "N/A"}\nType: {detail.tag_type or "N/A"}, \n'
            f'Length: {detail.content_length}\n Status: {status}\n Keys: {keys}'
        )

    return '\n'.join(lines)



async def main() -> int:
    import sys
    if len(sys.argv) < 2:
        url = input('Enter a URL to scan: ').strip()
    else:
        url = sys.argv[1].strip()

    async with httpx.AsyncClient(timeout=30.0) as client:
        parser = ClientsideParser(client)
        try:
            state = await parser.check_url(url)
        except Exception as exc:
            print(f'Error checking URL, check your network connection {exc}')
            return 1

    print(render_js_page_state(state))
    return 0



if __name__ == '__main__':
    import sys
    sys.exit(
        asyncio.run(main())
    )




