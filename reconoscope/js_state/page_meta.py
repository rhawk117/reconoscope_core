import dataclasses as dc
import re
from typing import NamedTuple
import bs4

def _get_tag_attr(tag: bs4.Tag, *attrs) -> str | None:
    '''
    used internall for getting tag attributes based on
    a list of possible attribute names to check.

    Parameters
    ----------
    tag : bs4.Tag
    *attrs : str


    Returns
    -------
    str | None
    '''
    for attr in attrs:
        if candidate := tag.get(attr):
            return str(candidate).strip()
    return None


_COMMON_SECURITY_META_TAGS = {
    'http-equiv',
    'x-content-type-options',
    'content-security-policy',
    'strict-transport-security',
    'referrer',
}

@dc.dataclass(slots=True)
class SiteDetails:
    charset: str | None = None
    description: str | None = None
    keywords: str | None = None
    robots: str | None = None


def get_site_details(soup: bs4.BeautifulSoup) -> SiteDetails:
    keys = dc.fields(SiteDetails)
    kwargs: dict[str, str | None] = {key.name: None for key in keys}
    for attrs in kwargs:
        meta_tag = soup.head.find('meta', attrs={'name': attrs})
        if not meta_tag:
            meta_tag = soup.head.find('meta', attrs={'property': attrs})

        if meta_tag and (content := _get_tag_attr(meta_tag, 'content')):
            kwargs[attrs] = content

    return SiteDetails(**kwargs)


@dc.dataclass(slots=True)
class Metadata:
    site_details: SiteDetails = dc.field(default_factory=SiteDetails)
    open_graph: dict[str, str] = dc.field(default_factory=dict)
    security: dict[str, str] = dc.field(default_factory=dict)
    extras: dict[str, str] = dc.field(default_factory=dict)

    def add_meta_tag(self, meta_tag: bs4.Tag) -> None:
        if not (prop := _get_tag_attr(meta_tag, 'name', 'property')):
            return

        prop = prop.lower()
        if not (content := _get_tag_attr(meta_tag, 'content')):
            return

        if prop.startswith('og:'):
            self.open_graph[prop] = content
            return

        global _COMMON_SECURITY_META_TAGS
        if prop in _COMMON_SECURITY_META_TAGS:
            self.security[prop] = content
            return

        self.extras[prop] = content

def get_site_metadata(soup: bs4.BeautifulSoup) -> Metadata:
    '''
    Extracts site metadata including standard meta tags, Open Graph tags,
    and common security-related meta tags.

    Parameters
    ----------
    soup : bs4.BeautifulSoup

    Returns
    -------
    Metadata
    '''
    metadata = Metadata()
    metadata.site_details = get_site_details(soup)

    for meta_tag in soup.head.find_all('meta'):
        metadata.add_meta_tag(meta_tag)

    return metadata

@dc.dataclass(slots=True)
class PagePackages:
    css: list[str] = dc.field(
        default_factory=list
    )
    javascript: list[str] = dc.field(
        default_factory=list
    )
    cdn_like: list[str] = dc.field(
        default_factory=list
    )

def _is_cdn_like(url: str, tag: bs4.Tag, cdn_indicators: list[str]) -> bool:
    if _get_tag_attr(tag, 'crossorigin') is not None:
        return True

    return any(indicator in url for indicator in cdn_indicators)

def _is_css_like(tag: bs4.Tag) -> bool:
    if tag.name != 'link':
        return False

    rel = _get_tag_attr(tag, 'rel')
    if not rel:
        return False

    return 'stylesheet' in rel.lower().split()

def get_package_list(soup: bs4.BeautifulSoup) -> PagePackages:
    '''
    Extracts CSS "packages" from <link> tags and JavaScript packages
    from <script> tags. Also identifies CDN-like resources based on
    common URL patterns and the presence of the `crossorigin` attribute.

    Parameters
    ----------
    soup : bs4.BeautifulSoup

    Returns
    -------
    PagePackages
    '''
    cdn_indicators = [
        'cdn.',
        '.cdn.',
        'cdnjs.cloudflare.com',
        'jsdelivr.net',
        'ajax.googleapis.com',
        'maxcdn.bootstrapcdn.com',
        'code.jquery.com',
        'unpkg.com',
    ]


    pkgs = PagePackages()

    for tag in soup.head.find_all(['link', 'script']):
        url = _get_tag_attr(tag, 'src', 'href', 'data-src', 'data-href')
        if not url:
            continue

        if tag.name == 'link' and _is_css_like(tag):
            pkgs.css.append(url)

        elif tag.name == 'script':
            pkgs.javascript.append(url)

        if _is_cdn_like(url, tag, cdn_indicators):
            pkgs.cdn_like.append(url)

    return pkgs


_FETCH_RE = (
    r"""
    fetch\(\s*(?P<q>
    `(?:\\.|[^`])*?` # template literal
    | "(?:\\.|[^"])*?" # double-quoted
    | '(?:\\.|[^'])*?' # single-quoted
    )"""
)
_JSON_PARSE_RE = (
    r"""
    JSON\.parse\(\s*(?P<q>
    `\s*(?:\{[\s\S]*?\}|\[[\s\S]*?\])\s*`   # template literal containing JSON
    | "\s*(?:\{[\s\S]*?\}|\[[\s\S]*?\])\s*"   # double-quoted JSON
    | '\s*(?:\{[\s\S]*?\}|\[[\s\S]*?\])\s*'   # single-quoted JSON
    )\s*\)
    """
)
_XHR_RE = (
    r"""
    (?:new\s+XMLHttpRequest\(\)|fetch\(\s*)\.open\(\s*(?P<q>
      `(?:\\.|[^`])*?` # template literal
    | "(?:\\.|[^"])*?" # double-quoted
    | '(?:\\.|[^'])*?' # single-quoted
    )
    """
)


class _ScriptTextRegexes(NamedTuple):
    fetch: re.Pattern
    json_parse: re.Pattern
    xhr: re.Pattern

@dc.dataclass(slots=True)
class JavascriptTextData:
    urls: list[str] = dc.field(default_factory=list)
    json_parse_strings: list[str] = dc.field(default_factory=list)

    def add_url(self, url: str) -> None:
        url = url.strip('\'"` ')
        if url and url not in self.urls:
            self.urls.append(url)



def _create_js_text_regexes() -> _ScriptTextRegexes:
    opts = re.DOTALL | re.MULTILINE | re.VERBOSE
    return _ScriptTextRegexes(
        fetch=re.compile(_FETCH_RE, opts),
        json_parse=re.compile(_JSON_PARSE_RE, opts),
        xhr=re.compile(_XHR_RE, opts)
    )

def analyze_javascript_code(scripts: bs4.ResultSet[bs4.Tag]) -> JavascriptTextData:
    '''
    Extracts URLs from `fetch` / XMLRequests and JSON.parse() strings
    to identify content initialized on page load and potential API endpoints.

    Parameters
    ----------
    scripts : bs4.ResultSet[bs4.Tag]

    Returns
    -------
    JavascriptTextData
    '''
    regexes = _create_js_text_regexes()
    results = JavascriptTextData()


    for script in scripts:
        if not script.get_text() or script.get('src'):
            continue
        content = script.get_text()
        for match in regexes.json_parse.finditer(content):
            if json_str := match.group('q'):
                results.json_parse_strings.append(json_str)
        for match in regexes.fetch.finditer(content):
            if url := match.group('q'):
                results.add_url(url)
        for match in regexes.xhr.finditer(content):
            if url := match.group('q'):
                results.add_url(url)

    return results
