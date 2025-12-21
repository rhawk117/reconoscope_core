'''
The data transfer objects for WhatsMyName module.
'''

from __future__ import annotations

import dataclasses as dc
from typing import Literal, TypedDict
import urllib
import urllib.parse


WMNMethods = Literal["GET", "POST"]



def normalize_url(site: WhatsMyNameSite, account: str) -> str:
    """
    Replace the account placeholder in the given template with the actual
    account name, although it should be in f-string format, this sometimes
    causes issues with curly braces in URLs.

    Parameters
    ----------
    template : str
        The template string containing the placeholder.
    account : str
        The account name to replace the placeholder with.

    Returns
    -------
    str
        The resulting string with the placeholder replaced.
    """
    username = account
    if site.options.strip_bad_char:
        username = username.replace(site.options.strip_bad_char, '')

    encoded = urllib.parse.quote(username, safe='')
    return site.entry.uri_check.replace('{account}', encoded)



@dc.dataclass(slots=True)
class WhatsMyNameOptions:
    '''
    The optional fields for a WhatsMyName entry.

    Attributes
    ----------
    - m_code: The HTTP status code that indicates a non-existent username.

    - uri_pretty: A URL to the profile page, with `{account}` as a placeholder.

    - headers: A dictionary of HTTP headers to include in the request.

    - post_body: The body to send with a POST request, with `{account}` as a placeholder

    - known: A list of strings that, if found in the response, indicate a valid username

    - strip_bad_char: A string of characters to strip from the account name before
    making the request.

    - protection: A list of protection mechanisms the site may have
    (e.g., "captcha", "cloudflare").
    '''

    m_code: int | None = None
    uri_pretty: str | None = None
    headers: dict[str, str] = dc.field(default_factory=dict)
    post_body: str | None = None
    known: list[str] = dc.field(default_factory=list)
    strip_bad_char: str | None = None
    protection: list[str] = dc.field(default_factory=list)


@dc.dataclass(slots=True)
class WhatsMyNameEntry:
    '''
    The required fields for a WhatsMyName entry.

    Attributes
    ----------
    - name: The name of the site.
    - uri_check: The URL to check for the username, with `{account}` as a placeholder.
    - e_code: The expected HTTP status code for a valid username.
    - e_string: A string that must be present in the response for a valid username.
    - m_string: A string that must be absent in the response for a valid username.
    - cat: The category of the site (e.g., social, email, etc.).
    '''

    name: str
    uri_check: str
    e_code: int
    e_string: str
    m_string: str
    cat: str


class WhatsMyNameResponse(TypedDict, total=False):
    '''
    The response structure for a JSON site.
    '''
    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[dict]


@dc.dataclass(slots=True, kw_only=True)
class WhatsMyNameSite:
    '''
    A WhatsMyName site entry, combining required and
    optional fields.
    '''
    entry: WhatsMyNameEntry
    options: WhatsMyNameOptions

    @property
    def method(self) -> WMNMethods:
        return "POST" if self.options.post_body else "GET"

    def get_header(self, hdr_name: str) -> str | None:
        '''
        Get a specific header value.

        Parameters
        ----------
        hdr_name : str

        Returns
        -------
        str | None
        '''
        return self.options.headers.get(hdr_name)

    def get_url(self, account: str) -> str:
        '''
        Get the URL to check for the given account name.

        Parameters
        ----------
        account : str

        Returns
        -------
        str
        '''
        return normalize_url(self, account)


    def get_pretty_url(self, account: str) -> str | None:
        '''
        Get the pretty URL for the given account name.

        Parameters
        ----------
        account : str

        Returns
        -------
        str | None
            The pretty url if set in the site options
        '''
        if not self.options.uri_pretty:
            return None
        return normalize_url(self, account)

    def get_body(self, account: str) -> str | None:
        '''
        Get the body to send with a POST request for the given account name.

        Parameters
        ----------
        account : str

        Returns
        -------
        str | None
            The body to send, or None if not a POST request.
        '''
        if not self.options.post_body:
            return None
        return self.options.post_body.replace('{account}', account)

    @property
    def is_content_type_json(self) -> bool:
        '''
        Check if the site expects or returns JSON content.

        Returns
        -------
        bool
        '''
        content_type = self.get_header('Content-Type') or (
            self.get_header('content-type')
        )
        return content_type is not None and 'application/json' in content_type.lower()


