"""
Utility functions for working with WhatsMyNameSite instances,
not attached to the instance to conserve memory.
"""

from __future__ import annotations

import json
import logging
import urllib
import urllib.parse
from typing import Final

import httpx

from reconoscope.wmn._schema import (
    WhatsMyNameSite,
    WMNRequestParts,
)

log = logging.getLogger(__name__)


class _Sanitizer:
    _ACCOUNT_PLACEHOLDER: Final[str] = '{account}'

    @staticmethod
    def placeholder(template: str, account: str) -> str:
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
        return template.replace(
            _Sanitizer._ACCOUNT_PLACEHOLDER,
            account
        )

    @staticmethod
    def safe_account(site: WhatsMyNameSite, account: str) -> str:
        """
        Sanitize the account name by removing any unwanted characters

        Parameters
        ----------
        account : str

        Returns
        -------
        str
        """
        user = account
        if site.options.strip_bad_char:
            user = user.replace(site.options.strip_bad_char, '')
        return user


class _WmnSiteUtils:
    @staticmethod
    def get_site_url(site: WhatsMyNameSite, account: str) -> str:
        safe_accountname = _Sanitizer.safe_account(
            site, account)
        encoded = urllib.parse.quote(safe_accountname, safe='')

        return _Sanitizer.placeholder(
            site.entry.uri_check,
            encoded
        )

    @staticmethod
    def get_site_pretty_url(site: WhatsMyNameSite, account: str) -> str | None:
        """
        Get the pretty URL for the given account name.

        Parameters
        ----------
        site : WhatsMyNameSite
        account : str

        Returns
        -------
        str | None
            _The pretty url if set in the site options_
        """
        if not site.options.uri_pretty:
            return None
        safe_accountname = _Sanitizer.safe_account(site, account)
        encoded = urllib.parse.quote(safe_accountname, safe='')
        return _Sanitizer.placeholder(
            site.entry.uri_check, encoded
        )

    @staticmethod
    def get_site_body(site: WhatsMyNameSite, account: str) -> str | None:
        """
        Get the body to send with the request for
        the given account name.

        Parameters
        ----------
        site : WhatsMyNameSite
        account : str

        Returns
        -------
        str | None
            _The body, if present in the site options_
        """
        if not site.options.post_body:
            return None
        safe_accountname = _Sanitizer.safe_account(site, account)

        return _Sanitizer.placeholder(
            site.options.post_body,
            safe_accountname
        )


    @staticmethod
    def is_content_type_json(site: WhatsMyNameSite) -> bool:
        """
        Check if the Content-Type header indicates JSON content.

        Parameters
        ----------
        site : WhatsMyNameSite

        Returns
        -------
        bool
        """
        candidate = site.options.headers.get(
            'Content-Type'
        ) or site.options.headers.get('content-type')
        return candidate is not None and 'application/json' in candidate.lower()

    @staticmethod
    def try_set_request_json(
        existing_parts: WMNRequestParts, body_string: str
    ) -> None:
        try:
            body_json = json.loads(body_string)
            existing_parts.json_payload = body_json
        except json.JSONDecodeError:
            log.warning(
                'Body is not valid JSON, sending as raw string, using fallback content_bytes'
            )
            existing_parts.content_bytes = body_string.encode('utf-8')

def get_request_parts(
    *,
    site: WhatsMyNameSite,
    account: str,
) -> WMNRequestParts:
    """
    Get the request parts for the given site and account name.

    Parameters
    ----------
    site : WhatsMyNameSite
    account : str

    Returns
    -------
    WMNRequestParts
        _The parts of the request to use_
    """
    method = site.method
    site_url = _WmnSiteUtils.get_site_url(site, account)


    parts = WMNRequestParts(
        method=method,
        url=site_url,
        headers=site.options.headers,
    )

    if method == 'GET':
        return parts

    body_string = _WmnSiteUtils.get_site_body(site, account) or ''
    if not _WmnSiteUtils.is_content_type_json(site):
        parts.content_bytes = body_string.encode('utf-8')
        return parts

    _WmnSiteUtils.try_set_request_json(parts, body_string)
    return parts


_MB_IN_BYTES: Final[int] = 1_048_576

def encode_nullable(s: str | None) -> bytes:
    return s.encode('utf-8') if s else b''

async def stream_contains(
    response: httpx.Response,
    *,
    must_contain: str | None,
    must_not_contain: str | None,
    chunk_size: int = 16_384,
    max_size_mb: int = 10,
) -> tuple[bool, bool]:
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

    This function could've been a class tbh but I'm too sleep deprived to
    refactor it now.

    Parameters
    ----------
    response : httpx.Response
    must_contain : str | None
    must_not_contain : str | None
    chunk_size : int, optional
        _description_, by default 16_384 (16 KB)
    max_size_mb : int, optional
        _description_, by default 10

    Returns
    -------
    tuple[bool, bool]
        _(seen_positive_identifier, seen_negative_identifier)_
    """
    global _MB_IN_BYTES
    seen_positive_identifier = False
    seen_negative_identifier = False

    pos_identifier: bytes = encode_nullable(must_contain)
    negative_identifier: bytes = encode_nullable(must_not_contain)

    need_positive = bool(pos_identifier)
    need_negative = bool(negative_identifier)

    overlap_boundary = max(len(pos_identifier), len(negative_identifier), 1) - 1
    tail = b''
    total_read = 0

    max_bytes = max_size_mb * _MB_IN_BYTES
    async for chunk in response.aiter_bytes(chunk_size=chunk_size):
        total_read += len(chunk)
        if total_read > max_bytes:
            break

        buffer = tail + chunk
        if need_positive and pos_identifier in buffer:
            seen_positive_identifier = True

        if need_negative and negative_identifier in buffer:
            seen_negative_identifier = True

        if need_negative and seen_negative_identifier:
            await response.aclose()
            return (seen_positive_identifier, seen_negative_identifier)

        if need_positive and seen_positive_identifier and not need_negative:
            await response.aclose()
            return (True, False)

        tail = buffer[-overlap_boundary:] if overlap_boundary > 0 else b''

    return (seen_positive_identifier, seen_negative_identifier)
