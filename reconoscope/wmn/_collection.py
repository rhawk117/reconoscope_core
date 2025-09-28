from __future__ import annotations

import dataclasses as dc
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple, TypedDict

import httpx

from reconoscope._http import retry_policy
from reconoscope.wmn._schema import WhatsMyNameEntry, WhatsMyNameOptions, WhatsMyNameSite

log = logging.getLogger(__name__)


class WhatsMyNameSchema(TypedDict, total=False):
    """
    The response structure for a JSON site.
    """

    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[dict]


class _WMNLoadResult(NamedTuple):
    site: WhatsMyNameSite | None
    error: Exception | None

def try_parse_wmn_json(
    json_entry: dict,
) -> _WMNLoadResult:
    """
    Does a best-effort attempt to load a WhatsMyNameSite from a JSON
    dictionary, returning either the site or an error if one occurred.

    Parameters
    ----------
    json_entry : dict

    Returns
    -------
    tuple[WhatsMyNameSite | None, Exception | None]
        _The loaded site instance or error_
    """
    entry_kwargs = {}
    try:
        for field in dc.fields(WhatsMyNameEntry):
            entry_kwargs[field.name] = json_entry.pop(field.name)
        entry = WhatsMyNameEntry(**entry_kwargs)

    except KeyError as e:
        return _WMNLoadResult(None, ValueError(f'Missing required key: {e}'))
    except TypeError as e:
        return _WMNLoadResult(
            None, ValueError(f'Invalid WMN entry or unexpected key: {e}')
        )

    try:
        extras = WhatsMyNameOptions(**json_entry)
    except TypeError as e:
        return _WMNLoadResult(
            None,
            ValueError(f'Invalid WMN options or unexpected key: {e}')
        )

    site = WhatsMyNameSite(entry=entry, options=extras)

    return _WMNLoadResult(site, None)

@dc.dataclass(slots=True)
class WMNRuleSet:
    include_categories: frozenset[str] = frozenset()
    exclude_categories: frozenset[str] = frozenset()

    any_known_accounts: bool = False
    require_protections_any_of: frozenset[str] = frozenset()

    http_get_only: bool = False
    ignore_protected: bool = False

    def is_allowed(self, site: WhatsMyNameSite) -> bool:
        if self.include_categories and site.entry.cat not in self.include_categories:
            return False

        if self.exclude_categories and site.entry.cat in self.exclude_categories:
            return False

        if self.http_get_only and site.method != 'GET':
            return False

        if self.ignore_protected and site.options.protection:
            return False

        if self.require_protections_any_of:
            have = {p.lower() for p in site.options.protection}
            if not (have & self.require_protections_any_of):
                return False

        return True

    def pre_filter(self, site_json: dict) -> bool:
        cat = site_json.get('cat', '')
        if self.include_categories and cat not in self.include_categories:
            return False
        if self.exclude_categories and cat in self.exclude_categories:
            return False

        if self.http_get_only and (
            'post_body' in site_json and site_json.get('post_body')
        ):
            return False

        if self.any_known_accounts and not site_json.get('known'):
            return False

        if self.ignore_protected and site_json.get('protection'):
            return False

        if self.require_protections_any_of:
            protection = site_json.get('protection') or []
            have = {p.lower() for p in protection}
            if not (have & self.require_protections_any_of):
                return False

        return True


@dc.dataclass(slots=True)
class WMNCollection:
    sites: list[dict] = dc.field(default_factory=list)
    categories: set[str] = dc.field(default_factory=set)
    authors: set[str] = dc.field(default_factory=set)
    rule_set: WMNRuleSet | None = None


    @property
    def size(self) -> int:
        """
        Get the total number of site entries in the collection.

        Returns
        -------
        int
        """
        return len(self.sites)

    def _auto_discard_iterator(self) -> Iterator[dict]:
        while self.sites:
            cur = self.sites.pop()
            if self.rule_set and not self.rule_set.pre_filter(cur):
                continue
            yield cur

    def _basic_iterator(self) -> Iterator[dict]:
        for entry in self.sites:
            if self.rule_set and not self.rule_set.pre_filter(entry):
                continue
            yield entry

    def iter_site_json(self, *, auto_discard: bool = True) -> Iterator[dict]:
        """
        Iterate over all sites in the collection, applying any rule set filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """

        if auto_discard:
            iterator = self._auto_discard_iterator
        else:
            iterator = self._basic_iterator

        for site_json in iterator():
            yield site_json

    def producer(self, *, auto_discard: bool = True) -> Iterator[WhatsMyNameSite]:
        """
        build WhatsMyNameSite instances from the collection, applying any rule set
        filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """
        for site_json in self.iter_site_json(auto_discard=auto_discard):
            result = try_parse_wmn_json(site_json)
            if not (site := result.site):
                log.warning(f'Skipping invalid site entry: {result.error}')
                continue
            yield site

    def chunkate(self, chunk_size: int) -> Iterator[list[WhatsMyNameSite]]:
        """
        Chunk the sites into lists of a given size.

        Parameters
        ----------
        chunk_size : int
            The size of each chunk.

        Yields
        ------
        Iterator[list[WhatsMyNameSite]]
        """

        if chunk_size <= 0:
            raise ValueError('chunk_size must be greater than 0')

        chunk: list = []
        for raw_json in self.iter_site_json():
            if self.rule_set and not self.rule_set.pre_filter(raw_json):
                continue

            result = try_parse_wmn_json(raw_json)

            if not (site := result.site):
                log.warning(f'Skipping invalid site entry: {result.error}')
                continue

            chunk.append(site)

            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

        if chunk:
            yield chunk


def create_wmn_collection(
    schema: WhatsMyNameSchema,
    rule_set: WMNRuleSet | None=None,
) -> WMNCollection:
    """
    build a WMNCollection from a WhatsMyNameSchema and optional rule set.

    Parameters
    ----------
    schema : WhatsMyNameSchema
        The schema to load sites from.
    rule_set : WMNRuleSet | None, optional
        An optional rule set to filter sites, by default None

    Returns
    -------
    WMNCollection
    """
    return WMNCollection(
        rule_set=rule_set,
        sites=schema.get('sites', []),
        authors=set(schema.get('authors', [])),
        categories=set(schema.get('categories', [])),
    )


