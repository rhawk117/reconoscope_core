
import json
import re

from bs4 import Tag, BeautifulSoup, ResultSet


def try_loads(content: str) -> tuple[dict | list | None, str | None]:
    if not content or not content.strip():
        return None, "Empty content"

    try:
        parsed = json.loads(content.strip())
    except (json.JSONDecodeError, Exception) as e:
        error_msg = f"JSON parse error in JSON: {str(e)[:100]}"
        return None, error_msg

    return parsed, None

def flatten_dict(
    current: dict | list,
    max_depth: int = 5,
    parent: str = ''
) -> set[str]:
    keys = set()
    if max_depth <= 0 or not isinstance(current, dict):
        return keys

    for key, value in current.items():
        cur_key = f'{parent}.{key}' if parent else key
        keys.add(cur_key)
        if isinstance(value, dict):
            keys.update(
                flatten_dict(
                    value,
                    max_depth - 1,
                    cur_key
                )
            )
    return keys

def is_json_like(content: str, tag_type: str | None) -> bool:
    if not content or not content.strip():
        return False

    if tag_type and tag_type.lower() in ('application/ld+json', 'application/json'):
        return True

    stripped = content.lstrip()
    return stripped.startswith('{') or stripped.startswith('[')


def get_hydrated_json(
    soup: 'BeautifulSoup',
    *,
    selector: str,
) -> tuple[str, dict | list]:

    tag_id = f'json-hydrated({selector})'
    tag = soup.select_one(selector)
    if '#' in selector and tag:
        tag_id = selector.split('#', 1)[1]

    if not tag:
        return tag_id, {}

    content = tag.string or tag.get_text() or ''
    parsed, _ = try_loads(content)
    return tag_id, parsed or {}

def parse_ld_json(tags: ResultSet[Tag])  -> dict:
    results = {}
    for i, script in enumerate(tags):
        content = script.string or script.get_text() or ""

        script_id: str = script.get('id') or f'LD+JSON[{i}]'  # type: ignore

        parsed_data, _ = try_loads(content)
        if parsed_data:
            results[script_id] = parsed_data

    return results


