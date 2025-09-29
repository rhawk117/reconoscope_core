from __future__ import annotations
import asyncio
import pprint
from reconoscope.js_state import JavascriptParser, PageState
from reconoscope import http


def render_js_page_state(state: PageState) -> str:
    lines = [
        f'URL: {state.url}',
        f'Status: {"OK" if state.ok else "Failed"}',
        f'Total Scripts: {state.total_scripts}',
        '',
        '--- JSON Script Blobs ---',
    ]

    app_fmt = pprint.pformat(state.blobs.application_blobs, indent=4, width=80)
    ld_fmt = pprint.pformat(state.blobs.ld_blobs, indent=4, width=80)

    lines.append('\nApplication/JSON blobs:')
    lines.append(app_fmt)
    lines.append('\nLD+JSON blobs:')
    lines.append(ld_fmt)

    lines.append('\n --- Hydration State --- \n')
    for var_name, data in state.hydration.items():
        if not data:
            lines.append(f'  - {var_name}: No data')
            continue

        lines.append(f'  - {var_name}:')
        lines.append(pprint.pformat(data, indent=4, width=80))

    lines.append('--- Inline JSON Patterns ---')
    for var_name, data in state.inline_json.items():
        fmt = pprint.pformat(data, indent=4, width=80)
        lines.append(f'\n  - {var_name}:\n')
        lines.append(fmt)
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
            f'Length: {detail.content_length}\n Status: {status}\n Keys: {keys}\n'
        )

    lines.append('--- All Anchors ---')
    for anchor in state.anchors:
        lines.append(f'\n  - {anchor}')
    lines.append('Metadata')
    lines.append(f'Title: {state.metadata.title}')
    lines.append(f'Meta Description: {state.metadata.description}')
    lines.append(f'Meta Keywords: {state.metadata.keywords}')


    return '\n'.join(lines)


async def main() -> int:
    import sys
    if len(sys.argv) < 2:
        url = input('Enter a URL to scan: ').strip()
    else:
        url = sys.argv[1].strip()

    async with http.ReconoscopeClient() as client:
        parser = JavascriptParser(client=client)
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
