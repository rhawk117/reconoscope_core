


import sys
import asyncio
from reconoscope import wmn, http




def wmn_result_str(result: wmn.WMNResult) -> str:
    return f'''
------------------------------
URL: {result.url}
Status Code: {result.status_code}
Success: {'yes' if result.success else 'no'}
------------------------------
'''




async def main() -> int:
    if len(sys.argv) < 2:
        username = input('Enter a username to search for: ').strip()
    else:
        username = sys.argv[1].strip()

    backend = wmn.UsernameScanner(
        client_config=http.ClientConfig(
            http2=False
        )
    )

    collection = await backend.get_collection()

    print(
        f'Scanning {collection.size} URLs for username: {username}, this may take a while...'
    )
    try:
        result = await backend.check_username(
            username,
            collection=collection
        )
    except Exception as exc:
        print(f'Error checking username, check your network connection {exc}')
        return 1

    hits = list(filter(
        lambda r: r.success,
        result
    ))
    input(f'Found {len(hits)} hits - press enter to see details')
    for res in hits:
        print(wmn_result_str(res))

    print(
        'Note: the errors are from sites that have been depracated '
        'or rejected due to SSL verification for the client being enabled'
        'to skip risky sites.'
    )

    return 0

if __name__ == '__main__':
    sys.exit(
        asyncio.run(main())
    )


