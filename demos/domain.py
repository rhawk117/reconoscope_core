import pprint
from aiointel import domain
import dataclasses as dc




async def main() -> int:
    thing = domain.DNSBackend()

    while True:
        dom = input('Enter a email to look up (e.g. example.com): ').strip()
        result = await thing.search_email(dom)
        pprint.pprint(dc.dataclass(result)) # type: ignore

    return 0


if __name__ == '__main__':
    import sys
    import asyncio

    sys.exit(asyncio.run(main()))
