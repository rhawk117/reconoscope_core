import asyncio
import sys
from reconoscope import ipinfo
import dataclasses as dc

def record_str(record: ipinfo.IpRecord) -> str:
    sep = '-------------------------'
    result = f'\n{sep}\n'
    for field in dc.fields(record):
        value = getattr(record, field.name, None)
        if isinstance(value, dict):
            result += '\n'.join(f'{k}={v}' for k, v in value.items())
            continue
        val = value or 'N/A'
        result += f'{field.name}: {val}\n'
    result += f'\nMaps link: {record.maps_link}\n{sep}'
    return result


async def main() -> int:
    if len(sys.argv) < 2:
        ip_addr = input('Enter an IP address to lookup: ').strip()
    else:
        ip_addr = sys.argv[1].strip()

    backend = ipinfo.IPInfoSearch()

    exit_code = 1
    try:
        record = await backend.get_ip_record(ip_addr)
        print(record_str(record))
        exit_code = 0
    except ValueError:
        print('IP Address is a bogon address')
    except Exception as exc:
        print(f'Error fetching IP information, check your network connection {exc}')

    return exit_code


if __name__ == '__main__':
    sys.exit(
        asyncio.run(main())
    )