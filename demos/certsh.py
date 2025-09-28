



import asyncio
import sys
from reconoscope import certsh


def subdomain_result_str(result: certsh.SubdomainResult) -> str:
    sep = '-------------------------'
    string = f'\n{sep}\nDomain: {result.domain}'
    for subdomain in result.subdomains:
        string += f'- {subdomain}\n'

    string += f'Total subdomains found: {result.total}\n{sep}'
    return string



async def main() -> int:

    if len(sys.argv) < 2:
        domain = input('Enter a domain to search for subdomains: ').strip()
    else:
        domain = sys.argv[1].strip()

    backend = certsh.CertshBackend()

    exit_code = 1
    try:
        result = await backend.get_subdomains(domain)
        print(subdomain_result_str(result))
    except Exception as exc:
        print(f'Error fetching subdomains, check your network connection {exc}')

    return exit_code

if __name__ == '__main__':
    sys.exit(
        asyncio.run(main())
    )