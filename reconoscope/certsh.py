'''
**reconoscope.certsh**

The CertSh client for querying subdomains from https://cert.sh.

When provided with a domain name, the CertShClient fetches associated
subdomains by querying the CertSh service. It processes the JSON response
into a structured format, returning the SubdomainResult dataclass from the
results gathered.
'''
import asyncio
from reconoscope import http
import dataclasses as dc

@dc.dataclass(slots=True)
class SubdomainResult:
    domain: str
    total: int
    subdomains: list[str]


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip('.')

def iter_name_values(name_value: str, domain: str):
    for line in str(name_value).splitlines():
        hostname = normalize_hostname(line)
        if hostname and hostname != domain:
            yield hostname

def walk_certsh_response(data: list[dict], domain: str):
    '''
    Walk the JSON response from cert.sh and yield subdomains
    by looking at the `name_value` and `common_name` fields
    to extract hostnames.

    Parameters
    ----------
    data : list[dict]
    domain : str

    Yields
    ------
    str
    '''
    for entry in data:
        if name_value := entry.get('name_value'):
            yield from iter_name_values(name_value, domain)
        elif common_name := entry.get('common_name'):
            hostname = normalize_hostname(common_name)
            if hostname and hostname != domain:
                yield hostname


class CertshBackend:
    url = 'https://crt.sh/'

    def __init__(self, config: http.ClientConfig | None = None) -> None:
        self._client = http.ReconoscopeClient(
            config=config,
            headers={
                'Accept': 'application/json',
            }
        )

    @http.retry_policy(attempts=3)
    async def fetchcert(self, domain: str) -> list[dict]:
        params = {
            'q': f'%.{domain}',
            'output': 'json',
        }
        response = await self._client.get(self.url, params=params)
        response.raise_for_status()
        return response.json()

    async def get_subdomains(self, domain: str) -> SubdomainResult:
        data = await self.fetchcert(domain)
        subdomains = set()
        for hostname in walk_certsh_response(data, domain):
            subdomains.add(hostname)

        return SubdomainResult(
            domain=domain,
            total=len(subdomains),
            subdomains=sorted(subdomains),
        )

    async def gather_subdomains(self, domains: list[str]) -> dict[str, SubdomainResult]:
        results = await asyncio.gather(*(
            self.get_subdomains(domain)
            for domain in domains
        ))
        return {result.domain: result for result in results}