
import asyncio
from reconoscope.api_client import HTTPClient
from reconoscope._http import retry_policy
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
    for entry in data:
        if name_value := entry.get('name_value'):
            yield from iter_name_values(name_value, domain)
        elif common_name := entry.get('common_name'):
            hostname = normalize_hostname(common_name)
            if hostname and hostname != domain:
                yield hostname


class CertShClient(HTTPClient):
    headers: dict[str, str] = {
        'Accept': 'application/json',
    }

    @retry_policy()
    async def fetchcert(self, domain: str) -> list[dict]:
        params = {
            'q': f'%25.{domain}',
            'output': 'json',
        }
        response = await self._client.get('https://cert.sh', params=params)
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

    async def search_domains(self, domains: list[str]) -> list[SubdomainResult]:
        tasks = (
            self.get_subdomains(domain)
            for domain in domains
        )
        return await asyncio.gather(*tasks)
