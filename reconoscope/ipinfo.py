'''
**reconoscope.ipinfo**
-----------------

The IP address information lookup client using the ipinfo.io service.
When provided with an IP address, the IPInfoClient fetches associated
geolocation and organizational data by querying the ipinfo.io API. It processes
the JSON response into a structured format, returning the IpRecord dataclass
from the results gathered.
'''
import asyncio
from reconoscope import http
import dataclasses as dc


@dc.dataclass(slots=True)
class IpRecord:
    """
    The results from an IP address lookup.
    """
    ip: str
    city: str | None = None
    country: str | None = None
    postal: str | None = None
    org: str | None = None
    location: str | None = None
    timezone: str | None = None
    extras: dict = dc.field(default_factory=dict)

    @property
    def maps_link(self) -> str | None:
        if not self.location:
            return None
        return f"https://maps.google.com/?q={self.location}"


class IPInfoSearch:
    base_url = 'https://ipinfo.io'

    def __init__(
        self,
        config: http.ClientConfig | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._client = http.ReconoscopeClient(
            base_url=self.base_url,
            config=config,
            headers={
                'Accept': 'application/json',
                **(headers or {}),
            }
        )


    @http.retry_policy(attempts=3)
    async def get_json(self, ip: str) -> dict:
        response = await self._client.get(f'/{ip}/json')
        response.raise_for_status()
        return response.json()

    async def get_ip_record(self, ip: str) -> IpRecord:
        '''
        Fetch the IP information for the given IP address.

        Parameters
        ----------
        ip : str

        Returns
        -------
        IpRecord

        Raises
        ------
        ValueError
            If the IP address is a bogon address.
        '''
        data = await self.get_json(ip)
        if data.get('bogon'):
            raise ValueError(f"{ip} is a bogon address")

        record_fields = {f.name for f in dc.fields(IpRecord)}
        kwargs = {
            'ip': ip,
            'extras': {},
        }
        for key, value in data.items():
            if key not in record_fields:
                kwargs['extras'][key] = value
            else:
                data[key] = value

        return IpRecord(**kwargs)

    async def get_records(self, *ips: str) -> dict[str, IpRecord]:
        '''
        Collect IP records for multiple IP addresses concurrently.

        Returns
        -------
        dict[str, IpRecord]
        '''
        results = await asyncio.gather(
            *(self.get_ip_record(ip) for ip in ips),
            return_exceptions=True
        )
        records: dict[str, IpRecord] = {}
        for record in results:
            if isinstance(record, BaseException):
                continue
            records[record.ip] = record

        return records


