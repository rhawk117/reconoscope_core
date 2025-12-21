import asyncio
import contextlib
import logging
import dns
from dns import asyncresolver
from dns.resolver import Answer as DNSAnswer
import dns.resolver
import dns.reversename
from aiointel.domain.artifacts
import email_validator
import dns.rdatatype as rtype
import dataclasses as dc
from pydantic import Field, BaseModel

logger = logging.getLogger(__name__)






class DnsEngine:
    _RECORD_TYPES = (
        rtype.A,
        rtype.AAAA,
        rtype.MX,
        rtype.NS,
        rtype.CNAME,
        rtype.SOA,
        rtype.TXT,
    )

    def __init__(self, config: ResolverConfig | None = None) -> None:
        self._config = config or ResolverConfig()
        self._resolver = asyncresolver.Resolver(
            filename=self._config.filename,
            configure=self._config.configure,
        )


    async def fetch(self, domain: str, rtype: rtype.RdataType) -> DNSAnswer:
        return await self._resolver.resolve(
            qname=domain,
            rdtype=rtype,
            lifetime=self._config.lifetime,
            search=self._config.search,
            tcp=self._config.tcp,
            source_port=self._config.source_port,
        )


    async def _collect_stream(
        self,
        domain: str,
        rtype: rtype.RdataType,
        query: DnsQuery,
    ) -> None:
        '''
        Collect DNS records of a specific type for a domain
        and appends them to the appropriate list in result.records.

        Parameters
        ----------
        domain : str
        rtype : rtype.RdataType
        result : DNSEngineResult
        '''
        result.rtypes_queried.add(rtype.to_text(rtype))
        async with _collect_warnings(result.warnings, rtype, domain):
            ans = await self.fetch(domain, rtype)


    async def search(
        self,
        domain: str,
        *,
        only_rtypes: list[str | rtype.RdataType] | None = None,
    ) -> DNSEngineResult:
        '''
        Search DNS records for a domain.

        Parameters
        ----------
        domain : str
        only_rtypes : list[str  |  rtype.RdataType] | None, optional
            List of record types to query. If None, all supported types are queried.
            Supported types are: A, AAAA, MX, NS, CNAME, SOA, TXT, by default None

        Returns
        -------
        DNSEngineResult
        '''
        if only_rtypes is not None:
            rtypes_parsed = _resolve_rtypes(only_rtypes)
        else:
            rtypes_parsed = list(self._RECORD_TYPES)

        results = DNSEngineResult()

        await asyncio.gather(*(
            self._collect_stream(domain, rt, results)
            for rt in rtypes_parsed
        ))

        return results

    async def search_email(self, email: str) -> EmailDnsResult:
        '''
        Search DNS records related to an email address by looking up its domain's MX records
        and then resolving the A and AAAA records for each mail server.

        Parameters
        ----------
        email : str

        Returns
        -------
        EmailDnsResult

        Raises
        ------
        ValueError
            If the email is invalid or the domain cannot be extracted.
        '''
        domain = get_email_domain(email)
        if not domain:
            raise ValueError(f"Cannot extract domain from email {email}")

        results = DNSEngineResult()
        await self._collect_stream(domain, rtype.MX, results)

        is_authentic = bool(results.records.MX)
        if not is_authentic:
            results.warnings.append(f"No MX records found for domain {domain}")
            return EmailDnsResult(
                email=email,
                domain=domain,
                records=results.records.MX.copy(),
                warnings=results.warnings,
            )

        hostname_ips = {}
        for mx_record in results.records.MX:
            await asyncio.gather(
                self._collect_stream(mx_record.exchange, rtype.A, results),
                self._collect_stream(mx_record.exchange, rtype.AAAA, results),
            )
            hostname_ips[mx_record.exchange] = HostIPS(
                ipv4=[m.address for m in results.records.A if m.address],
                ipv6=[m.address for m in results.records.AAAA if m.address],
            )
            results.records.A.clear()
            results.records.AAAA.clear()

        return EmailDnsResult(
            email=email,
            domain=domain,
            records=results.records.MX.copy(),
            host_ips=hostname_ips,
            warnings=results.warnings,
        )

    async def reversename(self, ip: str) -> ReverseDnsResult:
        '''
        Perform a reverse DNS lookup for an IP address.

        Parameters
        ----------
        ip : str

        Returns
        -------
        ReverseDnsResult
            A result containing the PTR records and any warnings
            and the reverse DNS name.
        '''
        rev_name = get_reversename(ip)
        result = DNSEngineResult()
        await self._collect_stream(rev_name, rtype.PTR, result)
        return ReverseDnsResult(
            ip=ip,
            reversename=rev_name,
            ptr=[rec.target for rec in result.records.PTR],
            warnings=result.warnings,
        )

    @property
    def resolver(self) -> asyncresolver.Resolver:
        return self._resolver

    import base64
