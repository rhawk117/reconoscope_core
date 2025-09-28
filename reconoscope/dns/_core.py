
import asyncio
import contextlib
import logging
import dns
import dns.asyncresolver
from dns.resolver import Answer as DNSAnswer
import dns.resolver
import dns.reversename
from reconoscope.dns._models import HostIPS, ResolverConfig, DomainRecords, EmailDnsResult, ReverseDnsResult
import email_validator
from reconoscope.dns import _parser as record_parser
import dns.rdatatype as rtype
import dataclasses as dc

logger = logging.getLogger(__name__)

@dc.dataclass
class DNSEngineResult:
    rtypes_queried: set[str] = dc.field(default_factory=set)
    records: DomainRecords = dc.field(default_factory=DomainRecords)
    warnings: list[str] = dc.field(default_factory=list)

    def reset(self) -> None:
        self.rtypes_queried.clear()
        self.records = DomainRecords()
        self.warnings.clear()

@contextlib.asynccontextmanager
async def _collect_warnings(warnings: list[str], rtype: rtype.RdataType, domain_name: str):
    '''
    Context manager to collect warnings during DNS queries.

    Parameters
    ----------
    warnings : list[str]
    rtype : rtype.RdataType
    domain_name : str
    '''
    queried = rtype.to_text(rtype)
    try:
        yield
    except dns.resolver.NoNameservers:
        warnings.append(f"No nameservers available for {domain_name}")
    except dns.resolver.NXDOMAIN:
        warnings.append(f"Domain {domain_name} does not exist")
    except dns.resolver.NoAnswer:
        warnings.append(f"No answer for {queried} record")
    except dns.resolver.Timeout:
        warnings.append(f"Timeout while querying {queried} record")
    except Exception as e:
        warnings.append(f"Error querying {queried} record: {e}")


def _str_to_rtype(rtype_str: str) -> rtype.RdataType | None:
    '''
    Convert a string representation of a DNS record type to its
    corresponding rtype.RdataType.

    Parameters
    ----------
    rtype_str : str

    Returns
    -------
    rtype.RdataType | None
    '''
    try:
        return rtype.from_text(rtype_str.upper())
    except Exception as e:
        logger.warning(f"Unknown rtype string '{rtype_str}': {e}")
        return None

def _resolve_rtypes(rtypes_list: list[str | rtype.RdataType]) -> list[rtype.RdataType]:
    '''
    Resolve a list of record types from strings or rtype.RdataType to rtype.RdataType.

    Parameters
    ----------
    rtypes_list : list[str  |  rtype.RdataType]

    Returns
    -------
    list[rtype.RdataType]
    '''
    resolved = []
    for rt in rtypes_list:
        if isinstance(rt, rtype.RdataType):
            resolved.append(rt)

        if rtyped := _str_to_rtype(rt): # type: ignore
            resolved.append(rtyped)

    return resolved


def get_email_domain(email: str) -> str | None:
    '''
    Extract the domain from an email address.

    Parameters
    ----------
    email : str

    Returns
    -------
    str | None

    Raises
    ------
    ValueError
    '''
    try:
        valid = email_validator.validate_email(email)
        return valid.domain
    except email_validator.EmailNotValidError as e:
        raise ValueError(f"Invalid email address {email}: {e}")

def get_reversename(ip: str) -> str:
    '''
    Get the reverse DNS name for an IP address.

    Parameters
    ----------
    ip : str

    Returns
    -------
    str

    Raises
    ------
    ValueError
    '''
    try:
        addr = dns.reversename.from_address(ip)
        return str(addr).rstrip('.')
    except Exception as e:
        raise ValueError(f"Invalid IP address {ip}: {e}")


class DNSBackend:
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
        self._resolver = dns.asyncresolver.Resolver(
            filename=self._config.filename,
            configure=self._config.configure,
        )


    async def _resolve(self, domain: str, rtype: rtype.RdataType) -> DNSAnswer:
        return await self._resolver.resolve(
            qname=domain,
            rdtype=rtype,
            lifetime=self._config.lifetime,
            search=self._config.search,
            tcp=self._config.tcp,
            source_port=self._config.source_port,
        )

    async def stream_search(
        self,
        domain: str,
        rtype: rtype.RdataType,
    ) :
        '''
        Stream DNS records of a specific type for a domain
        with the parsed records.

        Parameters
        ----------
        domain : str
        rtype : rtype.RdataType
        '''
        answer = await self._resolve(domain, rtype)
        for record in answer:
            yield record_parser.parse_rdata(rtype, record)


    async def _collect_stream(
        self,
        domain: str,
        rtype: rtype.RdataType,
        result: DNSEngineResult,
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
            async for record in self.stream_search(domain, rtype):
                record_parser.parse_and_append(
                    result.records,
                    rtype,
                    record
                )

    async def search_domain(
        self,
        domain: str,
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

        results = EmailDnsResult(
            email=email,
            domain=domain,
        )

        async for mx_record in self.stream_search(domain, rtype.MX):
            results.records.append(mx_record) # type: ignore

        results.is_authentic = bool(results.records)
        if not results.is_authentic:
            return results


        for mx_record in results.records:
            host_result = await self.search_domain(
                mx_record.exchange,
                only_rtypes=[
                    rtype.A,
                    rtype.AAAA,
                ]
            )

            results.host_ips[mx_record.exchange] = HostIPS(
                ipv4=[rec.address for rec in host_result.records.A],
                ipv6=[rec.address for rec in host_result.records.AAAA],
            )

            if host_result.warnings:
                results.warnings.extend(host_result.warnings)

        return results

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
    def resolver(self) -> dns.asyncresolver.Resolver:
        return self._resolver