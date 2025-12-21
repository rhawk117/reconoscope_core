'''
**reconoscope.dns**
-------------


The DNS Resolver module for looking up DNS records, reverse DNS, and email domain extraction.
See: `reconoscope.dns._core` and `reconoscope.dns._records` for more details.
'''
from aiointel.domain.engine import (
    DNSBackend,
    DNSEngineResult,
    get_email_domain,
    get_reversename,
)
from aiointel.domain._models import (
    DnsSearchResult,
    EmailDnsResult,
    HostIPS,
    ResolverConfig,
    ReverseDnsResult,
)
from aiointel.domain.artifacts import (
    AAAARecord,
    ARecord,
    CNAMERecord,
    DomainRecords,
    MXRecord,
    NSRecord,
    PTRRecord,
    SOARecord,
    TXTRecord,
)

__all__ = [
    "AAAARecord",
    "ARecord",
    "CNAMERecord",
    "DNSBackend",
    "DNSEngineResult",
    "DnsSearchResult",
    "DomainRecords",
    "EmailDnsResult",
    "HostIPS",
    "MXRecord",
    "NSRecord",
    "PTRRecord",
    "ResolverConfig",
    "ReverseDnsResult",
    "SOARecord",
    "TXTRecord",
    "get_email_domain",
    "get_reversename",
]
