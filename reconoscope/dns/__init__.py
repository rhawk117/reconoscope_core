'''
**reconoscope.dns**
-------------


The DNS Resolver module for looking up DNS records, reverse DNS, and email domain extraction.
See: `reconoscope.dns._core` and `reconoscope.dns._records` for more details.
'''
from reconoscope.dns._core import (
    DNSEngineResult,
    DNSBackend,
    get_email_domain,
    get_reversename
)
from reconoscope.dns._models import (
    DnsSearchResult,
    EmailDnsResult,
    HostIPS,
    ResolverConfig,
    ReverseDnsResult,
)
from reconoscope.dns._records import (
    DomainRecords,
    MXRecord,
    ARecord,
    AAAARecord,
    CNAMERecord,
    NSRecord,
    SOARecord,
    TXTRecord,
    PTRRecord,
)

__all__ = [
    "DNSEngineResult",
    "DNSBackend",
    "get_email_domain",
    "get_reversename",
    "DnsSearchResult",
    "EmailDnsResult",
    "HostIPS",
    "ResolverConfig",
    "ReverseDnsResult",
    "DomainRecords",
    "MXRecord",
    "ARecord",
    "AAAARecord",
    "CNAMERecord",
    "NSRecord",
    "SOARecord",
    "TXTRecord",
    "PTRRecord",
]