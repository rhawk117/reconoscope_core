import dataclasses as dc
from reconoscope.dns._records import (
    DomainRecords,
    MXRecord,
)


@dc.dataclass(slots=True)
class DnsSearchResult:
    domain: str
    records: DomainRecords
    warnings: list[str] = dc.field(default_factory=list)
    rtypes_queried: list[str] = dc.field(default_factory=list)

@dc.dataclass(slots=True)
class HostIPS:
    ipv4: list[str] = dc.field(default_factory=list)
    ipv6: list[str] = dc.field(default_factory=list)

@dc.dataclass(slots=True)
class EmailDnsResult:
    email: str
    domain: str
    records: list[MXRecord] = dc.field(default_factory=list)
    warnings: list[str] = dc.field(default_factory=list)
    is_authentic: bool = False
    host_ips: dict[str, HostIPS] = dc.field(default_factory=dict)



@dc.dataclass(slots=True)
class ResolverConfig:
    '''
    Options for DNS lookups.
    '''
    filename: str = "/etc/resolv.conf"
    configure: bool = True
    lifetime: float = 5.0
    search: bool | None = None
    source_port: int = 0
    tcp: bool = False

@dc.dataclass(slots=True)
class ReverseDnsResult:
    ip: str
    reversename: str
    ptr: list[str] = dc.field(default_factory=list)
    warnings: list[str] = dc.field(default_factory=list)
