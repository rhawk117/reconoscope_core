import contextlib
from collections.abc import Generator
from typing import TYPE_CHECKING, Any, NamedTuple, TypedDict, cast

import dns
import dns.resolver
import msgspec
from dns import rdatatype
from dns.rdtypes.ANY.TXT import TXT as R_TXT

from aiointel.core import obj_utils

if TYPE_CHECKING:
    from dns.rdtypes.ANY.CNAME import CNAME as R_CNAME
    from dns.rdtypes.ANY.MX import MX as R_MX
    from dns.rdtypes.ANY.NS import NS as R_NS
    from dns.rdtypes.ANY.PTR import PTR as R_PTR
    from dns.rdtypes.ANY.SOA import SOA as R_SOA
    from dns.rdtypes.IN.A import A as R_A
    from dns.rdtypes.IN.AAAA import AAAA as R_AAAA

def txt_join(r: R_TXT) -> str:
    if getattr(r, 'strings', None):
        parts = [
            s.decode(errors='ignore') if isinstance(s, (bytes, bytearray)) else str(s)
            for s in r.strings
        ]
        return ''.join(parts)

    return r.to_text().strip('"')


def dns_name(n: Any) -> str:
    return '' if n is None else str(n).rstrip('.')


class SOARecord(TypedDict):
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


class MailExchange(TypedDict):
    exchange: str
    preference: int


class DnsCollection(msgspec.Struct):
    ptr_targets: list[str] = msgspec.field(default_factory=list)
    txt_records: list[str] = msgspec.field(default_factory=list)
    soa_records: list[SOARecord] = msgspec.field(default_factory=list)
    cname_targets: list[str] = msgspec.field(default_factory=list)
    name_servers: list[str] = msgspec.field(default_factory=list)
    mail_exchanges: list[MailExchange] = msgspec.field(default_factory=list)
    ipv4: list[str] = msgspec.field(default_factory=list)
    ipv6: list[str] = msgspec.field(default_factory=list)


    def add_record(self, rtype: rdatatype.RdataType, record: Any) -> None:
        match rtype:
            case rdatatype.A:
                self.ipv4.append(cast('R_A', record).address)
            case rdatatype.AAAA:
                self.ipv6.append(cast('R_AAAA', record).address)
            case rdatatype.MX:
                r = cast('R_MX', record)
                self.mail_exchanges.append({
                    'exchange': dns_name(r.exchange),
                    'preference': r.preference,
                })
            case rdatatype.PTR:
                r = cast('R_PTR', record)
                self.ptr_targets.append(str(r.target))
            case rdatatype.SOA:
                r = cast('R_SOA', record)
                self.soa_records.append({
                    'mname': dns_name(r.mname),
                    'rname': dns_name(r.rname),
                    'serial': int(r.serial),
                    'refresh': int(r.refresh),
                    'retry': int(r.retry),
                    'expire': int(r.expire),
                    'minimum': int(r.minimum),
                })
            case rdatatype.CNAME:
                r = cast('R_CNAME', record)
                self.cname_targets.append(dns_name(r.target))
            case rdatatype.NS:
                r = cast('R_NS', record)
                self.name_servers.append(dns_name(r.target))
            case rdatatype.TXT:
                r = cast('R_TXT', record)
                self.txt_records.append(txt_join(r))
            case rdatatype.PTR:
                r = cast('R_PTR', record)
                self.ptr_targets.append(dns_name(r.target))

    def reset(self) -> None:
        for member in obj_utils.get_object_field_names(self):
            getattr(self, member).clear()


class DnsArtifact(msgspec.Struct):
    domain: str
    records: DnsCollection = msgspec.field(default_factory=DnsCollection)
    warnings: list[str] = msgspec.field(default_factory=list)
    rtypes_queried: set[str] = msgspec.field(default_factory=set)

    def reset(self) -> None:
        self.warnings.clear()
        self.rtypes_queried.clear()
        self.records.reset()

    def add_rtype(self, rtype: str) -> None:
        self.rtypes_queried.add(rtype)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    @contextlib.contextmanager
    def collect_warnings(self, rtype: rdatatype.RdataType) -> Generator[None]:
        queried = rtype.to_text(rtype)
        try:
            yield
        except dns.resolver.NoNameservers:
            self.warnings.append(f"No nameservers available for {self.domain}")
        except dns.resolver.NXDOMAIN:
            self.warnings.append(f"Domain {self.domain} does not exist")
        except dns.resolver.NoAnswer:
            self.warnings.append(f"No answer for {queried} record")
        except dns.resolver.Timeout:
            self.warnings.append(f"Timeout while querying {queried} record")
        except Exception as e:
            self.warnings.append(f"Error querying {queried} record: {e}")



class DnsReversename(msgspec.Struct):
    ip_address: str
    reversename: str
    warnings: list[str] = msgspec.field(default_factory=list)
    ptrs: list[str] = msgspec.field(default_factory=list)


class HostIP(NamedTuple):
    ipv4: list[str]
    ipv6: list[str]

class EmailDomainRecords(msgspec.Struct):
    email: str
    domain: str
    warnings: list[str] = msgspec.field(default_factory=list)
    mail_exchange: list[MailExchange] = msgspec.field(default_factory=list)


    def add_mx(self, record: Any) -> None:
        r = cast('R_MX', record)
        self.mail_exchange.append({
            'exchange': str(r.exchange),
            'preference': r.preference,
        })
