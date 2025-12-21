import logging

import dns
import dns.reversename
import email_validator
from dns import rdatatype as rtype

logger = logging.getLogger(__name__)

def string_to_rtype(rtype_str: str) -> rtype.RdataType | None:
    """
    Convert a string representation of a DNS record type to its
    corresponding rtype.RdataType.

    Parameters
    ----------
    rtype_str : str
        The string representation of the DNS record type.

    Returns
    -------
    rtype.RdataType | None
        The corresponding rtype.RdataType, or None if the string
        is not recognized.
    """
    try:
        return rtype.from_text(rtype_str.upper())
    except Exception as e:
        logger.warning(f"Unknown rtype string '{rtype_str}': {e}")
        return None


def resolve_rdatatypes(
    rtypes_list: list[str | rtype.RdataType]
) -> list[rtype.RdataType]:
    """
    Resolve a list of record types from strings or rtype.RdataType to rtype.RdataType.

    Parameters
    ----------
    rtypes_list : list[str  |  rtype.RdataType]
        A list of mixed record type representations.

    Returns
    -------
    list[rtype.RdataType]
    """
    resolved = []
    for rt in rtypes_list:
        if isinstance(rt, rtype.RdataType):
            resolved.append(rt)

        if rtyped := string_to_rtype(rt):  # type: ignore
            resolved.append(rtyped)

    return resolved


def get_email_domain(email: str) -> str | None:
    """
    Extract the domain from an email address.

    Parameters
    ----------
    email : str
        The email address.

    Returns
    -------
    str | None
        The domain part of the email address, or None if invalid.

    """
    try:
        valid = email_validator.validate_email(email)
    except email_validator.EmailNotValidError:
        return None

    return valid.domain

def get_reversename(ip_address: str) -> str:
    """
    Get the reverse DNS name for an IP address.

    Parameters
    ----------
    ip : str
        The IP address.

    Returns
    -------
    str

    Raises
    ------
    ValueError
    """
    try:
        addr = dns.reversename.from_address(ip_address)
        return str(addr).rstrip('.')
    except Exception as e:
        raise ValueError(f'Invalid IP address {ip_address}: {e}')
