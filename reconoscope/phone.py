import asyncio
import dataclasses as dc

import phonenumbers
from phonenumbers import carrier, geocoder


@dc.dataclass
class PhoneRecord:
    """
    Represents the result of a phone number lookup.
    """

    phone_number: str
    is_valid: bool
    e164: str | None = None
    country: str | None = None
    region: str | None = None
    operator: str | None = None


def get_phone_info(phone_number: str, lang: str = 'en') -> PhoneRecord:
    try:
        phone_obj = phonenumbers.parse(phone_number)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Error parsing phone number {phone_number}: {exc}")

    if is_valid := phonenumbers.is_valid_number(phone_obj):
        kwargs = {
            "e164": phonenumbers.format_number(
                phone_obj, phonenumbers.PhoneNumberFormat.E164
            ),
            "country": geocoder.country_name_for_number(phone_obj, lang),
            "region": geocoder.description_for_number(phone_obj, lang),
            "operator": carrier.name_for_number(phone_obj, lang),
        }
    else:
        kwargs = {
            "e164": None,
            "country": None,
            "region": None,
            "operator": None,
        }

    return PhoneRecord(phone_number=phone_number, is_valid=is_valid, **kwargs)


async def lookup_phone_numbers(phone_numbers: list[str], lang: str) -> list[PhoneRecord]:
    tasks = (
        asyncio.to_thread(get_phone_info, number, lang=lang)
        for number in phone_numbers
    )
    return await asyncio.gather(*tasks)

