from typing import TypedDict


class IpInfoResponse(TypedDict, total=False):
    """IpInfo IP address response type."""

    ip: str
    hostname: str
    city: str
    region: str
    country: str
    loc: str
    org: str
    postal: str
    timezone: str
    readme: str


class Country(TypedDict):
    """Represents the country from the countries.json file."""

    country: str
    iso2: str
