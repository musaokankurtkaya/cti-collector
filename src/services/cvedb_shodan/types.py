from typing import Any, TypedDict


class ShodanCveIdResponse(TypedDict):
    """Shodan CVE-{id} response type.

    For more details, see [Shodan CVEdb](https://cvedb.shodan.io/docs#/)
    """

    cve_id: str
    summary: str | None
    cvss: int | None
    cvss_version: float | None
    cvss_v2: float | None
    cvss_v3: float | None
    cvss_v4: float | None
    epss: float | None
    ranking_epss: float | None
    kev: bool
    propose_action: str | None
    ransomware_campaign: str | None
    references: list[str]
    cpes: list[str]
    published_time: str | None
    euvd: dict[str, Any] | None
