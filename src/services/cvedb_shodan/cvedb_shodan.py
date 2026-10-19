from ..http_client import HttpClient, Response, log_message
from .types import ShodanCveIdResponse


class CveDbShodan:
    """CveDbShodan class to interact with CveDB Shodan's API.

    For more details, see [CveDB Shodan REST API](https://cvedb.shodan.io/docs)
    """

    @classmethod
    def fetch_cve_by_cve_id(cls, cve_id: str) -> ShodanCveIdResponse | None:
        """Fetch CVE details from cvedb.shodan.io by CVE ID."""

        url: str = "https://cvedb.shodan.io"
        http_client: HttpClient = HttpClient(url=url, verify=True)

        cvedb_response: Response | None = http_client.request(
            method="get", endpoint=f"/cve/{cve_id}"
        )
        if cvedb_response is None:
            return

        cvedb_response_data: ShodanCveIdResponse = cvedb_response.json()
        if not cvedb_response_data:
            log_message(
                mode="warning", msg=f"{cve_id} not found in the cvedb.shodan.io"
            )
            return

        return cvedb_response_data
