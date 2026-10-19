from requests import Response

from ..siem import SIEM, log_message
from ..types import Event, EventSearchParams
from .types import (
    CryptoSIMSearchedEventResponse,
    CryptoSIMSearchedEvents,
    SearchResponse,
)


class CryptoSIM(SIEM[CryptoSIMSearchedEventResponse]):
    """CryptoSIM class to interact with CryptoSIM's API.

    For more details, see [CryptoSIM REST API](https://www.datakey.com.tr/cryptosim)
    """

    def _search_events(
        self, search_params: EventSearchParams
    ) -> CryptoSIMSearchedEvents:
        # query is optional for CryptoSIM
        query: str = search_params.query
        range_min: int = search_params.range
        from_date, to_date = self.get_query_dates(range_min=range_min)
        limit: int = search_params.limit

        body: dict[str, str | int] = {
            "startDate": from_date,
            "endDate": to_date,
            "conditions": query,
            "maxCount": limit,
        }

        search_response: Response | None = self.http_client.request(
            method="post", endpoint="/api/service/search", json=body
        )
        if search_response is None:
            return []

        searched_data: SearchResponse = search_response.json()

        status_code: int = int(searched_data.get("StatusCode", 200))
        if status_code != 200 and "ErrorMessage" in searched_data:
            response_message: str = (
                searched_data.get("ErrorMessage") or "response not contain message"
            )
            log_message(
                mode="error",
                msg=f"Error: {response_message} StatusCode: {status_code} URL: {self.http_client.url}",
            )

        searched_data_events: CryptoSIMSearchedEvents = searched_data.get("Data", [])
        return searched_data_events

    def _parse_event(self, event: CryptoSIMSearchedEventResponse) -> Event:
        """Parse the event to extract the required fields.

        Parameters
        ----------
        event : CryptoSIMSearchedEvents
            The event to parse.

        Returns
        -------
        Event
            The parsed event. (source IP, attack name, destination port, first seen)
        """

        src_ip: str = event.get("src_ip", "n/a")

        # get attack name based on the firewall type
        fw_attack_maps: dict[str, str] = {
            "checkpoint": "flexString2",
            "fortigate": "attack",
        }
        attack_name: str = event.get(
            fw_attack_maps.get(self.customer_fw_type, "n/a"), "n/a"
        )

        # dst_port type is str in CryptoSIM, converted to int for consistency with other SIEMs
        try:
            dst_port = int(event.get("dst_port", 0))
        except (ValueError, TypeError) as e:
            log_message(
                mode="warning",
                msg=f"while converting destination port to int, error occurred: {e} defaulting to 0",
            )
            dst_port = 0

        first_seen: str = event.get("date1", "n/a")

        return Event(
            src_ip=src_ip,
            attack_name=attack_name,
            dst_port=dst_port,
            first_seen=first_seen,
        )
