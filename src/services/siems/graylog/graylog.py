from datetime import datetime

from requests import Response

from ..siem import SIEM, log_message
from ..types import Event, EventSearchParams
from .types import (
    GraylogSearchedEventResponse,
    GraylogSearchedEvents,
    SearchResponse,
)


class Graylog(SIEM[GraylogSearchedEventResponse]):
    """Graylog class to interact with Graylog's API.

    For more details, see [Graylog REST API](https://go2docs.graylog.org/current/setting_up_graylog/rest_api.html)
    """

    def _search_events(self, search_params: EventSearchParams) -> GraylogSearchedEvents:
        query: str = search_params.query
        if not query:
            log_message(mode="warning", msg="query is required to search")
            return []

        # time range: in seconds for Graylog, converted from minutes for consistency with other SIEMs
        range_min: int = search_params.range * 60
        limit: int = search_params.limit

        params: dict[str, str | int] = {
            "query": r"{query}".format(query=query),  # noqa: UP032
            "range": range_min,
            "limit": limit,
        }

        search_response: Response | None = self.http_client.request(
            method="get", endpoint="/api/search/universal/relative", params=params
        )
        if search_response is None:
            return []

        searched_data: SearchResponse = search_response.json()

        searched_data_messages: GraylogSearchedEvents = searched_data.get(
            "messages", []
        )

        return [
            message
            for searched_data_message in searched_data_messages
            if (message := searched_data_message.get("message", {}))
        ]

    def _parse_event(self, event: GraylogSearchedEventResponse) -> Event:
        """Parse the event to extract the required fields.

        Parameters
        ----------
        event : GraylogSearchedEventResponse
            The event to parse.

        Returns
        -------
        Event
            The parsed event. (source IP, attack name, destination port, first seen)
        """

        src_ip: str = event.get("SourceIP", "n/a")

        # get attack name based on the firewall type
        fw_attack_maps: dict[str, str] = {
            "checkpoint": "ProtectionName",
            "fortigate": "DeviceMessage",
            "paloalto": "PaloAltoThreatID",
        }
        attack_name: str = event.get(
            fw_attack_maps.get(self.customer_fw_type, "n/a"), "n/a"
        )

        # dst_port type is str in Graylog, converted to int for consistency with other SIEMs
        try:
            dst_port = int(event.get("DestinationPort", 0))
        except (ValueError, TypeError) as e:
            log_message(
                mode="warning",
                msg=f"while converting destination port to int, error occurred: {e} defaulting to 0",
            )
            dst_port = 0

        # timestamp format is '%Y-%m-%dT%H:%M:%S.%fZ' in Graylog, converted to '%Y-%m-%d %H:%M:%S' format for consistency with other SIEMs
        first_seen: str = event.get("timestamp", "n/a")
        try:
            first_seen = datetime.fromisoformat(first_seen).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (ValueError, TypeError) as e:
            log_message(
                mode="warning",
                msg=f"while converting timestamp to datetime, error occurred: {e} defaulting to 'n/a'",
            )
            first_seen = "n/a"

        return Event(
            src_ip=src_ip,
            attack_name=attack_name,
            dst_port=dst_port,
            first_seen=first_seen,
        )
