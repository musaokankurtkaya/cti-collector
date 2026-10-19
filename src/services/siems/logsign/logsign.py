from requests import Response

from ..siem import SIEM, datetime, log_message, timedelta
from ..types import Event, EventSearchParams
from .types import (
    Any,
    Hits,
    LoginResponse,
    LogsignSearchedEventResponse,
    LogsignSearchedEvents,
    SearchResponse,
)


class Logsign(SIEM[LogsignSearchedEventResponse]):
    """Logsign class to interact with Logsign's API.

    For more details, see [Logsign REST API](https://support.logsign.net/hc/en-us/articles/35621281366930-Logsign-SIEM-API-Documentation)
    """

    def _login_siem(self) -> bool:
        """Login to Logsign, and return access and refresh tokens to be used in cookie based authentication.

        Returns
        -------
        bool
            True if login is successful, False otherwise.
        """

        session_auth = self.http_client.session.auth
        if not session_auth or not isinstance(session_auth, tuple):
            log_message(
                mode="warning",
                msg="session authentication is not a standard username/password tuple",
            )
            return False

        username, password = session_auth
        body: dict[str, str] = {"username": username, "password": password}

        res: Response | None = self.http_client.request(
            method="post", endpoint="/api/login", json=body
        )
        if res is None:
            return False

        login_response_data: LoginResponse = res.json()

        access_token: str | None = login_response_data.get("access_token")
        refresh_token: str | None = login_response_data.get("refresh_token")
        if not access_token or not refresh_token:
            login_response_message: str = login_response_data.get(
                "message",
                "access_token or refresh_token not found in login response, credentials may be wrong",
            )
            log_message(mode="warning", msg=login_response_message)
            return False

        tokens: dict[str, str] = {
            "accessToken": access_token,
            "refreshToken": refresh_token,
        }

        # update the session cookies with the tokens for authentication in the next requests
        self.http_client.session.cookies.update(other=tokens)

        return True

    def _search_events(self, search_params: EventSearchParams) -> LogsignSearchedEvents:
        query: str = search_params.query
        if not query:
            log_message(mode="warning", msg="query is required to search")
            return []

        range_min: int = search_params.range
        from_date, to_date = self.get_query_dates(range_min=range_min)
        limit: int = search_params.limit

        body: dict[str, Any] = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {
                            "range": {
                                "Time.Generated": {"from": from_date, "to": to_date}
                            }
                        },
                    ]
                }
            },
        }

        log_index: str = Logsign.get_log_index(range_min=range_min)
        search_response: Response | None = self.http_client.request(
            method="post", endpoint=f"/api/search/{log_index}/_search", json=body
        )
        if search_response is None:
            return []

        searched_data: SearchResponse = search_response.json()
        searched_data_hits: Hits = searched_data.get("hits", {})
        searched_data_hits_hits: list[dict[str, dict[str, Any]]] = (
            searched_data_hits.get("hits", [])
        )
        searched_data_hits_hits_sources: LogsignSearchedEvents = [
            _source
            for hit in searched_data_hits_hits
            if (_source := hit.get("_source", {}))
        ]
        return searched_data_hits_hits_sources

    def _parse_event(self, event: LogsignSearchedEventResponse) -> Event:
        """Parse the event to extract the required fields.

        Parameters
        ----------
        event : LogsignSearchedEventResponse
            The event to parse.

        Returns
        -------
        IPSEvent
            The parsed event. (source IP, attack name, destination port, first seen)
        """

        src_ip: str = event.get("Source", {}).get("IP", "n/a")

        # get attack name based on the firewall type
        fw_attack_maps: dict[str, str] = {
            "checkpoint": event.get("Attack", {}).get("Info", "n/a"),
            "fortigate": event.get("Event", {}).get("Info", "n/a"),
        }
        attack_name: str = fw_attack_maps.get(self.customer_fw_type, "n/a")

        dst_port: int = event.get("Destination", {}).get("Port", 0)

        first_seen: str = event.get("Time", {}).get("Generated", "n/a")

        return Event(
            src_ip=src_ip,
            attack_name=attack_name,
            dst_port=dst_port,
            first_seen=first_seen,
        )

    @staticmethod
    def get_log_index(range_min: int = 15) -> str:
        """Get the log index to use in the search events.
        In logsign, log index must be defined in the format of "log_%Y%m%d". This means that which index are we going to search in.

        Returns
        -------
        str
            The log index in the format of "log_%Y%m%d"
        """

        MINUTES_IN_A_DAY: int = 1440
        return ",".join(
            f"log_{(datetime.now() - timedelta(days=i)).strftime('%Y%m%d')}"
            for i in range(range_min // MINUTES_IN_A_DAY + 1)
        )
