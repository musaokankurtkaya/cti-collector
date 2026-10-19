from time import sleep

from requests import Response

from ..siem import SIEM, log_message
from ..types import Event, EventSearchParams
from .types import (
    PostArielSearchResponse,
    PostArielSearchResultsResponse,
    QRadarSearchedEventResponse,
    QRadarSearchedEvents,
)


class QRadar(SIEM[QRadarSearchedEventResponse]):
    """QRadar class to interact with IBM QRadar's API.

    For more details, see [IBM QRadar REST API](https://ibmsecuritydocs.github.io/qradar_api_16.0)
    """

    def _search_events(self, search_params: EventSearchParams) -> QRadarSearchedEvents:
        # range and limit are not used in QRadar because the search is done using a AQL query

        query: str = search_params.query
        if not query:
            log_message(mode="warning", msg="query is required to search")
            return []

        # create a new search based on the given AQL query
        create_search_response: Response | None = self.http_client.request(
            method="post",
            endpoint="/api/ariel/searches",
            params={"query_expression": query},
        )
        if create_search_response is None:
            return []

        created_search_data: PostArielSearchResponse = create_search_response.json()
        search_id: str | None = created_search_data.get("search_id")
        if not search_id:
            return []

        # repeat the search until it's completed to get the results
        max_retries: int = 10  # 10 retries * 2 seconds = 20 seconds
        retry_count: int = 0
        is_searching: bool = False
        while not is_searching and retry_count < max_retries:
            search_response: Response | None = self.http_client.request(
                method="get", endpoint=f"/api/ariel/searches/{search_id}"
            )
            if search_response is None:
                return []

            searched_data: PostArielSearchResponse = search_response.json()
            status: str = str(searched_data.get("status")).strip().upper()
            is_searching = status == "COMPLETED"

            if not is_searching:
                retry_count += 1
                sleep(2)

        if not is_searching:
            log_message(
                mode="warning",
                msg=f"QRadar search {search_id} did not complete within {max_retries * 2} seconds, skipping results",
            )
            return []

        # get the results of the search
        searched_data_results_response: Response | None = self.http_client.request(
            method="get", endpoint=f"/api/ariel/searches/{search_id}/results"
        )
        if searched_data_results_response is None:
            return []

        searched_data_results_data: PostArielSearchResultsResponse = (
            searched_data_results_response.json()
        )

        searched_data_results_events: QRadarSearchedEvents = (
            searched_data_results_data.get("events", [])
        )
        return searched_data_results_events

    def _parse_event(self, event: QRadarSearchedEventResponse) -> Event:
        """Parse the event to extract the required fields.

        Parameters
        ----------
        event : QRadarSearchedEventResponse
            The event to parse.

        Returns
        -------
        Event
            The parsed event. (source IP, attack name, destination port, first seen)
        """

        src_ip: str = event.get("src_ip", "n/a")
        attack_name: str = event.get("attack_name", "n/a")
        dst_port: int = event.get("dst_port", 0)
        first_seen: str = event.get("first_seen", "n/a")

        return Event(
            src_ip=src_ip,
            attack_name=attack_name,
            dst_port=dst_port,
            first_seen=first_seen,
        )
