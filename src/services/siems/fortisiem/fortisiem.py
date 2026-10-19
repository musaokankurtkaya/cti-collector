from datetime import UTC, datetime
from os import path as os_path
from time import sleep

from requests import Response
from xmltodict import parse as xmltodict_parse

from ..siem import SIEM, log_message
from ..types import Event, EventSearchParams
from .types import Any, FortiSIEMSearchedEventResponse, FortiSIEMSearchedEvents


class FortiSIEM(SIEM[FortiSIEMSearchedEventResponse]):
    """FortiSIEM class to interact with FortiSIEM's API.

    For more details, see [FortiSIEM REST API](https://docs.fortinet.com/document/fortisiem/7.4.0/integration-api-guide/991238/fortisiem-rest-api)
    """

    def _search_events(
        self, search_params: EventSearchParams
    ) -> FortiSIEMSearchedEvents:
        query: str = search_params.query
        if not query:
            log_message(mode="warning", msg="query is required to search")
            return []

        query_attrs: str = search_params.query_attrs or "rawEventMsg"
        range_min: int = search_params.range

        xml_template: str | None = FortiSIEM.get_xml_schema_template(
            schema_file_name="SearchEventSchema.xml"
        )
        if not xml_template:
            return []

        xml_query: str = xml_template.format(
            query=query, query_attrs=query_attrs, query_interval=range_min
        )

        self.http_client.session.headers.update({"Content-Type": "text/xml"})

        res: Response | None = self.http_client.request(
            method="post",
            endpoint="/phoenix/rest/query/eventQuery",
            data=xml_query,
        )
        parsed_response: dict[str, Any] | None = FortiSIEM._parse_response(res=res)
        if not parsed_response:
            return []

        request_id: str | None = parsed_response.get("response", {}).get("@requestId")
        expire_time: str | None = parsed_response.get("result", {}).get("expireTime")
        if not request_id or not expire_time:
            return []

        combined_query_id: str = f"{request_id},{expire_time}"
        is_progress_completed: bool = FortiSIEM.get_query_progress(
            self=self, query_id=combined_query_id
        )
        if not is_progress_completed:
            log_message(
                mode="warning",
                msg=f"query with id {combined_query_id} did not complete within the expected time, skipping fetching results",
            )
            return []

        events: FortiSIEMSearchedEvents = FortiSIEM.get_query_results(
            self=self, query_id=combined_query_id, limit=search_params.limit
        )
        return events

    def get_query_progress(self, query_id: str, max_retries: int = 10) -> bool:
        """Checks the progress of a query using the given query ID, retrying until it reaches 100% or max_retries * 5 seconds timeout occurs.

        Parameters
        ----------
        query_id : str
            The ID of the query whose progress is being checked.
        max_retries : int, optional
            Maximum number of retries (default: 10, total 20 seconds)

        Returns
        -------
        bool
            True if the query reaches 100% progress within timeout, False otherwise.
        """

        log_message(mode="info", msg=f"checking query progress for query id {query_id}")

        retry_count: int = 0
        while retry_count < max_retries:
            res: Response | None = self.http_client.request(
                method="get", endpoint=f"/phoenix/rest/query/progress/{query_id}"
            )
            parsed_response: dict[str, Any] | None = FortiSIEM._parse_response(res=res)
            if not parsed_response:
                log_message(mode="warning", msg="empty response received, retrying...")
                retry_count += 1
                sleep(2)
                continue

            progress: int = int(parsed_response.get("result", {}).get("progress", 0))
            if progress >= 100:
                log_message(mode="info", msg="query progress is completed")
                return True

            log_message(
                mode="info",
                msg=f"query progress is {progress}%, waiting for 2 seconds before rechecking",
            )
            retry_count += 1
            sleep(2)
            continue

        return False

    def get_query_results(
        self, query_id: str, offset: int = 0, limit: int = 9999
    ) -> list[dict[str, Any]]:

        all_events: list[dict[str, Any]] = []
        while True:
            res: Response | None = self.http_client.request(
                method="get",
                endpoint=f"/phoenix/rest/query/events/{query_id}/{offset}/{limit}",
            )
            parsed_response: dict[str, Any] | None = FortiSIEM._parse_response(res=res)
            if parsed_response is None:
                return all_events

            query_result: dict[str, Any] | None = parsed_response.get("result", {}).get(
                "queryResult"
            )
            if not query_result:
                return all_events

            total_count: int = int(query_result.get("@totalCount", 0))
            events: dict[str, Any] | None = query_result.get("events")
            if not events:
                return all_events

            events_event: list[dict[str, Any]] | dict[str, Any] | None = events.get(
                "event"
            )
            if not events_event:
                return all_events

            # if events_event is a dict, convert it to a list
            if isinstance(events_event, dict):
                events_event = [events_event]

            all_events.extend(events_event)

            offset += limit
            if offset >= total_count:
                log_message(
                    mode="info",
                    msg=f"fetched {len(all_events)} events successfully",
                )
                break

        return all_events

    def _parse_event(self, event: FortiSIEMSearchedEventResponse) -> Event:
        """Parse the event to extract the required fields.

        Parameters
        ----------
        event : FortiSIEMSearchedEventResponse
            The event to parse.

        Returns
        -------
        Event
            The parsed event. (source IP, attack name, destination port, first seen)
        """

        # get the event attributes from the searched event to parse
        event_attributes: list[dict[str, Any]] = event.get("attributes", {}).get(
            "attribute", []
        )
        if not event_attributes:
            log_message(
                mode="warning",
                msg="searched event does not have any attributes to parse, skipping the event",
            )
            return Event(src_ip="n/a", attack_name="n/a", dst_port=0, first_seen="n/a")

        src_ip: str = FortiSIEM._get_event_attribute_value(
            event_attributes=event_attributes, attribute_name="srcIpAddr"
        )

        attack_name: str = FortiSIEM._get_event_attribute_value(
            event_attributes=event_attributes, attribute_name="attackName"
        )

        try:
            dst_port: int = int(
                FortiSIEM._get_event_attribute_value(
                    event_attributes=event_attributes, attribute_name="destIpPort"
                )
            )
        except (ValueError, TypeError) as e:
            log_message(
                mode="warning",
                msg=f"while converting destination port to int, error occurred: {e} defaulting to 0",
            )
            dst_port = 0

        # timestamp format is '%a %b %d %H:%M:%S TRT %Y' in FortiSIEM, converted to '%Y-%m-%d %H:%M:%S' format for consistency with other SIEMs
        first_seen: str = FortiSIEM._get_event_attribute_value(
            event_attributes=event_attributes, attribute_name="phRecvTime"
        )
        try:
            first_seen = (
                datetime.strptime(first_seen, "%a %b %d %H:%M:%S TRT %Y")
                .replace(tzinfo=UTC)
                .strftime("%Y-%m-%d %H:%M:%S")
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

    @staticmethod
    def _parse_response(res: Response | None) -> dict[str, Any] | None:
        """Parse the response from the FortiSIEM API.

        Parameters
        ----------
        res : Response | None
            The response from the FortiSIEM API.

        Returns
        -------
        dict[str, Any] | None
            The parsed response as a dictionary if parsing is successful, else None.
        """

        if res is None:
            return

        try:
            res_content: str = res.content.decode()
            data: dict[str, Any] = xmltodict_parse(xml_input=res_content)

            data_response: dict[str, Any] | None = data.get("response")
            if not data_response:
                return

            data_response_result: dict[str, Any] | None = data_response.get("result")
            if not data_response_result:
                return

            error_msg: str | None = data_response.get("error", {}).get(
                "description"
            ) or data_response_result.get("error", {}).get("description")
            if error_msg:
                log_message(mode="error", msg=error_msg)
                return

            return {"response": data_response, "result": data_response_result}
        except Exception as e:  # noqa: BLE001
            error_msg = f"failed to parse response, error: {e!s}"
            log_message(mode="error", msg=error_msg)
            return

    @staticmethod
    def get_xml_schema_template(schema_file_name: str) -> str | None:
        """Get the XML schema template from the templates folder.

        Parameters
        ----------
        schema_file_name : str
            The name of the schema file to load.

        Returns
        -------
        str | None
            The XML schema template as a string if found, else None.
        """

        _, ext = os_path.splitext(p=schema_file_name)
        if ext.lower() != ".xml":
            error_msg: str = f"schema file name must be an xml file, but got {ext}"
            log_message(mode="error", msg=error_msg)
            return

        file_path: str = os_path.join(
            os_path.dirname(p=__file__), "templates", schema_file_name
        )
        if not os_path.exists(path=file_path):
            error_msg: str = (
                f"schema file: {schema_file_name} not found in fortisiem/templates/"
            )
            log_message(mode="error", msg=error_msg)
            return

        with open(file=file_path, encoding="utf-8") as template_file:
            template: str = template_file.read()

        return template

    @staticmethod
    def _get_event_attribute_value(
        event_attributes: list[dict[str, Any]], attribute_name: str
    ) -> str:
        """Get the attribute value from the event attributes.

        Parameters
        ----------
        event_attributes : list[dict[str, Any]]
            The list of event attributes.
        attribute_name : str
            The name of the attribute to get the value.

        Returns
        -------
        str
            The value of the attribute. If the attribute is not found, "n/a" is returned.
        """

        return (
            next(
                event_attr.get("#text")
                for event_attr in event_attributes
                if event_attr.get("@name") == attribute_name
            )
            or "n/a"
        )
