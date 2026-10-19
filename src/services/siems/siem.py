import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Generic, TypeVar

from pandas import DataFrame

from src.utils.globals import read_json_file

from ..http_client import HttpClient, log_message
from .types import (
    AggregatedEvent,
    Event,
    EventSearchParams,
    ParsedEvent,
    SearchedEventResponses,
    SearchedEvents,
)


@lru_cache(maxsize=1)
def _load_attack_tags() -> dict[str, str]:
    from src.utils.constants import ATTACK_TAGS_JSON_FILE_PATH

    attack_tags = read_json_file(
        file_path=ATTACK_TAGS_JSON_FILE_PATH.parent,
        file_name=ATTACK_TAGS_JSON_FILE_PATH.name,
    )

    return attack_tags if isinstance(attack_tags, dict) else {}


@lru_cache(maxsize=1)
def _load_excluded_ips() -> list[str]:
    from src.utils.constants import EXCLUDED_IPS_JSON_FILE_PATH

    excluded_ips = read_json_file(
        file_path=EXCLUDED_IPS_JSON_FILE_PATH.parent,
        file_name=EXCLUDED_IPS_JSON_FILE_PATH.name,
    )

    return excluded_ips if isinstance(excluded_ips, list) else []


TEvent = TypeVar("TEvent", bound=SearchedEventResponses)


class SIEM(ABC, Generic[TEvent]):
    def __init__(
        self,
        c_name: str,
        c_sector: str,
        c_fw_type: str,
        c_siem_name: str,
        c_siem_url: str,
        c_siem_username: str,
        c_siem_password: str,
    ) -> None:
        self.customer_name: str = c_name
        self.customer_sector: str = c_sector
        self.customer_fw_type: str = c_fw_type
        self.customer_siem_name: str = c_siem_name.lower()
        self.customer_siem_url: str = c_siem_url.rstrip("/")
        self.customer_siem_username: str = c_siem_username
        self.customer_siem_password: str = c_siem_password

        # http client for SIEM API requests
        self.http_client: HttpClient = HttpClient(
            url=self.customer_siem_url,
            suppress_warnings=True,
            auth=(self.customer_siem_username, self.customer_siem_password),
        )

    def login_siem(self) -> bool:
        """Login to the SIEM to be able to search.

        Returns
        -------
        bool
            True if login is successful, False otherwise.
        """

        login_method: Callable[[], bool] | None = getattr(self, "_login_siem", None)

        return login_method() if login_method else True

    def search_events(self, search_params: EventSearchParams) -> SearchedEvents:
        """Search for any events in the SIEM using queries based on defined in config file."""

        return self._search_events(search_params=search_params)

    @abstractmethod
    def _search_events(self, search_params: EventSearchParams) -> SearchedEvents: ...

    def parse_events(
        self, event_type: str, searched_events: list[TEvent]
    ) -> list[AggregatedEvent]:
        """Parse the events to extract the required fields. (src_ip, attack_name, dst_port, first_seen)

        Parameters
        ----------
        event_type: str
            Which type of event. (e.g. ips, waf etc.)
        searched_events : list[TEvent]
            List of searched events to parse.

        Returns
        -------
        list[AggregatedEvent]
            List of parsed events.
        """

        parsed_events: list[ParsedEvent] = []

        for searched_event in searched_events:
            src_ip, attack_name, dst_port, first_seen = self._parse_event(
                event=searched_event
            )

            is_event_valid: bool = self._is_event_valid(
                src_ip=src_ip,
                attack_name=attack_name,
                dst_port=dst_port,
                first_seen=first_seen,
            )

            is_ip_excluded: bool = self._is_ip_excluded(ip=src_ip)

            if is_event_valid and not is_ip_excluded:
                attack_category: str = self._get_attack_category(attack=attack_name)

                parsed_event: ParsedEvent = {
                    "event_type": event_type,
                    "src_ip": src_ip,
                    "customer_name": self.customer_name,
                    "sector": self.customer_sector,
                    "first_seen": first_seen,
                    "last_seen": [],
                    "attack_name": attack_name,
                    "attack_category": attack_category,
                    "dst_port": dst_port,
                    "number_of_occurrences": 1,
                }

                parsed_events.append(parsed_event)

        return (
            self._aggregate_events(parsed_events=parsed_events) if parsed_events else []
        )

    @abstractmethod
    def _parse_event(self, event: TEvent) -> Event: ...

    @staticmethod
    def _is_event_valid(
        src_ip: str, attack_name: str, dst_port: int, first_seen: str
    ) -> bool:
        """Check if the event is valid.

        Parameters
        ----------
        src_ip : str
            Source IP address of the event.
        attack_name : str
            Name of the attack in the event.
        dst_port : int
            Destination port of the event.
        first_seen : str
            First seen date of the event. (e.g. '2021-09-01 00:00:00')

        Returns
        -------
        bool
            True if the event is valid, False otherwise.
        """

        is_ip: bool = SIEM._is_ip_valid(ip=src_ip)
        is_port: bool = SIEM._is_port_valid(port=dst_port)
        is_first_seen: bool = SIEM._is_first_seen_valid(first_seen=first_seen)
        return all((is_ip, attack_name, is_port, is_first_seen))

    @staticmethod
    def _is_ip_valid(ip: str) -> bool:
        """Validate an IP address using the ipaddress module.

        Parameters
        ----------
        ip : str
            IP address to validate.

        Returns
        -------
        bool
            True if the IP address is valid, False otherwise.
        """

        try:
            ip_address(address=ip)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _is_port_valid(port: int) -> bool:
        """Validate a port number. Port number should be between 1 and 65535.

        Parameters
        ----------
        port : int
            Port number to validate.

        Returns
        -------
        bool
            True if the port number is valid, False otherwise.
        """

        return 0 < port <= 65535 if isinstance(port, int) else False

    @staticmethod
    def _is_first_seen_valid(first_seen: str) -> bool:
        """Validate the first seen date. First seen date should be in the format of 'YYYY-MM-DD HH:MM:SS'.

        Parameters
        ----------
        first_seen : str
            First seen date to validate.

        Returns
        -------
        bool
            True if the first seen date is valid, False otherwise.
        """

        return (
            bool(
                re.match(
                    pattern=r"^\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}$",
                    string=first_seen,
                )
            )
            if isinstance(first_seen, str)
            else False
        )

    @staticmethod
    def _get_attack_category(attack: str) -> str:
        """Determine the attack category for a given attack name.

        - Reads attack tags from 'data/siems/attack_tags.json'.
        - Returns the CVE ID if the attack name matches a CVE pattern.
        - Searches for the attack name in the tags and returns the corresponding category. Otherwise, returns 'Unknown'.

        Parameters
        ----------
        attack : str
            The attack name to categorize.

        Returns
        -------
        str
            Category of attack or 'Unknown'.
        """

        cve_id_pattern: str = r"\bCVE-\d{4}-\d{4,7}\b"
        is_cve: re.Match | None = re.search(pattern=cve_id_pattern, string=attack)
        if is_cve is not None:
            cve_id: str = is_cve.group()
            return cve_id

        attack_tags: dict[str, str] = _load_attack_tags()

        attack_category: str = next(
            (v for k, v in attack_tags.items() if k in attack.lower()), "Unknown"
        )
        return attack_category

    @staticmethod
    def _is_ip_excluded(ip: str) -> bool:
        """Check if the given IP address is in the exclude list.

        Parameters
        ----------
        ip : str
            IP address to check.

        Returns
        -------
        bool
            True if the IP address is in the exclude list, False otherwise.
        """

        try:
            is_ip_private: bool = ip_address(address=ip).is_private
            if is_ip_private:
                return True
        except (ValueError, TypeError):
            log_message(
                mode="warning",
                msg=f"{ip} is not a valid IP address, skipping it",
            )
            return True

        excluded_ips: list[str] = SIEM._get_excluded_ips()
        ip_obj: IPv4Address | IPv6Address = ip_address(address=ip)
        return any(
            ip_obj in ip_network(address=excluded_ip) for excluded_ip in excluded_ips
        )

    @staticmethod
    def _get_excluded_ips() -> list[str]:
        """Get the list of excluded IP addresses from the 'data/siems/excluded_ips.json' file.
        The file should contain a list of IP addresses or CIDR ranges."""

        return _load_excluded_ips()

    @staticmethod
    def _aggregate_events(
        parsed_events: list[ParsedEvent],
    ) -> list[AggregatedEvent]:
        """Aggregate parsed events grouped by source IP address.

        Groups events by 'src_ip' and aggregates fields:
        - Takes the first occurrence of 'event_type', 'customer_name', 'sector', 'first_seen', and 'last_seen'.
        - Aggregates 'attack_name', 'attack_category' and 'dst_port' into unique lists.
        - Counts the number of occurrences for each 'src_ip'.

        Removes 'Unknown' from 'attack_category' if there are multiple categories.

        Parameters
        ----------
        parsed_events : list[ParsedEvent]
            List of parsed events to aggregate.

        Returns
        -------
        list[AggregatedEvent]
            List of aggregated events ready for database insertion.
        """

        df: DataFrame = (
            DataFrame(data=parsed_events)
            .groupby(by="src_ip")
            .agg(
                {
                    **{
                        col: "first"
                        for col in [
                            "event_type",
                            "customer_name",
                            "sector",
                            "first_seen",
                            "last_seen",
                        ]
                    },
                    "attack_name": lambda an: an.explode().unique().tolist(),
                    "attack_category": lambda ac: ac.explode().unique().tolist(),
                    "dst_port": lambda dp: dp.explode().unique().tolist(),
                    "number_of_occurrences": "count",
                }
            )
            .reset_index()
        )

        df["attack_category"] = [
            (
                [item for item in ac if item != "Unknown"]
                if "Unknown" in ac and len(ac) > 1
                else ac
            )
            for ac in df["attack_category"]
        ]

        return df.to_dict(orient="records")  # pyright: ignore[reportReturnType]

    @staticmethod
    def get_query_dates(range_min: int = 15) -> tuple[str, str]:
        """Get from and to date in the format of "%Y-%m-%d %H:%M:%S" based on the range minutes."""

        now: datetime = datetime.now(tz=UTC)
        to_date: str = now.strftime("%Y-%m-%d %H:%M:%S")
        from_date: str = (now - timedelta(minutes=range_min)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        return from_date, to_date
