from dataclasses import dataclass
from typing import NamedTuple, TypedDict

from src.utils.constants import QUERY_INTERVAL, QUERY_LIMIT

from .cryptosim import CryptoSIMSearchedEventResponse, CryptoSIMSearchedEvents
from .fortisiem import FortiSIEMSearchedEventResponse, FortiSIEMSearchedEvents
from .graylog import GraylogSearchedEventResponse, GraylogSearchedEvents
from .logsign import LogsignSearchedEventResponse, LogsignSearchedEvents
from .qradar import QRadarSearchedEventResponse, QRadarSearchedEvents


@dataclass
class EventSearchParams:
    """Parameters used to search a SIEM for events.

    Attributes
    ----------
    query : str
        Query to search.
    query_attrs : str, optional
        Query attributes to filter.
    range : int, optional
        Time range in minutes. Default is QUERY_INTERVAL.
    limit : int, optional
        Maximum number of events to return. Default is QUERY_LIMIT.
    """

    query: str
    query_attrs: str | None
    range: int = QUERY_INTERVAL
    limit: int = QUERY_LIMIT


type SearchedEventResponses = (
    GraylogSearchedEventResponse
    | LogsignSearchedEventResponse
    | CryptoSIMSearchedEventResponse
    | QRadarSearchedEventResponse
    | FortiSIEMSearchedEventResponse
)

type SearchedEvents = (
    GraylogSearchedEvents
    | LogsignSearchedEvents
    | CryptoSIMSearchedEvents
    | QRadarSearchedEvents
    | FortiSIEMSearchedEvents
)


class Event(NamedTuple):
    src_ip: str
    attack_name: str
    dst_port: int
    first_seen: str


class ParsedEvent(TypedDict):
    event_type: str
    src_ip: str
    customer_name: str
    sector: str
    first_seen: str
    last_seen: list[str]
    attack_name: str
    attack_category: str
    dst_port: int
    number_of_occurrences: int


class AggregatedEvent(TypedDict):
    event_type: str
    src_ip: str
    customer_name: str
    sector: str
    first_seen: str
    last_seen: list[str]
    attack_name: list[str]
    attack_category: list[str]
    dst_port: list[int]
    number_of_occurrences: int
