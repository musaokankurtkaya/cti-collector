from typing import TYPE_CHECKING

from .types import GraylogSearchedEventResponse, GraylogSearchedEvents, SearchResponse

if TYPE_CHECKING:
    from .graylog import Graylog

__all__ = [
    "Graylog",
    "GraylogSearchedEventResponse",
    "GraylogSearchedEvents",
    "SearchResponse",
]


def __getattr__(name: str) -> object:
    if name == "Graylog":
        from .graylog import Graylog

        return Graylog
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
