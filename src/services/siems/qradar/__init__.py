from typing import TYPE_CHECKING

from .types import (
    PostArielSearchResponse,
    PostArielSearchResultItem,
    PostArielSearchResultsResponse,
    QRadarSearchedEventResponse,
    QRadarSearchedEvents,
)

if TYPE_CHECKING:
    from .qradar import QRadar

__all__ = [
    "PostArielSearchResponse",
    "PostArielSearchResultItem",
    "PostArielSearchResultsResponse",
    "QRadar",
    "QRadarSearchedEventResponse",
    "QRadarSearchedEvents",
]


def __getattr__(name: str) -> object:
    if name == "QRadar":
        from .qradar import QRadar

        return QRadar
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
