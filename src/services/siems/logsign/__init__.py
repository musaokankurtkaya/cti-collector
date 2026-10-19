from typing import TYPE_CHECKING

from .types import (
    Hits,
    LoginResponse,
    LogsignSearchedEventResponse,
    LogsignSearchedEvents,
    SearchResponse,
)

if TYPE_CHECKING:
    from .logsign import Logsign

__all__ = [
    "Hits",
    "LoginResponse",
    "Logsign",
    "LogsignSearchedEventResponse",
    "LogsignSearchedEvents",
    "SearchResponse",
]


def __getattr__(name: str) -> object:
    if name == "Logsign":
        from .logsign import Logsign

        return Logsign
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
