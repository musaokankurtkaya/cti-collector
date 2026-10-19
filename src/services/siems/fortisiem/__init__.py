from typing import TYPE_CHECKING

from .types import FortiSIEMSearchedEventResponse, FortiSIEMSearchedEvents

if TYPE_CHECKING:
    from .fortisiem import FortiSIEM

__all__ = [
    "FortiSIEM",
    "FortiSIEMSearchedEventResponse",
    "FortiSIEMSearchedEvents",
]


def __getattr__(name: str) -> object:
    if name == "FortiSIEM":
        from .fortisiem import FortiSIEM

        return FortiSIEM
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
