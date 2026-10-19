from typing import TYPE_CHECKING

from .types import (
    CryptoSIMSearchedEventResponse,
    CryptoSIMSearchedEvents,
    Data,
    SearchResponse,
)

if TYPE_CHECKING:
    from .cryptosim import CryptoSIM

__all__ = [
    "CryptoSIM",
    "CryptoSIMSearchedEventResponse",
    "CryptoSIMSearchedEvents",
    "Data",
    "SearchResponse",
]


def __getattr__(name: str) -> object:
    if name == "CryptoSIM":
        from .cryptosim import CryptoSIM

        return CryptoSIM
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
