from typing import Any, TypedDict

type LogsignSearchedEventResponse = dict[str, dict[str, Any]]

type LogsignSearchedEvents = list[LogsignSearchedEventResponse]


class LoginResponse(TypedDict, total=False):
    """Logsign login response type"""

    status: bool
    message: str
    user_info: dict[str, Any]
    access_token: str
    refresh_token: str


class Hits(TypedDict, total=False):
    """Logsign search response hits type"""

    total: dict[str, Any]
    max_score: float
    hits: list[dict[str, Any]]


class SearchResponse(TypedDict, total=False):
    """Logsign search response type"""

    took: int
    timed_out: bool
    _shards: dict[str, int]
    hits: Hits
