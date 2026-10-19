from datetime import datetime
from typing import Any, TypedDict

type GraylogSearchedEventResponse = dict[str, Any]

type GraylogSearchedEvents = list[GraylogSearchedEventResponse]


class SearchResponse(TypedDict, total=False):
    """Graylog /api/search/universal/relative response type.

    For more details, see [SearchResponse](https://github.com/yumimobi/graylog.py/blob/master/docs/SearchResponse.md)
    """

    to: datetime
    fields: list[str]
    from_: datetime
    time: int
    query: str
    messages: list[dict[str, Any]]
    built_query: str
    decoration_stats: dict[str, Any]
    total_results: int
    used_indices: list[dict[str, Any]]
