from typing import Any, TypedDict


class PostArielSearchResponse(TypedDict, total=False):
    """QRadar post ariel search response type"""

    cursor_id: str
    compressed_data_file_count: int
    compressed_data_total_size: int
    data_file_count: int
    data_total_size: int
    index_file_count: int
    index_total_size: int
    processed_record_count: int
    error_messages: list[dict[str, Any]]
    desired_retention_time_msec: int
    progress: int
    progress_details: list[Any]
    query_execution_time: int
    query_string: str
    record_count: int
    save_results: bool
    status: str
    snapshot: dict[str, list[dict[str, Any]]]
    subsearch_ids: list[str]
    search_id: str


class PostArielSearchResultItem(TypedDict, total=False):
    """QRadar post ariel search result item type"""

    src_ip: str
    attack_name: str
    dst_port: int
    first_seen: str
    log_source: str


class PostArielSearchResultsResponse(TypedDict, total=False):
    """QRadar post ariel search results response type"""

    events: list[PostArielSearchResultItem]


type QRadarSearchedEventResponse = PostArielSearchResultItem

type QRadarSearchedEvents = list[QRadarSearchedEventResponse]
