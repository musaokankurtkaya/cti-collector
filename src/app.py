from pymongo.errors import PyMongoError

from src.db.mongo import MongoDB
from src.services.cvedb_shodan import CveDbShodan, ShodanCveIdResponse
from src.services.ipinfo import IpInfo
from src.services.siems import SIEM, AggregatedEvent, EventSearchParams, SearchedEvents
from src.services.siems.registry import SIEM_CLASSES
from src.utils.constants import CONFIG, QUERY_INTERVAL
from src.utils.globals import func_measure_time, missing_params_exists, time
from src.utils.logger import log_message


@func_measure_time
def main():
    customers_events: list[AggregatedEvent] = get_customers_events()
    if not customers_events:
        log_message(mode="warning", msg="no any events found in any SIEM")
        return

    mongodb: MongoDB = MongoDB()
    try:
        mongodb_events_process(mongodb=mongodb, events=customers_events)
    except PyMongoError as e:
        log_message(mode="error", msg=f"mongodb error: {e}")
    finally:
        mongodb.close_connection()


def get_customers_events() -> list[AggregatedEvent]:
    # get all customers' SIEM configurations from CONFIG
    customers_configs: list[dict[str, str]] = [
        v for k, v in CONFIG.items() if k.startswith("customer")
    ]

    customers_events: list[AggregatedEvent] = []

    for c_conf in customers_configs:
        missing_params: list[str] = missing_params_exists(
            func=SIEM.__init__, expected_params=c_conf, is_self_excluded=True
        )
        if missing_params:
            msg: str = f"{missing_params} not found in {c_conf.get('c_name', '-')} configuration {c_conf}, skipping.."
            log_message(mode="warning", msg=msg)
            continue

        customer_siem_name: str = c_conf.get("c_siem_name", "-").lower()

        siem_class: type[SIEM] | None = SIEM_CLASSES.get(customer_siem_name)

        if siem_class is None:
            msg = f"SIEM:{customer_siem_name} is not supported, make sure to add a class in siems/<{customer_siem_name}>"
            log_message(mode="warning", msg=msg)
            continue

        siem = siem_class(**{k: v for k, v in c_conf.items() if "query" not in k})

        is_logged_in: bool = siem.login_siem()
        if not is_logged_in:
            continue

        c_queries: dict[str, str] = {
            k: v for k, v in c_conf.items() if "query" in k and "attrs" not in k
        }
        for c_query_key, c_query in c_queries.items():
            event_type: str = c_query_key.split("c_siem_")[-1].split("_query")[0]

            searched_events: SearchedEvents = siem.search_events(
                search_params=EventSearchParams(
                    query=c_query,
                    query_attrs=c_conf.get(f"c_siem_{event_type}_query_attrs"),
                )
            )
            if not searched_events:
                log_message(
                    mode="warning",
                    msg=f"no {event_type.upper()} events found for {c_conf['c_name']} in the last {QUERY_INTERVAL}m",
                )
                continue

            parsed_events: list[AggregatedEvent] = siem.parse_events(
                event_type=event_type, searched_events=searched_events
            )
            customers_events.extend(parsed_events)

    return customers_events


def mongodb_upsert_cve(mongodb: MongoDB, cve_id: str) -> None:
    """Insert or update the CVE data to 'cves' collection in the mongodb.

    Parameters
    ----------
    mongodb : MongoDB
        MongoDB object to crud operations on the database.
    cve_id : str
        CVE ID to insert or update in the database.
    """

    is_cve_id_exists: bool = mongodb.is_cve_id_exists(cve_id=cve_id)
    if not is_cve_id_exists:
        cve_structure: ShodanCveIdResponse | None = CveDbShodan.fetch_cve_by_cve_id(
            cve_id=cve_id
        )
        if cve_structure:
            mongodb.upsert_cve(cve_data=cve_structure)


def mongodb_events_process(mongodb: MongoDB, events: list[AggregatedEvent]) -> None:
    """Process on all customers' events & store them in mongodb.

    - Upsert the aggregated event.
    - Upsert the CVE data if cve id exists in attack category list.
    - Score unique ip addresses & update scored ip addresses.
    - Get location of ip address & update it.
    - If the time is between 23:45 and 23:59, repeat scoring for all ip addresses.

    Parameters
    ----------
    mongodb : MongoDB
        MongoDB object to crud operations on the database.
    events : list[AggregatedEvent]
        Aggregated events on all customers' SIEM.
    """

    unique_ips: set[str] = set()
    pending_cves: set[str] = set()

    for e in events:
        unique_ips.add(e["src_ip"])
        pending_cves.update(ac for ac in e["attack_category"] if ac.startswith("CVE-"))

    mongodb.upsert_events(events=events)

    for cve_id in sorted(pending_cves):
        mongodb_upsert_cve(mongodb=mongodb, cve_id=cve_id)
        time.sleep(0.2)

    # ip scoring and location are common, so we do it here instead of above loop
    for ip in unique_ips:
        # ip scoring
        ip, score = mongodb.score_ip(ip=ip)
        mongodb.update_scored_ip(ip=ip, score=score)

        # ip location
        is_ip_located: bool = mongodb.is_ip_located(ip=ip)
        if not is_ip_located:
            country_name, geo_loc = IpInfo.get_ip_info(ip=ip)
            mongodb.update_ip_location(ip=ip, country=country_name, loc=geo_loc)

    # if the time is between 23:45 and 23:59, repeat the scoring for all the IP addresses.
    # this is to ensure that the scoring is updated for the last 15 minutes of the day.
    mongodb.last_check_ip_score()
