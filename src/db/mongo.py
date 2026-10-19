import urllib.parse

from pymongo import InsertOne, MongoClient, UpdateOne
from pymongo.collection import Collection
from pymongo.database import Database

from src.services.cvedb_shodan import ShodanCveIdResponse
from src.services.siems import AggregatedEvent
from src.utils.constants import CONFIG
from src.utils.logger import datetime, log_message

from .types import MongoDbEvent


class MongoDB:
    """Manage MongoDB storage for events, CVEs, and IP enrichment data."""

    def __init__(self) -> None:
        mongo_url, database = self._setup_mongodb_config()

        self.client: MongoClient = MongoClient(mongo_url)
        self.db: Database = self.client[database]
        self.collection: Collection | None = None

        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        events = self.db["events"]
        events.create_index(
            [("event_type", 1), ("src_ip", 1), ("customer_name", 1)],
            name="search_by_event_type_ip_customer_name",
        )
        events.create_index(keys="src_ip", name="search_by_src_ip")

        cves = self.db["cves"]
        cves.create_index(keys="cve_id", name="search_by_cve_id")

    def upsert_events(self, events: list[AggregatedEvent]) -> None:
        """Insert or update multiple events using a single prefetch and bulk write."""

        collapsed_events: dict[tuple[str, str, str], AggregatedEvent] = {}
        for e in events:
            key = (e["event_type"], e["src_ip"], e["customer_name"])
            if key not in collapsed_events:
                collapsed_events[key] = e
                continue

            base: AggregatedEvent = collapsed_events[key]

            temp_doc: MongoDbEvent = MongoDbEvent(
                event_type=base["event_type"],
                src_ip=base["src_ip"],
                customer_name=base["customer_name"],
                sector=base["sector"],
                first_seen=base["first_seen"],
                attack_name=base["attack_name"],
                dst_port=base["dst_port"],
                attack_category=base["attack_category"],
                last_seen=base["last_seen"],
            )

            merged_doc: MongoDbEvent = self._merge_event(doc=temp_doc, event=e)

            collapsed_events[key] = {
                **base,
                "attack_name": merged_doc.attack_name,
                "dst_port": merged_doc.dst_port,
                "attack_category": merged_doc.attack_category,
                "last_seen": merged_doc.last_seen,
                "number_of_occurrences": base.get("number_of_occurrences", 1) + 1,
            }

        self.collection = self.db["events"]
        event_keys: set[tuple[str, str, str]] = set(collapsed_events.keys())
        filters: list[dict[str, str]] = [
            {"event_type": event_type, "src_ip": src_ip, "customer_name": customer_name}
            for event_type, src_ip, customer_name in event_keys
        ]

        existing_docs: dict[tuple[str, str, str], MongoDbEvent] = {}
        if filters:
            for raw_doc in self.collection.find(filter={"$or": filters}):
                doc = MongoDbEvent(**raw_doc)
                existing_docs[(doc.event_type, doc.src_ip, doc.customer_name)] = doc

        operations: list[InsertOne | UpdateOne] = []

        for key, event in collapsed_events.items():
            event_type, src_ip, customer_name = key
            doc: MongoDbEvent | None = existing_docs.get(key)

            if doc is None:
                operations.append(InsertOne(document=event))
                log_message(
                    mode="info",
                    msg=f"{event_type} event {src_ip} with ip inserted with customer {customer_name}",
                )
                continue

            doc = self._merge_event(doc=doc, event=event)
            operations.append(
                UpdateOne(
                    filter={"_id": doc._id},
                    update={
                        "$set": {
                            "attack_name": doc.attack_name,
                            "dst_port": doc.dst_port,
                            "attack_category": doc.attack_category,
                            "last_seen": doc.last_seen,
                        },
                        "$inc": {"number_of_occurrences": 1},
                    },
                )
            )
            log_message(
                mode="info",
                msg=f"{event_type} event {src_ip} with ip updated with customer {customer_name}",
            )

        if operations:
            self.collection.bulk_write(requests=operations, ordered=True)

    def is_cve_id_exists(self, cve_id: str) -> bool:
        """Checks if the given CVE ID exists in the 'cves' collection.

        Parameters
        ----------
        cve_id : str
            CVE ID to check (e.g. CVE-2021-1234)

        Returns
        -------
        bool
            True if the CVE ID exists, otherwise False
        """

        self.collection = self.db["cves"]

        f = {"cve_id": cve_id}

        return bool(self.collection.find_one(filter=f))

    def upsert_cve(self, cve_data: ShodanCveIdResponse) -> None:
        """Insert or update the CVE data in the 'cves' collection.

        Parameters
        ----------
        cve_data : ShodanCveIdResponse
            CVE data to be inserted or updated.
        """

        self.collection = self.db["cves"]

        cve_id: str = cve_data["cve_id"]

        f = {"cve_id": cve_id}
        u = {"$set": cve_data}

        result = self.collection.update_one(filter=f, update=u, upsert=True)
        log_message(
            mode="info",
            msg=f"{cve_id} {'inserted' if result.upserted_id else 'updated'} in cve collection",
        )

    def score_ip(self, ip: str) -> tuple[str, int]:
        """Calculates the score of the given IP address.

        The score is calculated based on the following criteria:
            - Time-based score: 10 points for 0-15 days, 8 points for 16-30 days, 6 points for 31-90 days, 4 points for 90+ days.
            - Total occurrence count: max 15 points.
            - Total attack count: max 15 points.
            - Total score: max 100 points.
            - Severity: Low (0-25), Medium (26-50), High (51-75), Critical (76-100).

        Parameters
        ----------
        ip : str
            IP address to score.

        Returns
        -------
        tuple[str, int]
            Tuple containing the IP address and its score.
        """

        self.collection = self.db["events"]

        ip_score: int = 0  # total score of the ip
        total_occurrence_count: int = 0  # total occurrence count of the ip
        total_attack_count: int = 0  # total attack count of the ip
        # time-based score
        time_difference_score_map = {
            range(16): 10,  # 0-15 days > 10 points
            range(16, 31): 8,
            range(31, 91): 6,  # 31-90 days > 6 points
        }

        docs: list[MongoDbEvent] = list(self.collection.find(filter={"src_ip": ip}))
        if not docs:
            log_message(
                mode="warning",
                msg=f"ip:{ip} not found in the database, returning ip with score 0",
            )
            return ip, 0

        for ip_doc in docs:
            try:
                doc_last_seen: str = ip_doc.last_seen[-1]
            except IndexError:
                doc_last_seen = (
                    ip_doc.first_seen
                )  # fallback to first_seen if last_seen is empty

            time_difference = abs(
                datetime.now() - datetime.strptime(doc_last_seen, "%Y-%m-%d %H:%M:%S")
            )
            # adds time-based points for each customer
            if time_difference.days > 90:
                ip_score += 4  # 90+ days > 4 points
            else:
                ip_score += next(
                    time_score
                    for time_range, time_score in time_difference_score_map.items()
                    if time_difference.days in time_range
                )

            total_occurrence_count += ip_doc.number_of_occurrences
            total_attack_count += len(ip_doc.attack_name)

        # max 15 points for total occurrence & total attack count
        ip_score += min(total_occurrence_count, 15) + min(total_attack_count, 15)
        # max 100 points total score
        ip_score = min(ip_score, 100)
        return ip, int(ip_score)

    def update_scored_ip(self, ip: str, score: int) -> None:
        """Updates score and severity of the given IP address in the 'events' collection.

        Parameters
        ----------
        ip : str
            IP address to update.
        score : int
            Score to update.
        """

        self.collection = self.db["events"]

        severity_map = {
            range(26): "Low",  # 0-25 points > Low
            range(26, 51): "Medium",
            range(51, 76): "High",
            range(76, 101): "Critical",  # 76-100 points > Critical
        }

        ip_severity: str = next(
            severity
            for score_range, severity in severity_map.items()
            if score in score_range
        )

        f = {"src_ip": ip}
        u = {"$set": {"score": score, "severity": ip_severity}}

        self.collection.update_many(filter=f, update=u)
        log_message(
            mode="info",
            msg=f"score of {ip} address has been updated to {score}",
        )

    def is_ip_located(self, ip: str) -> bool:
        """Checks if the given IP address is located in 'events' collection.

        Parameters
        ----------
        ip : str
            IP address to check.

        Returns
        -------
        bool
            True if the IP address is located, False otherwise.
        """

        self.collection = self.db["events"]

        f = {"src_ip": ip}
        p = {"_id": 0, "country": 1, "loc": 1}

        docs: list[dict[str, str]] = list(self.collection.find(filter=f, projection=p))
        return (
            all(
                (
                    doc.get("country")
                    and doc.get("loc")
                    and doc.get("country") != "Unknown"
                )
                for doc in docs
            )
            if docs
            else False
        )

    def update_ip_location(self, ip: str, country: str, loc: str) -> None:
        """Updates country and loc of the given IP address in the 'events' collection.

        Parameters
        ----------
        ip : str
            IP address to update.
        country : str
            Country to update.
        loc : str
            Location to update.
        """

        self.collection = self.db["events"]

        f = {"src_ip": ip}
        u = {"$set": {"country": country, "loc": loc}}

        self.collection.update_many(filter=f, update=u)
        log_message(mode="info", msg=f"country & loc of {ip} updated")

    def last_check_ip_score(self) -> None:
        """Checks the last 15 minutes of the day and updates the score of the IP addresses in the 'events' collection.

        Why this function is needed?
        - Documents for some ip addresses may be deleted over time due to the retention policy.
        """

        cdate: datetime = datetime.now()
        # checks the last 15 minutes of the day (23:45 - 23:59)
        last_check_date: bool = cdate.hour == 23 and 45 <= cdate.minute <= 59
        if last_check_date:
            self.collection = self.db["events"]

            unique_ips: list[str] = self.collection.distinct(key="src_ip")
            for ip in unique_ips:
                ip, score = self.score_ip(ip=ip)
                self.update_scored_ip(ip=ip, score=score)

            log_message(
                mode="info",
                msg="mongodb: last check for the ip scores has been completed successfully",
            )

    def close_connection(self) -> None:
        if self.client:
            self.client.close()
            log_message(mode="info", msg="mongodb: connection terminated successfully")

    @staticmethod
    def _setup_mongodb_config() -> tuple[str, str]:
        """Retrieves MongoDB configuration from the config file and constructs the MongoDB URL.
        When ``uri`` is set in the mongodb section it is used directly (e.g. Atlas connection strings).
        Otherwise host/port/username/password/database are assembled into a connection URL.
        If the configuration is not provided, it defaults to localhost:27017 and test database.

        Returns
        -------
        tuple[str, str]
            MongoDB URL and database name.
        """

        mongodb_conf: dict[str, str] = CONFIG.get("mongodb", {})
        uri: str | None = mongodb_conf.get("uri")
        database: str | None = mongodb_conf.get("database")

        if uri:
            if not database:
                log_message(
                    mode="warning",
                    msg="mongodb: database name is missing in the config file, defaulting to test",
                )
                database = "test"
            return uri, database

        host, port, username, password, database = (
            mongodb_conf.get(key, "")
            for key in ["host", "port", "username", "password", "database"]
        )

        if not all((host, port)):
            log_message(
                mode="warning",
                msg="mongodb: host or port is missing in the config file, defaulting to localhost:27017",
            )
            host, port = "localhost", 27017

        if not database:
            log_message(
                mode="warning",
                msg="mongodb: database name is missing in the config file, defaulting to test",
            )
            database = "test"

        mongo_url = f"mongodb://{host}:{port}/{database}"

        if all((username, password)):
            username: str = urllib.parse.quote_plus(string=username)
            password: str = urllib.parse.quote_plus(string=password)

            mongo_url = f"mongodb://{username}:{password}@{host}:{port}/{database}"
        else:
            log_message(
                mode="warning",
                msg="mongodb: username or password is missing in the config file, connecting without auth",
            )

        return mongo_url, database

    @staticmethod
    def _merge_event(doc: MongoDbEvent, event: AggregatedEvent) -> MongoDbEvent:
        doc_attack_names: list[str] = doc.attack_name
        doc_attack_names.extend(
            an for an in event["attack_name"] if an not in doc_attack_names
        )

        doc_dst_ports: list[int] = doc.dst_port
        doc_dst_ports.extend(dp for dp in event["dst_port"] if dp not in doc_dst_ports)

        doc_attack_categories: list[str] = doc.attack_category
        doc_attack_categories.extend(
            ac for ac in event["attack_category"] if ac not in doc_attack_categories
        )

        if "Unknown" in doc_attack_categories and len(doc_attack_categories) > 1:
            doc_attack_categories.remove("Unknown")

        event_last_date: datetime = datetime.strptime(
            event["first_seen"], "%Y-%m-%d %H:%M:%S"
        )
        doc_last_seen_dates: list[str] = doc.last_seen
        doc_last_date: datetime | None = (
            datetime.strptime(doc_last_seen_dates[-1], "%Y-%m-%d %H:%M:%S")
            if doc_last_seen_dates
            else None
        )
        if doc_last_date and doc_last_date.date() == event_last_date.date():
            doc_last_seen_dates[-1] = event["first_seen"]
        else:
            doc_last_seen_dates.append(event["first_seen"])

        return doc
