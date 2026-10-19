"""Integration-style tests for MongoDB IPS event upsert helpers."""

from unittest.mock import MagicMock, patch

from pymongo.database import Database
from src.db.mongo import MongoDB
from src.db.types import MongoDbEvent
from src.services.siems.types import AggregatedEvent


def _sample_event(
    src_ip: str = "203.0.113.1",
    customer_name: str = "acme",
    first_seen: str = "2024-01-15 10:30:00",
) -> AggregatedEvent:
    return {
        "event_type": "ips",
        "src_ip": src_ip,
        "customer_name": customer_name,
        "sector": "finance",
        "attack_name": ["Attack A"],
        "attack_category": ["Web Attack"],
        "dst_port": [443],
        "number_of_occurrences": 1,
        "first_seen": first_seen,
        "last_seen": [],
    }


class TestMergeIpsEvent:
    def test_appends_last_seen_for_new_day(self):
        doc = MongoDbEvent(
            event_type="ips",
            src_ip="203.0.113.1",
            customer_name="acme",
            sector="security",
            first_seen="2024-01-15 10:30:00",
        )
        incoming = _sample_event(first_seen="2024-01-16 08:00:00")

        merged: MongoDbEvent = MongoDB._merge_event(doc=doc, event=incoming)

        assert merged.last_seen == ["2024-01-16 08:00:00"]

    def test_updates_last_seen_for_same_day(self):
        doc = MongoDbEvent(
            event_type="ips",
            src_ip="203.0.113.1",
            customer_name="acme",
            sector="security",
            first_seen="2024-01-15 10:30:00",
            last_seen=["2024-01-15 10:30:00"],
        )
        incoming = _sample_event(first_seen="2024-01-15 18:45:00")

        merged = MongoDB._merge_event(doc=doc, event=incoming)

        assert merged.last_seen == ["2024-01-15 18:45:00"]

    @patch.object(MongoDB, "_ensure_indexes")
    @patch.object(
        MongoDB,
        "_setup_mongodb_config",
        return_value=("mongodb://localhost:27017/test", "test"),
    )
    def test_bulk_write_inserts_new_events(self, _setup, _indexes):
        collection = MagicMock()
        collection.find.return_value = []

        db = MagicMock(spec=Database)
        db.__getitem__.return_value = collection

        mongodb = MongoDB()
        mongodb.db = db
        mongodb.collection = collection

        events = [
            _sample_event(),
            _sample_event(src_ip="203.0.113.2"),
        ]

        mongodb.upsert_events(events=events)

        collection.bulk_write.assert_called_once()

        operations = collection.bulk_write.call_args.kwargs["requests"]

        assert len(operations) == 2

    @patch.object(MongoDB, "_ensure_indexes")
    @patch.object(
        MongoDB,
        "_setup_mongodb_config",
        return_value=("mongodb://localhost:27017/test", "test"),
    )
    def test_bulk_write_updates_existing_event(self, _setup, _indexes):
        collection = MagicMock()
        collection.find.return_value = [
            {
                "_id": "existing-id",
                "event_type": "ips",
                "src_ip": "203.0.113.1",
                "sector": "security",
                "customer_name": "acme",
                "attack_name": ["Attack A"],
                "attack_category": ["Web Attack"],
                "dst_port": [443],
                "first_seen": "2024-01-14 10:30:00",
                "last_seen": ["2024-01-15 10:30:00"],
            }
        ]

        db = MagicMock(spec=Database)
        db.__getitem__.return_value = collection

        mongodb = MongoDB()
        mongodb.collection = collection
        mongodb.db = db

        incoming = _sample_event()
        incoming["attack_name"] = ["Attack B"]
        incoming["first_seen"] = "2024-01-16 08:00:00"

        mongodb.upsert_events(events=[incoming])

        operations = collection.bulk_write.call_args.kwargs["requests"]

        assert len(operations) == 1
        assert operations[0]._filter == {"_id": "existing-id"}
