"""Tests for SIEM validation and document preparation helpers."""

import pytest
from src.services.siems.siem import SIEM
from src.services.siems.types import ParsedEvent


class TestIsIpValid:
    @pytest.mark.parametrize(
        "ip",
        ["192.168.1.1", "10.0.0.1", "203.0.113.50", "::1", "2001:db8::1"],
    )
    def test_accepts_valid_ips(self, ip):
        assert SIEM._is_ip_valid(ip=ip) is True

    @pytest.mark.parametrize(
        "ip",
        ["999.999.999.999", "not-an-ip", "", "256.1.1.1", "1.2.3"],
    )
    def test_rejects_invalid_ips(self, ip):
        assert SIEM._is_ip_valid(ip=ip) is False


class TestIsPortValid:
    @pytest.mark.parametrize("port", [1, 80, 443, 65535])
    def test_accepts_valid_ports(self, port):
        assert SIEM._is_port_valid(port=port) is True

    @pytest.mark.parametrize("port", [0, -1, 65536, "80"])
    def test_rejects_invalid_ports(self, port):
        assert SIEM._is_port_valid(port=port) is False


class TestIsFirstSeenValid:
    def test_accepts_expected_format(self):
        assert SIEM._is_first_seen_valid(first_seen="2024-01-15 10:30:00") is True

    @pytest.mark.parametrize(
        "first_seen",
        ["2024-01-15", "15-01-2024 10:30:00", "invalid", ""],
    )
    def test_rejects_invalid_formats(self, first_seen):
        assert SIEM._is_first_seen_valid(first_seen=first_seen) is False


class TestIsEventValid:
    def test_valid_event(self):
        assert (
            SIEM._is_event_valid(
                src_ip="203.0.113.1",
                attack_name="SQL Injection",
                dst_port=443,
                first_seen="2024-01-15 10:30:00",
            )
            is True
        )

    def test_rejects_invalid_ip(self):
        assert (
            SIEM._is_event_valid(
                src_ip="999.999.999.999",
                attack_name="SQL Injection",
                dst_port=443,
                first_seen="2024-01-15 10:30:00",
            )
            is False
        )

    def test_rejects_empty_attack_name(self):
        assert (
            SIEM._is_event_valid(
                src_ip="203.0.113.1",
                attack_name="",
                dst_port=443,
                first_seen="2024-01-15 10:30:00",
            )
            is False
        )


class TestGetAttackCategory:
    def test_extracts_cve_from_attack_name(self):
        category = SIEM._get_attack_category(attack="Exploit CVE-2021-44228 in log4j")
        assert category == "CVE-2021-44228"

    def test_returns_unknown_for_unmapped_attack(self):
        category = SIEM._get_attack_category(attack="totally-unknown-attack-xyz")
        assert category == "Unknown"


class TestPrepareMongoDocument:
    def test_groups_events_by_src_ip(self):
        events: list[ParsedEvent] = [
            {
                "event_type": "ips",
                "src_ip": "203.0.113.1",
                "customer_name": "acme",
                "sector": "finance",
                "first_seen": "2024-01-15 10:30:00",
                "last_seen": [],
                "attack_name": "Attack A",
                "attack_category": "Web Attack",
                "dst_port": 80,
                "number_of_occurrences": 1,
            },
            {
                "event_type": "ips",
                "src_ip": "203.0.113.1",
                "customer_name": "acme",
                "sector": "finance",
                "first_seen": "2024-01-15 10:35:00",
                "last_seen": [],
                "attack_name": "Attack B",
                "attack_category": "Unknown",
                "dst_port": 443,
                "number_of_occurrences": 1,
            },
        ]

        result = SIEM._aggregate_events(parsed_events=events)

        assert len(result) == 1
        doc = result[0]
        assert doc["src_ip"] == "203.0.113.1"
        assert doc["number_of_occurrences"] == 2
        assert set(doc["attack_name"]) == {"Attack A", "Attack B"}
        assert set(doc["dst_port"]) == {80, 443}
        assert doc["attack_category"] == ["Web Attack"]
