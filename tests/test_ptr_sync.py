from pathlib import Path
from app.bind.ptr_sync import ip_to_reverse_fqdn, find_matching_reverse_zone
from app.bind.discovery import DiscoveredZone


def test_ip_to_reverse_fqdn():
    assert ip_to_reverse_fqdn("192.168.1.50") == "50.1.168.192.in-addr.arpa."
    assert ip_to_reverse_fqdn("10.0.0.1") == "1.0.0.10.in-addr.arpa."
    assert ip_to_reverse_fqdn("invalid-ip") is None


def test_find_matching_reverse_zone():
    zones = [
        DiscoveredZone(
            name="1.168.192.in-addr.arpa",
            file_path=Path("/tmp/db.192.168.1"),
            zone_type="master",
            is_reverse=True,
            source="manual",
        ),
        DiscoveredZone(
            name="home.lab",
            file_path=Path("/tmp/db.home.lab"),
            zone_type="master",
            is_reverse=False,
            source="manual",
        ),
    ]

    rev_fqdn = ip_to_reverse_fqdn("192.168.1.50")
    matched_zone, rel_name = find_matching_reverse_zone(rev_fqdn, zones=zones)

    assert matched_zone is not None
    assert matched_zone.name == "1.168.192.in-addr.arpa"
    assert rel_name == "50"
