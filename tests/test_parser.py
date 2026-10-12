from app.bind.parser import parse_zone_text, serialize_zone, DnsRecord

SAMPLE_ZONE = """$ORIGIN home.lab.
$TTL 3600
@       IN      SOA     ns1.home.lab. hostmaster.home.lab. (
                        2026101101 ; Serial
                        3600       ; Refresh
                        600        ; Retry
                        1209600    ; Expire
                        86400      ; Minimum TTL
                        )
@       IN      NS      ns1.home.lab.
@       IN      A       192.168.1.1
ns1     IN      A       192.168.1.2
router  IN      A       192.168.1.1
nas     IN      A       192.168.1.10
cname1  IN      CNAME   router.home.lab.
@       IN      MX      10 mail.home.lab.
"""


def test_parse_zone_text():
    model = parse_zone_text(SAMPLE_ZONE, origin="home.lab.")
    assert model.origin == "home.lab."
    assert model.soa is not None
    assert model.soa.serial == 2026101101
    assert model.soa.mname == "ns1.home.lab."

    record_names = {r.name for r in model.records}
    assert "@" in record_names
    assert "router" in record_names
    assert "nas" in record_names
    assert "cname1" in record_names

    types = {r.rtype for r in model.records}
    assert "A" in types
    assert "CNAME" in types
    assert "MX" in types
    assert "NS" in types


def test_serialize_zone_bumps_serial():
    model = parse_zone_text(SAMPLE_ZONE, origin="home.lab.")
    original_serial = model.soa.serial
    serialized = serialize_zone(model, bump_serial=True)

    assert "; Zone file for home.lab." in serialized
    assert "IN      SOA" in serialized
    assert "router" in serialized
    # Re-parse to verify serial was incremented
    new_model = parse_zone_text(serialized, origin="home.lab.")
    assert new_model.soa.serial > original_serial
