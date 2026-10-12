import ipaddress
from app.bind.discovery import DiscoveredZone, get_all_zones
from app.bind.parser import parse_zone_file, serialize_zone, DnsRecord
from app.bind.executor import save_zone_file


def ip_to_reverse_fqdn(ip_str: str) -> str | None:
    """Convert an IPv4 or IPv6 string to its reverse in-addr.arpa or ip6.arpa FQDN."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.reverse_pointer + "."
    except ValueError:
        return None


def find_matching_reverse_zone(reverse_fqdn: str, zones: list[DiscoveredZone] | None = None) -> tuple[DiscoveredZone | None, str | None]:
    """Find the most specific reverse zone that covers the given reverse FQDN.
    Returns (zone, relative_record_name).
    """
    if not reverse_fqdn:
        return None, None

    all_zones = zones or get_all_zones()
    reverse_zones = [z for z in all_zones if z.is_reverse]

    best_zone: DiscoveredZone | None = None
    best_len = 0

    clean_fqdn = reverse_fqdn.lower().rstrip(".") + "."

    for rz in reverse_zones:
        rz_origin = rz.name.lower().rstrip(".") + "."
        if clean_fqdn.endswith("." + rz_origin) or clean_fqdn == rz_origin:
            if len(rz_origin) > best_len:
                best_len = len(rz_origin)
                best_zone = rz

    if not best_zone:
        return None, None

    # Calculate relative record name
    rz_origin = best_zone.name.lower().rstrip(".") + "."
    rel_name = clean_fqdn[:-len(rz_origin)].rstrip(".")
    if not rel_name:
        rel_name = "@"

    return best_zone, rel_name


async def sync_ptr_record(
    ip_str: str,
    target_fqdn: str,
    action: str = "create",  # "create", "delete"
    ttl: int = 3600,
) -> tuple[bool, str]:
    """Automatically create, update, or remove a PTR record in the corresponding reverse zone."""
    rev_fqdn = ip_to_reverse_fqdn(ip_str)
    if not rev_fqdn:
        return False, f"Invalid IP address: {ip_str}"

    rev_zone, rel_name = find_matching_reverse_zone(rev_fqdn)
    if not rev_zone or not rel_name:
        return False, f"No matching reverse zone found for {ip_str}"

    clean_target = target_fqdn.strip()
    if not clean_target.endswith("."):
        clean_target += "."

    try:
        model = parse_zone_file(rev_zone.file_path, origin=rev_zone.name)
    except Exception as e:
        return False, f"Failed reading reverse zone {rev_zone.name}: {e}"

    # Filter or update
    if action == "delete":
        model.records = [
            r for r in model.records
            if not (r.rtype == "PTR" and r.name.lower() == rel_name.lower() and r.rdata.rstrip(".").lower() == clean_target.rstrip(".").lower())
        ]
    else:  # create or update
        # Remove any existing PTR for this relative name or add new
        model.records = [
            r for r in model.records
            if not (r.rtype == "PTR" and r.name.lower() == rel_name.lower())
        ]
        model.records.append(DnsRecord(
            name=rel_name,
            rtype="PTR",
            ttl=ttl,
            rdata=clean_target,
        ))

    # Serialize & save
    new_text = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(rev_zone.file_path, rev_zone.name, new_text)
    return ok, f"PTR in {rev_zone.name}: {msg}"
