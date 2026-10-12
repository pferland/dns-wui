from dataclasses import dataclass
from pathlib import Path
import logging
from app.config import settings
from app.bind.parser import parse_zone_file, serialize_zone, ZoneModel, SoaData, DnsRecord
from app.bind.executor import save_zone_file

logger = logging.getLogger(__name__)


@dataclass
class DnsOverride:
    fqdn: str           # e.g. "nas.example.com"
    target: str         # e.g. "192.168.1.100" or "core.home.randomintervals.com."
    record_type: str    # "A", "AAAA", "CNAME"
    ttl: int = 300
    comment: str | None = None


def get_override_zone_path() -> Path:
    if settings.OVERRIDE_ZONE_FILE:
        return settings.OVERRIDE_ZONE_FILE
    return settings.ZONES_DIR / settings.OVERRIDE_ZONE_NAME


def init_override_zone_if_missing() -> Path:
    """Ensure the local override RPZ zone file exists with a valid initial SOA and NS."""
    path = get_override_zone_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        initial_model = ZoneModel(
            origin=f"{settings.OVERRIDE_ZONE_NAME}.",
            records=[
                DnsRecord(name="@", rtype="NS", ttl=300, rdata="localhost."),
            ],
            soa=SoaData(
                mname="localhost.",
                rname="hostmaster.localhost.",
                serial=1,
                refresh=3600,
                retry=600,
                expire=86400,
                minimum=60,
            ),
            default_ttl=300,
        )
        content = serialize_zone(initial_model, bump_serial=False)
        path.write_text(content, encoding="utf-8")
    return path


def list_overrides() -> list[DnsOverride]:
    """Parse the override RPZ zone file and return active host overrides."""
    path = init_override_zone_if_missing()
    try:
        model = parse_zone_file(path, origin=settings.OVERRIDE_ZONE_NAME)
    except Exception as e:
        logger.error(f"Error parsing override zone {path}: {e}")
        return []

    overrides: list[DnsOverride] = []
    for r in model.records:
        if r.rtype in ("A", "AAAA", "CNAME"):
            # In an RPZ zone, the record name represents the intercepted FQDN
            fqdn = r.name.rstrip(".")
            overrides.append(DnsOverride(
                fqdn=fqdn,
                target=r.rdata,
                record_type=r.rtype,
                ttl=r.ttl,
            ))
    return sorted(overrides, key=lambda o: o.fqdn)


async def set_override(fqdn: str, target: str, record_type: str = "A", ttl: int = 300) -> None:
    """Add or update a local split-horizon DNS override and reload BIND."""
    path = init_override_zone_if_missing()
    model = parse_zone_file(path, origin=settings.OVERRIDE_ZONE_NAME)

    clean_fqdn = fqdn.strip().rstrip(".")
    clean_target = target.strip()
    if record_type == "CNAME" and not clean_target.endswith("."):
        clean_target += "."

    # Replace existing record for this fqdn or append
    new_records = [r for r in model.records if r.name.rstrip(".").lower() != clean_fqdn.lower()]
    new_records.append(DnsRecord(
        name=clean_fqdn,
        rtype=record_type.upper(),
        ttl=ttl,
        rdata=clean_target,
    ))

    model.records = new_records
    new_content = serialize_zone(model, bump_serial=True, strategy=settings.DEFAULT_SOA_STRATEGY)
    ok, msg = await save_zone_file(path, settings.OVERRIDE_ZONE_NAME, new_content)
    if not ok:
        raise RuntimeError(f"Failed to save override zone: {msg}")


async def delete_override(fqdn: str) -> bool:
    """Remove a local split-horizon DNS override and reload BIND."""
    path = init_override_zone_if_missing()
    model = parse_zone_file(path, origin=settings.OVERRIDE_ZONE_NAME)

    clean_fqdn = fqdn.strip().rstrip(".").lower()
    initial_count = len(model.records)
    model.records = [r for r in model.records if r.name.rstrip(".").lower() != clean_fqdn]

    if len(model.records) == initial_count:
        return False

    new_content = serialize_zone(model, bump_serial=True, strategy=settings.DEFAULT_SOA_STRATEGY)
    ok, msg = await save_zone_file(path, settings.OVERRIDE_ZONE_NAME, new_content)
    if not ok:
        raise RuntimeError(f"Failed to save override zone: {msg}")
    return True
