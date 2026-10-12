from dataclasses import dataclass
from pathlib import Path
import re
from app.config import settings

ZONE_BLOCK_PATTERN = re.compile(
    r'zone\s+"([^"]+)"(?:\s+IN)?\s*\{([^}]+)\};',
    re.MULTILINE | re.IGNORECASE,
)
FILE_PATTERN = re.compile(r'file\s+"([^"]+)";', re.IGNORECASE)
TYPE_PATTERN = re.compile(r'type\s+(master|primary|slave|secondary|forward|hint);', re.IGNORECASE)


@dataclass
class DiscoveredZone:
    name: str
    file_path: Path
    zone_type: str  # master, slave, etc.
    is_reverse: bool
    source: str  # "named.conf" or "directory_scan"


def is_reverse_zone(name: str) -> bool:
    clean = name.strip().lower()
    return clean.endswith(".in-addr.arpa") or clean.endswith(".ip6.arpa") or clean.endswith(".in-addr.arpa.") or clean.endswith(".ip6.arpa.")


def parse_named_conf(conf_path: Path) -> list[DiscoveredZone]:
    """Parse named.conf or named.conf.local to find configured zones and files."""
    if not conf_path.exists() or not conf_path.is_file():
        return []

    content = conf_path.read_text(encoding="utf-8")
    zones: list[DiscoveredZone] = []

    for match in ZONE_BLOCK_PATTERN.finditer(content):
        zone_name = match.group(1).strip()
        body = match.group(2)

        file_match = FILE_PATTERN.search(body)
        type_match = TYPE_PATTERN.search(body)

        if not file_match:
            continue

        raw_path = file_match.group(1).strip()
        ztype = type_match.group(1).lower() if type_match else "master"

        # Resolve path
        p = Path(raw_path)
        if not p.is_absolute():
            # Try relative to conf_path parent, or zones_dir
            if (conf_path.parent / p).exists():
                file_path = conf_path.parent / p
            elif (settings.ZONES_DIR / p).exists():
                file_path = settings.ZONES_DIR / p
            else:
                file_path = settings.ZONES_DIR / p
        else:
            file_path = p

        zones.append(DiscoveredZone(
            name=zone_name,
            file_path=file_path,
            zone_type=ztype,
            is_reverse=is_reverse_zone(zone_name),
            source="named.conf",
        ))

    return zones


def scan_zones_directory(zones_dir: Path) -> list[DiscoveredZone]:
    """Scan directory for zone files (*.zone, *.db, db.*)."""
    if not zones_dir.exists() or not zones_dir.is_dir():
        return []

    discovered: list[DiscoveredZone] = []
    for f in sorted(zones_dir.iterdir()):
        if not f.is_file() or f.name.startswith("."):
            continue

        ext = f.suffix.lower()
        name = f.name
        if ext in (".zone", ".db") or name.startswith("db."):
            zone_name = name
            if name.startswith("db."):
                zone_name = name[3:]
            elif ext in (".zone", ".db"):
                zone_name = f.stem

            discovered.append(DiscoveredZone(
                name=zone_name,
                file_path=f,
                zone_type="master",
                is_reverse=is_reverse_zone(zone_name),
                source="directory_scan",
            ))

    return discovered


def get_all_zones() -> list[DiscoveredZone]:
    """Combine zones from named.conf and zones directory (hybrid discovery)."""
    conf_zones = parse_named_conf(settings.NAMED_CONF)
    dir_zones = scan_zones_directory(settings.ZONES_DIR)

    known_names = {z.name.rstrip("."): z for z in conf_zones}
    merged = list(conf_zones)

    for dz in dir_zones:
        clean_name = dz.name.rstrip(".")
        if clean_name not in known_names:
            merged.append(dz)

    return sorted(merged, key=lambda z: (z.is_reverse, z.name))


def append_zone_to_named_conf(zone_name: str, file_path: Path, conf_path: Path | None = None) -> None:
    """Add new zone entry to named.conf or named.conf.local."""
    target_conf = conf_path or settings.NAMED_CONF
    target_conf.parent.mkdir(parents=True, exist_ok=True)

    block = (
        f'\nzone "{zone_name}" IN {{\n'
        f'    type master;\n'
        f'    file "{file_path.resolve()}";\n'
        f'}};\n'
    )
    with target_conf.open("a", encoding="utf-8") as f:
        f.write(block)
