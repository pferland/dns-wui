from dataclasses import dataclass, field
from pathlib import Path
import re
from app.config import settings

ZONE_BLOCK_PATTERN = re.compile(
    r'zone\s+"([^"]+)"(?:\s+IN)?\s*\{([^}]+)\};',
    re.MULTILINE | re.IGNORECASE,
)
FILE_PATTERN = re.compile(r'file\s+"([^"]+)";', re.IGNORECASE)
TYPE_PATTERN = re.compile(r'type\s+(master|primary|slave|secondary|forward|hint);', re.IGNORECASE)
MASTERS_PATTERN = re.compile(r'(?:masters|primaries)\s*\{([^}]+)\};', re.IGNORECASE)


@dataclass
class DiscoveredZone:
    name: str
    file_path: Path
    zone_type: str  # master, slave, etc.
    is_reverse: bool
    source: str  # "named.conf" or "directory_scan"
    masters: list[str] = field(default_factory=list)


def is_reverse_zone(name: str) -> bool:
    clean = name.strip().lower()
    return clean.endswith(".in-addr.arpa") or clean.endswith(".ip6.arpa") or clean.endswith(".in-addr.arpa.") or clean.endswith(".ip6.arpa.")


INCLUDE_PATTERN = re.compile(r'include\s+"([^"]+)";', re.IGNORECASE)
DIRECTORY_PATTERN = re.compile(r'directory\s+"([^"]+)";', re.IGNORECASE)


def strip_bind_comments(text: str) -> str:
    """Remove //, #, and /* */ comments from BIND 9 config."""
    # Remove block comments /* ... */
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Remove line comments // and #
    lines = []
    for line in text.splitlines():
        # Strip trailing // or # comments
        clean = re.sub(r'(?://|#).*$', '', line)
        lines.append(clean)
    return "\n".join(lines)


def find_named_options_dir(
    conf_path: Path,
    visited: set[Path] | None = None,
) -> Path | None:
    """Find directory directive in named.conf or included files."""
    if not conf_path.exists() or not conf_path.is_file():
        return None

    visited = visited or set()
    real_conf = conf_path.resolve()
    if real_conf in visited:
        return None
    visited.add(real_conf)

    raw_content = conf_path.read_text(encoding="utf-8")
    content = strip_bind_comments(raw_content)

    dir_match = DIRECTORY_PATTERN.search(content)
    if dir_match:
        return Path(dir_match.group(1).strip())

    for inc_match in INCLUDE_PATTERN.finditer(content):
        inc_raw = inc_match.group(1).strip()
        inc_p = Path(inc_raw)
        if not inc_p.is_absolute():
            inc_p = conf_path.parent / inc_p
        found = find_named_options_dir(inc_p, visited=visited)
        if found:
            return found
def get_named_conf_paths() -> list[Path]:
    """Return list of main and included named.conf paths that exist."""
    conf = settings.NAMED_CONF
    paths = [conf]
    if not conf.exists():
        return paths

    raw_content = conf.read_text(encoding="utf-8")
    content = strip_bind_comments(raw_content)
    for inc_match in INCLUDE_PATTERN.finditer(content):
        inc_raw = inc_match.group(1).strip()
        inc_p = Path(inc_raw)
        if not inc_p.is_absolute():
            inc_p = conf.parent / inc_p
        if inc_p.exists() and inc_p not in paths:
            paths.append(inc_p)
    return paths


def parse_named_conf(

    conf_path: Path,
    options_dir: Path | None = None,
    visited: set[Path] | None = None,
) -> list[DiscoveredZone]:
    """Parse named.conf, follow includes, and find configured zones and files."""
    if not conf_path.exists() or not conf_path.is_file():
        return []

    if options_dir is None:
        options_dir = find_named_options_dir(conf_path)

    visited = visited or set()
    real_conf = conf_path.resolve()
    if real_conf in visited:
        return []
    visited.add(real_conf)

    raw_content = conf_path.read_text(encoding="utf-8")
    content = strip_bind_comments(raw_content)

    zones: list[DiscoveredZone] = []

    # 1. Parse zones in this file
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
            # Try options_dir if known (e.g. /var/cache/bind)
            if options_dir and (options_dir / p).exists():
                file_path = options_dir / p
            elif (conf_path.parent / p).exists():
                file_path = conf_path.parent / p
            elif (settings.ZONES_DIR / p).exists():
                file_path = settings.ZONES_DIR / p
            elif options_dir:
                file_path = options_dir / p
            else:
                file_path = settings.ZONES_DIR / p
        else:
            file_path = p

        masters_list: list[str] = []
        masters_match = MASTERS_PATTERN.search(body)
        if masters_match:
            raw_m = masters_match.group(1).replace(";", " ")
            masters_list = [ip.strip() for ip in raw_m.split() if ip.strip()]

        zones.append(DiscoveredZone(
            name=zone_name,
            file_path=file_path,
            zone_type=ztype,
            is_reverse=is_reverse_zone(zone_name),
            source="named.conf",
            masters=masters_list,
        ))

    # 2. Recursively follow included configuration files
    for inc_match in INCLUDE_PATTERN.finditer(content):
        inc_raw = inc_match.group(1).strip()
        inc_p = Path(inc_raw)
        if not inc_p.is_absolute():
            inc_p = conf_path.parent / inc_p

        if inc_p.exists():
            inc_zones = parse_named_conf(inc_p, options_dir=options_dir, visited=visited)
            zones.extend(inc_zones)

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


def is_zone_ignored(zone_name: str) -> bool:
    """Check if zone should be ignored/hidden from WUI."""
    clean = zone_name.strip().rstrip(".").lower()
    for ign in settings.IGNORED_ZONES:
        ign_clean = ign.strip().rstrip(".").lower()
        if clean == ign_clean:
            return True
        # Also support prefix/wildcard match if someone specifies e.g. "rpz.*"
        if ign_clean.endswith("*") and clean.startswith(ign_clean[:-1]):
            return True
    return False


def get_all_zones(include_ignored: bool = False) -> list[DiscoveredZone]:
    """Combine zones from named.conf and zones directory (hybrid discovery)."""
    conf_zones = parse_named_conf(settings.NAMED_CONF)
    dir_zones = scan_zones_directory(settings.ZONES_DIR)

    known_names = {z.name.rstrip("."): z for z in conf_zones}
    merged = list(conf_zones)

    for dz in dir_zones:
        clean_name = dz.name.rstrip(".")
        if clean_name not in known_names:
            merged.append(dz)

    if not include_ignored:
        merged = [z for z in merged if not is_zone_ignored(z.name)]

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


def append_slave_zone_to_named_conf(
    zone_name: str,
    file_path: Path,
    masters: list[str],
    conf_path: Path | None = None,
) -> None:
    """Add new secondary/slave zone entry with master nameserver IPs to named.conf."""
    target_conf = conf_path or settings.NAMED_CONF
    target_conf.parent.mkdir(parents=True, exist_ok=True)

    clean_origin = zone_name.strip().rstrip(".")
    masters_str = " ".join(f"{m.strip()};" for m in masters if m.strip())

    block = (
        f'\nzone "{clean_origin}" IN {{\n'
        f'    type slave;\n'
        f'    masters {{ {masters_str} }};\n'
        f'    file "{file_path.resolve()}";\n'
        f'}};\n'
    )
    with target_conf.open("a", encoding="utf-8") as f:
        f.write(block)

