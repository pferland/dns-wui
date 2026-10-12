from pathlib import Path
import re
from typing import Any
from httpx import AsyncClient
from app.config import settings
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_file, serialize_zone, ZoneModel, SoaData, DnsRecord
from app.bind.executor import save_zone_file, reload_zone_rndc

DEFAULT_BLOCKLIST_SOURCE = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def get_adblock_zone_path() -> Path:
    p = settings.ZONES_DIR / "rpz.adblock.spam.local"
    if not p.exists() and Path("/var/cache/bind/zones/rpz.adblock.spam.local").exists():
        return Path("/var/cache/bind/zones/rpz.adblock.spam.local")
    return p


def get_adblock_summary() -> dict[str, Any]:
    """Retrieve statistics and whitelist entries for rpz.adblock.spam.local."""
    path = get_adblock_zone_path()
    if not path.exists():
        return {
            "exists": False,
            "path": str(path),
            "total_rules": 0,
            "whitelist": [],
            "size_mb": 0.0,
        }

    stat = path.stat()
    size_mb = round(stat.st_size / (1024 * 1024), 2)

    whitelist: list[str] = []
    total_rules = 0

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith(";") or s.startswith("$"):
                continue
            if "rpz-passthru" in s:
                # e.g. "whitelisted.com CNAME rpz-passthru."
                parts = s.split()
                if parts:
                    whitelist.append(parts[0].rstrip("."))
            elif "CNAME" in s or "A" in s:
                total_rules += 1

    return {
        "exists": True,
        "path": str(path),
        "total_rules": total_rules,
        "whitelist": sorted(whitelist),
        "size_mb": size_mb,
    }


async def add_adblock_whitelist(domain: str) -> bool:
    """Add a domain to the RPZ whitelist by pointing it to rpz-passthru."""
    clean_domain = domain.strip().rstrip(".").lower()
    path = get_adblock_zone_path()
    if not path.exists():
        return False

    content = path.read_text(encoding="utf-8", errors="ignore")
    rule = f"{clean_domain} CNAME rpz-passthru.\n"

    if rule in content or f"{clean_domain} CNAME rpz-passthru." in content:
        return True

    # Prepend right after SOA/NS
    lines = content.splitlines(keepends=True)
    insert_idx = 0
    for idx, l in enumerate(lines):
        if "IN NS" in l or "NS localhost" in l:
            insert_idx = idx + 1
            break

    lines.insert(insert_idx, f"{clean_domain} CNAME rpz-passthru.\n")
    new_content = "".join(lines)

    ok, msg = await save_zone_file(path, "rpz.adblock.spam.local", new_content)
    if not ok:
        raise RuntimeError(msg)
    return True


async def remove_adblock_whitelist(domain: str) -> bool:
    """Remove a domain from the RPZ whitelist."""
    clean_domain = domain.strip().rstrip(".").lower()
    path = get_adblock_zone_path()
    if not path.exists():
        return False

    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines(keepends=True)
    new_lines = [l for l in lines if not (clean_domain in l.lower() and "rpz-passthru" in l.lower())]

    if len(new_lines) == len(lines):
        return False

    new_content = "".join(new_lines)
    ok, msg = await save_zone_file(path, "rpz.adblock.spam.local", new_content)
    if not ok:
        raise RuntimeError(msg)
    return True


async def update_adblock_from_upstream(source_url: str = DEFAULT_BLOCKLIST_SOURCE) -> dict[str, Any]:
    """Download host list from upstream URL, compile into RPZ format, and reload BIND."""
    path = get_adblock_zone_path()
    current_summary = get_adblock_summary()
    existing_whitelist = current_summary["whitelist"]

    # Download host list
    async with AsyncClient(timeout=30.0) as client:
        resp = await client.get(source_url)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed fetching blocklist: HTTP {resp.status_code}")
        raw_hosts = resp.text

    # Parse hosts (0.0.0.0 domain or 127.0.0.1 domain)
    domains = set()
    for line in raw_hosts.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            dom = parts[1].strip().lower().rstrip(".")
            if dom not in ("localhost", "localhost.localdomain", "broadcasthost"):
                domains.add(dom)

    # Exclude whitelisted domains
    for w in existing_whitelist:
        domains.discard(w.lower())

    # Build RPZ zone file content
    zone_lines = [
        "; Zone file for rpz.adblock.spam.local\n",
        "$ORIGIN rpz.adblock.spam.local.\n",
        "$TTL 300\n",
        "@ IN SOA localhost. hostmaster.localhost. (\n",
        "  1 ; Serial\n",
        "  3600 600 86400 60 )\n",
        "@ 300 IN NS localhost.\n\n",
        "; --- Whitelisted Passthrough Domains ---\n",
    ]

    for w in existing_whitelist:
        zone_lines.append(f"{w} CNAME rpz-passthru.\n")

    zone_lines.append("\n; --- Blocked RPZ CNAME . Rules ---\n")
    for d in sorted(domains):
        zone_lines.append(f"{d} CNAME .\n")

    full_content = "".join(zone_lines)
    ok, msg = await save_zone_file(path, "rpz.adblock.spam.local", full_content)
    if not ok:
        raise RuntimeError(f"Failed saving updated blocklist: {msg}")

    return {
        "status": "success",
        "rules_count": len(domains),
        "whitelist_count": len(existing_whitelist),
        "source": source_url,
    }
