import difflib
from pathlib import Path
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models.revision import ZoneRevision
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_text, serialize_zone
from app.bind.executor import save_zone_file
from app.config import settings


def extract_serial_from_text(content: str) -> int | None:
    try:
        model = parse_zone_text(content, origin="dummy.local.")
        return model.soa.serial if model.soa else None
    except Exception:
        return None


async def record_zone_revision(
    session: AsyncSession,
    zone_name: str,
    content: str,
    author: str = "system",
    comment: str | None = None,
) -> ZoneRevision:
    """Save a snapshot revision of the zone before or after modifications."""
    serial = extract_serial_from_text(content)
    clean_name = zone_name.strip().rstrip(".")
    rev = ZoneRevision(
        zone_name=clean_name,
        content=content,
        serial=serial,
        author=author,
        comment=comment,
    )
    session.add(rev)
    await session.commit()
    await session.refresh(rev)
    return rev


async def list_zone_revisions(
    session: AsyncSession,
    zone_name: str,
    limit: int = 50,
) -> list[ZoneRevision]:
    """Retrieve revision history for a specific zone, newest first."""
    clean_name = zone_name.strip().rstrip(".")
    result = await session.exec(
        select(ZoneRevision)
        .where(ZoneRevision.zone_name == clean_name)
        .order_by(ZoneRevision.id.desc())
        .limit(limit)
    )
    return list(result.all())


def generate_unified_diff(original_text: str, modified_text: str, fromfile: str = "Before", tofile: str = "After") -> str:
    """Generate readable unified diff between two zone configurations."""
    orig_lines = original_text.splitlines(keepends=True)
    mod_lines = modified_text.splitlines(keepends=True)
    diff = difflib.unified_diff(orig_lines, mod_lines, fromfile=fromfile, tofile=tofile)
    return "".join(diff)


async def rollback_zone_to_revision(
    session: AsyncSession,
    zone_name: str,
    revision_id: int,
    author: str = "admin",
) -> tuple[bool, str]:
    """Roll back zone to an older revision, bumping the serial to ensure propagation."""
    clean_name = zone_name.strip().rstrip(".")
    rev_res = await session.exec(
        select(ZoneRevision).where(ZoneRevision.id == revision_id, ZoneRevision.zone_name == clean_name)
    )
    target_rev = rev_res.first()
    if not target_rev:
        return False, f"Revision #{revision_id} not found for zone '{clean_name}'"

    # Find file path
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == clean_name.lower()), None)
    if not matched:
        return False, f"Zone '{clean_name}' file not located on disk."

    # Parse and bump serial so secondary servers and resolvers accept update
    try:
        model = parse_zone_text(target_rev.content, origin=matched.name)
        new_content = serialize_zone(model, bump_serial=True, strategy=settings.DEFAULT_SOA_STRATEGY)
    except Exception as e:
        return False, f"Failed restoring and serial-bumping target revision: {e}"

    # Save to disk and reload via rndc
    ok, msg = await save_zone_file(matched.file_path, matched.name, new_content)
    if not ok:
        return False, msg

    # Record new rollback revision
    await record_zone_revision(
        session=session,
        zone_name=clean_name,
        content=new_content,
        author=author,
        comment=f"Rolled back to revision #{revision_id} from {target_rev.created_at.strftime('%Y-%m-%d %H:%M')}",
    )

    return True, f"Successfully rolled back to revision #{revision_id} and reloaded BIND."
