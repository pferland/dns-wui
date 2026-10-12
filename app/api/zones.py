from pathlib import Path
import re
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.api.deps import get_current_user, log_audit
from app.bind.discovery import get_all_zones, append_zone_to_named_conf, is_reverse_zone
from app.bind.parser import (
    parse_zone_file,
    serialize_zone,
    ZoneModel,
    SoaData,
    DnsRecord,
)
from app.bind.executor import save_zone_file, reload_zone_rndc
from app.bind.soa import calculate_next_serial

router = APIRouter(prefix="/zones", tags=["zones"])


class CreateZoneRequest(BaseModel):
    origin: str  # e.g. "home.lab" or "1.168.192.in-addr.arpa"
    primary_ns: str = "ns1.home.lab."
    primary_ns_ip: str | None = "192.168.1.3"
    admin_email: str = "hostmaster.home.lab."
    default_ttl: int = 3600
    create_named_conf_entry: bool = True


class RawZoneUpdateRequest(BaseModel):
    content: str
    bump_serial: bool = True


def _quick_inspect_zone(file_path: Path, max_bytes: int = 500_000) -> tuple[int, int | None]:
    """Quickly extract record count and SOA serial without full AST parsing on huge files."""
    try:
        size = file_path.stat().st_size
    except Exception:
        return 0, None

    # If small file (< 500KB), standard parse is fast and accurate
    if size <= max_bytes:
        try:
            model = parse_zone_file(file_path)
            return len(model.records), (model.soa.serial if model.soa else None)
        except Exception:
            pass

    # For large files (e.g. multi-megabyte RPZ adblock lists), scan lines/SOA quickly
    serial = None
    records_count = 0
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            in_soa = False
            for line in f:
                s = line.strip()
                if not s or s.startswith(";") or s.startswith("$"):
                    continue

                records_count += 1
                if "SOA" in line.upper():
                    in_soa = True
                    # Check if single line SOA
                    parts = line.split()
                    for idx, p in enumerate(parts):
                        if p.upper() == "SOA" and len(parts) > idx + 3:
                            if parts[idx + 3].isdigit():
                                serial = int(parts[idx + 3])
                                in_soa = False
                    continue

                if in_soa:
                    # Find first number in SOA block (the serial)
                    m = re.search(r"(\d+)", s)
                    if m:
                        serial = int(m.group(1))
                    in_soa = False
    except Exception:
        pass

    return records_count, serial


@router.get("")
async def list_zones(include_ignored: bool = False, _user: User = Depends(get_current_user)):
    zones = get_all_zones(include_ignored=include_ignored)
    out = []
    for z in zones:
        record_count = 0
        serial = None
        exists_on_disk = z.file_path.exists()

        if exists_on_disk:
            record_count, serial = _quick_inspect_zone(z.file_path)

        out.append({
            "name": z.name,
            "file_path": str(z.file_path),
            "zone_type": z.zone_type,
            "is_reverse": z.is_reverse,
            "source": z.source,
            "record_count": record_count,
            "serial": serial,
            "exists": exists_on_disk,
        })
    return out


@router.get("/{zone_name}")
async def get_zone(zone_name: str, _user: User = Depends(get_current_user)):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail=f"Zone '{zone_name}' not found")

    if not matched.file_path.exists():
        raise HTTPException(status_code=404, detail=f"Zone file '{matched.file_path}' does not exist on disk")

    try:
        model = parse_zone_file(matched.file_path, origin=matched.name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error parsing zone file: {e}")

    return {
        "name": matched.name,
        "origin": model.origin,
        "file_path": str(matched.file_path),
        "is_reverse": matched.is_reverse,
        "default_ttl": model.default_ttl,
        "soa": model.soa,
        "records": [
            {
                "name": r.name,
                "rtype": r.rtype,
                "ttl": r.ttl,
                "rdata": r.rdata,
            }
            for r in model.records
        ],
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_zone(
    req: CreateZoneRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    clean_origin = req.origin.strip()
    if not clean_origin.endswith("."):
        clean_origin += "."

    zones = get_all_zones()
    if any(z.name.rstrip(".").lower() == clean_origin.rstrip(".").lower() for z in zones):
        raise HTTPException(status_code=400, detail=f"Zone '{clean_origin}' already exists")

    # Generate filename
    slug = clean_origin.rstrip(".").replace("/", "-")
    file_path = settings.ZONES_DIR / f"db.{slug}"

    # Generate initial SOA
    today_serial = calculate_next_serial(None, strategy="date_revision")
    soa = SoaData(
        mname=req.primary_ns if req.primary_ns.endswith(".") else f"{req.primary_ns}.",
        rname=req.admin_email if req.admin_email.endswith(".") else f"{req.admin_email}.",
        serial=today_serial,
    )
    initial_records = [
        DnsRecord(name="@", rtype="NS", ttl=req.default_ttl, rdata=soa.mname),
    ]

    # If forward zone and primary NS is inside this zone, add glue A record
    if not is_reverse_zone(clean_origin) and req.primary_ns_ip:
        if soa.mname.endswith("." + clean_origin):
            ns_host = soa.mname[:-len("." + clean_origin)]
            initial_records.append(DnsRecord(name=ns_host, rtype="A", ttl=req.default_ttl, rdata=req.primary_ns_ip))
        elif soa.mname == clean_origin:
            initial_records.append(DnsRecord(name="@", rtype="A", ttl=req.default_ttl, rdata=req.primary_ns_ip))

    model = ZoneModel(
        origin=clean_origin,
        records=initial_records,
        soa=soa,
        default_ttl=req.default_ttl,
    )

    text = serialize_zone(model, bump_serial=False)
    ok, msg = await save_zone_file(file_path, clean_origin, text)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Failed to create zone: {msg}")

    if req.create_named_conf_entry:
        try:
            append_zone_to_named_conf(clean_origin, file_path)
        except Exception as e:
            # Non-fatal if config path is read-only
            msg += f" (Note: named.conf update skipped: {e})"

    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_ZONE",
        zone_name=clean_origin,
        details=f"Created zone file at {file_path}",
    )

    return {
        "name": clean_origin,
        "file_path": str(file_path),
        "message": msg,
    }


@router.post("/{zone_name}/reload")
async def reload_zone(
    zone_name: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    ok, msg = await reload_zone_rndc(zone_name)
    await log_audit(
        session=session,
        username=user.username,
        action="RELOAD_ZONE",
        zone_name=zone_name,
        details=msg,
        status="SUCCESS" if ok else "FAILED",
    )
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"message": msg}


@router.get("/{zone_name}/raw")
async def get_raw_zone(zone_name: str, _user: User = Depends(get_current_user)):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone file not found")
    return {"content": matched.file_path.read_text(encoding="utf-8")}


@router.put("/{zone_name}/raw")
async def update_raw_zone(
    zone_name: str,
    req: RawZoneUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    content = req.content
    if req.bump_serial:
        try:
            model = parse_zone_file(matched.file_path, origin=matched.name)
            # Re-parse the incoming text to bump serial
            from app.bind.parser import parse_zone_text
            new_model = parse_zone_text(content, origin=matched.name)
            content = serialize_zone(new_model, bump_serial=True)
        except Exception:
            pass

    ok, msg = await save_zone_file(matched.file_path, matched.name, content)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await log_audit(
        session=session,
        username=user.username,
        action="UPDATE_RAW_ZONE",
        zone_name=matched.name,
        details="Updated zone file directly via raw editor",
    )
    return {"message": msg}
