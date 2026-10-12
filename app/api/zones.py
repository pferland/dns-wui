import io
import zipfile
import csv
from datetime import datetime, timezone
from pathlib import Path
import re
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.api.deps import get_current_user, require_role, log_audit
from app.bind.discovery import (
    get_all_zones,
    append_zone_to_named_conf,
    append_slave_zone_to_named_conf,
    is_reverse_zone,
)
from app.bind.parser import (
    parse_zone_file,
    parse_zone_text,
    serialize_zone,
    ZoneModel,
    SoaData,
    DnsRecord,
)
from app.bind.executor import save_zone_file, reload_zone_rndc, rndc_retransfer, rndc_reconfig
from app.bind.soa import calculate_next_serial
from app.bind.tools import lint_zone_content
from app.bind.health import inspect_zone_health
from app.bind.revisions import (
    record_zone_revision,
    list_zone_revisions,
    generate_unified_diff,
    rollback_zone_to_revision,
)

router = APIRouter(prefix="/zones", tags=["zones"])


class CreateZoneRequest(BaseModel):
    origin: str  # e.g. "home.lab" or "1.168.192.in-addr.arpa"
    primary_ns: str = "ns1.home.lab."
    primary_ns_ip: str | None = "192.168.1.3"
    admin_email: str = "hostmaster.home.lab."
    default_ttl: int = 3600
    create_named_conf_entry: bool = True


class CreateSecondaryZoneRequest(BaseModel):
    origin: str  # e.g. "externalcloud.com"
    masters: list[str] = Field(..., min_length=1, description="List of primary cloud nameserver IPs")


class RawZoneUpdateRequest(BaseModel):
    content: str
    bump_serial: bool = True


class ValidateZoneRequest(BaseModel):
    content: str


class BulkTtlRequest(BaseModel):
    ttl: int = Field(..., ge=10, le=604800, description="New TTL value for all records in seconds")


class ImportRecordsRequest(BaseModel):
    content: str
    format: str = Field(default="bind", description="'bind', 'json', or 'csv'")
    mode: str = Field(default="append", description="'append' to add records or 'replace' to overwrite all")


def _quick_inspect_zone(file_path: Path, max_bytes: int = 500_000) -> tuple[int, int | None]:
    """Quickly extract record count and SOA serial without full AST parsing on huge files."""
    try:
        size = file_path.stat().st_size
    except Exception:
        return 0, None

    if size <= max_bytes:
        try:
            model = parse_zone_file(file_path)
            return len(model.records), (model.soa.serial if model.soa else None)
        except Exception:
            pass

    serial = None
    records_count = 0
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith(";") or s.startswith("$"):
                    continue

                records_count += 1
                if "SOA" in line.upper():
                    parts = line.split()
                    for idx, p in enumerate(parts):
                        if p.upper() == "SOA" and len(parts) > idx + 3:
                            if parts[idx + 3].isdigit():
                                serial = int(parts[idx + 3])
                    continue
    except Exception:
        pass
    return records_count, serial


@router.get("")
async def list_zones(
    type: str | None = Query(None, description="Filter: 'forward' or 'reverse'"),
    include_ignored: bool = Query(False, description="Include ignored/hidden zones like adblock RPZ"),
    _user: User = Depends(get_current_user),
):
    all_discovered = get_all_zones(include_ignored=include_ignored)
    if type == "forward":
        zones = [z for z in all_discovered if not z.is_reverse]
    elif type == "reverse":
        zones = [z for z in all_discovered if z.is_reverse]
    else:
        zones = all_discovered

    result = []
    for z in zones:
        record_count = 0
        serial = None
        if z.file_path.exists():
            record_count, serial = _quick_inspect_zone(z.file_path)

        result.append({
            "name": z.name,
            "file_path": str(z.file_path),
            "zone_type": z.zone_type,
            "is_reverse": z.is_reverse,
            "source": z.source,
            "masters": z.masters,
            "record_count": record_count,
            "serial": serial,
        })
    return result


@router.get("/export/all")
async def export_all_zones_archive(_user: User = Depends(get_current_user)):
    """Export a ZIP backup archive containing all zone files."""
    zones = get_all_zones(include_ignored=True)
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for z in zones:
            if z.file_path.exists():
                try:
                    content = z.file_path.read_text(encoding="utf-8", errors="ignore")
                    clean_name = z.name.rstrip(".").replace("/", "-")
                    zip_file.writestr(f"{clean_name}.zone", content)
                except Exception:
                    pass

    zip_buffer.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"bind_zones_backup_{timestamp}.zip"
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_zone(
    req: CreateZoneRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    clean_origin = req.origin.strip()
    if not clean_origin.endswith("."):
        clean_origin += "."

    zones = get_all_zones()
    if any(z.name.rstrip(".").lower() == clean_origin.rstrip(".").lower() for z in zones):
        raise HTTPException(status_code=400, detail=f"Zone '{clean_origin}' already exists")

    slug = clean_origin.rstrip(".").replace("/", "-")
    file_path = settings.ZONES_DIR / f"db.{slug}"

    today_serial = int(calculate_next_serial(None, strategy=settings.DEFAULT_SOA_STRATEGY))

    soa = SoaData(
        mname=req.primary_ns if req.primary_ns.endswith(".") else f"{req.primary_ns}.",
        rname=req.admin_email if req.admin_email.endswith(".") else f"{req.admin_email}.",
        serial=today_serial,
    )
    initial_records = [
        DnsRecord(name="@", rtype="NS", ttl=req.default_ttl, rdata=soa.mname),
    ]

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

    # Record initial revision
    await record_zone_revision(
        session=session,
        zone_name=clean_origin,
        content=text,
        author=user.username,
        comment="Initial master zone creation",
    )

    if req.create_named_conf_entry:
        try:
            append_zone_to_named_conf(clean_origin, file_path)
        except Exception as e:
            msg += f" (Note: named.conf update skipped: {e})"

    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_ZONE",
        zone_name=clean_origin,
        details=f"Created master zone at {file_path}",
    )

    return {
        "name": clean_origin,
        "file_path": str(file_path),
        "message": msg,
    }


@router.post("/secondary", status_code=status.HTTP_201_CREATED)
async def create_secondary_zone(
    req: CreateSecondaryZoneRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Configure BIND 9 as a secondary/slave mirror for an external cloud zone."""
    clean_origin = req.origin.strip().rstrip(".")
    if not req.masters:
        raise HTTPException(status_code=400, detail="At least one master nameserver IP is required.")

    zones = get_all_zones()
    if any(z.name.rstrip(".").lower() == clean_origin.lower() for z in zones):
        raise HTTPException(status_code=400, detail=f"Zone '{clean_origin}' already exists")

    slug = clean_origin.replace("/", "-")
    file_path = settings.ZONES_DIR / f"slave.{slug}"

    try:
        append_slave_zone_to_named_conf(clean_origin, file_path, req.masters)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed appending secondary zone to named.conf: {e}")

    # Reconfig BIND so it accepts the new slave zone and begins AXFR transfer
    reconfig_ok, reconfig_msg = await rndc_reconfig()

    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_SLAVE_ZONE",
        zone_name=clean_origin,
        details=f"Configured secondary zone mirroring masters {req.masters}",
    )

    return {
        "name": clean_origin,
        "file_path": str(file_path),
        "zone_type": "slave",
        "masters": req.masters,
        "message": f"Secondary zone '{clean_origin}' configured. AXFR transfer initialized ({reconfig_msg}).",
    }


@router.get("/{zone_name}")
async def get_zone(zone_name: str, _user: User = Depends(get_current_user)):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    if not matched.file_path.exists():
        if matched.zone_type in ("slave", "secondary"):
            return {
                "name": matched.name,
                "file_path": str(matched.file_path),
                "zone_type": matched.zone_type,
                "is_reverse": matched.is_reverse,
                "masters": matched.masters,
                "status": "Awaiting initial AXFR transfer from master",
                "records": [],
            }
        raise HTTPException(status_code=404, detail="Zone file does not exist on disk")

    model = parse_zone_file(matched.file_path, origin=matched.name)
    return {
        "name": matched.name,
        "origin": model.origin,
        "file_path": str(matched.file_path),
        "zone_type": matched.zone_type,
        "is_reverse": matched.is_reverse,
        "default_ttl": model.default_ttl,
        "masters": matched.masters,
        "soa": model.soa.__dict__ if model.soa else None,
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


@router.post("/{zone_name}/reload")
async def reload_zone(
    zone_name: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
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


@router.post("/{zone_name}/retransfer")
async def retransfer_secondary_zone(
    zone_name: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Force an immediate AXFR/IXFR retransfer of a secondary/slave zone."""
    ok, msg = await rndc_retransfer(zone_name)
    await log_audit(
        session=session,
        username=user.username,
        action="RETRANSFER_ZONE",
        zone_name=zone_name,
        details=msg,
        status="SUCCESS" if ok else "FAILED",
    )
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"message": f"Retransfer triggered for '{zone_name}': {msg}"}


@router.post("/{zone_name}/validate")
async def validate_zone_syntax(
    zone_name: str,
    req: ValidateZoneRequest,
    _user: User = Depends(get_current_user),
):
    """Perform pre-flight dry-run syntax and anti-pattern linting."""
    res = await lint_zone_content(zone_name, req.content)
    return {
        "valid": res.valid,
        "message": res.message,
        "issues": [
            {"level": i.level, "message": i.message, "record": i.record}
            for i in res.issues
        ],
    }


@router.get("/{zone_name}/health")
async def check_zone_health(
    zone_name: str,
    _user: User = Depends(get_current_user),
):
    """Run automated zone health inspection and best-practice audit."""
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone file not found")

    report = inspect_zone_health(matched.file_path, matched.name)
    return {
        "zone_name": report.zone_name,
        "score": report.score,
        "status": report.status,
        "issues": [
            {
                "level": i.level,
                "category": i.category,
                "message": i.message,
                "suggestion": i.suggestion,
            }
            for i in report.issues
        ],
        "total_records": report.total_records,
        "has_spf": report.has_spf,
        "has_dmarc": report.has_dmarc,
        "has_mx": report.has_mx,
    }


@router.post("/{zone_name}/bulk-ttl")
async def bulk_update_ttl(
    zone_name: str,
    req: BulkTtlRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Bulk update TTL across all resource records in the zone."""
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone not found")

    model = parse_zone_file(matched.file_path, origin=matched.name)
    model.default_ttl = req.ttl
    for r in model.records:
        r.ttl = req.ttl

    new_content = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(matched.file_path, matched.name, new_content)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=new_content,
        author=user.username,
        comment=f"Bulk TTL set to {req.ttl}s",
    )

    await log_audit(
        session=session,
        username=user.username,
        action="BULK_TTL",
        zone_name=matched.name,
        details=f"Bulk updated record TTLs to {req.ttl}s",
    )

    return {"status": "success", "message": f"Updated TTL for all records to {req.ttl}s."}


@router.get("/{zone_name}/revisions")
async def get_zone_revisions(
    zone_name: str,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """List historical revision snapshots for a zone."""
    revs = await list_zone_revisions(session, zone_name)
    return [
        {
            "id": r.id,
            "serial": r.serial,
            "author": r.author,
            "comment": r.comment,
            "created_at": r.created_at.isoformat(),
        }
        for r in revs
    ]


@router.get("/{zone_name}/revisions/{rev_id}/diff")
async def get_zone_revision_diff(
    zone_name: str,
    rev_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
):
    """Generate visual unified diff between a past revision and current zone file."""
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone file not found")

    revs = await list_zone_revisions(session, zone_name, limit=100)
    target_rev = next((r for r in revs if r.id == rev_id), None)
    if not target_rev:
        raise HTTPException(status_code=404, detail=f"Revision #{rev_id} not found")

    current_content = matched.file_path.read_text(encoding="utf-8")
    diff_text = generate_unified_diff(
        target_rev.content,
        current_content,
        fromfile=f"Revision #{rev_id} ({target_rev.created_at.strftime('%Y-%m-%d %H:%M')})",
        tofile="Current File",
    )
    return {
        "revision_id": rev_id,
        "diff": diff_text or "(No differences detected)",
        "target_content": target_rev.content,
    }


@router.post("/{zone_name}/rollback/{rev_id}")
async def rollback_zone(
    zone_name: str,
    rev_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Roll back zone to a selected revision snapshot."""
    ok, msg = await rollback_zone_to_revision(session, zone_name, rev_id, author=user.username)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await log_audit(
        session=session,
        username=user.username,
        action="ROLLBACK_ZONE",
        zone_name=zone_name,
        details=f"Rolled back to revision #{rev_id}",
    )
    return {"status": "success", "message": msg}


@router.get("/{zone_name}/export")
async def export_zone(
    zone_name: str,
    format: str = Query("bind", description="'bind', 'json', or 'csv'"),
    _user: User = Depends(get_current_user),
):
    """Export zone in standard BIND RFC 1035 text, JSON, or CSV."""
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone file not found")

    clean_name = matched.name.rstrip(".")
    if format == "bind":
        content = matched.file_path.read_text(encoding="utf-8")
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{clean_name}.zone"'},
        )

    model = parse_zone_file(matched.file_path, origin=matched.name)
    if format == "json":
        import json
        records_data = [
            {"name": r.name, "type": r.rtype, "ttl": r.ttl, "data": r.rdata}
            for r in model.records
        ]
        return Response(
            content=json.dumps({"origin": model.origin, "records": records_data}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{clean_name}.json"'},
        )

    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["name", "type", "ttl", "data"])
        for r in model.records:
            writer.writerow([r.name, r.rtype, r.ttl, r.rdata])
        return Response(
            content=out.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{clean_name}.csv"'},
        )

    raise HTTPException(status_code=400, detail=f"Unsupported export format: {format}")


@router.post("/{zone_name}/import")
async def import_records(
    zone_name: str,
    req: ImportRecordsRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Bulk import records from raw BIND text, JSON, or CSV."""
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        raise HTTPException(status_code=404, detail="Zone not found")

    model = parse_zone_file(matched.file_path, origin=matched.name)
    new_records: list[DnsRecord] = []

    if req.format == "bind":
        imported_model = parse_zone_text(req.content, origin=matched.name)
        new_records = imported_model.records
    elif req.format == "json":
        import json
        try:
            data = json.loads(req.content)
            rec_list = data if isinstance(data, list) else data.get("records", [])
            for item in rec_list:
                new_records.append(DnsRecord(
                    name=item["name"],
                    rtype=item["type"].upper(),
                    ttl=int(item.get("ttl", model.default_ttl)),
                    rdata=item["data"],
                ))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed parsing JSON import: {e}")
    elif req.format == "csv":
        reader = csv.DictReader(io.StringIO(req.content))
        for row in reader:
            new_records.append(DnsRecord(
                name=row["name"],
                rtype=row["type"].upper(),
                ttl=int(row.get("ttl", model.default_ttl)),
                rdata=row["data"],
            ))

    if req.mode == "replace":
        model.records = new_records
    else:
        model.records.extend(new_records)

    serialized = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(matched.file_path, matched.name, serialized)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=serialized,
        author=user.username,
        comment=f"Bulk imported {len(new_records)} records ({req.mode})",
    )

    await log_audit(
        session=session,
        username=user.username,
        action="IMPORT_RECORDS",
        zone_name=matched.name,
        details=f"Bulk imported {len(new_records)} records ({req.mode})",
    )

    return {"status": "success", "message": f"Successfully imported {len(new_records)} records."}


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
    user: User = Depends(require_role("operator")),
):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    # Snapshot current file content before applying change
    if matched.file_path.exists():
        try:
            old_content = matched.file_path.read_text(encoding="utf-8")
            await record_zone_revision(
                session=session,
                zone_name=matched.name,
                content=old_content,
                author=user.username,
                comment="Pre-edit snapshot before Raw Editor update",
            )
        except Exception:
            pass

    content = req.content
    if req.bump_serial:
        try:
            new_model = parse_zone_text(content, origin=matched.name)
            content = serialize_zone(new_model, bump_serial=True)
        except Exception:
            pass

    ok, msg = await save_zone_file(matched.file_path, matched.name, content)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # Record post-edit revision
    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=content,
        author=user.username,
        comment="Updated via Raw Zone Editor",
    )

    await log_audit(
        session=session,
        username=user.username,
        action="UPDATE_RAW_ZONE",
        zone_name=matched.name,
        details="Updated zone file directly via raw editor",
    )
    return {"message": msg}
