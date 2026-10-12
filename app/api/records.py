from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.api.deps import get_current_user, require_role, log_audit
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_file, serialize_zone, DnsRecord
from app.bind.executor import save_zone_file
from app.bind.ptr_sync import sync_ptr_record
from app.bind.revisions import record_zone_revision

router = APIRouter(prefix="/zones/{zone_name}/records", tags=["records"])


class RecordCreateRequest(BaseModel):
    name: str  # e.g. "www", "mail", "@"
    rtype: str  # A, AAAA, CNAME, MX, TXT, PTR, SRV, NS, CAA
    ttl: int = 3600
    rdata: str  # e.g. "192.168.1.100", "10 mail.example.com."
    sync_ptr: bool = True


class RecordDeleteRequest(BaseModel):
    name: str
    rtype: str
    rdata: str
    sync_ptr: bool = True


class RecordUpdateRequest(BaseModel):
    old_name: str
    old_rtype: str
    old_rdata: str
    new_name: str
    new_rtype: str
    new_ttl: int = 3600
    new_rdata: str
    sync_ptr: bool = True


@router.post("", status_code=status.HTTP_201_CREATED)
async def add_record(
    zone_name: str,
    req: RecordCreateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    if matched.zone_type in ("slave", "secondary"):
        raise HTTPException(status_code=400, detail="Cannot manually edit secondary/slave zone. Changes must be made on master nameserver.")

    model = parse_zone_file(matched.file_path, origin=matched.name)

    clean_rtype = req.rtype.upper().strip()
    clean_name = req.name.strip()
    clean_rdata = req.rdata.strip()

    # Append record
    model.records.append(DnsRecord(
        name=clean_name,
        rtype=clean_rtype,
        ttl=req.ttl,
        rdata=clean_rdata,
    ))

    # Serialize & atomically save
    new_text = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(matched.file_path, matched.name, new_text)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # Snapshot revision
    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=new_text,
        author=user.username,
        comment=f"Added {clean_rtype} record {clean_name} -> {clean_rdata}",
    )

    ptr_msg = None
    if req.sync_ptr and clean_rtype in ("A", "AAAA"):
        if clean_name == "@":
            fqdn = matched.name
        elif clean_name.endswith("."):
            fqdn = clean_name
        else:
            fqdn = f"{clean_name}.{matched.name}"

        ptr_ok, ptr_detail = await sync_ptr_record(clean_rdata, fqdn, action="create", ttl=req.ttl)
        if ptr_ok:
            ptr_msg = ptr_detail

    await log_audit(
        session=session,
        username=user.username,
        action="ADD_RECORD",
        zone_name=matched.name,
        record_name=clean_name,
        record_type=clean_rtype,
        details=f"Added {clean_rtype} {clean_name} -> {clean_rdata}. {ptr_msg or ''}",
    )

    return {
        "message": msg,
        "ptr_sync": ptr_msg,
    }


@router.delete("")
async def delete_record(
    zone_name: str,
    req: RecordDeleteRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    if matched.zone_type in ("slave", "secondary"):
        raise HTTPException(status_code=400, detail="Cannot manually edit secondary/slave zone. Changes must be made on master nameserver.")

    model = parse_zone_file(matched.file_path, origin=matched.name)

    initial_len = len(model.records)
    model.records = [
        r for r in model.records
        if not (
            r.name.lower() == req.name.lower() and
            r.rtype.upper() == req.rtype.upper() and
            r.rdata.strip().rstrip(".").lower() == req.rdata.strip().rstrip(".").lower()
        )
    ]

    if len(model.records) == initial_len:
        raise HTTPException(status_code=404, detail="Matching record not found to delete")

    new_text = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(matched.file_path, matched.name, new_text)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # Snapshot revision
    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=new_text,
        author=user.username,
        comment=f"Deleted {req.rtype} record {req.name}",
    )

    ptr_msg = None
    if req.sync_ptr and req.rtype.upper() in ("A", "AAAA"):
        if req.name == "@":
            fqdn = matched.name
        elif req.name.endswith("."):
            fqdn = req.name
        else:
            fqdn = f"{req.name}.{matched.name}"

        ptr_ok, ptr_detail = await sync_ptr_record(req.rdata, fqdn, action="delete")
        if ptr_ok:
            ptr_msg = ptr_detail

    await log_audit(
        session=session,
        username=user.username,
        action="DELETE_RECORD",
        zone_name=matched.name,
        record_name=req.name,
        record_type=req.rtype,
        details=f"Deleted {req.rtype} {req.name} ({req.rdata}). {ptr_msg or ''}",
    )

    return {
        "message": msg,
        "ptr_sync": ptr_msg,
    }


@router.put("")
async def update_record(
    zone_name: str,
    req: RecordUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Zone not found")

    if matched.zone_type in ("slave", "secondary"):
        raise HTTPException(status_code=400, detail="Cannot manually edit secondary/slave zone. Changes must be made on master nameserver.")

    model = parse_zone_file(matched.file_path, origin=matched.name)

    found_idx = None
    for idx, r in enumerate(model.records):
        if (
            r.name.lower() == req.old_name.lower() and
            r.rtype.upper() == req.old_rtype.upper() and
            r.rdata.strip().rstrip(".").lower() == req.old_rdata.strip().rstrip(".").lower()
        ):
            found_idx = idx
            break

    if found_idx is None:
        raise HTTPException(status_code=404, detail="Original record to update not found")

    model.records[found_idx] = DnsRecord(
        name=req.new_name.strip(),
        rtype=req.new_rtype.upper().strip(),
        ttl=req.new_ttl,
        rdata=req.new_rdata.strip(),
    )

    new_text = serialize_zone(model, bump_serial=True)
    ok, msg = await save_zone_file(matched.file_path, matched.name, new_text)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # Snapshot revision
    await record_zone_revision(
        session=session,
        zone_name=matched.name,
        content=new_text,
        author=user.username,
        comment=f"Updated {req.old_rtype} {req.old_name} -> {req.new_rtype} {req.new_name}",
    )

    ptr_msg = None
    if req.sync_ptr and (req.old_rtype.upper() in ("A", "AAAA") or req.new_rtype.upper() in ("A", "AAAA")):
        if req.old_name == "@":
            old_fqdn = matched.name
        elif req.old_name.endswith("."):
            old_fqdn = req.old_name
        else:
            old_fqdn = f"{req.old_name}.{matched.name}"

        if req.new_name == "@":
            new_fqdn = matched.name
        elif req.new_name.endswith("."):
            new_fqdn = req.new_name
        else:
            new_fqdn = f"{req.new_name}.{matched.name}"

        if req.old_rdata != req.new_rdata or req.old_name != req.new_name:
            await sync_ptr_record(req.old_rdata, old_fqdn, action="delete")
            ptr_ok, ptr_detail = await sync_ptr_record(req.new_rdata, new_fqdn, action="create", ttl=req.new_ttl)
            if ptr_ok:
                ptr_msg = ptr_detail

    await log_audit(
        session=session,
        username=user.username,
        action="UPDATE_RECORD",
        zone_name=matched.name,
        record_name=req.new_name,
        record_type=req.new_rtype,
        details=f"Updated {req.old_rtype} {req.old_name} to {req.new_rtype} {req.new_name} -> {req.new_rdata}. {ptr_msg or ''}",
    )

    return {
        "message": msg,
        "ptr_sync": ptr_msg,
    }
