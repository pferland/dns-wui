import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from pydantic import BaseModel, Field
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.api.deps import get_current_user, require_role, log_audit
from app.database import get_session
from app.models.user import User
from app.models.ddns import DdnsToken
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_file, serialize_zone, DnsRecord
from app.bind.executor import save_zone_file
from app.bind.ptr_sync import sync_ptr_record

router = APIRouter(prefix="/ddns", tags=["ddns"])


class CreateDdnsTokenRequest(BaseModel):
    name: str = Field(..., description="Label, e.g. 'Home Router WAN'")
    zone_name: str = Field(..., description="Zone to update, e.g. 'mycorp.com'")
    record_name: str = Field(..., description="Hostname/record name, e.g. 'vpn' or 'router'")


@router.get("/update")
@router.post("/update")
async def ddns_update(
    request: Request,
    token: str = Query(..., description="Secret DDNS token string"),
    hostname: str | None = Query(None, description="Optional hostname verification"),
    myip: str | None = Query(None, description="New IPv4 or IPv6 address (detected if omitted)"),
    session: AsyncSession = Depends(get_session),
):
    """Dynamic DNS endpoint compatible with routers (pfSense, OpenWrt, UniFi, Mikrotik, curl)."""
    clean_token = token.strip()
    key_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

    res = await session.exec(select(DdnsToken).where(DdnsToken.token_hash == key_hash))
    ddns_entry = res.first()
    if not ddns_entry:
        return Response(content="badauth\n", media_type="text/plain", status_code=401)

    # Determine IP
    target_ip = myip.strip() if myip else None
    if not target_ip:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            target_ip = forwarded.split(",")[0].strip()
        elif request.client:
            target_ip = request.client.host

    if not target_ip:
        return Response(content="dnserr No IP detected\n", media_type="text/plain", status_code=400)

    # Check if IP unchanged
    if ddns_entry.last_ip == target_ip:
        return Response(content=f"nochg {target_ip}\n", media_type="text/plain")

    # Locate Zone
    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == ddns_entry.zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        return Response(content="nohost Zone not found on server\n", media_type="text/plain", status_code=404)

    try:
        model = parse_zone_file(matched.file_path, origin=matched.name)
        rtype = "AAAA" if ":" in target_ip else "A"

        # Update or append record
        found = False
        for r in model.records:
            if r.name.lower() == ddns_entry.record_name.lower() and r.rtype == rtype:
                r.rdata = target_ip
                found = True
                break

        if not found:
            model.records.append(DnsRecord(
                name=ddns_entry.record_name,
                rtype=rtype,
                ttl=300,  # DDNS records default to 5m TTL
                rdata=target_ip,
            ))

        new_content = serialize_zone(model, bump_serial=True)
        ok, msg = await save_zone_file(matched.file_path, matched.name, new_content)
        if not ok:
            return Response(content=f"dnserr {msg}\n", media_type="text/plain", status_code=500)

        # Update token record
        ddns_entry.last_ip = target_ip
        ddns_entry.last_updated_at = datetime.now(timezone.utc)
        session.add(ddns_entry)
        await session.commit()

        # Update reverse PTR if applicable
        fqdn = f"{ddns_entry.record_name}.{matched.name}" if ddns_entry.record_name != "@" else matched.name
        await sync_ptr_record(target_ip, fqdn, action="create", ttl=300)

        await log_audit(
            session=session,
            username=f"ddns:{ddns_entry.name}",
            action="DDNS_UPDATE",
            zone_name=matched.name,
            record_name=ddns_entry.record_name,
            details=f"Updated DDNS {ddns_entry.record_name}.{matched.name} -> {target_ip}",
        )

        return Response(content=f"good {target_ip}\n", media_type="text/plain")
    except Exception as e:
        return Response(content=f"dnserr {e}\n", media_type="text/plain", status_code=500)


@router.get("/tokens")
async def list_ddns_tokens(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(require_role("operator")),
):
    """List configured Dynamic DNS update tokens."""
    res = await session.exec(select(DdnsToken).order_by(DdnsToken.id.desc()))
    tokens = res.all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "zone_name": t.zone_name,
            "record_name": t.record_name,
            "last_ip": t.last_ip,
            "last_updated_at": t.last_updated_at.isoformat() if t.last_updated_at else None,
            "created_at": t.created_at.isoformat(),
        }
        for t in tokens
    ]


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_ddns_token(
    req: CreateDdnsTokenRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Create a new Dynamic DNS token for a specific record."""
    raw_token = f"ddns_{secrets.token_urlsafe(24)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    ddns_token = DdnsToken(
        name=req.name.strip(),
        token_secret=raw_token,
        token_hash=token_hash,
        zone_name=req.zone_name.strip(),
        record_name=req.record_name.strip(),
    )
    session.add(ddns_token)
    await session.commit()
    await session.refresh(ddns_token)

    update_url = f"{request.base_url}api/v1/ddns/update?token={raw_token}"

    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_DDNS_TOKEN",
        zone_name=req.zone_name,
        details=f"Created DDNS token for {req.record_name}.{req.zone_name} ({req.name})",
    )

    return {
        "id": ddns_token.id,
        "name": ddns_token.name,
        "zone_name": ddns_token.zone_name,
        "record_name": ddns_token.record_name,
        "token": raw_token,
        "update_url": update_url,
        "sample_curl": f"curl -s '{update_url}'",
    }


@router.delete("/tokens/{token_id}")
async def delete_ddns_token(
    token_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Delete a Dynamic DNS token."""
    res = await session.exec(select(DdnsToken).where(DdnsToken.id == token_id))
    token_entry = res.first()
    if not token_entry:
        raise HTTPException(status_code=404, detail="DDNS Token not found")

    await session.delete(token_entry)
    await session.commit()

    await log_audit(
        session=session,
        username=user.username,
        action="DELETE_DDNS_TOKEN",
        zone_name=token_entry.zone_name,
        details=f"Deleted DDNS token '{token_entry.name}'",
    )
    return {"status": "success", "message": f"DDNS Token '{token_entry.name}' removed."}
