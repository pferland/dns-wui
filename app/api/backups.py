from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession
from app.database import get_session
from app.models.user import User
from app.api.deps import require_role, log_audit
from app.bind.backups import (
    list_backups,
    create_backup_archive,
    restore_backup_archive,
    delete_backup_archive,
    get_backups_dir,
)

router = APIRouter(prefix="/backups", tags=["backups"])


class CreateBackupRequest(BaseModel):
    comment: str = ""


class RestoreBackupRequest(BaseModel):
    filename: str


@router.get("")
async def get_all_backups(
    user: User = Depends(require_role("operator")),
):
    """List all available backup snapshots."""
    return {"backups": list_backups()}


@router.post("")
async def trigger_backup(
    req: CreateBackupRequest = CreateBackupRequest(),
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    """Create a new full backup archive."""
    res = create_backup_archive(comment=req.comment)
    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_BACKUP",
        zone_name=None,
        details=f"Created backup snapshot {res['filename']}",
    )
    return res


@router.get("/{filename}/download")
async def download_backup(
    filename: str,
    user: User = Depends(require_role("operator")),
):
    """Download a backup tar.gz archive."""
    backup_path = get_backups_dir() / filename
    if not backup_path.exists() or not backup_path.is_file():
        raise HTTPException(status_code=404, detail="Backup file not found")
    return FileResponse(
        path=backup_path,
        filename=filename,
        media_type="application/gzip",
    )


@router.post("/restore")
async def restore_backup(
    req: RestoreBackupRequest,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    """Restore from a backup archive snapshot."""
    ok, msg = await restore_backup_archive(req.filename)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    await log_audit(
        session=session,
        username=user.username,
        action="RESTORE_BACKUP",
        zone_name=None,
        details=f"Restored backup snapshot {req.filename}",
    )
    return {"message": msg}


@router.delete("/{filename}")
async def delete_backup(
    filename: str,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    """Delete a backup archive."""
    ok, msg = delete_backup_archive(filename)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    await log_audit(
        session=session,
        username=user.username,
        action="DELETE_BACKUP",
        zone_name=None,
        details=f"Deleted backup snapshot {filename}",
    )
    return {"message": msg}
