import io
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.config import settings
from app.bind.discovery import get_named_conf_paths
from app.bind.executor import reload_bind


def get_backups_dir() -> Path:
    """Return path to backup archive directory, creating it if needed."""
    backup_dir = Path("data/backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def list_backups() -> list[dict[str, Any]]:
    """List all available backup archives sorted by creation time descending."""
    backup_dir = get_backups_dir()
    backups = []
    for f in backup_dir.glob("*.tar.gz"):
        stat = f.stat()
        backups.append({
            "filename": f.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    backups.sort(key=lambda x: x["created_at"], reverse=True)
    return backups


def create_backup_archive(comment: str = "") -> dict[str, Any]:
    """Create a tar.gz snapshot of all BIND zone files and config."""
    backup_dir = get_backups_dir()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_name = f"dns_wui_backup_{timestamp}.tar.gz"
    archive_path = backup_dir / archive_name

    zones_dir = Path(settings.ZONES_DIR)
    conf_paths = get_named_conf_paths()

    with tarfile.open(archive_path, "w:gz") as tar:
        # Add zone files
        if zones_dir.exists():
            for zone_file in zones_dir.glob("*"):
                if zone_file.is_file():
                    tar.add(zone_file, arcname=f"zones/{zone_file.name}")

        # Add configuration files
        for conf_path in conf_paths:
            if conf_path.exists():
                tar.add(conf_path, arcname=f"config/{conf_path.name}")

    stat = archive_path.stat()
    return {
        "filename": archive_name,
        "size_bytes": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "comment": comment,
    }


async def restore_backup_archive(filename: str) -> tuple[bool, str]:
    """Restore zone files and configs from a backup archive."""
    backup_dir = get_backups_dir()
    archive_path = backup_dir / filename

    if not archive_path.exists() or not archive_path.is_file():
        return False, f"Backup file {filename} does not exist"

    zones_dir = Path(settings.ZONES_DIR)
    zones_dir.mkdir(parents=True, exist_ok=True)


    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                # Prevent directory traversal attacks
                if member.name.startswith("/") or ".." in member.name:
                    continue

                if member.name.startswith("zones/") and member.isfile():
                    target_file = zones_dir / Path(member.name).name
                    f = tar.extractfile(member)
                    if f:
                        with open(target_file, "wb") as out:
                            out.write(f.read())
                        try:
                            import pwd, grp
                            bind_uid = pwd.getpwnam("bind").pw_uid
                            bind_gid = grp.getgrnam("bind").gr_gid
                            os.chown(target_file, bind_uid, bind_gid)
                        except Exception:
                            pass

        # Reload BIND to apply restored configuration and zones
        await reload_bind()
        return True, f"Successfully restored {filename} and reloaded BIND"
    except Exception as e:
        return False, f"Failed to restore backup: {str(e)}"


def delete_backup_archive(filename: str) -> tuple[bool, str]:
    """Delete a backup archive."""
    backup_dir = get_backups_dir()
    archive_path = backup_dir / filename
    if not archive_path.exists() or not archive_path.is_file():
        return False, f"Backup {filename} not found"
    try:
        archive_path.unlink()
        return True, f"Backup {filename} deleted"
    except Exception as e:
        return False, f"Error deleting backup: {str(e)}"
