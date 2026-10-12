import asyncio
from pathlib import Path
import os
import logging
from app.config import settings
from app.bind.validator import validate_zone_text

logger = logging.getLogger(__name__)


async def reload_zone_rndc(zone_origin: str) -> tuple[bool, str]:
    """Execute rndc reload <zone>."""
    if not settings.RNDC_BIN or not Path(settings.RNDC_BIN).exists():
        logger.info("rndc not configured or installed on this system; skipping active daemon reload.")
        return True, "rndc omitted (not found)"

    clean_origin = zone_origin.strip().rstrip(".")
    cmd = []
    if settings.USE_SUDO_FOR_RNDC:
        cmd.append("sudo")
    cmd.extend([settings.RNDC_BIN, "reload", clean_origin])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True, stdout.decode().strip() or "Zone reloaded via rndc"
        else:
            err = stderr.decode().strip() or stdout.decode().strip()
            return False, f"rndc error (code {proc.returncode}): {err}"
    except Exception as e:
        return False, f"Failed executing rndc: {e}"


async def save_zone_file(file_path: Path, origin: str, content: str) -> tuple[bool, str]:
    """Atomically validate and save zone file to disk, then reload via rndc."""
    valid, message = await validate_zone_text(origin, content)
    if not valid:
        return False, message

    # Ensure parent dir
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write pattern: write to .tmp.<name> and os.replace
    staging_file = file_path.parent / f".tmp.{file_path.name}"
    try:
        staging_file.write_text(content, encoding="utf-8")
        os.replace(staging_file, file_path)
    except Exception as e:
        staging_file.unlink(missing_ok=True)
        return False, f"Filesystem write error: {e}"

    # Trigger rndc reload
    rndc_ok, rndc_msg = await reload_zone_rndc(origin)
    if not rndc_ok:
        logger.warning(f"Zone written, but rndc reload reported: {rndc_msg}")
        return True, f"Saved successfully (Warning: {rndc_msg})"

    return True, "Saved and reloaded successfully"
