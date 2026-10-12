import asyncio
from pathlib import Path
import os
import logging
from app.config import settings
from app.bind.validator import validate_zone_text

logger = logging.getLogger(__name__)


async def execute_rndc_cmd(*args: str) -> tuple[bool, str]:
    """Execute arbitrary rndc command with sudo support."""
    if not settings.RNDC_BIN or not Path(settings.RNDC_BIN).exists():
        logger.info("rndc not configured or installed on this system; skipping execution.")
        return True, "rndc omitted (binary not found)"

    cmd = []
    if settings.USE_SUDO_FOR_RNDC:
        cmd.append("sudo")
    cmd.append(settings.RNDC_BIN)
    cmd.extend(args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        out_str = stdout.decode().strip()
        err_str = stderr.decode().strip()
        if proc.returncode == 0:
            return True, out_str or "Command completed successfully"
        else:
            return False, f"rndc error (code {proc.returncode}): {err_str or out_str}"
    except Exception as e:
        return False, f"Failed executing rndc: {e}"


async def reload_zone_rndc(zone_origin: str) -> tuple[bool, str]:
    """Execute rndc reload <zone>."""
    clean_origin = zone_origin.strip().rstrip(".")
    return await execute_rndc_cmd("reload", clean_origin)


async def rndc_flush() -> tuple[bool, str]:
    """Flush the resolver cache: rndc flush."""
    return await execute_rndc_cmd("flush")


async def rndc_flushname(domain: str) -> tuple[bool, str]:
    """Flush specific domain cache: rndc flushname <domain>."""
    clean_domain = domain.strip().rstrip(".")
    return await execute_rndc_cmd("flushname", clean_domain)


async def rndc_reconfig() -> tuple[bool, str]:
    """Reload configuration files and new zones: rndc reconfig."""
    return await execute_rndc_cmd("reconfig")


async def rndc_status() -> tuple[bool, str]:
    """Display BIND server status: rndc status."""
    return await execute_rndc_cmd("status")


async def reload_bind() -> tuple[bool, str]:
    """Reload entire BIND server configuration and zones: rndc reload."""
    return await execute_rndc_cmd("reload")



async def rndc_dumpdb() -> tuple[bool, str]:
    """Dump cache to dump file: rndc dumpdb -all."""
    return await execute_rndc_cmd("dumpdb", "-all")


async def rndc_retransfer(zone_origin: str) -> tuple[bool, str]:
    """Force retransfer of a secondary/slave zone: rndc retransfer <zone>."""
    clean_origin = zone_origin.strip().rstrip(".")
    return await execute_rndc_cmd("retransfer", clean_origin)


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
