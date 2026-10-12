import asyncio
from pathlib import Path
import tempfile
import logging
import dns.zone
from app.config import settings

logger = logging.getLogger(__name__)


async def validate_zone_text(origin: str, text: str) -> tuple[bool, str]:
    """Validate zone syntax using dnspython and named-checkzone if available."""
    clean_origin = origin.strip()
    if not clean_origin.endswith("."):
        clean_origin += "."

    # 1. Pure-Python validation via dnspython
    try:
        dns.zone.from_text(text, origin=clean_origin, relativize=False)
    except Exception as e:
        return False, f"Syntax error (dnspython): {e}"

    # 2. Binary validation via named-checkzone if available
    if settings.CHECKZONE_BIN and Path(settings.CHECKZONE_BIN).exists():
        with tempfile.NamedTemporaryFile("w", suffix=".zone", delete=False) as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)

        try:
            cmd = [settings.CHECKZONE_BIN, clean_origin, str(tmp_path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                err_msg = stderr.decode().strip() or stdout.decode().strip()
                return False, f"named-checkzone failed (code {proc.returncode}): {err_msg}"
        except Exception as e:
            logger.warning(f"Error running named-checkzone: {e}")
        finally:
            tmp_path.unlink(missing_ok=True)

    return True, "Valid"


async def validate_named_conf(conf_path: Path) -> tuple[bool, str]:
    """Validate BIND named.conf syntax using named-checkconf if available."""
    if not conf_path.exists():
        return False, f"Configuration file {conf_path} does not exist"

    if settings.CHECKCONF_BIN and Path(settings.CHECKCONF_BIN).exists():
        try:
            cmd = [settings.CHECKCONF_BIN, str(conf_path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                err_msg = stderr.decode().strip() or stdout.decode().strip()
                return False, f"named-checkconf failed: {err_msg}"
        except Exception as e:
            logger.warning(f"Error executing named-checkconf: {e}")

    return True, "Configuration valid"
