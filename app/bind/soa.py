from datetime import datetime, timezone
import re

DATE_SERIAL_PATTERN = re.compile(r"^(20\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\d\d)$")


def detect_serial_strategy(serial: int) -> str:
    """Detect if serial follows YYYYMMDDnn date convention or simple increment."""
    serial_str = str(serial)
    if DATE_SERIAL_PATTERN.match(serial_str):
        return "date_revision"
    return "increment"


def calculate_next_serial(current_serial: int | None, strategy: str = "auto") -> int:
    """Calculate the next SOA serial number based on detected or specified strategy."""
    today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    today_int = int(today_str)

    if current_serial is None or current_serial <= 0:
        # Default for new zone
        return int(f"{today_str}01")

    if strategy == "auto":
        strategy = detect_serial_strategy(current_serial)

    if strategy == "increment":
        return current_serial + 1

    # Date + revision strategy (YYYYMMDDnn)
    serial_str = str(current_serial)
    match = DATE_SERIAL_PATTERN.match(serial_str)
    if not match:
        # Was not date format, convert to today's date + 01
        return int(f"{today_str}01")

    year, month, day, revision = match.groups()
    serial_date = int(f"{year}{month}{day}")
    rev_num = int(revision)

    if serial_date < today_int:
        # New day, reset revision to 01
        return int(f"{today_str}01")
    elif serial_date == today_int:
        # Same day, increment revision counter
        new_rev = rev_num + 1
        return int(f"{today_str}{new_rev:02d}")
    else:
        # Current serial date is in future, don't roll back to avoid secondary zone sync failures
        return current_serial + 1
