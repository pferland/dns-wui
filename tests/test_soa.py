from datetime import datetime, timezone
from app.bind.soa import detect_serial_strategy, calculate_next_serial


def test_detect_serial_strategy():
    assert detect_serial_strategy(2026101101) == "date_revision"
    assert detect_serial_strategy(2024010101) == "date_revision"
    assert detect_serial_strategy(1) == "increment"
    assert detect_serial_strategy(42) == "increment"
    assert detect_serial_strategy(1005) == "increment"


def test_calculate_next_serial_new_zone():
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    expected = int(f"{today}01")
    assert calculate_next_serial(None) == expected
    assert calculate_next_serial(0) == expected


def test_calculate_next_serial_same_day():
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    current = int(f"{today}05")
    expected = int(f"{today}06")
    assert calculate_next_serial(current) == expected


def test_calculate_next_serial_rollover_old_date():
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    old_serial = 2020010101
    expected = int(f"{today}01")
    assert calculate_next_serial(old_serial) == expected


def test_calculate_next_serial_increment_strategy():
    assert calculate_next_serial(10, strategy="increment") == 11
    assert calculate_next_serial(42) == 43
