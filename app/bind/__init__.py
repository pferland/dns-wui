from app.bind.soa import detect_serial_strategy, calculate_next_serial
from app.bind.parser import DnsRecord, SoaData, ZoneModel, parse_zone_file, parse_zone_text, serialize_zone
from app.bind.discovery import (
    DiscoveredZone,
    get_all_zones,
    append_zone_to_named_conf,
    append_slave_zone_to_named_conf,
    is_reverse_zone,
)
from app.bind.validator import validate_zone_text, validate_named_conf
from app.bind.executor import (
    save_zone_file,
    reload_zone_rndc,
    execute_rndc_cmd,
    rndc_flush,
    rndc_flushname,
    rndc_reconfig,
    rndc_status,
    rndc_dumpdb,
    rndc_retransfer,
)
from app.bind.ptr_sync import ip_to_reverse_fqdn, find_matching_reverse_zone, sync_ptr_record
from app.bind.tools import execute_dns_query, lint_zone_content
from app.bind.health import inspect_zone_health
from app.bind.revisions import (
    record_zone_revision,
    list_zone_revisions,
    generate_unified_diff,
    rollback_zone_to_revision,
)

__all__ = [
    "detect_serial_strategy",
    "calculate_next_serial",
    "DnsRecord",
    "SoaData",
    "ZoneModel",
    "parse_zone_file",
    "parse_zone_text",
    "serialize_zone",
    "DiscoveredZone",
    "get_all_zones",
    "append_zone_to_named_conf",
    "append_slave_zone_to_named_conf",
    "is_reverse_zone",
    "validate_zone_text",
    "validate_named_conf",
    "save_zone_file",
    "reload_zone_rndc",
    "execute_rndc_cmd",
    "rndc_flush",
    "rndc_flushname",
    "rndc_reconfig",
    "rndc_status",
    "rndc_dumpdb",
    "rndc_retransfer",
    "ip_to_reverse_fqdn",
    "find_matching_reverse_zone",
    "sync_ptr_record",
    "execute_dns_query",
    "lint_zone_content",
    "inspect_zone_health",
    "record_zone_revision",
    "list_zone_revisions",
    "generate_unified_diff",
    "rollback_zone_to_revision",
]
