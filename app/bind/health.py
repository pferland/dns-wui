from dataclasses import dataclass
from pathlib import Path
from typing import Any
from app.bind.parser import parse_zone_file, ZoneModel
from app.bind.discovery import get_all_zones


@dataclass
class HealthIssue:
    level: str  # "error", "warning", "info"
    category: str
    message: str
    suggestion: str | None = None


@dataclass
class ZoneHealthReport:
    zone_name: str
    score: int
    status: str  # "HEALTHY", "WARNING", "CRITICAL"
    issues: list[HealthIssue]
    total_records: int
    has_spf: bool
    has_dmarc: bool
    has_mx: bool


def inspect_zone_health(file_path: Path, origin: str) -> ZoneHealthReport:
    """Analyze a zone file and compute health metrics and best-practice recommendations."""
    issues: list[HealthIssue] = []
    score = 100

    try:
        model = parse_zone_file(file_path, origin=origin)
    except Exception as e:
        return ZoneHealthReport(
            zone_name=origin,
            score=0,
            status="CRITICAL",
            issues=[HealthIssue(level="error", category="Syntax", message=f"Failed parsing zone: {e}")],
            total_records=0,
            has_spf=False,
            has_dmarc=False,
            has_mx=False,
        )

    # 1. SOA Checks
    if not model.soa:
        score -= 40
        issues.append(HealthIssue(
            level="error",
            category="SOA",
            message="Zone is missing an SOA (Start of Authority) record.",
            suggestion="Add a valid SOA record defining serial, refresh, retry, and expire intervals.",
        ))
    else:
        if model.soa.expire < model.soa.refresh + model.soa.retry:
            score -= 10
            issues.append(HealthIssue(
                level="warning",
                category="SOA",
                message=f"SOA expire time ({model.soa.expire}s) is too short relative to refresh ({model.soa.refresh}s).",
                suggestion="Standard practice recommends an expire interval between 1209600s (14 days) and 2419200s (28 days).",
            ))

    # 2. Nameserver (NS) Checks
    ns_records = [r for r in model.records if r.rtype == "NS"]
    if len(ns_records) == 0:
        score -= 30
        issues.append(HealthIssue(
            level="error",
            category="Nameservers",
            message="No NS records found at zone origin.",
            suggestion="Declare at least one authoritative NS record.",
        ))
    elif len(ns_records) < 2:
        score -= 5
        issues.append(HealthIssue(
            level="info",
            category="Nameservers",
            message=f"Only {len(ns_records)} NS record declared. RFC 2182 recommends at least 2 distinct nameservers for redundancy.",
            suggestion="Add secondary nameserver (e.g., ns2.domain.com).",
        ))

    # 3. Glue Records Check
    clean_origin = origin.strip().rstrip(".").lower()
    for ns in ns_records:
        ns_target = ns.rdata.strip().rstrip(".").lower()
        if ns_target.endswith("." + clean_origin) or ns_target == clean_origin:
            # Must have A or AAAA
            glue_found = any(
                r.rtype in ("A", "AAAA") and (
                    r.name.strip().rstrip(".").lower() == ns_target or
                    (ns_target == clean_origin and r.name.strip() in ("@", clean_origin))
                )
                for r in model.records
            )
            if not glue_found:
                score -= 15
                issues.append(HealthIssue(
                    level="error",
                    category="Glue Records",
                    message=f"Nameserver '{ns.rdata}' is in-zone but missing a glue A/AAAA record.",
                    suggestion=f"Add an 'A' record pointing '{ns.rdata}' to the nameserver's IP address.",
                ))

    # 4. Email Security (SPF / DMARC) Checks
    has_mx = any(r.rtype == "MX" for r in model.records)
    has_spf = False
    has_dmarc = False

    for r in model.records:
        if r.rtype == "TXT":
            val = r.rdata.strip().strip('"').lower()
            if val.startswith("v=spf1"):
                has_spf = True
            name_norm = r.name.strip().lower()
            if (name_norm.startswith("_dmarc") or name_norm == "_dmarc") and "v=dmarc1" in val:
                has_dmarc = True

    if has_mx:
        if not has_spf:
            score -= 10
            issues.append(HealthIssue(
                level="warning",
                category="Email Security",
                message="Zone handles email (has MX records) but no SPF (v=spf1) TXT record is configured.",
                suggestion="Use the Email Stack Wizard to generate an SPF record to prevent email spoofing.",
            ))
        if not has_dmarc:
            score -= 5
            issues.append(HealthIssue(
                level="info",
                category="Email Security",
                message="Zone handles email but no DMARC (_dmarc) policy is defined.",
                suggestion="Use the Email Stack Wizard to create a DMARC policy record.",
            ))

    # Determine status label
    score = max(0, min(100, score))
    status_label = "HEALTHY" if score >= 85 else ("WARNING" if score >= 60 else "CRITICAL")

    return ZoneHealthReport(
        zone_name=origin,
        score=score,
        status=status_label,
        issues=issues,
        total_records=len(model.records),
        has_spf=has_spf,
        has_dmarc=has_dmarc,
        has_mx=has_mx,
    )
