import time
from dataclasses import dataclass, asdict
from typing import Any
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
from app.bind.parser import parse_zone_text, ZoneModel
from app.bind.validator import validate_zone_text


@dataclass
class DigRecordResult:
    name: str
    ttl: int
    rtype: str
    rdata: str


@dataclass
class DigResponse:
    query: str
    rtype: str
    server: str
    port: int
    status: str
    response_time_ms: float
    flags: list[str]
    answers: list[DigRecordResult]
    authority: list[DigRecordResult]
    additional: list[DigRecordResult]
    raw_text: str


def execute_dns_query(
    qname: str,
    rtype: str = "A",
    server: str = "127.0.0.1",
    port: int = 53,
    timeout: float = 3.0,
) -> DigResponse:
    """Perform real DNS lookup via UDP/TCP using dnspython."""
    clean_qname = qname.strip()
    if not clean_qname.endswith("."):
        clean_qname += "."

    rdtype = dns.rdatatype.from_text(rtype.upper())
    msg = dns.message.make_query(clean_qname, rdtype)

    start_time = time.perf_counter()
    try:
        response = dns.query.udp(msg, server, port=port, timeout=timeout)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
    except dns.message.Truncated:
        start_time = time.perf_counter()
        response = dns.query.tcp(msg, server, port=port, timeout=timeout)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return DigResponse(
            query=qname,
            rtype=rtype.upper(),
            server=server,
            port=port,
            status=f"ERROR: {e}",
            response_time_ms=round(duration_ms, 2),
            flags=[],
            answers=[],
            authority=[],
            additional=[],
            raw_text=f";; Connection to {server}#{port} failed: {e}",
        )

    rcode_str = dns.rcode.to_text(response.rcode())

    def extract_rr(rrset_list) -> list[DigRecordResult]:
        res = []
        for rrset in rrset_list:
            for item in rrset:
                res.append(DigRecordResult(
                    name=str(rrset.name),
                    ttl=rrset.ttl,
                    rtype=dns.rdatatype.to_text(rrset.rdtype),
                    rdata=str(item),
                ))
        return res

    flags_list = [f.name for f in dns.flags.Flag if f in response.flags]

    return DigResponse(
        query=qname,
        rtype=rtype.upper(),
        server=server,
        port=port,
        status=rcode_str,
        response_time_ms=round(duration_ms, 2),
        flags=flags_list,
        answers=extract_rr(response.answer),
        authority=extract_rr(response.authority),
        additional=extract_rr(response.additional),
        raw_text=str(response),
    )


@dataclass
class PreFlightIssue:
    level: str  # "error", "warning", "info"
    message: str
    record: str | None = None


@dataclass
class PreFlightResult:
    valid: bool
    message: str
    issues: list[PreFlightIssue]


async def lint_zone_content(origin: str, content: str) -> PreFlightResult:
    """Run syntax checking and DNS anti-pattern linting on proposed zone text."""
    issues: list[PreFlightIssue] = []

    # 1. Base validation
    is_valid, val_msg = await validate_zone_text(origin, content)
    if not is_valid:
        issues.append(PreFlightIssue(level="error", message=val_msg))
        return PreFlightResult(valid=False, message="Zone syntax error", issues=issues)

    # 2. Parse into model
    try:
        model = parse_zone_text(content, origin=origin)
    except Exception as e:
        issues.append(PreFlightIssue(level="error", message=f"Failed parsing zone text: {e}"))
        return PreFlightResult(valid=False, message="Parsing failure", issues=issues)

    # 3. Linter: CNAME coexistence
    records_by_name: dict[str, list[Any]] = {}
    for r in model.records:
        norm = r.name.strip().lower()
        records_by_name.setdefault(norm, []).append(r)

    for name, rrs in records_by_name.items():
        types = [r.rtype for r in rrs]
        if "CNAME" in types and len(types) > 1:
            issues.append(PreFlightIssue(
                level="error",
                message=f"RFC 1034 violation: CNAME record at '{name}' coexists with other record types ({', '.join(types)}).",
                record=name,
            ))

    # 4. Linter: Trailing dot checks
    for r in model.records:
        if r.rtype in ("CNAME", "MX", "NS", "PTR", "SRV"):
            target = r.rdata.strip().split()[-1]
            # If target contains a dot but no trailing dot, might unintentionally append origin
            if "." in target and not target.endswith(".") and not target.replace(".", "").isdigit():
                issues.append(PreFlightIssue(
                    level="warning",
                    message=f"Target '{target}' on {r.rtype} record for '{r.name}' has no trailing dot. BIND will treat it as relative and append '${model.origin}'.",
                    record=f"{r.name} {r.rtype}",
                ))

    # 5. Linter: MX pointing to IP or CNAME
    for r in model.records:
        if r.rtype == "MX":
            parts = r.rdata.split()
            if len(parts) >= 2:
                mx_host = parts[1].strip()
                if mx_host.replace(".", "").isdigit():
                    issues.append(PreFlightIssue(
                        level="error",
                        message=f"RFC 2181 violation: MX record target '{mx_host}' is an IP address; must be an FQDN hostname with an A/AAAA record.",
                        record=f"{r.name} MX",
                    ))

    # 6. Linter: Abnormal TTLs
    for r in model.records:
        if r.ttl < 30:
            issues.append(PreFlightIssue(
                level="warning",
                message=f"Extremely low TTL ({r.ttl}s) on '{r.name}'. May cause excessive upstream DNS query load.",
                record=f"{r.name} ({r.ttl}s)",
            ))
        elif r.ttl > 604800:
            issues.append(PreFlightIssue(
                level="warning",
                message=f"Very high TTL ({r.ttl}s > 7 days) on '{r.name}'. Changes will propagate slowly.",
                record=f"{r.name} ({r.ttl}s)",
            ))

    has_errors = any(i.level == "error" for i in issues)
    status_msg = "Zone has pre-flight errors" if has_errors else ("Zone has warnings" if issues else "Zone is healthy and valid")
    return PreFlightResult(valid=not has_errors, message=status_msg, issues=issues)
