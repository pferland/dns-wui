import asyncio
import time
from dataclasses import dataclass, asdict
from typing import Any
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
from app.bind.parser import parse_zone_text, ZoneModel
from app.bind.validator import validate_zone_text

GLOBAL_RESOLVERS = [
    {"name": "Local BIND 9", "ip": "127.0.0.1", "location": "Local Host"},
    {"name": "Cloudflare", "ip": "1.1.1.1", "location": "Global Anycast"},
    {"name": "Google Public DNS", "ip": "8.8.8.8", "location": "Global Anycast"},
    {"name": "Quad9 Security", "ip": "9.9.9.9", "location": "Zurich / Anycast"},
    {"name": "Cisco OpenDNS", "ip": "208.67.222.222", "location": "Global Anycast"},
    {"name": "AdGuard Public", "ip": "94.140.14.14", "location": "Cyprus / Global"},
    {"name": "Hurricane Electric", "ip": "74.82.42.42", "location": "Fremont, CA"},
    {"name": "Level3 / Lumen", "ip": "4.2.2.2", "location": "Tier 1 Backbone"},
]


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


async def check_global_propagation(query: str, rtype: str = "A") -> list[dict[str, Any]]:
    """Query global resolvers in parallel and compare propagation status."""
    async def query_one(resolver):
        res = await asyncio.to_thread(execute_dns_query, query, rtype, resolver["ip"], 53, 3.5)
        answers_str = [a.rdata for a in res.answers]
        return {
            "name": resolver["name"],
            "provider": resolver["name"],
            "ip": resolver["ip"],
            "server": resolver["ip"],
            "location": resolver["location"],
            "status": res.status,
            "response_time_ms": res.response_time_ms,
            "latency_ms": res.response_time_ms,
            "answers": answers_str,
        }

    tasks = [query_one(r) for r in GLOBAL_RESOLVERS]
    results = await asyncio.gather(*tasks)

    # Reference local answer (first item)
    local_answers = set(results[0]["answers"]) if results else set()

    for item in results:
        curr_set = set(item["answers"])
        if item["status"] == "NOERROR" and curr_set and curr_set == local_answers:
            item["matches_local"] = True
        elif not local_answers and item["status"] == "NOERROR":
            item["matches_local"] = True
        else:
            item["matches_local"] = False

    return results



async def benchmark_resolvers(query: str = "google.com", rounds: int = 5) -> list[dict[str, Any]]:
    """Benchmark query latencies across Local BIND and major public resolvers."""
    target_resolvers = [
        {"name": "Local BIND 9", "ip": "127.0.0.1"},
        {"name": "Cloudflare", "ip": "1.1.1.1"},
        {"name": "Google DNS", "ip": "8.8.8.8"},
        {"name": "Quad9", "ip": "9.9.9.9"},
    ]

    bench_results = []
    for r in target_resolvers:
        latencies = []
        for _ in range(rounds):
            res = await asyncio.to_thread(execute_dns_query, query, "A", r["ip"], 53, 2.0)
            if not res.status.startswith("ERROR"):
                latencies.append(res.response_time_ms)
        if latencies:
            avg_lat = round(sum(latencies) / len(latencies), 2)
            min_lat = round(min(latencies), 2)
            max_lat = round(max(latencies), 2)
            jitter = round(max_lat - min_lat, 2)
            success_rate = round((len(latencies) / rounds) * 100)
        else:
            avg_lat, min_lat, max_lat, jitter, success_rate = 0, 0, 0, 0, 0

        bench_results.append({
            "name": r["name"],
            "provider": r["name"],
            "ip": r["ip"],
            "server": r["ip"],
            "avg_ms": avg_lat,
            "avg_latency_ms": avg_lat,
            "min_ms": min_lat,
            "min_latency_ms": min_lat,
            "max_ms": max_lat,
            "max_latency_ms": max_lat,
            "jitter_ms": jitter,
            "success_rate": success_rate,
            "samples": len(latencies),
        })

    return sorted(bench_results, key=lambda x: (x["avg_latency_ms"] == 0, x["avg_latency_ms"]))



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
