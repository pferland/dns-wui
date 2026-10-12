from dataclasses import dataclass, field
from pathlib import Path
import dns.zone
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.rdata
from app.bind.soa import calculate_next_serial


@dataclass
class DnsRecord:
    name: str
    rtype: str
    ttl: int
    rdata: str


@dataclass
class SoaData:
    mname: str = "ns1.local."
    rname: str = "hostmaster.local."
    serial: int = 1
    refresh: int = 3600
    retry: int = 600
    expire: int = 1209600
    minimum: int = 86400


@dataclass
class ZoneModel:
    origin: str  # e.g. "example.com."
    records: list[DnsRecord] = field(default_factory=list)
    soa: SoaData | None = None
    default_ttl: int = 3600


def parse_zone_file(file_path: Path, origin: str | None = None) -> ZoneModel:
    """Parse a BIND 9 zone file into a ZoneModel."""
    if not file_path.exists():
        raise FileNotFoundError(f"Zone file {file_path} not found")

    text = file_path.read_text(encoding="utf-8")
    return parse_zone_text(text, origin=origin or file_path.stem)


def parse_zone_text(text: str, origin: str) -> ZoneModel:
    """Parse zone text using dnspython."""
    clean_origin = origin.strip()
    if not clean_origin.endswith("."):
        clean_origin += "."

    z = dns.zone.from_text(text, origin=clean_origin, relativize=False)

    records: list[DnsRecord] = []
    soa_data: SoaData | None = None
    default_ttl = 3600

    origin_name = dns.name.from_text(clean_origin)

    for name, node in z.nodes.items():
        # name is dns.name.Name
        rel_name = name.relativize(origin_name).to_text()
        if rel_name == "@":
            disp_name = "@"
        else:
            disp_name = rel_name

        for rdataset in node.rdatasets:
            rtype_str = dns.rdatatype.to_text(rdataset.rdtype)
            ttl = rdataset.ttl

            for rdata in rdataset:
                rdata_str = rdata.to_text()

                if rdataset.rdtype == dns.rdatatype.SOA:
                    # Extract SOA parts
                    default_ttl = ttl
                    soa_data = SoaData(
                        mname=rdata.mname.to_text(),
                        rname=rdata.rname.to_text(),
                        serial=rdata.serial,
                        refresh=rdata.refresh,
                        retry=rdata.retry,
                        expire=rdata.expire,
                        minimum=rdata.minimum,
                    )
                else:
                    records.append(DnsRecord(
                        name=disp_name,
                        rtype=rtype_str,
                        ttl=ttl,
                        rdata=rdata_str,
                    ))

    return ZoneModel(
        origin=clean_origin,
        records=records,
        soa=soa_data,
        default_ttl=default_ttl,
    )


def serialize_zone(zone_model: ZoneModel, bump_serial: bool = True, strategy: str = "auto") -> str:
    """Format ZoneModel back into clean RFC 1035 zone text."""
    origin = zone_model.origin
    if not origin.endswith("."):
        origin += "."

    soa = zone_model.soa or SoaData()
    if bump_serial:
        new_serial = calculate_next_serial(soa.serial, strategy=strategy)
        soa.serial = new_serial

    lines = [
        f"; Zone file for {origin}",
        f"; Managed by BIND 9 DNS-WUI",
        f"$ORIGIN {origin}",
        f"$TTL {zone_model.default_ttl}",
        "",
        f"@       IN      SOA     {soa.mname} {soa.rname} (",
        f"                        {soa.serial:<12} ; Serial",
        f"                        {soa.refresh:<12} ; Refresh",
        f"                        {soa.retry:<12} ; Retry",
        f"                        {soa.expire:<12} ; Expire",
        f"                        {soa.minimum:<12} ; Negative Cache TTL",
        "                        )",
        "",
        "; --- Resource Records ---",
    ]

    # Sort records: NS first, then by name and rtype
    def sort_key(r: DnsRecord):
        type_priority = 0 if r.rtype == "NS" else (1 if r.rtype in ("A", "AAAA") else 2)
        return (type_priority, r.name, r.rtype, r.rdata)

    sorted_records = sorted(zone_model.records, key=sort_key)

    for rec in sorted_records:
        name_col = rec.name.ljust(24)
        ttl_col = str(rec.ttl).ljust(8)
        type_col = rec.rtype.ljust(8)
        lines.append(f"{name_col}{ttl_col}IN      {type_col}{rec.rdata}")

    lines.append("")
    return "\n".join(lines)
