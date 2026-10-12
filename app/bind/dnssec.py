import hashlib
import struct
from pathlib import Path
from typing import Any
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_file


def compute_keytag(rdata_bytes: bytes) -> int:
    """Calculate 16-bit Key Tag for DNSKEY according to RFC 4034 Appendix B."""
    ac = 0
    for i, byte in enumerate(rdata_bytes):
        ac += (byte << 8) if (i % 2 == 0) else byte
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def compute_ds_digest(origin: str, rdata_bytes: bytes, digest_type: int = 2) -> str:
    """Compute DS digest for a DNSKEY according to RFC 4034 Section 5.1.4."""
    # Wire format of owner name in lowercase
    wire_name = b""
    for part in origin.strip(".").split("."):
        wire_name += bytes([len(part)]) + part.lower().encode("ascii")
    wire_name += b"\x00"

    data_to_hash = wire_name + rdata_bytes
    if digest_type == 1:
        return hashlib.sha1(data_to_hash).hexdigest().upper()
    elif digest_type == 2:
        return hashlib.sha256(data_to_hash).hexdigest().upper()
    return ""


def get_zone_dnssec_info(file_path: Path, origin: str) -> dict[str, Any]:
    """Inspect zone for DNSKEY records and compute Registrar DS records."""
    if not file_path.exists():
        return {"signed": False, "keys": [], "ds_records": []}

    try:
        model = parse_zone_file(file_path, origin=origin)
    except Exception:
        return {"signed": False, "keys": [], "ds_records": []}

    keys = []
    ds_records = []
    clean_origin = origin.strip().rstrip(".")

    for r in model.records:
        if r.rtype == "DNSKEY":
            parts = r.rdata.split(maxsplit=3)
            if len(parts) >= 4:
                try:
                    flags = int(parts[0])
                    proto = int(parts[1])
                    algo = int(parts[2])
                    pubkey = parts[3].replace(" ", "").replace("\t", "")

                    import base64
                    key_bytes = base64.b64decode(pubkey)
                    rdata_bytes = struct.pack("!HBB", flags, proto, algo) + key_bytes

                    key_tag = compute_keytag(rdata_bytes)
                    key_type = "KSK (Key Signing Key)" if flags == 257 else "ZSK (Zone Signing Key)"

                    algo_names = {
                        8: "RSA/SHA-256",
                        10: "RSA/SHA-512",
                        13: "ECDSA Curve P-256 with SHA-256",
                        14: "ECDSA Curve P-384 with SHA-384",
                        15: "Ed25519",
                    }

                    keys.append({
                        "key_tag": key_tag,
                        "key_type": key_type,
                        "flags": flags,
                        "algorithm": algo,
                        "algorithm_name": algo_names.get(algo, f"Algorithm {algo}"),
                        "public_key": pubkey,
                    })

                    # If KSK, generate DS records for domain registrars
                    if flags == 257:
                        ds_sha1 = compute_ds_digest(clean_origin, rdata_bytes, digest_type=1)
                        ds_sha256 = compute_ds_digest(clean_origin, rdata_bytes, digest_type=2)

                        ds_records.append({
                            "key_tag": key_tag,
                            "algorithm": algo,
                            "digest_type": 2,
                            "digest_type_name": "SHA-256 (Recommended)",
                            "digest": ds_sha256,
                            "ds_string": f"{clean_origin}. IN DS {key_tag} {algo} 2 {ds_sha256}",
                        })
                        ds_records.append({
                            "key_tag": key_tag,
                            "algorithm": algo,
                            "digest_type": 1,
                            "digest_type_name": "SHA-1",
                            "digest": ds_sha1,
                            "ds_string": f"{clean_origin}. IN DS {key_tag} {algo} 1 {ds_sha1}",
                        })
                except Exception:
                    pass

    return {
        "signed": len(keys) > 0,
        "keys": keys,
        "ds_records": ds_records,
    }
