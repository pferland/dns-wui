# DNS-WUI Feature Roadmap & Future Enhancements

This document tracks prioritized future features and operational improvements for the BIND 9 Web User Interface (`dns-wui`).

---

## 1. Operations, Reliability & Safety

- **Zone Versioning & 1-Click Rollback (Diff Viewer)**
  - Automatically create timestamped snapshot revisions or git-backed commits before any write (UI form edits and raw zone text edits).
  - Side-by-side visual diff viewer between revisions.
  - 1-click rollback to any previous revision with automatic serial incrementing and `rndc reload`.
- **Dry-Run & Pre-Flight Validation Panel**
  - Execute `named-checkzone` and display warnings/errors in the UI *before* saving changes to disk.
  - Warn on common DNS anti-patterns (e.g., CNAME coexisting with other records, missing trailing dot on FQDNs).
- **RNDC Server Controls Panel**
  - Dedicated operational controls in the UI:
    - `rndc flush` (clear resolver cache)
    - `rndc flushname <domain>` (clear specific domain cache)
    - `rndc reload <zone>` (reload single zone)
    - `rndc reconfig` (reload new zones without full restart)
    - `rndc status` / `rndc dumpdb`

---

## 2. DNS Record Management & Power Tools

- **In-Browser DNS Lookup / Dig Tool**
  - Built-in query console to test records against local BIND (`127.0.0.1:53`) and upstream resolvers (e.g., `1.1.1.1`, `8.8.8.8`) side-by-side to verify resolution and authoritative flags immediately.
- **Secondary / Slave Zone Mirroring (Local Copy of External Cloud DNS)**
  - Configure local BIND 9 as an automated secondary / slave mirror for external zones hosted on ClouDNS, Namecheap, Hurricane Electric, etc.
  - Automatically append `type slave;` / `type secondary;` blocks with specified cloud master nameserver IPs (`primaries { <IP>; };`).
  - Supports RFC 1996 `NOTIFY` and RFC 5936 `AXFR`/`IXFR` incremental zone transfers so local zone copies automatically stay synchronized with cloud providers in real-time.
  - UI displays synchronized slave records in a read-only table with transfer health indicators, last sync timestamps, and a manual **"Sync Now / Retransfer"** (`rndc retransfer <zone>`) trigger.
- **Bulk Record Import & Export**
  - Upload standard RFC 1035 zone files, CSV, or JSON record sets.
  - 1-click download of all zones as backup archive or single `.zone` exports.
- **Email Stack Wizard (SPF / DMARC / DKIM)**
  - Form-based wizard to generate valid SPF (`v=spf1 ...`), DMARC (`_dmarc.domain.com`), and DKIM TXT records with automated syntax checking.
- **Advanced Record Helpers**
  - Guided form builders for `SRV` (service, priority, weight, port) and `CAA` (issue, issuewild, iodef for Let's Encrypt / DigiCert).
- **Dynamic TTL Quick-Set**
  - Bulk TTL modification across entire zones (e.g., temporarily lowering TTL to 60s ahead of server migration).

---

## 3. Monitoring, Telemetry & Diagnostics

- **BIND 9 XML/JSON Statistics Channel Dashboard**
  - Connect to BIND's native statistics channel (`statistics-channels { inet 127.0.0.1 port 8053; };`).
  - Graph live query traffic: Queries per second (QPS), cache hit rates, query distribution by type (`A`, `AAAA`, `PTR`, `CNAME`), and rejected queries.
- **RPZ Ad-Block Analytics**
  - Dashboard widget for `rpz.adblock.spam.local` showing total blocked domain count, file size, and query blocking activity.
- **Zone Health Checker**
  - Automated checks for missing reverse PTR pointers, expired SOA serials, and unreachable nameservers.

---

## 4. Enterprise Access, API & Automation

- **API Keys & Automation Webhooks**
  - Long-lived API bearer tokens for CI/CD pipelines, Ansible, Terraform, or Certbot (automated DNS-01 ACME Let's Encrypt challenge validation).
- **Secondary / Replica Zone Management**
  - Monitor AXFR / IXFR zone transfer statuses, last transfer timestamps, and trigger `rndc retransfer <zone>` on secondary nameservers.
- **Role-Based Access Control (RBAC)**
  - Multi-user permission tiers:
    - *Super Admin*: Full server configuration, raw file editor, user management.
    - *Operator*: Record editing on assigned forward/reverse zones.
    - *Viewer*: Read-only record search and inspection.
