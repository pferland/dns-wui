# DNS-WUI Feature Roadmap & Implementation Status

This document tracks prioritized features and operational capabilities for the BIND 9 Web User Interface (`dns-wui`).

---

## 1. Operations, Reliability & Safety

- [x] **Zone Versioning & 1-Click Rollback (Diff Viewer)**
  - Automatically creates timestamped snapshot revisions before and after any write (UI form edits and raw zone text edits).
  - Visual unified diff viewer comparing past revisions against current zone file.
  - 1-click rollback to any historical revision with automated serial incrementing and `rndc reload`.
- [x] **Dry-Run & Pre-Flight Validation Panel**
  - Syntax verification via `named-checkzone` and dnspython AST parser before saving to disk.
  - Lints common DNS anti-patterns: CNAME coexisting with other records, missing trailing dots on targets, MX pointing to IPs, and abnormal TTL values.
- [x] **RNDC Server Controls Panel**
  - Operational controls in the UI (`/system`):
    - `rndc flush` (clear resolver cache)
    - `rndc flushname <domain>` (clear specific domain cache)
    - `rndc reload <zone>` (reload single zone)
    - `rndc reconfig` (reload new zones without full restart)
    - `rndc status` / `rndc dumpdb`

---

## 2. DNS Record Management & Power Tools

- [x] **In-Browser DNS Lookup / Dig Tool**
  - Built-in query console (`/tools`) to test records against local BIND (`127.0.0.1:53`) and upstream resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`).
  - Side-by-side comparison mode (Local BIND vs Cloudflare) with response latency, authoritative flags, answer/authority/additional records, and raw dig output.
- [x] **Secondary / Slave Zone Mirroring (Local Copy of External Cloud DNS)**
  - Configure local BIND 9 as an automated secondary mirror for external zones hosted on ClouDNS, Namecheap, Hurricane Electric, etc.
  - Automatically writes `type slave; masters { <IP>; };` blocks with specified cloud master nameserver IPs.
  - Read-only table view with dedicated **"Sync Now / Retransfer"** (`rndc retransfer <zone>`) trigger.
- [x] **Local DNS Split-Horizon Overrides (RPZ-Powered Custom LAN Intercepts)**
  - Dedicated **"Local Overrides"** section (`/overrides`) to selectively redirect specific subdomains of secondary or cloud-mirrored zones to local LAN IPs.
  - Uses a dedicated high-priority Response Policy Zone (`rpz.overrides.local`) evaluated before external resolution.
  - Leaves cloud zones pure and untouched while providing instant table-based addition, editing, and deletion.
- [x] **Bulk Record Import & Export**
  - Single-zone exports to standard RFC 1035 zone text, JSON record sets, and CSV.
  - 1-click download of all active zones as a complete `.zip` backup archive.
  - Bulk import from BIND text, JSON, or CSV with Append or Replace modes.
- [x] **Email Stack Wizard (SPF / DMARC / DKIM)**
  - Form-based wizard in Zone Detail to generate valid SPF (`v=spf1 ...`), DMARC (`_dmarc.domain.com`), and DKIM TXT records with 1-click addition to the zone.
- [x] **Advanced Record Helpers**
  - Guided form builders for `SRV` and `CAA` records.
- [x] **Dynamic TTL Quick-Set**
  - Bulk TTL modification across entire zones (60s migration mode, 300s, 3600s, 86400s).

---

## 3. Monitoring, Telemetry & Diagnostics

- [x] **RPZ Ad-Block & System Telemetry Analytics**
  - Telemetry cards for `rpz.adblock.spam.local` showing total blocked domain count, zone file size, split-horizon overrides count, and disk storage usage.
- [x] **Zone Health Checker**
  - Automated diagnostic audits calculating a health score (0-100) with categorized issue reports (SOA validity, Nameserver redundancy, Glue records, Email security compliance).
- [ ] **BIND 9 Native Statistics Channel Live Graphs**
  - Real-time QPS charts connecting directly to BIND's statistics-channels socket (`inet 127.0.0.1 port 8053;`).

---

## 4. Enterprise Access, API & Automation

- [x] **API Keys & Automation Tokens**
  - Long-lived API bearer tokens (`wui_...`) for CI/CD pipelines, Ansible, Terraform, and automated Certbot ACME DNS-01 validation.
  - Full management interface (`/api-keys`) supporting role scoping (`operator`, `admin`), expiration dates, and immediate revocation.
- [x] **Secondary / Replica Zone Management**
  - AXFR/IXFR transfer initiation and monitoring via `rndc retransfer <zone>`.
- [x] **Role-Based Access Control (RBAC)**
  - Multi-user permission tiers:
    - *Super Admin*: Full server configuration, RNDC controls, API keys, raw file editor, user management.
    - *Operator*: Record editing and zone operations on managed zones.
    - *Viewer*: Read-only record search, inspection, and DNS dig queries.
