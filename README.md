# BIND 9 DNS-WUI

A secure, modern, self-hosted web management interface for BIND 9 DNS servers. Designed to run co-located as a systemd service directly on your DNS host (e.g. `192.168.1.3`).

## Key Features

- **Safe Atomic Zone Pipeline**:
  - Validates all zone modifications using `dnspython` and `named-checkzone` before touching live files.
  - Automatically bumps SOA serial numbers based on detected scheme (`YYYYMMDDnn` or incremental).
  - Atomically stages and swaps zone files on disk, then executes `rndc reload <zone>` with zero downtime.
- **Hybrid Zone Discovery**:
  - Automatically parses existing zones from `named.conf` / `named.conf.local` and scans the designated zones directory.
- **Automatic Reverse DNS (PTR) Synchronization**:
  - When creating, editing, or deleting `A` or `AAAA` records, optionally auto-detects and synchronizes the matching `PTR` record in the corresponding reverse zone (`.in-addr.arpa` / `.ip6.arpa`).
- **Dual UI Modes**:
  - **Modern Homelab Dashboard**: Visual cards with zone status, record counts, and quick actions.
  - **Compact Sysadmin Table View**: Dense tabular display for rapid record auditing and management.
- **Enterprise-Grade Security**:
  - Argon2id password hashing and JWT sessions.
  - Two-Factor Authentication (TOTP / RFC 6238) with QR code setup for Google Authenticator / 1Password / Bitwarden.
  - Comprehensive Audit Log tracking every record addition, edit, deletion, and reload.
- **Raw Zone Syntax Editor**:
  - Full-text zone editor with syntax validation before applying changes.

---

## Quick Start (Development & Local Test)

```bash
# Clone the repository
cd dns-wui

# Install dependencies and start server
uv run uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Open your browser at `http://localhost:8080`.
- **Default Username:** `admin`
- **Default Password:** `admin123`

---

## Deployment on BIND 9 Host (192.168.1.3)

### 1. Copy Project to Host
```bash
rsync -avz --exclude='.venv' --exclude='data' ./ user@192.168.1.3:/opt/dns-wui
```

### 2. Install Dependencies on Host
```bash
cd /opt/dns-wui
uv sync --no-dev
```

### 3. Setup Systemd Service
```bash
sudo cp deploy/dns-wui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns-wui
```

### 4. Setup Sudoers Permissions (Optional for rndc / checkzone)
```bash
sudo cp deploy/sudoers.d/dns-wui /etc/sudoers.d/dns-wui
sudo chmod 0440 /etc/sudoers.d/dns-wui
```

---

## Configuration Reference (`.env` or Environment Variables)

| Variable | Default | Description |
|---|---|---|
| `DNS_WUI_SERVER_HOST` | `0.0.0.0` | Listen host |
| `DNS_WUI_SERVER_PORT` | `8080` | Listen port |
| `DNS_WUI_NAMED_CONF` | `/etc/bind/named.conf` | Path to BIND named.conf or named.conf.local |
| `DNS_WUI_ZONES_DIR` | `/etc/bind/zones` | Managed zone files directory |
| `DNS_WUI_DEFAULT_SOA_STRATEGY`| `date_revision` | Serial bump strategy (`date_revision` or `increment`) |
| `DNS_WUI_AUTO_PTR_SYNC` | `true` | Enable automatic PTR reverse record sync |
| `DNS_WUI_ADMIN_USERNAME` | `admin` | Initial admin username |
| `DNS_WUI_ADMIN_PASSWORD` | `admin123` | Initial admin password |
| `DNS_WUI_JWT_SECRET` | `...` | Secret key for JWT session tokens |