# Changelog

## v4

- **Backup & Transfer page** replaces the old one-shot "download backup"
  link with proper export/import for cloning configuration across
  multiple servers:
  - Export: choose to include clients and/or certificates in the `.zip`.
    Admin credentials and host-specific settings are deliberately excluded.
  - Import: upload another instance's export, with merge (add new, keep
    existing) or replace for clients, and append or replace for the CA
    bundle. Everything is validated the same way as a direct upload - a
    mismatched certificate/key pair or malformed client list is rejected
    with a specific reason rather than silently applied.

## v3

Bug fixes:
- **Auth log wasn't catching rejections, and only showed the username.**
  Root cause: the previous version parsed FreeRADIUS's free-text auth log,
  guessing at a format that didn't match reality (no `cn=` field exists in
  it at all, and `cli=<mac>` broke the client-details regex silently).
  Replaced entirely with a dedicated `linelog` module the GUI installs and
  hooks into both the accept and reject paths directly, with a fixed
  structured format. This reliably catches all events now and adds NAS
  IP, MAC address, client cert CN, and EAP type - not just the username.
- **Upgrading via `install.sh` didn't load the new code until reboot.**
  Root cause: `systemctl enable --now` is a no-op on a service that's
  already running - it doesn't restart it. Now explicitly restarts the
  service on every install/upgrade, plus verifies it actually came up.

New features:
- Certificate upload now supports PKCS#12/PFX bundles (common
  Windows/Intune export format), separate PEM or DER cert+key files, or
  pasted PEM - in addition to the existing paste option.
- Certificate/key validation on save: confirms the key actually matches
  the certificate before writing anything to disk, flags expired/soon-
  expiring/CA-flagged certificates, and rejects unparsable input with a
  specific error.
- CA bundle: add certificates one at a time or in bulk, with per-
  certificate removal and automatic dedup by fingerprint.
- Dashboard rebuilt as a proper status view: a setup checklist (what's
  configured vs. missing), FreeRADIUS version, last-hour auth activity
  summary, and a banner when there are unsaved changes pending Apply.
- Auth Log page: added NAS IP, MAC address, and EAP type columns, plus a
  live client-side search/filter box.
- Backup/restore: download a zip of GUI-managed clients + certificates
  from the Dashboard.
- Auth log file gets automatic weekly logrotate rotation.

## v2

- **Authentication log viewer** (`/auth_log`) — shows recent Access-Accept /
  Access-Reject events with timestamp, username, RADIUS client, client
  certificate CN, and rejection reason. Filterable by 15 min / 1 hour /
  6 hours / 24 hours, with optional auto-refresh. Backed by turning on
  standard FreeRADIUS auth logging (`auth`/`auth_badpass`/`auth_goodpass`
  in `radiusd.conf`) and parsing the resulting log lines.
- **CSRF protection** on every state-changing request.
- **Login rate limiting** — 5 failed attempts locks out an IP for 5 minutes.
- **Session timeout** — 30 minutes of inactivity logs you out.
- **Validate only** button — runs `freeradius -CX` against pending changes
  without restarting the live service.
- **Certificate expiry warnings** — flagged on the Dashboard and
  Certificates page for anything expired or expiring within 30 days.
- **Full CA chain display** — the Certificates page now shows every
  certificate in the trusted CA bundle, not just the first.
- **In-GUI password change** (`/settings`).
- **Upgrade-friendly installer** — re-running `install.sh` on an existing
  install preserves your admin credentials and settings.

## v1

- Server certificate + private key upload for EAP-TLS.
- Trusted CA bundle upload for client certificate validation.
- RADIUS client (NAS) management with generated shared secrets.
- Targeted, non-destructive edits to `eap.conf` / `clients.conf`.
- `freeradius -CX` validation before restart.
- Self-signed TLS for the GUI itself, systemd service, existing-clients
  import on install.
