# FreeRADIUS GUI

A small, self-contained web UI for configuring FreeRADIUS 3.x for EAP-TLS
(certificate) Wi-Fi authentication — the local, free/open-source equivalent
of pointing RADIUSaaS at Intune Cloud PKI. It manages exactly three things:

1. The RADIUS server's own certificate + private key (what the server
   presents to Wi-Fi clients during the TLS handshake).
2. The trusted CA bundle (which CA(s) issued your client/device certs — this
   is what makes cert-based client auth work).
3. RADIUS clients (your APs / Wi-Fi controllers) and their shared secrets.

It edits FreeRADIUS's real config files, validates with `freeradius -CX`
before touching anything live, and restarts the service for you.

## Requirements

- A Debian/Ubuntu or RHEL/CentOS/Fedora host with FreeRADIUS 3.x already
  installed via the distro package manager (`apt install freeradius` /
  `yum install freeradius`), same as your working FreeRADIUS setup.
- Root access (installer and service run as root — see **Security notes**
  below for why, and how to lock it down).
- Python 3.8+.

## Install

```bash
sudo ./install.sh
```

The installer will:
- Auto-detect your FreeRADIUS config directory and service name.
- Set up a Python virtualenv and install dependencies.
- Ask for an admin username/password for the GUI (or generate one).
- Generate a self-signed TLS cert so the GUI itself is served over HTTPS.
- Import any RADIUS clients you already have in `clients.conf` so nothing
  is lost.
- Install and start a `freeradius-gui.service` systemd unit.

At the end it prints the URL, e.g. `https://<host-ip>:8443`, and your login
credentials. Your browser will warn about the self-signed cert — that's
expected.

## Using it

1. **Certificates page** — three ways to load your server certificate +
   key: upload a PKCS#12/PFX bundle (the common Windows/Intune export
   format), upload separate cert + key files (PEM or DER), or paste PEM
   text directly. Same for the trusted CA bundle, which also supports
   adding certificates one at a time (with per-certificate remove) or all
   at once. Everything is parsed and validated on save — a certificate
   and key that don't actually match each other will be rejected with a
   clear error instead of silently breaking FreeRADIUS later. Expired or
   soon-to-expire certificates are flagged here and on the Dashboard.
2. **Clients page** — add each AP/controller with its IP (or a CIDR range
   if several APs share one entry) and a shared secret. Use "Generate" for
   a strong random secret.
3. **Dashboard** — a setup checklist shows what's configured and what
   isn't at a glance, plus service status, FreeRADIUS version, and
   authentication activity for the last hour. Click **Validate only** to
   run `freeradius -CX` against your pending changes without touching the
   live service, or **Apply & restart FreeRADIUS** to do the same check
   and then restart if it passes. A banner warns if you have unsaved
   changes that haven't been applied yet. If validation fails, nothing is
   touched and you get the raw error output to fix.
4. **Auth Log page** — shows who authenticated, when, from which
   AP/client (with its IP), the device's MAC address, the client
   certificate's CN, EAP type, and whether it was accepted or rejected
   (with the rejection reason). Filterable by time range with a live
   search box and optional 15-second auto-refresh.
5. **Settings page** — change the GUI's own admin password.
6. **Backup & Transfer page** — export RADIUS clients and/or certificates
   to a `.zip`, and import one on another FreeRADIUS GUI instance to give
   it an identical configuration. Useful for standing up a second server
   with the same setup. Admin credentials and host-specific settings
   (bind address, config paths) are never included in the export - each
   server keeps its own. Import offers merge (add new, keep existing) or
   replace for clients, and append or replace for the CA bundle; anything
   imported is validated the same way as a direct upload (a mismatched
   cert/key pair is rejected, not silently applied).

Nothing is written to disk on the FreeRADIUS side until you click Validate
or Apply.

## Upgrading

```bash
sudo ./install.sh
```
Re-running the installer detects your existing `/etc/freeradius-gui/config.json`
and leaves your admin credentials and settings alone — it only redeploys the
app code and systemd unit, and explicitly restarts the service so the new
code actually takes effect immediately (older versions of this installer
had a bug where `enable --now` on an already-running service was a no-op,
leaving the old code running until a reboot - fixed as of this version).
Click **Apply** once after upgrading so the new version can (re-)install
its logging hooks.

## Cloning configuration to multiple servers

1. Set up and configure the first server fully (certificates, CA, clients).
2. On its **Backup & Transfer** page, download an export with both clients
   and certificates checked.
3. Install this GUI on the second server the normal way (`sudo ./install.sh`).
4. On the second server's **Backup & Transfer** page, upload that export
   file. Choose "Replace" for clients if it should end up identical to
   the first server, or "Merge" if it already has its own clients you
   want to keep alongside the imported ones.
5. Go to Dashboard and click **Apply**.

Repeat step 3-5 for as many servers as you need. Each server keeps its own
admin login, bind address, and auto-detected FreeRADIUS paths - only the
RADIUS-facing configuration (clients, server cert, CA bundle) is cloned.

## What it actually edits

- `<raddb>/clients.conf` — fully regenerated from the GUI's client list on
  every Apply. Existing entries were imported once at install time; after
  that, the GUI is the source of truth for this file (a timestamped backup
  of the original is kept alongside it).
- `<raddb>/mods-available/eap` — only the specific `tls-config tls-common`
  keys (`certificate_file`, `private_key_file`, `private_key_password`,
  `ca_file`) and `default_eap_type` are updated in place; everything else
  in the file (PEAP/TTLS settings, comments, etc.) is left untouched.
- `<raddb>/mods-enabled/eap` — symlink created if missing.
- `<raddb>/sites-enabled/default` — a commented-out `eap` module reference
  in `authorize {}` is uncommented if found (most stock installs already
  have this enabled and nothing changes). Separately, a bare
  `linelog_auth_accept` call is inserted at the end of the `post-auth {}`
  block, and `linelog_auth_reject` at the end of the nested
  `Post-Auth-Type REJECT {}` block - both idempotent (won't be added
  twice) and found via brace-depth matching, not naive regex, so they
  land correctly even in a file with nested `if {}` blocks and comments.
- `<raddb>/mods-available/linelog_authlog` (new file, fully GUI-owned) —
  defines the two linelog module instances that write to the Auth Log's
  dedicated log file, plus a `mods-enabled/linelog_authlog` symlink.
- `/etc/logrotate.d/freeradius-gui` — weekly rotation, 8 weeks kept, for
  the auth log file, if `logrotate` is present on the system.

## How the auth log actually works

Earlier versions of this tool tried to parse FreeRADIUS's default
human-readable `Auth: ... Login OK / Login incorrect` log lines. That
turned out to be unreliable — the format varies (`cli=<mac>` vs no MAC at
all), it doesn't include the client certificate's CN at all, and some
EAP-TLS rejection paths didn't produce a matching line the parser
expected.

Instead, the GUI installs its own `linelog` module with a fixed, simple
format (`unixtime|Accept-or-Reject|user|nas-shortname|nas-ip|mac|cert-cn|eap-type|reason`)
and hooks explicit calls into both the accept and reject paths in
`sites-enabled/default`, so every authentication attempt is guaranteed to
produce one structured line the GUI can parse exactly, with no password
ever included in the log.

## Certificate validation

On every certificate save, the GUI:
- Parses whatever you gave it (PEM, DER, or PKCS#12) and rejects anything
  it can't actually parse, with a specific error rather than a silent
  failure.
- For the server certificate, confirms the private key you provided
  actually matches it (comparing public keys) - a mismatched pair is
  rejected outright rather than being written to disk and breaking
  FreeRADIUS on the next restart.
- Flags (but doesn't block) certificates that are expired, expiring
  within 30 days, or that have the CA:TRUE basic constraint set on what's
  supposed to be a leaf/server certificate - useful for catching an
  accidental upload of the wrong file.
- Deduplicates the trusted CA bundle by fingerprint, so re-adding the
  same CA twice is harmless.

## Security notes

This tool handles your RADIUS server's private key and client shared
secrets, and runs as root to write config and restart services. Treat it
like you would FreeRADIUS itself:

- It binds to `0.0.0.0:8443` by default with your own login required and
  a locally-generated TLS cert. For anything beyond a home lab, restrict
  access at the firewall to your admin IP/subnet, or only reach it over
  a VPN/SSH tunnel:
  ```bash
  ufw allow from <your-ip> to any port 8443 proto tcp
  ```
- Client secrets and the server private key are stored as plaintext on
  disk under `/etc/freeradius-gui/` and in FreeRADIUS's own config dir,
  the same way FreeRADIUS itself requires — file permissions are set to
  `600`/`640`, owner root.
- Consider running it only while you're actively making changes
  (`systemctl stop freeradius-gui`) rather than leaving it up permanently.

Built in: all state-changing requests require a CSRF token tied to your
session; failed logins are throttled (5 attempts locks an IP out for 5
minutes); and sessions expire after 30 minutes of inactivity.

## Uninstall

```bash
sudo systemctl disable --now freeradius-gui.service
sudo rm /etc/systemd/system/freeradius-gui.service
sudo rm -rf /opt/freeradius-gui /etc/freeradius-gui
sudo systemctl daemon-reload
```

Your FreeRADIUS config itself is untouched by uninstalling — only the GUI
is removed.
