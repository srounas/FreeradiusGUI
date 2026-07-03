# FreeRADIUS GUI

A small, self-contained web UI for configuring **FreeRADIUS 3.x** for **EAP-TLS certificate-based Wi-Fi authentication**.

Think of it as a local, free/open-source alternative to pointing RADIUSaaS at Intune Cloud PKI. It focuses on the practical pieces needed for certificate-based Wi-Fi authentication:

- The RADIUS server certificate and private key used during the TLS handshake.
- The trusted CA bundle used to validate client/device certificates.
- RADIUS clients, such as access points and Wi-Fi controllers, including their shared secrets.

The GUI edits the real FreeRADIUS configuration files, validates the configuration with `freeradius -CX` before applying changes, and restarts the FreeRADIUS service when needed.

---

## Features

- Manage the FreeRADIUS server certificate and private key.
- Upload certificates as:
  - PKCS#12 / PFX bundle
  - Separate certificate and key files
  - PEM text pasted directly into the UI
- Manage the trusted CA bundle used for EAP-TLS client authentication.
- Add, edit, remove, export, and import RADIUS clients.
- Import existing `clients.conf` entries during installation.
- Validate FreeRADIUS configuration before applying changes.
- Restart FreeRADIUS from the web UI after successful validation.
- View authentication activity using a structured FreeRADIUS linelog integration.
- Export and import configuration packages for cloning the setup to another server.
- Change the GUI admin password from the Settings page.
- Uses HTTPS by default with a locally generated self-signed certificate.
- CSRF protection, login throttling, and session timeout included.

---

## Requirements

The target server should already be a working FreeRADIUS host or a clean server where FreeRADIUS can be installed from the operating system package manager.

Supported platforms should include most modern:

- Debian
- Ubuntu
- RHEL
- CentOS Stream
- Fedora
- Other similar Linux distributions using systemd

Required software:

- FreeRADIUS 3.x
- Python 3.8 or newer
- Python virtual environment support
- Git or curl
- Root access

The installer and service run as root because the tool needs to write FreeRADIUS configuration files and restart the FreeRADIUS service. See [Security notes](#security-notes) for hardening recommendations.

---

## Quick install from GitHub

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y git freeradius python3 python3-venv python3-pip openssl

git clone https://github.com/srounas/FreeradiusGUI.git
cd FreeradiusGUI

chmod +x install.sh
sudo ./install.sh
```

### RHEL / CentOS Stream / Fedora

```bash
sudo dnf install -y git freeradius python3 python3-pip openssl

git clone https://github.com/srounas/FreeradiusGUI.git
cd FreeradiusGUI

chmod +x install.sh
sudo ./install.sh
```

If your distribution still uses `yum`, use:

```bash
sudo yum install -y git freeradius python3 python3-pip openssl
```

Then continue with:

```bash
git clone https://github.com/srounas/FreeradiusGUI.git
cd FreeradiusGUI

chmod +x install.sh
sudo ./install.sh
```

---

## Install without Git

If you do not want to install Git, download the repository archive directly from GitHub.

```bash
cd /tmp
curl -fsSL https://github.com/srounas/FreeradiusGUI/archive/refs/heads/main.tar.gz | tar -xz

cd FreeradiusGUI-main
chmod +x install.sh
sudo ./install.sh
```

If the default branch is changed in the future, replace `main` with the correct branch name.

---

## What the installer does

The installer will:

- Auto-detect your FreeRADIUS configuration directory.
- Auto-detect the FreeRADIUS systemd service name.
- Set up a Python virtual environment.
- Install the required Python dependencies.
- Ask for an admin username and password for the GUI, or generate credentials.
- Generate a self-signed TLS certificate for the GUI HTTPS listener.
- Import existing RADIUS clients from `clients.conf`.
- Install a `freeradius-gui.service` systemd unit.
- Enable and start the GUI service.

At the end of the installation, the installer prints the URL and login credentials.

Example:

```text
https://<server-ip>:8443
```

Your browser will warn about the self-signed certificate. This is expected unless you replace it with a trusted certificate.

---

## Accessing the GUI

After installation, open:

```text
https://<server-ip>:8443
```

Log in with the admin credentials shown by the installer.

If you are managing a production environment, restrict access to the GUI using a firewall, VPN, or SSH tunnel.

Example using UFW:

```bash
sudo ufw allow from <your-admin-ip> to any port 8443 proto tcp
```

---

## Using it

### Certificates page

The Certificates page lets you configure:

- The FreeRADIUS server certificate.
- The server private key.
- The trusted CA bundle used to validate client certificates.

Supported upload methods include:

- PKCS#12 / PFX bundle
- Separate certificate and private key files
- PEM text pasted directly into the UI

The tool validates certificates when saving.

It checks that:

- The certificate can be parsed.
- The private key matches the server certificate.
- The certificate is not expired.
- The certificate is not close to expiry.
- The uploaded server certificate does not appear to be a CA certificate.
- Duplicate CA certificates are removed from the trusted CA bundle.

A mismatched certificate and key pair is rejected before it can break FreeRADIUS.

---

### Clients page

The Clients page is used to manage RADIUS clients, such as:

- Wireless access points
- Wi-Fi controllers
- Network access servers

For each client, configure:

- Name
- IP address or CIDR range
- Shared secret

You can use the **Generate** button to create a strong random shared secret.

---

### Dashboard

The Dashboard shows:

- FreeRADIUS service status
- FreeRADIUS version
- Setup checklist
- Certificate status
- Recent authentication activity
- Pending unapplied changes

Available actions:

- **Validate only**  
  Runs `freeradius -CX` against the pending configuration without applying changes.

- **Apply & restart FreeRADIUS**  
  Validates the configuration and restarts FreeRADIUS if validation succeeds.

If validation fails, the live FreeRADIUS configuration is not touched and the raw validation output is shown in the UI.

---

### Auth Log page

The Auth Log page displays certificate authentication activity.

It shows:

- Authentication time
- Username
- RADIUS client / AP
- NAS IP address
- Device MAC address
- Client certificate CN
- EAP type
- Accept or reject result
- Rejection reason, when available

The page supports:

- Time range filtering
- Live search
- Optional 15-second auto-refresh

---

### Settings page

The Settings page lets you change the GUI admin password.

---

### Backup & Transfer page

The Backup & Transfer page can export and import configuration packages.

You can export:

- RADIUS clients
- Server certificate and private key
- Trusted CA bundle

This is useful when standing up a second FreeRADIUS server with an identical RADIUS-facing configuration.

The export does not include:

- GUI admin credentials
- Bind address
- Host-specific paths
- Local service settings

When importing clients, you can choose:

- Merge
- Replace

When importing CA certificates, you can choose:

- Append
- Replace

Imported certificates are validated the same way as directly uploaded certificates.

Nothing is written to the FreeRADIUS configuration until you validate or apply the changes.

---

## Upgrading from GitHub

To upgrade an existing installation, pull the latest version and rerun the installer.

If you installed using Git:

```bash
cd FreeradiusGUI
git pull
sudo ./install.sh
```

If the repository directory no longer exists, clone it again:

```bash
git clone https://github.com/srounas/FreeradiusGUI.git
cd FreeradiusGUI
sudo ./install.sh
```

If you installed from the archive:

```bash
cd /tmp
rm -rf FreeradiusGUI-main

curl -fsSL https://github.com/srounas/FreeradiusGUI/archive/refs/heads/main.tar.gz | tar -xz
cd FreeradiusGUI-main

sudo ./install.sh
```

Re-running the installer detects the existing configuration file:

```text
/etc/freeradius-gui/config.json
```

Existing admin credentials and settings are preserved. The installer redeploys the app code and systemd unit, then restarts the GUI service so the new code takes effect immediately.

After upgrading, open the Dashboard and click **Apply** once so the current version can install or update its FreeRADIUS logging hooks.

---

## Cloning configuration to multiple servers

To clone the RADIUS-facing configuration to another server:

1. Fully configure the first FreeRADIUS GUI server.
2. Go to **Backup & Transfer**.
3. Export both clients and certificates.
4. Install FreeRADIUS GUI on the second server.
5. Go to **Backup & Transfer** on the second server.
6. Import the export package.
7. Choose **Replace** for clients if the second server should be identical.
8. Choose **Merge** if the second server already has clients that should be kept.
9. Go to Dashboard.
10. Click **Apply**.

Repeat the process for as many servers as needed.

Each server keeps its own:

- Admin login
- Bind address
- Auto-detected FreeRADIUS paths
- Host-specific settings

Only the RADIUS-facing configuration is cloned.

---

## What it actually edits

The GUI modifies a focused set of FreeRADIUS files.

### `<raddb>/clients.conf`

Fully regenerated from the GUI client list on every apply.

Existing entries are imported once during installation. After that, the GUI becomes the source of truth for this file.

A timestamped backup of the original file is kept.

---

### `<raddb>/mods-available/eap`

Only selected `tls-config tls-common` values are updated in place:

- `certificate_file`
- `private_key_file`
- `private_key_password`
- `ca_file`
- `default_eap_type`

Other settings, such as PEAP/TTLS configuration and comments, are left untouched.

---

### `<raddb>/mods-enabled/eap`

A symlink is created if missing.

---

### `<raddb>/sites-enabled/default`

The installer and apply process may update this file to ensure EAP and auth logging work correctly.

Changes include:

- Uncommenting a commented-out `eap` module reference in `authorize {}` if found.
- Inserting `linelog_auth_accept` at the end of the `post-auth {}` block.
- Inserting `linelog_auth_reject` at the end of the nested `Post-Auth-Type REJECT {}` block.

These changes are idempotent and should not be added twice.

The code uses brace-depth matching instead of simple regex matching, so the hooks are placed correctly even when the file contains nested `if {}` blocks and comments.

---

### `<raddb>/mods-available/linelog_authlog`

A new GUI-owned FreeRADIUS module file.

It defines the linelog module instances used by the Auth Log page.

A corresponding symlink is created under:

```text
<raddb>/mods-enabled/linelog_authlog
```

---

### `/etc/logrotate.d/freeradius-gui`

If logrotate is present, the installer adds log rotation for the GUI authentication log.

Default behavior:

- Weekly rotation
- 8 weeks retained

---

## How the auth log works

Earlier versions attempted to parse FreeRADIUS default human-readable authentication log lines such as:

```text
Auth: Login OK
Auth: Login incorrect
```

That approach was unreliable because the format can vary, MAC addresses are not always present, client certificate CN values are not always included, and some EAP-TLS rejection paths may not produce a line that can be parsed consistently.

FreeRADIUS GUI instead installs its own linelog module with a fixed structured format:

```text
unixtime|Accept-or-Reject|user|nas-shortname|nas-ip|mac|cert-cn|eap-type|reason
```

The GUI hooks explicit linelog calls into both the accept and reject paths in `sites-enabled/default`.

This gives the GUI one predictable structured line per authentication attempt.

No password is included in the auth log.

---

## Certificate validation

On every certificate save, the GUI validates the submitted certificate material.

It will:

- Parse PEM, DER, and PKCS#12 input.
- Reject files that cannot be parsed.
- Confirm that the server certificate and private key match.
- Reject mismatched certificate and key pairs.
- Flag expired certificates.
- Flag certificates expiring within 30 days.
- Flag certificates with `CA:TRUE` when they appear to be uploaded as a server certificate.
- Deduplicate the trusted CA bundle by certificate fingerprint.

This helps prevent invalid certificate material from being written to disk and breaking FreeRADIUS during restart.

---

## Security notes

This tool handles sensitive RADIUS configuration, including:

- RADIUS server private key
- RADIUS client shared secrets
- Trusted CA certificates
- FreeRADIUS configuration files

It also runs as root because it needs to write FreeRADIUS configuration and restart system services.

Treat the GUI with the same care as the FreeRADIUS server itself.

Recommended hardening:

1. Restrict access to TCP port `8443`.

   Example:

   ```bash
   sudo ufw allow from <your-admin-ip> to any port 8443 proto tcp
   ```

2. Prefer access over VPN or SSH tunnel.

   Example SSH tunnel:

   ```bash
   ssh -L 8443:127.0.0.1:8443 root@<server-ip>
   ```

   Then open locally:

   ```text
   https://127.0.0.1:8443
   ```

3. Stop the GUI when not actively making changes.

   ```bash
   sudo systemctl stop freeradius-gui
   ```

4. Start it only when needed.

   ```bash
   sudo systemctl start freeradius-gui
   ```

5. Keep the host patched.

6. Use a strong admin password.

7. Limit shell and sudo access to trusted administrators.

Sensitive values are stored on disk because FreeRADIUS itself requires access to them.

Stored values include:

- Client shared secrets
- Server private key
- GUI configuration

Files are written with restrictive permissions, typically owned by root and using permissions such as `600` or `640`.

Built-in GUI protections include:

- HTTPS by default
- CSRF protection for state-changing requests
- Login throttling
- Temporary IP lockout after repeated failed logins
- Session timeout after inactivity

---

## Service management

Check GUI service status:

```bash
sudo systemctl status freeradius-gui
```

Start the GUI:

```bash
sudo systemctl start freeradius-gui
```

Stop the GUI:

```bash
sudo systemctl stop freeradius-gui
```

Restart the GUI:

```bash
sudo systemctl restart freeradius-gui
```

View logs:

```bash
sudo journalctl -u freeradius-gui -f
```

---

## FreeRADIUS validation

You can manually validate FreeRADIUS configuration with:

```bash
sudo freeradius -CX
```

Depending on the distribution, the binary may also be named:

```bash
sudo radiusd -CX
```

The GUI performs validation automatically before applying changes.

---

## Troubleshooting

### Browser warns about certificate

This is expected after installation because the GUI generates a local self-signed HTTPS certificate.

To remove the warning, replace the GUI certificate with one trusted by your browser or access the GUI through a properly secured reverse proxy.

---

### Cannot access the GUI

Check that the service is running:

```bash
sudo systemctl status freeradius-gui
```

Check listening ports:

```bash
sudo ss -lntp | grep 8443
```

Check firewall rules:

```bash
sudo ufw status
```

or, on firewalld-based systems:

```bash
sudo firewall-cmd --list-all
```

View service logs:

```bash
sudo journalctl -u freeradius-gui -n 100 --no-pager
```

---

### FreeRADIUS does not restart after applying changes

Run validation manually:

```bash
sudo freeradius -CX
```

Then check the FreeRADIUS service logs.

Debian / Ubuntu examples:

```bash
sudo systemctl status freeradius
sudo journalctl -u freeradius -n 100 --no-pager
```

RHEL / CentOS / Fedora examples:

```bash
sudo systemctl status radiusd
sudo journalctl -u radiusd -n 100 --no-pager
```

---

### Authentication log is empty

After installation or upgrade, open the Dashboard and click **Apply** once.

This ensures the linelog module and auth logging hooks are installed into the FreeRADIUS configuration.

Also confirm that clients are actually sending RADIUS requests to this server.

---

## Uninstall

Stop and disable the GUI service:

```bash
sudo systemctl disable --now freeradius-gui.service
```

Remove the systemd unit:

```bash
sudo rm -f /etc/systemd/system/freeradius-gui.service
```

Remove the application and GUI configuration:

```bash
sudo rm -rf /opt/freeradius-gui /etc/freeradius-gui
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

The FreeRADIUS configuration itself is not removed by uninstalling the GUI.

Only the GUI application and its own configuration are removed.

---

## Repository

GitHub repository:

```text
https://github.com/srounas/FreeradiusGUI
```

Clone command:

```bash
git clone https://github.com/srounas/FreeradiusGUI.git
```

---

## License

Add your project license information here.

For example, if this project is MIT licensed, add a `LICENSE` file and update this section:

```text
MIT License
```
