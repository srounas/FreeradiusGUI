# FreeRADIUS GUI

A small vibecoded, self-contained web UI for configuring **FreeRADIUS 3.x** for **EAP-TLS certificate-based Wi-Fi authentication**.
<img width="1367" height="1239" alt="image" src="https://github.com/user-attachments/assets/bae17d30-7c22-4814-bd57-5e7eea1085a9" />

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

The installer and service run as root because the tool needs to write FreeRADIUS configuration files and restart the FreeRADIUS service.

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

If you are managing a production environment, restrict access to the GUI using a firewall, VPN, or SSH tunnel - for example:

```bash
sudo ufw allow from <your-admin-ip> to any port 8443 proto tcp
```

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

Depending on the distribution, the binary may also be named:

```bash
sudo radiusd -CX
```

The GUI performs this same validation automatically before applying changes.

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
