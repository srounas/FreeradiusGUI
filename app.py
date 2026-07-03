#!/usr/bin/env python3
"""
FreeRADIUS GUI - a small, purpose-built web UI for configuring FreeRADIUS
for EAP-TLS (certificate) authentication: server certificate, trusted CA
bundle, RADIUS clients (NAS) with shared secrets, an authentication log
viewer, and a system status/health view.

Runs on the same host as FreeRADIUS. Edits the real config files, validates
with `freeradius -CX`, and restarts the service.
"""
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request,
                    send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

APP_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("FRGUI_STATE_DIR", "/etc/freeradius-gui"))
CONFIG_FILE = STATE_DIR / "config.json"
CLIENTS_FILE = STATE_DIR / "clients.json"

SESSION_LIFETIME_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300
AUTH_LOG_FILENAME = "gui-auth.log"

EAP_TYPE_NAMES = {
    "1": "Identity", "3": "NAK", "4": "MD5-Challenge", "6": "GTC",
    "13": "TLS", "17": "LEAP", "21": "TTLS", "25": "PEAP",
    "26": "MS-EAP-Auth", "43": "FAST",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB, generous for certs


# --------------------------------------------------------------------------
# State / config helpers
# --------------------------------------------------------------------------

def load_state():
    if not CONFIG_FILE.exists():
        sys.exit(f"Missing {CONFIG_FILE}. Run install.sh first to configure the app.")
    with open(CONFIG_FILE) as f:
        return json.load(f)


def _persist_state():
    with open(CONFIG_FILE, "w") as f:
        json.dump(STATE, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


STATE = load_state()
app.secret_key = STATE["secret_key"]
app.permanent_session_lifetime = timedelta(minutes=SESSION_LIFETIME_MINUTES)

RADDB = Path(STATE["raddb_dir"])
CERTS_DIR = RADDB / "certs"
EAP_CONF = RADDB / "mods-available" / "eap"
MODS_ENABLED = RADDB / "mods-enabled"
CLIENTS_CONF = RADDB / "clients.conf"
SITES_ENABLED_DEFAULT = RADDB / "sites-enabled" / "default"
RADIUSD_CONF = RADDB / "radiusd.conf"
LINELOG_CONF = RADDB / "mods-available" / "linelog_authlog"
SERVICE_NAME = STATE.get("service_name", "freeradius")
RADIUSD_BIN = STATE.get("radiusd_bin", "freeradius")

_failed_logins = {}  # in-memory login throttle: {ip: [failure timestamps]}


def load_clients():
    if not CLIENTS_FILE.exists():
        return []
    with open(CLIENTS_FILE) as f:
        return json.load(f)


def save_clients(clients):
    CLIENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2)
    os.chmod(CLIENTS_FILE, 0o600)


# --------------------------------------------------------------------------
# Auth (session login) + CSRF + rate limiting
# --------------------------------------------------------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("authed"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def enforce_csrf():
    if request.method == "POST" and request.endpoint != "login":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token. Please reload the page and try again.")


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


def is_locked_out(ip):
    attempts = [t for t in _failed_logins.get(ip, []) if time.time() - t < LOGIN_LOCKOUT_SECONDS]
    _failed_logins[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(ip):
    _failed_logins.setdefault(ip, []).append(time.time())


def clear_failed_logins(ip):
    _failed_logins.pop(ip, None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        if is_locked_out(ip):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html")
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        if user == STATE["admin_user"] and check_password_hash(STATE["admin_pass_hash"], pw):
            clear_failed_logins(ip)
            session.permanent = True
            session["authed"] = True
            return redirect(url_for("dashboard"))
        record_failed_login(ip)
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Shell helpers
# --------------------------------------------------------------------------

def run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def config_test():
    return run([RADIUSD_BIN, "-CX"])


def service_status():
    rc, out = run(["systemctl", "is-active", SERVICE_NAME])
    return out.strip()


def service_restart():
    return run(["systemctl", "restart", SERVICE_NAME])


def freeradius_version():
    rc, out = run([RADIUSD_BIN, "-v"])
    if rc != 0:
        return None
    m = re.search(r'FreeRADIUS Version ([\d.]+)', out)
    return m.group(1) if m else out.splitlines()[0].strip() if out else None


# --------------------------------------------------------------------------
# Certificate parsing / validation / format conversion
# --------------------------------------------------------------------------

class CertError(Exception):
    pass


def _load_all_certs(data: bytes):
    """Return a list of x509 Certificate objects found in PEM or DER bytes."""
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        blocks = re.findall(
            rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.DOTALL
        )
        if not blocks:
            raise CertError("No '-----BEGIN CERTIFICATE-----' block found in the PEM data")
        certs = []
        for b in blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(b))
            except Exception as e:  # noqa: BLE001
                raise CertError(f"Could not parse a certificate block: {e}") from e
        return certs
    else:
        try:
            return [x509.load_der_x509_certificate(data)]
        except Exception as e:  # noqa: BLE001
            raise CertError(f"Not a recognizable PEM or DER certificate: {e}") from e


def _load_private_key(data: bytes, password: str):
    pw = password.encode() if password else None
    stripped = data.lstrip()
    try:
        if stripped.startswith(b"-----BEGIN"):
            m = re.search(
                rb'-----BEGIN (?:ENCRYPTED )?(?:RSA |EC )?PRIVATE KEY-----.*?'
                rb'-----END (?:ENCRYPTED )?(?:RSA |EC )?PRIVATE KEY-----', data, re.DOTALL
            )
            block = m.group(0) if m else data
            return serialization.load_pem_private_key(block, password=pw)
        return serialization.load_der_private_key(data, password=pw)
    except TypeError as e:
        raise CertError("Private key is encrypted - a password is required") from e
    except ValueError as e:
        raise CertError(f"Could not read private key (wrong password, or unsupported format?): {e}") from e


def _cert_to_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_to_pem(key, password: str) -> str:
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    ).decode()


def _keys_match(cert, key) -> bool:
    try:
        a = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        b = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return a == b
    except Exception:  # noqa: BLE001
        return False


def _is_ca_cert(cert) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(bc.ca)
    except x509.ExtensionNotFound:
        return False


def _cert_fingerprint(cert) -> str:
    return cert.fingerprint(cert.signature_hash_algorithm).hex()


def build_server_cert_key(form, files):
    """Validate + normalize an uploaded server cert/key from any supported
    source (pasted PEM, uploaded PEM/DER files, or a PKCS#12 bundle).
    Returns (cert_pem_str, key_pem_str, key_password) or raises CertError.
    """
    p12_file = files.get("p12_file")
    p12_password = form.get("p12_password", "")

    if p12_file and p12_file.filename:
        data = p12_file.read()
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(
                data, p12_password.encode() if p12_password else None
            )
        except Exception as e:  # noqa: BLE001
            raise CertError(f"Could not open PKCS#12 file (wrong password?): {e}") from e
        if cert is None or key is None:
            raise CertError("The PKCS#12 file did not contain both a certificate and a private key")
        cert_pem = _cert_to_pem(cert)
        for c in (extra or []):
            cert_pem += _cert_to_pem(c)
        key_pem = _key_to_pem(key, "")
        return cert_pem, key_pem, ""

    cert_file = files.get("cert_file")
    key_file = files.get("key_file")
    cert_raw = cert_file.read() if (cert_file and cert_file.filename) else form.get("cert_pem", "").strip().encode()
    key_raw = key_file.read() if (key_file and key_file.filename) else form.get("key_pem", "").strip().encode()
    key_password = form.get("key_password", "")

    if not cert_raw:
        raise CertError("No certificate provided (paste PEM or upload a file)")
    if not key_raw:
        raise CertError("No private key provided (paste PEM or upload a file)")

    certs = _load_all_certs(cert_raw)
    cert_pem = "".join(_cert_to_pem(c) for c in certs)
    key_obj = _load_private_key(key_raw, key_password)
    key_pem = _key_to_pem(key_obj, key_password)

    if not _keys_match(certs[0], key_obj):
        raise CertError("The certificate and private key do not match each other")

    return cert_pem, key_pem, key_password


def build_ca_bundle(form, files):
    """Validate + normalize an uploaded CA bundle from pasted PEM, an
    uploaded PEM/DER file, or a PKCS#12 file (cert(s) only, key ignored).
    Returns a list of PEM cert strings.
    """
    p12_file = files.get("ca_p12_file")
    p12_password = form.get("ca_p12_password", "")

    if p12_file and p12_file.filename:
        data = p12_file.read()
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(
                data, p12_password.encode() if p12_password else None
            )
        except Exception as e:  # noqa: BLE001
            raise CertError(f"Could not open PKCS#12 file (wrong password?): {e}") from e
        certs = ([cert] if cert else []) + list(extra or [])
        if not certs:
            raise CertError("The PKCS#12 file did not contain any certificates")
        return [_cert_to_pem(c) for c in certs]

    ca_file = files.get("ca_file_upload")
    raw = ca_file.read() if (ca_file and ca_file.filename) else form.get("ca_pem", "").strip().encode()
    if not raw:
        raise CertError("No CA certificate provided (paste PEM or upload a file)")
    certs = _load_all_certs(raw)
    return [_cert_to_pem(c) for c in certs]


def combine_ca_pems(existing_pems, new_pems):
    """Dedup-merge two lists of PEM cert strings by fingerprint."""
    seen = set()
    combined = []
    for pem in existing_pems + new_pems:
        fp = hashlib.sha256(pem.encode()).hexdigest()
        if fp not in seen:
            seen.add(fp)
            combined.append(pem)
    return combined


def existing_ca_pems(ca_bundle_path):
    if not ca_bundle_path.exists():
        return []
    try:
        return [_cert_to_pem(c) for c in _load_all_certs(ca_bundle_path.read_bytes())]
    except CertError:
        return []


def cert_display_info(cert):
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": str(not_after),
        "expired": days_left < 0,
        "expiring_soon": 0 <= days_left <= 30,
        "days_left": days_left,
        "is_ca": _is_ca_cert(cert),
        "fingerprint": _cert_fingerprint(cert)[:16],
    }


def certs_info_list(path: Path):
    if not HAVE_CRYPTOGRAPHY or not path.exists():
        return []
    try:
        data = path.read_bytes()
    except Exception as e:  # noqa: BLE001
        return [{"error": str(e)}]
    results = []
    try:
        for cert in _load_all_certs(data):
            results.append(cert_display_info(cert))
    except CertError as e:
        results.append({"error": str(e)})
    return results


def cert_info(path: Path):
    certs = certs_info_list(path)
    return certs[0] if certs else None


def eap_tls_paths():
    return {
        "server_cert": CERTS_DIR / "server.pem",
        "server_key": CERTS_DIR / "server.key",
        "ca_bundle": CERTS_DIR / "ca.pem",
    }


def any_cert_warning(info_dict):
    for v in info_dict.values():
        items = v if isinstance(v, list) else [v]
        for item in items:
            if item and (item.get("expired") or item.get("expiring_soon")):
                return True
    return False


# --------------------------------------------------------------------------
# eap.conf editing (targeted, non-destructive)
# --------------------------------------------------------------------------

def set_conf_value(text, key, value, quote=True):
    val = f'"{value}"' if quote else str(value)
    pattern = re.compile(rf'^[ \t]*#?[ \t]*{re.escape(key)}[ \t]*=.*$', re.MULTILINE)
    new_text, n = pattern.subn(f"\t{key} = {val}", text, count=1)
    return new_text, n


def apply_eap_tls_settings(cert_path, key_path, key_password, ca_path):
    text = EAP_CONF.read_text()
    changes = []
    for key, value, quote in [
        ("default_eap_type", "tls", False),
        ("private_key_password", key_password or "", True),
        ("private_key_file", str(key_path), True),
        ("certificate_file", str(cert_path), True),
        ("ca_file", str(ca_path), True),
    ]:
        text, n = set_conf_value(text, key, value, quote)
        changes.append(f"{key}: {'updated' if n else 'NOT FOUND (left unchanged)'}")
    EAP_CONF.write_text(text)
    return changes


def ensure_eap_module_enabled():
    link = MODS_ENABLED / "eap"
    if link.exists() or link.is_symlink():
        return "mods-enabled/eap already present"
    os.symlink("../mods-available/eap", link)
    return "created mods-enabled/eap symlink"


def ensure_eap_in_default_site():
    if not SITES_ENABLED_DEFAULT.exists():
        return "sites-enabled/default not found, skipped"
    text = SITES_ENABLED_DEFAULT.read_text()
    original = text
    text = re.sub(r'^([ \t]*)#[ \t]*eap[ \t]*$', r'\1eap', text, flags=re.MULTILINE)
    if text != original:
        SITES_ENABLED_DEFAULT.write_text(text)
        return "uncommented 'eap' reference in sites-enabled/default"
    return "no commented 'eap' reference found (likely already enabled)"


# --------------------------------------------------------------------------
# clients.conf generation (GUI is source of truth once installed)
# --------------------------------------------------------------------------

CLIENTS_HEADER = "# Managed by FreeRADIUS GUI - manual edits will be overwritten on next Apply\n\n"


def render_clients_conf(clients):
    lines = [CLIENTS_HEADER]
    for c in clients:
        lines.append(f'client {c["name"]} {{')
        lines.append(f'\tipaddr = {c["ipaddr"]}')
        lines.append(f'\tsecret = {c["secret"]}')
        if c.get("shortname"):
            lines.append(f'\tshortname = {c["shortname"]}')
        if c.get("nas_type"):
            lines.append(f'\tnas_type = {c["nas_type"]}')
        if c.get("require_message_authenticator"):
            lines.append('\trequire_message_authenticator = yes')
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def write_clients_conf(clients):
    CLIENTS_CONF.write_text(render_clients_conf(clients))


# --------------------------------------------------------------------------
# Authentication logging - dedicated linelog module hooked into both the
# accept and reject paths, instead of parsing FreeRADIUS's free-text log.
# --------------------------------------------------------------------------

def resolve_logdir():
    if not RADIUSD_CONF.exists():
        return "/var/log/freeradius"
    text = RADIUSD_CONF.read_text()
    m = re.search(r'^\s*logdir\s*=\s*"?([^"\n]+)"?\s*$', text, re.MULTILINE)
    return m.group(1).strip() if m else "/var/log/freeradius"


def auth_log_path():
    return f"{resolve_logdir()}/{AUTH_LOG_FILENAME}"


def _mask_comments(text):
    """Blank out comment-only lines while preserving exact character offsets,
    so brace-matching below never gets confused by braces inside comments."""
    return "\n".join(
        (" " * len(line)) if line.lstrip().startswith("#") else line
        for line in text.split("\n")
    )


def _insert_module_call(text, header_regex, module_name):
    """Insert a bare `module_name` call just before the closing brace of the
    first block whose opening line matches header_regex. Idempotent - if the
    module is already referenced anywhere, does nothing."""
    if re.search(rf'^[ \t]*{re.escape(module_name)}[ \t]*$', text, re.MULTILINE):
        return text, f"{module_name} already present"

    masked = _mask_comments(text)
    m = re.search(header_regex, masked, re.MULTILINE)
    if not m:
        return text, f"could not find block for {module_name} (pattern not found) - add it manually"

    start = masked.index("{", m.start())
    depth = 0
    i = start
    while i < len(masked):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth != 0:
        return text, f"could not find matching closing brace for {module_name} - add it manually"

    # Insert at the start of the closing brace's own line, not immediately
    # before the '}' character, so that line's original indentation is left
    # untouched and our new line gets its own clean indentation.
    line_start = text.rfind("\n", 0, i) + 1
    new_text = text[:line_start] + f"\t{module_name}\n" + text[line_start:]
    return new_text, f"inserted {module_name}"


def ensure_linelog_hooks():
    """Set up a dedicated linelog module for auth events and hook it into
    both post-auth{} (accept) and Post-Auth-Type REJECT{} (reject)."""
    messages = []
    log_file = auth_log_path()

    fmt_accept = (
        '%l|Accept|%{User-Name}|%{client:shortname}|%{Packet-Src-IP-Address}|'
        '%{Calling-Station-Id}|%{TLS-Client-Cert-Common-Name}|%{EAP-Type}|-'
    )
    fmt_reject = (
        '%l|Reject|%{User-Name}|%{client:shortname}|%{Packet-Src-IP-Address}|'
        '%{Calling-Station-Id}|%{TLS-Client-Cert-Common-Name}|%{EAP-Type}|'
        '%{%{Module-Failure-Message}:-%{Reply-Message}}'
    )
    conf_text = f"""# Managed by FreeRADIUS GUI - dedicated auth event log for the Auth Log page
linelog linelog_auth_accept {{
\tfilename = {log_file}
\tpermissions = 0640
\tformat = "{fmt_accept}"
}}

linelog linelog_auth_reject {{
\tfilename = {log_file}
\tpermissions = 0640
\tformat = "{fmt_reject}"
}}
"""
    LINELOG_CONF.write_text(conf_text)
    messages.append("wrote mods-available/linelog_authlog")

    link = MODS_ENABLED / "linelog_authlog"
    if not (link.exists() or link.is_symlink()):
        os.symlink("../mods-available/linelog_authlog", link)
        messages.append("created mods-enabled/linelog_authlog symlink")
    else:
        messages.append("mods-enabled/linelog_authlog already present")

    if SITES_ENABLED_DEFAULT.exists():
        text = SITES_ENABLED_DEFAULT.read_text()
        text, msg1 = _insert_module_call(text, r'^post-auth[ \t]*\{', "linelog_auth_accept")
        messages.append(msg1)
        text, msg2 = _insert_module_call(text, r'^[ \t]*Post-Auth-Type[ \t]+REJECT[ \t]*\{', "linelog_auth_reject")
        messages.append(msg2)
        SITES_ENABLED_DEFAULT.write_text(text)
    else:
        messages.append("sites-enabled/default not found - could not hook in linelog calls")

    _write_logrotate_conf(log_file)
    return messages, log_file


def _write_logrotate_conf(log_file):
    logrotate_dir = Path("/etc/logrotate.d")
    if not logrotate_dir.is_dir():
        return
    conf = logrotate_dir / "freeradius-gui"
    conf.write_text(f"""{log_file} {{
\tweekly
\trotate 8
\tmissingok
\tnotifempty
\tcompress
\tdelaycompress
}}
""")


def parse_auth_log(log_file, minutes, max_lines=50000):
    if not log_file or not Path(log_file).exists():
        return [], {"accept": 0, "reject": 0}, (
            "Auth log not found yet - click Apply on the Dashboard once, then generate "
            "some auth traffic. (This creates the log hooks; FreeRADIUS creates the file "
            "itself on the first authentication attempt.)"
        )

    cutoff = datetime.now().timestamp() - minutes * 60
    entries = []
    counts = {"accept": 0, "reject": 0}

    rc, out = run(["tail", "-n", str(max_lines), str(log_file)])
    lines = out.splitlines() if rc == 0 else []

    for line in lines:
        parts = line.split("|", 8)
        if len(parts) != 9:
            continue
        ts_raw, outcome, user, client, nas_ip, calling_station, cn, eap_type, reason = parts
        try:
            ts = float(ts_raw)
        except ValueError:
            continue
        if ts < cutoff:
            continue
        if outcome not in ("Accept", "Reject"):
            continue
        counts["accept" if outcome == "Accept" else "reject"] += 1
        entries.append({
            "time": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            "sort_ts": ts,
            "outcome": outcome,
            "user": user or "-",
            "client": client or "-",
            "nas_ip": nas_ip or "-",
            "calling_station": calling_station or "-",
            "cn": cn or "-",
            "eap_type": EAP_TYPE_NAMES.get(eap_type, eap_type) if eap_type else "-",
            "reason": reason if reason and reason != "-" else "",
        })

    entries.sort(key=lambda e: e["sort_ts"], reverse=True)
    return entries, counts, None


# --------------------------------------------------------------------------
# Status / health checks + pending-changes detection
# --------------------------------------------------------------------------

def compute_pending_hash():
    parts = [json.dumps(load_clients(), sort_keys=True)]
    for p in eap_tls_paths().values():
        if p.exists():
            try:
                parts.append(p.read_text())
            except Exception:  # noqa: BLE001
                pass
    return hashlib.sha256("||".join(parts).encode()).hexdigest()


def system_checks():
    checks = []
    status = service_status()
    checks.append({
        "label": "FreeRADIUS service", "ok": status == "active",
        "detail": status,
    })
    eap_link = (MODS_ENABLED / "eap").exists() or (MODS_ENABLED / "eap").is_symlink()
    checks.append({
        "label": "EAP module enabled", "ok": eap_link,
        "detail": "mods-enabled/eap present" if eap_link else "not enabled yet - click Apply",
    })
    paths = eap_tls_paths()
    cert_ok = paths["server_cert"].exists() and paths["server_key"].exists()
    checks.append({
        "label": "Server certificate configured", "ok": cert_ok,
        "detail": "configured" if cert_ok else "not uploaded yet",
    })
    ca_ok = paths["ca_bundle"].exists()
    checks.append({
        "label": "Trusted CA configured", "ok": ca_ok,
        "detail": "configured" if ca_ok else "not uploaded yet",
    })
    n_clients = len(load_clients())
    checks.append({
        "label": "RADIUS clients configured", "ok": n_clients > 0,
        "detail": f"{n_clients} client(s)",
    })
    linelog_ok = (MODS_ENABLED / "linelog_authlog").exists()
    checks.append({
        "label": "Auth logging hooks installed", "ok": linelog_ok,
        "detail": "installed" if linelog_ok else "click Apply to install",
    })
    return checks


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    status = service_status()
    paths = eap_tls_paths()
    info = {
        "server_cert": cert_info(paths["server_cert"]),
        "ca_bundle": certs_info_list(paths["ca_bundle"]),
    }
    warning = any_cert_warning({"server_cert": info["server_cert"], "ca_bundle": info["ca_bundle"]})
    clients = load_clients()
    pending = compute_pending_hash() != STATE.get("last_applied_hash")
    log_file = STATE.get("auth_log_file") or (auth_log_path() if RADIUSD_CONF.exists() else None)
    _, counts, _ = parse_auth_log(log_file, 60)
    return render_template(
        "dashboard.html",
        status=status,
        info=info,
        cert_warning=warning,
        client_count=len(clients),
        raddb=str(RADDB),
        last_apply=STATE.get("last_apply"),
        pending_changes=pending,
        checks=system_checks(),
        auth_counts=counts,
        freeradius_version=freeradius_version(),
    )


@app.route("/certs", methods=["GET", "POST"])
@login_required
def certs():
    paths = eap_tls_paths()
    if request.method == "POST":
        action = request.form.get("action")
        CERTS_DIR.mkdir(parents=True, exist_ok=True)

        if action == "upload_server":
            try:
                cert_pem, key_pem, key_password = build_server_cert_key(request.form, request.files)
            except CertError as e:
                flash(f"Certificate not saved: {e}", "error")
                return redirect(url_for("certs"))
            paths["server_cert"].write_text(cert_pem)
            paths["server_key"].write_text(key_pem)
            os.chmod(paths["server_cert"], 0o640)
            os.chmod(paths["server_key"], 0o640)
            STATE["last_key_password"] = key_password
            _persist_state()
            info = cert_display_info(_load_all_certs(cert_pem.encode())[0])
            msg = f"Server certificate saved and verified (subject: {info['subject']})."
            if info["expired"]:
                msg += " WARNING: this certificate is already expired."
            elif info["expiring_soon"]:
                msg += f" Note: this certificate expires in {info['days_left']} days."
            flash(msg + " Go to Dashboard and click Apply.", "success")

        elif action == "upload_ca":
            mode = request.form.get("ca_mode", "replace")
            try:
                new_pems = build_ca_bundle(request.form, request.files)
            except CertError as e:
                flash(f"CA bundle not saved: {e}", "error")
                return redirect(url_for("certs"))
            existing_pems = existing_ca_pems(paths["ca_bundle"]) if mode == "append" else []
            combined = combine_ca_pems(existing_pems, new_pems)
            paths["ca_bundle"].write_text("".join(combined))
            os.chmod(paths["ca_bundle"], 0o640)
            flash(f"Trusted CA bundle saved ({len(combined)} certificate(s) total). "
                  "Go to Dashboard and click Apply.", "success")

        elif action == "delete_ca_cert":
            idx = int(request.form.get("index", -1))
            if paths["ca_bundle"].exists():
                try:
                    certs_list = [_cert_to_pem(c) for c in _load_all_certs(paths["ca_bundle"].read_bytes())]
                    if 0 <= idx < len(certs_list):
                        del certs_list[idx]
                        paths["ca_bundle"].write_text("".join(certs_list))
                        flash("Certificate removed from CA bundle. Go to Dashboard and click Apply.", "success")
                except CertError as e:
                    flash(f"Could not update CA bundle: {e}", "error")

        return redirect(url_for("certs"))

    info = {
        "server_cert": cert_info(paths["server_cert"]),
        "ca_bundle": certs_info_list(paths["ca_bundle"]),
    }
    return render_template("certs.html", info=info)


@app.route("/clients", methods=["GET", "POST"])
@login_required
def clients():
    all_clients = load_clients()

    if request.method == "POST":
        action = request.form.get("action")

        if action in ("add", "edit"):
            name = request.form.get("name", "").strip()
            ipaddr = request.form.get("ipaddr", "").strip()
            secret = request.form.get("secret", "").strip()
            shortname = request.form.get("shortname", "").strip()
            nas_type = request.form.get("nas_type", "").strip()
            require_ma = bool(request.form.get("require_message_authenticator"))

            if not name or not ipaddr or not secret:
                flash("Name, IP/network, and secret are required", "error")
                return redirect(url_for("clients"))
            try:
                ipaddress.ip_network(ipaddr, strict=False)
            except ValueError:
                flash(f"'{ipaddr}' is not a valid IP address or CIDR network", "error")
                return redirect(url_for("clients"))
            if not re.match(r'^[A-Za-z0-9_.\-]+$', name):
                flash("Client name may only contain letters, numbers, dots, dashes, underscores", "error")
                return redirect(url_for("clients"))

            new_entry = {
                "name": name, "ipaddr": ipaddr, "secret": secret,
                "shortname": shortname, "nas_type": nas_type,
                "require_message_authenticator": require_ma,
            }

            if action == "edit":
                orig_name = request.form.get("orig_name", "")
                all_clients = [c for c in all_clients if c["name"] != orig_name]
            elif any(c["name"] == name for c in all_clients):
                flash(f"A client named '{name}' already exists", "error")
                return redirect(url_for("clients"))

            all_clients.append(new_entry)
            save_clients(all_clients)
            flash(f"Client '{name}' saved. Go to Dashboard and click Apply.", "success")

        elif action == "delete":
            name = request.form.get("name", "")
            all_clients = [c for c in all_clients if c["name"] != name]
            save_clients(all_clients)
            flash(f"Client '{name}' deleted. Go to Dashboard and click Apply.", "success")

        return redirect(url_for("clients"))

    return render_template("clients.html", clients=all_clients)


@app.route("/generate_secret")
@login_required
def generate_secret():
    return secrets.token_urlsafe(24)


@app.route("/auth_log")
@login_required
def auth_log():
    try:
        minutes = int(request.args.get("range", "60"))
    except ValueError:
        minutes = 60
    autorefresh = request.args.get("autorefresh") == "1"
    log_file = STATE.get("auth_log_file") or (auth_log_path() if RADIUSD_CONF.exists() else None)
    entries, counts, err = parse_auth_log(log_file, minutes)
    return render_template(
        "auth_log.html", entries=entries, counts=counts, error=err,
        minutes=minutes, autorefresh=autorefresh, log_file=log_file,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(STATE["admin_pass_hash"], current):
                flash("Current password is incorrect", "error")
            elif len(new) < 8:
                flash("New password must be at least 8 characters", "error")
            elif new != confirm:
                flash("New passwords do not match", "error")
            else:
                STATE["admin_pass_hash"] = generate_password_hash(new)
                _persist_state()
                flash("Password changed successfully", "success")
        return redirect(url_for("settings"))
    return render_template(
        "settings.html",
        raddb=str(RADDB), service_name=SERVICE_NAME,
        admin_user=STATE["admin_user"],
        auth_log_file=STATE.get("auth_log_file") or auth_log_path(),
    )


EXPORT_README = (
    "FreeRADIUS GUI configuration export.\n\n"
    "Contains the GUI-managed RADIUS client list and/or certificates,\n"
    "depending on what was selected at export time. Import this file on\n"
    "another FreeRADIUS GUI instance via the Backup & Transfer page to\n"
    "clone this server's client/certificate configuration onto it. Admin\n"
    "login credentials and host-specific settings (bind address, config\n"
    "directory, etc.) are intentionally NOT included - each server keeps\n"
    "its own.\n\n"
    "This file contains RADIUS client shared secrets and the server's\n"
    "private key in plaintext. Handle it like you would the FreeRADIUS\n"
    "config itself.\n"
)


def _validate_client_list(data):
    if not isinstance(data, list):
        raise ValueError("clients.json in the import file is not a list")
    cleaned = []
    for c in data:
        if not isinstance(c, dict) or not c.get("name") or not c.get("ipaddr") or not c.get("secret"):
            raise ValueError(f"a client entry is missing name/ipaddr/secret: {c!r}"[:200])
        try:
            ipaddress.ip_network(c["ipaddr"], strict=False)
        except ValueError:
            raise ValueError(f"client '{c.get('name')}' has an invalid ipaddr: {c.get('ipaddr')!r}")
        cleaned.append({
            "name": c["name"], "ipaddr": c["ipaddr"], "secret": c["secret"],
            "shortname": c.get("shortname", ""), "nas_type": c.get("nas_type", ""),
            "require_message_authenticator": bool(c.get("require_message_authenticator")),
        })
    return cleaned


@app.route("/backup")
@login_required
def backup():
    return render_template("backup.html", client_count=len(load_clients()))


@app.route("/backup/export")
@login_required
def backup_export():
    include_clients = request.args.get("clients") is not None
    include_certs = request.args.get("certs") is not None

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest = {
            "format_version": 1,
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "exported_from": socket.gethostname(),
            "includes_clients": include_clients,
            "includes_certs": include_certs,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        if include_clients:
            zf.writestr("clients.json", json.dumps(load_clients(), indent=2))

        if include_certs:
            paths = eap_tls_paths()
            for arcname, p in [("certs/server.pem", paths["server_cert"]),
                                ("certs/server.key", paths["server_key"]),
                                ("certs/ca.pem", paths["ca_bundle"])]:
                if p.exists():
                    zf.write(p, arcname)

        zf.writestr("README.txt", EXPORT_README)

    buf.seek(0)
    fname = f"freeradius-gui-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=fname)


@app.route("/backup/import", methods=["POST"])
@login_required
def backup_import():
    f = request.files.get("import_file")
    clients_mode = request.form.get("clients_mode", "off")
    import_server_cert = bool(request.form.get("import_server_cert"))
    ca_mode = request.form.get("ca_mode", "off")

    if not f or not f.filename:
        flash("Choose an export .zip file to import first", "error")
        return redirect(url_for("backup"))

    results = []
    warnings = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(f.read()))
    except zipfile.BadZipFile:
        flash("That doesn't look like a valid .zip file", "error")
        return redirect(url_for("backup"))

    names = zf.namelist()
    if "manifest.json" not in names:
        flash("That .zip doesn't look like a FreeRADIUS GUI export (no manifest.json found)", "error")
        return redirect(url_for("backup"))

    # --- clients ---
    if clients_mode != "off" and "clients.json" in names:
        try:
            imported_clients = _validate_client_list(json.loads(zf.read("clients.json")))
        except (ValueError, json.JSONDecodeError) as e:
            warnings.append(f"clients: import skipped ({e})")
        else:
            if clients_mode == "replace":
                save_clients(imported_clients)
                results.append(f"{len(imported_clients)} client(s) (replaced existing list)")
            elif clients_mode == "merge":
                existing = load_clients()
                existing_names = {c["name"] for c in existing}
                added = [c for c in imported_clients if c["name"] not in existing_names]
                skipped = len(imported_clients) - len(added)
                save_clients(existing + added)
                msg = f"{len(added)} new client(s) merged in"
                if skipped:
                    msg += f" ({skipped} skipped - name already exists)"
                results.append(msg)
    elif clients_mode != "off":
        warnings.append("clients: selected for import, but the export file didn't include clients.json")

    # --- server cert + key ---
    if import_server_cert:
        if "certs/server.pem" in names and "certs/server.key" in names:
            cert_bytes = zf.read("certs/server.pem")
            key_bytes = zf.read("certs/server.key")
            try:
                certs = _load_all_certs(cert_bytes)
                key_obj = _load_private_key(key_bytes, "")
                if not _keys_match(certs[0], key_obj):
                    raise CertError("certificate and key in the export don't match each other")
            except CertError as e:
                warnings.append(f"server certificate: import skipped ({e})")
            else:
                CERTS_DIR.mkdir(parents=True, exist_ok=True)
                paths = eap_tls_paths()
                paths["server_cert"].write_bytes(cert_bytes)
                paths["server_key"].write_bytes(key_bytes)
                os.chmod(paths["server_cert"], 0o640)
                os.chmod(paths["server_key"], 0o640)
                results.append(f"server certificate ({certs[0].subject.rfc4514_string()})")
        else:
            warnings.append("server certificate: selected for import, but the export file didn't include one")

    # --- CA bundle ---
    if ca_mode != "off":
        if "certs/ca.pem" in names:
            try:
                new_pems = [_cert_to_pem(c) for c in _load_all_certs(zf.read("certs/ca.pem"))]
            except CertError as e:
                warnings.append(f"CA bundle: import skipped ({e})")
            else:
                CERTS_DIR.mkdir(parents=True, exist_ok=True)
                paths = eap_tls_paths()
                existing = existing_ca_pems(paths["ca_bundle"]) if ca_mode == "append" else []
                combined = combine_ca_pems(existing, new_pems)
                paths["ca_bundle"].write_text("".join(combined))
                os.chmod(paths["ca_bundle"], 0o640)
                results.append(f"trusted CA bundle ({len(combined)} certificate(s) total)")
        else:
            warnings.append("CA bundle: selected for import, but the export file didn't include one")

    if results:
        flash("Imported: " + "; ".join(results) + ". Go to Dashboard and click Apply to activate.", "success")
    if warnings:
        flash(" / ".join(warnings), "error" if not results else "warn")
    if not results and not warnings:
        flash("Nothing was selected to import", "error")

    return redirect(url_for("backup"))


@app.route("/validate", methods=["POST"])
@login_required
def validate():
    write_clients_conf(load_clients())
    log = ["Wrote clients.conf from GUI client list (not yet live - validate only)"]
    paths = eap_tls_paths()
    if paths["server_cert"].exists() and paths["server_key"].exists():
        changes = apply_eap_tls_settings(
            paths["server_cert"], paths["server_key"],
            STATE.get("last_key_password", ""), paths["ca_bundle"],
        )
        log.extend(changes)
    rc, out = config_test()
    log.append("--- freeradius -CX output ---")
    log.append(out)
    log.append("Validation only - service was not restarted.")
    return render_template("apply_result.html", log=log, success=(rc == 0), validate_only=True)


@app.route("/apply", methods=["POST"])
@login_required
def apply():
    log = []

    write_clients_conf(load_clients())
    log.append("Wrote clients.conf from GUI client list")

    paths = eap_tls_paths()
    if paths["server_cert"].exists() and paths["server_key"].exists():
        changes = apply_eap_tls_settings(
            paths["server_cert"], paths["server_key"],
            STATE.get("last_key_password", ""), paths["ca_bundle"],
        )
        log.extend(changes)
        log.append(ensure_eap_module_enabled())
        log.append(ensure_eap_in_default_site())
    else:
        log.append("No server certificate/key on disk yet - skipped eap.conf update")

    linelog_messages, log_file = ensure_linelog_hooks()
    log.extend(linelog_messages)
    STATE["auth_log_file"] = log_file

    rc, out = config_test()
    log.append("--- freeradius -CX output ---")
    log.append(out)

    if rc != 0:
        log.append("Config test FAILED - service was NOT restarted. Fix the issue above and try again.")
        _persist_state()
        return render_template("apply_result.html", log=log, success=False)

    rc2, out2 = service_restart()
    log.append("--- restart output ---")
    log.append(out2 or "(no output)")
    success = rc2 == 0
    log.append("Service restarted successfully" if success else "Service restart FAILED")

    STATE["last_apply"] = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "success": success,
    }
    if success:
        STATE["last_applied_hash"] = compute_pending_hash()
    _persist_state()

    return render_template("apply_result.html", log=log, success=success)


if __name__ == "__main__":
    ssl_ctx = None
    cert_file = STATE.get("gui_tls_cert")
    key_file = STATE.get("gui_tls_key")
    if cert_file and key_file and Path(cert_file).exists():
        ssl_ctx = (cert_file, key_file)
    app.run(
        host=STATE.get("bind_host", "0.0.0.0"),
        port=STATE.get("bind_port", 8443),
        ssl_context=ssl_ctx,
    )
