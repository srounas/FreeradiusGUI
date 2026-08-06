#!/usr/bin/env python3
"""
FreeRADIUS GUI - a small, purpose-built web UI for configuring FreeRADIUS
for EAP-TLS (certificate) authentication: server certificate, trusted CA
bundle, RADIUS clients (NAS) with shared secrets, an authentication log
viewer, and a system status/health view.

Runs on the same host as FreeRADIUS. Edits the real config files, validates
with `freeradius -CX`, and restarts the service.
"""
import base64
import grp
import hashlib
import hmac
import io
import ipaddress
import json
import os
import pwd
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from markupsafe import escape

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                    request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

APP_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("FRGUI_STATE_DIR", "/etc/freeradius-gui"))
CONFIG_FILE = STATE_DIR / "config.json"
CLIENTS_FILE = STATE_DIR / "clients.json"
HISTORY_DIR = STATE_DIR / "history"
MAX_HISTORY_SNAPSHOTS = 20

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
# Harden the session cookie: JS can't read it, browser won't send it on
# cross-site requests, and (once TLS is on, which is the default) it's
# never sent in the clear.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


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

GUI_TLS_ENABLED = bool(STATE.get("gui_tls_cert") and STATE.get("gui_tls_key")
                        and Path(STATE["gui_tls_cert"]).exists())
# Only mark the cookie Secure (HTTPS-only) when we're actually serving HTTPS -
# otherwise the browser would silently refuse to store/send it at all.
app.config["SESSION_COOKIE_SECURE"] = GUI_TLS_ENABLED

# Trust X-Forwarded-For only when the app is deliberately run behind a
# reverse proxy on this host (config-driven), never by default - otherwise
# any client can forge the header to spoof its source IP and dodge the
# login-attempt lockout entirely.
TRUST_PROXY_HEADERS = bool(STATE.get("trust_proxy_headers", False))

if not STATE.get("api_key"):
    STATE["api_key"] = secrets.token_hex(24)
    _persist_state()


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'"
    )
    if GUI_TLS_ENABLED:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


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


# --------------------------------------------------------------------------
# Ownership of files FreeRADIUS itself has to read
# --------------------------------------------------------------------------
# This app (per install.sh) runs as root, but FreeRADIUS drops privileges to
# an unprivileged account (security.user/security.group in radiusd.conf -
# "freerad" on Debian/Ubuntu, "radiusd" on RHEL-likes) before it ever opens
# a cert, key, or clients.conf. A file written by this app and only chmod'd
# 0640 is owned by root:root - readable by root and root's group, NOT by
# that account - so FreeRADIUS fails with a permission error at exactly the
# point it tries to load it. This bit us the first time someone replaced
# the install-generated certificate (owned correctly by the installer) with
# their own upload (owned by whoever/whatever wrote it): identical
# permissions, wrong owner. Every write below now goes through
# secure_radius_file() so mode AND ownership are always set together.

_radius_uid_gid_cache = None


def _detect_radius_user_group():
    """Read the account FreeRADIUS actually drops privileges to from the
    security {} block in radiusd.conf, so this doesn't hard-code a
    distro-specific username. Falls back to 'freerad' (the Debian/Ubuntu
    default) if radiusd.conf can't be read or parsed."""
    default = ("freerad", "freerad")
    if not RADIUSD_CONF.exists():
        return default
    try:
        text = RADIUSD_CONF.read_text()
    except OSError:
        return default
    m = re.search(r'\bsecurity\s*\{([^}]*)\}', text, re.DOTALL)
    if not m:
        return default
    block = m.group(1)
    user_m = re.search(r'^\s*user\s*=\s*"?([\w.-]+)"?', block, re.MULTILINE)
    group_m = re.search(r'^\s*group\s*=\s*"?([\w.-]+)"?', block, re.MULTILINE)
    return (user_m.group(1) if user_m else default[0],
            group_m.group(1) if group_m else default[1])


def radius_uid_gid():
    """Resolve the (uid, gid) FreeRADIUS runs as. Checks for an explicit
    override in config.json first (radius_user/radius_group - useful if
    autodetection ever guesses wrong), otherwise parses radiusd.conf.
    Cached for the life of the process; returns (None, None) if the
    account doesn't exist on this system so callers can warn instead of
    crashing the request."""
    global _radius_uid_gid_cache
    if _radius_uid_gid_cache is not None:
        return _radius_uid_gid_cache
    user = STATE.get("radius_user")
    group = STATE.get("radius_group")
    if not user or not group:
        user, group = _detect_radius_user_group()
    try:
        result = (pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    except KeyError:
        app.logger.warning(
            "FreeRADIUS service account '%s:%s' not found on this system - "
            "cert/config files will be chmod'd but NOT chowned, which will "
            "likely make FreeRADIUS unable to read them. Set radius_user / "
            "radius_group in %s to correct this.", user, group, CONFIG_FILE)
        result = (None, None)
    _radius_uid_gid_cache = result
    return result


def secure_radius_file(path, mode=0o640):
    """Set both the mode AND the owner on a file FreeRADIUS reads directly
    (server cert/key, CA bundle, clients.conf, ...). Use this instead of a
    bare os.chmod() for anything under CERTS_DIR or CLIENTS_CONF - chmod
    alone isn't enough when this app's own process (root) and FreeRADIUS's
    process (freerad/radiusd) are different accounts."""
    os.chmod(path, mode)
    uid, gid = radius_uid_gid()
    if uid is None:
        return
    try:
        os.chown(path, uid, gid)
    except OSError as e:
        app.logger.warning("Could not chown %s to the FreeRADIUS service account: %s", path, e)


def ensure_certs_dir():
    """Create CERTS_DIR if needed and make sure FreeRADIUS's account can
    at least traverse/list it - a directory left root:root 0700 blocks
    reads of files inside it regardless of the files' own permissions."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CERTS_DIR, 0o750)
    uid, gid = radius_uid_gid()
    if uid is not None:
        try:
            os.chown(CERTS_DIR, uid, gid)
        except OSError as e:
            app.logger.warning("Could not chown %s to the FreeRADIUS service account: %s", CERTS_DIR, e)


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
# Configuration history (automatic snapshots + revert)
# --------------------------------------------------------------------------
# Captures the GUI-managed RADIUS clients and certificates - never host-level
# settings like the admin password or bind address, which aren't part of
# what "revert" is meant to undo. Stored under the same locked-down state
# directory as everything else here (config.json, clients.json), so the same
# file permissions model applies.

def _snapshot_paths():
    if not HISTORY_DIR.exists():
        return []
    return sorted(HISTORY_DIR.glob("snap-*.json"), reverse=True)


def save_config_snapshot(label):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    paths = eap_tls_paths()
    gen_paths = generated_ca_paths()

    def _b64(p):
        try:
            return base64.b64encode(p.read_bytes()).decode() if p.exists() else None
        except OSError:
            return None

    snapshot = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "label": label,
        "clients": load_clients(),
        "server_cert": _b64(paths["server_cert"]),
        "server_key": _b64(paths["server_key"]),
        "ca_bundle": _b64(paths["ca_bundle"]),
        "generated_ca_cert": _b64(gen_paths["cert"]),
        "generated_ca_key": _b64(gen_paths["key"]),
    }
    fname = HISTORY_DIR / f"snap-{datetime.now().strftime('%Y%m%d%H%M%S%f')}.json"
    fname.write_text(json.dumps(snapshot))
    os.chmod(fname, 0o600)

    # Prune oldest beyond the cap so this can't grow unbounded.
    for old in _snapshot_paths()[MAX_HISTORY_SNAPSHOTS:]:
        try:
            old.unlink()
        except OSError:
            pass


def load_snapshot_summaries():
    summaries = []
    for p in _snapshot_paths():
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        summaries.append({
            "id": p.stem,
            "time": data.get("time", "?"),
            "label": data.get("label", ""),
            "client_count": len(data.get("clients", []) or []),
            "has_server_cert": bool(data.get("server_cert")),
        })
    return summaries


def restore_snapshot(snapshot_id):
    """Restores clients + certificates from a snapshot by id. Returns the
    restored snapshot dict, or None if the id is invalid/missing (the id
    format is validated here since it's used to build a filesystem path)."""
    if not re.match(r'^snap-\d+$', snapshot_id or ""):
        return None
    p = HISTORY_DIR / f"{snapshot_id}.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None

    save_clients(data.get("clients", []) or [])
    paths = eap_tls_paths()
    gen_paths = generated_ca_paths()

    def _restore(path, b64):
        if b64:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(b64))
            secure_radius_file(path, 0o640)
        elif path.exists():
            path.unlink()

    _restore(paths["server_cert"], data.get("server_cert"))
    _restore(paths["server_key"], data.get("server_key"))
    _restore(paths["ca_bundle"], data.get("ca_bundle"))
    _restore(gen_paths["cert"], data.get("generated_ca_cert"))
    _restore(gen_paths["key"], data.get("generated_ca_key"))
    return data


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


def api_key_required(fn):
    """Guards machine-to-machine endpoints (used by the multi-server view on
    other GUI instances) with a bearer token instead of the admin session -
    these are polled by other servers, not by a logged-in browser."""
    @wraps(fn)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token or not STATE.get("api_key") or not secrets.compare_digest(token, STATE["api_key"]):
            abort(401)
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
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Left-most entry is the original client per the de-facto standard.
            return forwarded.split(",")[0].strip() or "unknown"
    return request.remote_addr or "unknown"


def _prune_failed_logins():
    now = time.time()
    for ip in list(_failed_logins):
        attempts = [t for t in _failed_logins[ip] if now - t < LOGIN_LOCKOUT_SECONDS]
        if attempts:
            _failed_logins[ip] = attempts
        else:
            del _failed_logins[ip]


def is_locked_out(ip):
    now = time.time()
    attempts = [t for t in _failed_logins.get(ip, []) if now - t < LOGIN_LOCKOUT_SECONDS]
    _failed_logins[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(ip):
    # Cheap opportunistic sweep of every IP's stale attempts, not just this
    # one, so the table doesn't grow forever from one-off scanner traffic.
    if len(_failed_logins) > 200:
        _prune_failed_logins()
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


def _build_ca_cert(ca_cn: str, validity_years: int):
    """Generate a fresh self-signed root CA key + certificate."""
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=365 * validity_years)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_cn)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def _build_server_cert(ca_key, ca_cert, server_cn: str, san_entries, validity_years: int):
    """Generate a server leaf key + certificate signed by the given CA.
    Clamps validity so the leaf never outlives its issuing root."""
    now = datetime.now(timezone.utc)
    ca_not_after = getattr(ca_cert, "not_valid_after_utc", None) or ca_cert.not_valid_after
    if ca_not_after.tzinfo is None:
        ca_not_after = ca_not_after.replace(tzinfo=timezone.utc)
    not_after = min(now + timedelta(days=365 * validity_years), ca_not_after)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_cn)])
    san_list = [x509.DNSName(server_cn)]
    for entry in san_entries:
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_list.append(x509.DNSName(entry))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return server_key, server_cert


def load_generated_ca():
    """Load the stored generated-root CA key+cert, if one exists on disk."""
    paths = generated_ca_paths()
    if not (paths["key"].exists() and paths["cert"].exists()):
        return None, None
    ca_key = serialization.load_pem_private_key(paths["key"].read_bytes(), password=None)
    ca_cert = _load_all_certs(paths["cert"].read_bytes())[0]
    return ca_key, ca_cert


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


def generated_ca_paths():
    """Dedicated files for a GUI-generated self-signed root CA. Kept separate
    from the trusted CA bundle (which validates *client* certs) because this
    root exists to sign the *server's own* certificate - a different trust
    role. Keeping the key means a later server-cert renewal can reuse the
    same root without re-distributing a new one to every device."""
    return {
        "key": CERTS_DIR / "generated-ca-root.key",
        "cert": CERTS_DIR / "generated-ca-root.pem",
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
    # Contains shared secrets in plaintext - keep it as locked down as the
    # other secret-bearing files this app manages.
    secure_radius_file(CLIENTS_CONF, 0o640)


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

    # minutes <= 0 means "all time" - don't filter anything out by age, just
    # by how many lines we tail. Entries were disappearing from the Auth Log
    # page purely because they aged past whatever window was selected, which
    # looked like data loss even though the log file itself was untouched.
    cutoff = (datetime.now().timestamp() - minutes * 60) if minutes > 0 else 0
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


def get_last_auth_event(log_file):
    """Cheap single-line read for the Servers page - avoids tailing/parsing
    the whole log just to show a timestamp."""
    if not log_file or not Path(log_file).exists():
        return None
    rc, out = run(["tail", "-n", "1", str(log_file)])
    if rc != 0 or not out.strip():
        return None
    parts = out.strip().split("|", 8)
    if len(parts) != 9:
        return None
    ts_raw, outcome, user = parts[0], parts[1], parts[2]
    try:
        ts = float(ts_raw)
    except ValueError:
        return None
    if outcome not in ("Accept", "Reject"):
        return None
    return {
        "time": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
        "outcome": outcome,
        "user": user or "-",
    }


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
        ensure_certs_dir()

        if action == "delete_generated_ca":
            gen_paths = generated_ca_paths()
            if not gen_paths["cert"].exists():
                flash("No GUI-generated root CA to remove", "error")
                return redirect(url_for("certs"))
            save_config_snapshot("Before removing GUI-generated root CA")
            removed_server_cert = False
            for p in (gen_paths["cert"], gen_paths["key"]):
                if p.exists():
                    p.unlink()
            # Only clear the active server cert/key if they were actually issued
            # by this root - if the admin later uploaded a different cert on top
            # (option A/B/C), leave that one alone.
            if STATE.get("root_ca_source") == "local":
                for p in (paths["server_cert"], paths["server_key"]):
                    if p.exists():
                        p.unlink()
                        removed_server_cert = True
                STATE.pop("root_ca_source", None)
                _persist_state()
            msg = "Removed the GUI-generated root CA."
            if removed_server_cert:
                msg += (" Its server certificate was also removed, since it was issued by this "
                        "root and can't be renewed without it - upload or generate a new one "
                        "before applying, or FreeRADIUS will fail to start.")
            flash(msg, "success")

        elif action == "upload_server":
            try:
                cert_pem, key_pem, key_password = build_server_cert_key(request.form, request.files)
            except CertError as e:
                flash(f"Certificate not saved: {e}", "error")
                return redirect(url_for("certs"))
            save_config_snapshot("Before uploading a new server certificate")
            paths["server_cert"].write_text(cert_pem)
            paths["server_key"].write_text(key_pem)
            secure_radius_file(paths["server_cert"], 0o640)
            secure_radius_file(paths["server_key"], 0o640)
            STATE["last_key_password"] = key_password
            STATE.pop("root_ca_source", None)
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
            save_config_snapshot("Before updating trusted CA bundle")
            paths["ca_bundle"].write_text("".join(combined))
            secure_radius_file(paths["ca_bundle"], 0o640)
            flash(f"Trusted CA bundle saved ({len(combined)} certificate(s) total). "
                  "Go to Dashboard and click Apply.", "success")

        elif action == "delete_ca_cert":
            try:
                idx = int(request.form.get("index", -1))
            except ValueError:
                flash("Invalid certificate index", "error")
                return redirect(url_for("certs"))
            if paths["ca_bundle"].exists():
                try:
                    certs_list = [_cert_to_pem(c) for c in _load_all_certs(paths["ca_bundle"].read_bytes())]
                    if 0 <= idx < len(certs_list):
                        save_config_snapshot("Before removing a certificate from the trusted CA bundle")
                        del certs_list[idx]
                        paths["ca_bundle"].write_text("".join(certs_list))
                        flash("Certificate removed from CA bundle. Go to Dashboard and click Apply.", "success")
                except CertError as e:
                    flash(f"Could not update CA bundle: {e}", "error")

        elif action == "generate_selfsigned":
            if not HAVE_CRYPTOGRAPHY:
                flash("The 'cryptography' package is required to generate certificates", "error")
                return redirect(url_for("certs"))

            ca_cn = request.form.get("ca_common_name", "").strip() or f"{socket.gethostname()} Root CA"
            server_cn = request.form.get("server_common_name", "").strip() or socket.gethostname()
            san_raw = request.form.get("server_san", "").strip()
            san_entries = [s.strip() for s in san_raw.split(",") if s.strip()]
            try:
                validity_years = int(request.form.get("validity_years", "10"))
            except ValueError:
                validity_years = -1
            if not (1 <= validity_years <= 30):
                flash("Validity period must be a whole number of years between 1 and 30", "error")
                return redirect(url_for("certs"))

            ca_key, ca_cert = _build_ca_cert(ca_cn, validity_years)
            server_key, server_cert = _build_server_cert(ca_key, ca_cert, server_cn, san_entries, validity_years)

            save_config_snapshot("Before generating a new self-signed root CA + server cert")
            gen_paths = generated_ca_paths()
            gen_paths["key"].write_text(_key_to_pem(ca_key, ""))
            gen_paths["cert"].write_text(_cert_to_pem(ca_cert))
            secure_radius_file(gen_paths["key"], 0o600)
            secure_radius_file(gen_paths["cert"], 0o640)

            paths["server_cert"].write_text(_cert_to_pem(server_cert))
            paths["server_key"].write_text(_key_to_pem(server_key, ""))
            secure_radius_file(paths["server_cert"], 0o640)
            secure_radius_file(paths["server_key"], 0o640)
            STATE["last_key_password"] = ""
            STATE["root_ca_source"] = "local"
            STATE.pop("root_ca_issuer_name", None)
            _persist_state()

            flash(
                f"Generated a new self-signed root CA ({ca_cn}) and server certificate ({server_cn}), "
                f"valid {validity_years} year(s). This REPLACED the previous server certificate/key. "
                "This root is separate from the trusted CA bundle above (that one validates client "
                "certificates - this one just signs the server's own certificate). Download the root "
                "below and deploy it to devices, e.g. via an Intune Trusted Certificate profile, so "
                "they trust this server during EAP-TLS. Go to Dashboard and click Apply.",
                "success",
            )

        elif action == "renew_selfsigned_server":
            if not HAVE_CRYPTOGRAPHY:
                flash("The 'cryptography' package is required to generate certificates", "error")
                return redirect(url_for("certs"))
            ca_key, ca_cert = load_generated_ca()
            if ca_key is None:
                flash("No GUI-generated root CA found yet - use 'Generate new self-signed "
                      "certificate' first.", "error")
                return redirect(url_for("certs"))

            server_cn = request.form.get("server_common_name", "").strip() or socket.gethostname()
            san_raw = request.form.get("server_san", "").strip()
            san_entries = [s.strip() for s in san_raw.split(",") if s.strip()]
            try:
                validity_years = int(request.form.get("validity_years", "10"))
            except ValueError:
                validity_years = -1
            if not (1 <= validity_years <= 30):
                flash("Validity period must be a whole number of years between 1 and 30", "error")
                return redirect(url_for("certs"))

            server_key, server_cert = _build_server_cert(ca_key, ca_cert, server_cn, san_entries, validity_years)
            save_config_snapshot("Before renewing self-signed server certificate")
            paths["server_cert"].write_text(_cert_to_pem(server_cert))
            paths["server_key"].write_text(_key_to_pem(server_key, ""))
            secure_radius_file(paths["server_cert"], 0o640)
            secure_radius_file(paths["server_key"], 0o640)
            STATE["last_key_password"] = ""
            _persist_state()

            info = cert_display_info(server_cert)
            note = ""
            if info["days_left"] < validity_years * 365 - 30:
                note = " (clamped to the root CA's own expiry, which is sooner than requested)"
            flash(
                f"Renewed server certificate ({server_cn}) using the existing root CA{note}. "
                "Devices that already trust the root don't need anything re-pushed. "
                "Go to Dashboard and click Apply.",
                "success",
            )

        elif action == "request_cert_from_ca_host":
            if not HAVE_CRYPTOGRAPHY:
                flash("The 'cryptography' package is required to generate certificates", "error")
                return redirect(url_for("certs"))
            known = STATE.get("known_servers", [])
            try:
                idx = int(request.form.get("ca_host_index", -1))
            except ValueError:
                idx = -1
            if not (0 <= idx < len(known)):
                flash("Select a valid known server to request a certificate from - add one "
                      "under Settings first if the list is empty.", "error")
                return redirect(url_for("certs"))
            peer = known[idx]
            peer_label = peer.get("name") or peer["url"]

            gen_paths = generated_ca_paths()
            if gen_paths["key"].exists() and STATE.get("ca_host_enabled"):
                flash(f"This server is itself set up as a CA host for other servers - switching "
                      f"to {peer_label}'s root would break trust for anything relying on this "
                      f"one's root. Disable 'Allow other servers to request certificates from "
                      f"this one' under Settings first if you really want to do this.", "error")
                return redirect(url_for("certs"))

            server_cn = request.form.get("server_common_name", "").strip() or socket.gethostname()
            san_raw = request.form.get("server_san", "").strip()
            san_entries = [s.strip() for s in san_raw.split(",") if s.strip()]
            try:
                validity_years = int(request.form.get("validity_years", "10"))
            except ValueError:
                validity_years = -1
            if not (1 <= validity_years <= 30):
                flash("Validity period must be a whole number of years between 1 and 30", "error")
                return redirect(url_for("certs"))

            server_key, csr = _build_csr(server_cn, san_entries)
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            result, err = _request_csr_signature(peer["url"], peer.get("token", ""), csr_pem, validity_years)
            if err:
                flash(f"Could not get a certificate from {peer_label}: {err}", "error")
                return redirect(url_for("certs"))

            save_config_snapshot(f"Before requesting a certificate from {peer_label}")
            paths["server_cert"].write_text(result["cert_pem"])
            paths["server_key"].write_text(_key_to_pem(server_key, ""))
            secure_radius_file(paths["server_cert"], 0o640)
            secure_radius_file(paths["server_key"], 0o640)
            STATE["last_key_password"] = ""

            # Cache a local copy of the issuer's root cert (public part only -
            # never its key) so this server can display/download it too, and
            # so Intune only ever needs the one shared root regardless of
            # which server in the fleet you got it from.
            if gen_paths["key"].exists():
                backup = gen_paths["key"].with_name(
                    gen_paths["key"].name + f".bak-{int(time.time())}"
                )
                gen_paths["key"].rename(backup)
                flash(f"Note: this server previously had its own root CA key - it was moved to "
                      f"{backup.name} rather than deleted, in case you need it back.", "warn")
            gen_paths["cert"].write_text(result["root_cert_pem"])
            secure_radius_file(gen_paths["cert"], 0o640)
            STATE["root_ca_source"] = "remote"
            STATE["root_ca_issuer_name"] = peer_label
            _persist_state()

            flash(
                f"Got a server certificate for {server_cn} signed by {peer_label}'s root CA "
                f"(common name in request: {result.get('common_name', server_cn)}). Since it's "
                "the same root as your other servers, Intune only needs the one Trusted "
                "Certificate. Go to Dashboard and click Apply.",
                "success",
            )

        return redirect(url_for("certs"))

    generated_ca_info = None
    gen_paths = generated_ca_paths()
    if HAVE_CRYPTOGRAPHY and gen_paths["cert"].exists():
        generated_ca_info = cert_info(gen_paths["cert"])

    info = {
        "server_cert": cert_info(paths["server_cert"]),
        "ca_bundle": certs_info_list(paths["ca_bundle"]),
    }
    return render_template(
        "certs.html", info=info, have_crypto=HAVE_CRYPTOGRAPHY,
        generated_ca=generated_ca_info, default_server_cn=socket.gethostname(),
        has_root_key=gen_paths["key"].exists(),
        root_ca_source=STATE.get("root_ca_source"),
        root_ca_issuer_name=STATE.get("root_ca_issuer_name"),
        known_servers=STATE.get("known_servers", []),
        ca_host_enabled=STATE.get("ca_host_enabled", False),
    )


@app.route("/certs/generated_ca/download")
@login_required
def download_generated_ca():
    gen_paths = generated_ca_paths()
    if not gen_paths["cert"].exists():
        abort(404)
    fmt = request.args.get("fmt", "pem")
    cert = _load_all_certs(gen_paths["cert"].read_bytes())[0]
    if fmt == "der":
        data = cert.public_bytes(serialization.Encoding.DER)
        return send_file(io.BytesIO(data), mimetype="application/pkix-cert",
                          as_attachment=True, download_name="freeradius-gui-root-ca.cer")
    data = gen_paths["cert"].read_bytes()
    return send_file(io.BytesIO(data), mimetype="application/x-pem-file",
                      as_attachment=True, download_name="freeradius-gui-root-ca.pem")


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
                save_config_snapshot(f"Before editing client '{orig_name}'")
                all_clients = [c for c in all_clients if c["name"] != orig_name]
            elif any(c["name"] == name for c in all_clients):
                flash(f"A client named '{name}' already exists", "error")
                return redirect(url_for("clients"))
            else:
                save_config_snapshot(f"Before adding client '{name}'")

            all_clients.append(new_entry)
            save_clients(all_clients)
            flash(f"Client '{name}' saved. Go to Dashboard and click Apply.", "success")

        elif action == "delete":
            name = request.form.get("name", "")
            save_config_snapshot(f"Before deleting client '{name}'")
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
    # "All time" (minutes<=0) needs a much bigger tail buffer, since a wide
    # window on a busy server can span far more than the usual 50k-line default.
    max_lines = 500000 if minutes <= 0 else 50000
    entries, counts, err = parse_auth_log(log_file, minutes, max_lines=max_lines)
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

        elif action == "regenerate_api_key":
            STATE["api_key"] = secrets.token_hex(24)
            _persist_state()
            flash("API key regenerated. Update it on any other FreeRADIUS GUI server that "
                  "monitors this one under Known servers, or its multi-server view will show "
                  "this server as unreachable.", "success")

        elif action == "add_known_server":
            name = request.form.get("server_name", "").strip()
            url = request.form.get("server_url", "").strip().rstrip("/")
            token = request.form.get("server_token", "").strip()
            if not url or not token:
                flash("Server URL and API key are both required", "error")
            elif not url.startswith("https://"):
                flash("Server URL must start with https://", "error")
            else:
                STATE.setdefault("known_servers", []).append(
                    {"name": name or url, "url": url, "token": token}
                )
                _persist_state()
                flash(f"Added '{name or url}' to known servers", "success")

        elif action == "delete_known_server":
            try:
                idx = int(request.form.get("index", -1))
            except ValueError:
                idx = -1
            known = STATE.get("known_servers", [])
            if 0 <= idx < len(known):
                removed = known.pop(idx)
                _persist_state()
                flash(f"Removed '{removed.get('name', removed.get('url'))}' from known servers", "success")

        elif action == "set_ca_host_enabled":
            STATE["ca_host_enabled"] = request.form.get("ca_host_enabled") == "1"
            _persist_state()
            flash(
                "Other servers can now request certificates signed by this server's root CA."
                if STATE["ca_host_enabled"] else
                "This server will no longer sign certificate requests from other servers.",
                "success",
            )

        return redirect(url_for("settings"))
    return render_template(
        "settings.html",
        raddb=str(RADDB), service_name=SERVICE_NAME,
        admin_user=STATE["admin_user"],
        auth_log_file=STATE.get("auth_log_file") or auth_log_path(),
        api_key=STATE.get("api_key", ""),
        known_servers=STATE.get("known_servers", []),
        this_hostname=socket.gethostname(),
        bind_port=STATE.get("bind_port", 8443),
        ca_host_enabled=STATE.get("ca_host_enabled", False),
        has_root_key=generated_ca_paths()["key"].exists(),
    )


def _peer_request(url, token, path, method="GET", body=None, timeout=5):
    """Shared HTTP helper for talking to another FreeRADIUS GUI instance's
    API (status, config-summary, auth-log, CSR signing). These peers use
    self-signed GUI certs by default (same as this one), so we don't verify
    the peer's TLS chain here - this is meant for a private admin network,
    not the open internet. Returns (data_dict_or_None, error_str_or_None)."""
    data_bytes = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if data_bytes is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, data=data_bytes, headers=headers, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, "rejected (401) - check the API key matches on both sides"
        try:
            payload = json.loads(e.read().decode())
            return None, payload.get("error", f"HTTP {e.code}")
        except Exception:  # noqa: BLE001
            return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"unreachable ({e.reason})"
    except (TimeoutError, ValueError, json.JSONDecodeError) as e:
        return None, str(e)


def _fetch_peer_status(url, token, timeout=5):
    return _peer_request(url, token, "/api/status", timeout=timeout)


def _fetch_peer_config_summary(url, token, timeout=5):
    return _peer_request(url, token, "/api/config-summary", timeout=timeout)


def _request_csr_signature(url, token, csr_pem, validity_years, timeout=10):
    return _peer_request(
        url, token, "/api/sign-csr", method="POST",
        body={"csr_pem": csr_pem, "validity_years": validity_years},
        timeout=timeout,
    )


def build_config_summary(hmac_key: bytes):
    """A locally-computed, comparison-only snapshot of this server's config.
    Deliberately excludes anything that would let a peer reconstruct secrets:
    client shared secrets are reduced to an HMAC-SHA256 fingerprint keyed by
    the pairwise API token both sides already share (not a plain hash - RADIUS
    secrets are often short/guessable, and a bare SHA-256 of one would let
    anyone who saw it offline-crack the value; keying it means only someone
    who already holds that same API key can verify a guess). Certificates are
    represented by their public fingerprint, which isn't sensitive to begin
    with, so those need no keying."""
    paths = eap_tls_paths()
    client_summaries = []
    for c in load_clients():
        secret = c.get("secret", "")
        client_summaries.append({
            "name": c.get("name", ""),
            "ipaddr": c.get("ipaddr", ""),
            "secret_sha256": hmac.new(hmac_key, secret.encode(), hashlib.sha256).hexdigest() if secret else None,
        })

    def _fp(path):
        if not path.exists():
            return None
        try:
            return _cert_fingerprint(_load_all_certs(path.read_bytes())[0])
        except CertError:
            return None

    ca_fps = []
    if paths["ca_bundle"].exists():
        try:
            ca_fps = sorted(_cert_fingerprint(c) for c in _load_all_certs(paths["ca_bundle"].read_bytes()))
        except CertError:
            ca_fps = []

    return {
        "clients": sorted(client_summaries, key=lambda c: c["name"]),
        "server_cert_fingerprint": _fp(paths["server_cert"]),
        "ca_bundle_fingerprints": ca_fps,
        "root_ca_fingerprint": _fp(generated_ca_paths()["cert"]),
        "freeradius_version": freeradius_version(),
    }


def diff_config_summaries(local, remote):
    """Compare two config summaries built by build_config_summary() and
    return a list of plain-English differences - naming what's different
    (which client, which cert) without ever including secret values, since
    only fingerprints/hashes were exchanged in the first place."""
    diffs = []

    local_by_name = {c["name"]: c for c in local.get("clients", [])}
    remote_by_name = {c["name"]: c for c in remote.get("clients", [])}
    for name in sorted(set(local_by_name) | set(remote_by_name)):
        lc, rc = local_by_name.get(name), remote_by_name.get(name)
        if lc and not rc:
            diffs.append(f"Client '{name}' exists on this server but not on the other")
        elif rc and not lc:
            diffs.append(f"Client '{name}' exists on the other server but not on this one")
        elif lc["ipaddr"] != rc["ipaddr"]:
            diffs.append(f"Client '{name}' has a different IP/network on each server")
        elif lc["secret_sha256"] != rc["secret_sha256"]:
            diffs.append(f"Client '{name}' has a different shared secret on each server")

    if local.get("server_cert_fingerprint") != remote.get("server_cert_fingerprint"):
        diffs.append("Server certificates differ (expected if each has its own leaf cert - "
                      "only a concern if you intended them to match)")

    local_ca = set(local.get("ca_bundle_fingerprints", []))
    remote_ca = set(remote.get("ca_bundle_fingerprints", []))
    if local_ca != remote_ca:
        only_local = len(local_ca - remote_ca)
        only_remote = len(remote_ca - local_ca)
        parts = []
        if only_local:
            parts.append(f"{only_local} trusted CA cert(s) only on this server")
        if only_remote:
            parts.append(f"{only_remote} trusted CA cert(s) only on the other")
        diffs.append("Trusted CA bundle differs: " + ", ".join(parts))

    if local.get("root_ca_fingerprint") != remote.get("root_ca_fingerprint"):
        if local.get("root_ca_fingerprint") and remote.get("root_ca_fingerprint"):
            diffs.append("Self-signed root CA differs between servers (expected unless you "
                          "deliberately shared one root via 'Request certificate from CA host')")
        elif local.get("root_ca_fingerprint") or remote.get("root_ca_fingerprint"):
            diffs.append("Only one of the two servers has a GUI-generated root CA on file")

    if local.get("freeradius_version") != remote.get("freeradius_version"):
        diffs.append(f"FreeRADIUS version differs: {local.get('freeradius_version')} vs "
                      f"{remote.get('freeradius_version')}")

    return diffs


def _build_csr(common_name: str, san_entries):
    """Generate a fresh private key + CSR locally. The key never leaves this
    server; only the CSR (a public-key request, not sensitive) is sent to a
    CA host for signing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    san_list = [x509.DNSName(common_name)]
    for entry in san_entries:
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_list.append(x509.DNSName(entry))
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, csr


def _sign_csr(ca_key, ca_cert, csr, validity_years: int):
    """Sign a peer's CSR with this server's local root CA. Only ever called
    on the CA host, which is the only place the root's private key exists."""
    if not csr.is_signature_valid:
        raise CertError("CSR signature is invalid")
    now = datetime.now(timezone.utc)
    ca_not_after = getattr(ca_cert, "not_valid_after_utc", None) or ca_cert.not_valid_after
    if ca_not_after.tzinfo is None:
        ca_not_after = ca_not_after.replace(tzinfo=timezone.utc)
    not_after = min(now + timedelta(days=365 * validity_years), ca_not_after)

    try:
        san_list = list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        san_list = []
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attrs[0].value if cn_attrs else "unknown"
    if not any(isinstance(n, x509.DNSName) and n.value == cn for n in san_list):
        san_list.append(x509.DNSName(cn))

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, cn


@app.route("/api/status")
@api_key_required
def api_status():
    """Machine-readable status for the multi-server view on other GUI
    instances. Deliberately excludes anything secret (no secrets, keys, or
    client lists) - just enough to show at-a-glance health."""
    paths = eap_tls_paths()
    server_cert = cert_info(paths["server_cert"])
    ca_bundle = certs_info_list(paths["ca_bundle"])
    log_file = STATE.get("auth_log_file") or (auth_log_path() if RADIUSD_CONF.exists() else None)
    return jsonify({
        "name": socket.gethostname(),
        "freeradius_status": service_status(),
        "freeradius_version": freeradius_version(),
        "client_count": len(load_clients()),
        "pending_changes": compute_pending_hash() != STATE.get("last_applied_hash"),
        "cert_warning": any_cert_warning({"server_cert": server_cert, "ca_bundle": ca_bundle}),
        "last_apply": STATE.get("last_apply"),
        "last_auth": get_last_auth_event(log_file),
    })


@app.route("/api/config-summary")
@api_key_required
def api_config_summary():
    """Comparison-only config snapshot - see build_config_summary() for what
    is and isn't included. Used by a peer's Servers page to check config
    drift without either side ever sending the other its actual secrets."""
    return jsonify(build_config_summary(STATE.get("api_key", "").encode()))


@app.route("/api/sign-csr", methods=["POST"])
@api_key_required
def api_sign_csr():
    """Lets a satellite server request a certificate signed by this server's
    local root CA, so a fleet of servers can share one root and Intune only
    needs one Trusted Certificate profile. The root's private key never
    leaves this server - only the (public) CSR comes in and the (public)
    signed cert + root cert go out."""
    if not HAVE_CRYPTOGRAPHY:
        return jsonify({"error": "The 'cryptography' package is not available on this server"}), 500
    if not STATE.get("ca_host_enabled"):
        return jsonify({"error": "This server is not configured to sign requests from other "
                                  "servers (enable it under Settings first)"}), 403
    ca_key, ca_cert = load_generated_ca()
    if ca_key is None:
        return jsonify({"error": "No root CA is present on this server yet - generate one on "
                                  "the Certificates page first"}), 400

    body = request.get_json(silent=True) or {}
    try:
        validity_years = int(body.get("validity_years", 10))
    except (TypeError, ValueError):
        validity_years = 10
    validity_years = max(1, min(30, validity_years))

    try:
        csr = x509.load_pem_x509_csr(body.get("csr_pem", "").encode())
        cert, cn = _sign_csr(ca_key, ca_cert, csr, validity_years)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Could not sign CSR: {e}"}), 400

    return jsonify({
        "cert_pem": _cert_to_pem(cert),
        "root_cert_pem": _cert_to_pem(ca_cert),
        "common_name": cn,
    })


@app.route("/changelog", methods=["GET", "POST"])
@login_required
def changelog():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "revert":
            snapshot_id = request.form.get("snapshot_id", "")
            # Snapshot the current state first, so reverting is itself
            # reversible - "before this revert" becomes a normal entry too.
            save_config_snapshot(f"Before reverting to a previous snapshot ({snapshot_id})")
            restored = restore_snapshot(snapshot_id)
            if restored is None:
                flash("Could not find that snapshot - it may have been pruned", "error")
            else:
                flash(
                    f"Reverted configuration to the snapshot from {restored.get('time', '?')} "
                    f"({restored.get('label', '')}). Go to Dashboard and click Apply to activate it.",
                    "success",
                )
        return redirect(url_for("changelog"))
    return render_template("changelog.html", snapshots=load_snapshot_summaries())


@app.route("/servers")
@login_required
def servers():
    known = STATE.get("known_servers", [])
    results = []
    for s in known:
        data, err = _fetch_peer_status(s["url"], s.get("token", ""))
        config_diffs = None
        config_error = None
        if not err:
            remote_summary, cfg_err = _fetch_peer_config_summary(s["url"], s.get("token", ""))
            if cfg_err:
                config_error = cfg_err
            else:
                # Keyed with THIS peer's token, since that's the key the peer
                # used to fingerprint its own secrets - has to match per-peer,
                # not computed once for all of them.
                local_summary = build_config_summary(s.get("token", "").encode())
                config_diffs = diff_config_summaries(local_summary, remote_summary)
        results.append({
            "name": s.get("name") or s["url"], "url": s["url"], "data": data, "error": err,
            "config_diffs": config_diffs, "config_error": config_error,
        })
    log_file = STATE.get("auth_log_file") or (auth_log_path() if RADIUSD_CONF.exists() else None)
    return render_template(
        "servers.html", results=results, this_hostname=socket.gethostname(),
        this_last_auth=get_last_auth_event(log_file),
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
                ensure_certs_dir()
                paths = eap_tls_paths()
                paths["server_cert"].write_bytes(cert_bytes)
                paths["server_key"].write_bytes(key_bytes)
                secure_radius_file(paths["server_cert"], 0o640)
                secure_radius_file(paths["server_key"], 0o640)
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
                ensure_certs_dir()
                paths = eap_tls_paths()
                existing = existing_ca_pems(paths["ca_bundle"]) if ca_mode == "append" else []
                combined = combine_ca_pems(existing, new_pems)
                paths["ca_bundle"].write_text("".join(combined))
                secure_radius_file(paths["ca_bundle"], 0o640)
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
