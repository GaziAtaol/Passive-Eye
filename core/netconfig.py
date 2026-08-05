"""Optional System Network module — **NOT passive**.

This is a separate, opt-in administration tool: it changes the *operating
system's* network configuration (DNS servers, web proxy, interface MTU,
service on/off). It is disabled by default, requires root/Administrator, asks
for confirmation before every change, backs up the previous value, and can
revert. The GhostWire capture engine remains strictly passive regardless.

Currently implemented for macOS (via ``networksetup``). Other platforms report
``supported() == False`` and the UI stays disabled.
"""
import os
import sys
import json
import time
import subprocess

BACKUP_PATH = "ghostwire_netbackup.json"
_TIMEOUT = 8


def is_root() -> bool:
    if os.name == "posix":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def supported() -> bool:
    return sys.platform == "darwin"


def platform_name() -> str:
    return {"darwin": "macOS"}.get(sys.platform, sys.platform)


def _run(args, timeout=_TIMEOUT):
    """Run a command, returning (rc, stdout, stderr)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


# --------------------------------------------------------------------------- #
#  Read-only queries (safe, no elevation needed)                             #
# --------------------------------------------------------------------------- #
def list_services() -> list:
    """Network service names (e.g. 'Wi-Fi', 'Ethernet')."""
    if not supported():
        return []
    rc, out, _ = _run(["networksetup", "-listallnetworkservices"])
    if rc != 0:
        return []
    lines = out.splitlines()[1:]  # skip the informational header line
    return [l.lstrip("*").strip() for l in lines if l.strip()]


def get_dns(service: str) -> list:
    rc, out, _ = _run(["networksetup", "-getdnsservers", service])
    if rc != 0 or "aren't any" in out.lower() or "there aren" in out.lower():
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def get_proxy(service: str) -> dict:
    rc, out, _ = _run(["networksetup", "-getwebproxy", service])
    info = {}
    if rc == 0:
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().lower()] = v.strip()
    return info


def get_mtu(service: str) -> str:
    rc, out, _ = _run(["networksetup", "-getMTU", service])
    if rc != 0:
        return ""
    # Typical: "Active MTU: 1500 (Current Setting: 1500) ..."
    import re
    m = re.search(r"Active MTU:\s*(\d+)", out)
    if m:
        return m.group(1)
    m = re.search(r"(\d{3,5})", out)  # fall back to first plausible MTU value
    return m.group(1) if m else ""


def current_state(service: str) -> dict:
    return {
        "dns": get_dns(service),
        "proxy": get_proxy(service),
        "mtu": get_mtu(service),
    }


# --------------------------------------------------------------------------- #
#  Backup / revert                                                            #
# --------------------------------------------------------------------------- #
def _load_backup() -> dict:
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_backup(data: dict):
    try:
        with open(BACKUP_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def backup_service(service: str):
    """Snapshot a service's current settings once, before the first change."""
    data = _load_backup()
    if service not in data:
        data[service] = {"saved_at": time.time(), **current_state(service)}
        _save_backup(data)


def has_backup(service: str) -> bool:
    return service in _load_backup()


# --------------------------------------------------------------------------- #
#  Mutating operations (require root; always back up first)                   #
# --------------------------------------------------------------------------- #
def _guard():
    if not supported():
        return "System Network is only implemented on macOS."
    if not is_root():
        return "Root/Administrator privileges are required."
    return None


def set_dns(service: str, servers: list):
    err = _guard()
    if err:
        return False, err
    backup_service(service)
    args = ["networksetup", "-setdnsservers", service]
    args += servers if servers else ["Empty"]
    rc, _out, serr = _run(args)
    return (rc == 0), (serr or f"DNS set for {service}: {', '.join(servers) or 'cleared'}")


def set_proxy(service: str, host: str, port: str, enabled: bool):
    err = _guard()
    if err:
        return False, err
    backup_service(service)
    if enabled and host:
        rc, _o, serr = _run(["networksetup", "-setwebproxy", service, host, str(port or 8080)])
        if rc != 0:
            return False, serr or "failed to set proxy"
    rc2, _o2, serr2 = _run(["networksetup", "-setwebproxystate", service,
                            "on" if enabled else "off"])
    return (rc2 == 0), (serr2 or f"Proxy {'enabled' if enabled else 'disabled'} for {service}")


def set_mtu(service: str, mtu: int):
    err = _guard()
    if err:
        return False, err
    backup_service(service)
    rc, _o, serr = _run(["networksetup", "-setMTU", service, str(mtu)])
    return (rc == 0), (serr or f"MTU set to {mtu} for {service}")


def set_service_enabled(service: str, enabled: bool):
    err = _guard()
    if err:
        return False, err
    backup_service(service)
    rc, _o, serr = _run(["networksetup", "-setnetworkserviceenabled", service,
                         "on" if enabled else "off"])
    return (rc == 0), (serr or f"Service {service} {'enabled' if enabled else 'disabled'}")


def revert_service(service: str):
    """Restore a service to its backed-up settings."""
    err = _guard()
    if err:
        return False, err
    data = _load_backup()
    snap = data.get(service)
    if not snap:
        return False, f"No backup for {service}."
    msgs = []
    if "dns" in snap:
        ok, m = set_dns(service, snap["dns"])
        msgs.append(m)
    if snap.get("mtu", "").isdigit():
        ok, m = set_mtu(service, int(snap["mtu"]))
        msgs.append(m)
    proxy = snap.get("proxy", {})
    if proxy:
        enabled = proxy.get("enabled", "no").lower() in ("yes", "on", "1", "true")
        ok, m = set_proxy(service, proxy.get("server", ""), proxy.get("port", ""), enabled)
        msgs.append(m)
    # Clear the backup so a future change snapshots fresh state.
    data.pop(service, None)
    _save_backup(data)
    return True, "Reverted: " + "; ".join(msgs)
