"""Passive fingerprinting helpers: JA3 (TLS), p0f-style OS from IP/TCP, MAC.

Everything here is computed from bytes already observed on the wire — no probing.
"""
import hashlib
import struct
import math

# GREASE values (RFC 8701) are excluded from JA3 per the spec.
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


# --------------------------------------------------------------------------- #
#  TLS ClientHello  ->  SNI + JA3                                             #
# --------------------------------------------------------------------------- #
def parse_tls_client_hello(payload: bytes) -> dict:
    """Parse a TLS record carrying a ClientHello.

    Returns a dict with keys: ``is_client_hello``, ``sni``, ``version``,
    ``ciphers`` (list), ``ja3`` (str string form), ``ja3_hash`` (md5 hex).
    Returns ``{"is_client_hello": False}`` if this is not a ClientHello.
    """
    out = {"is_client_hello": False}
    try:
        if len(payload) < 6:
            return out
        # TLS record header: type(1)=22 handshake, version(2), length(2)
        if payload[0] != 0x16:
            return out
        # Handshake header: type(1)=1 ClientHello, length(3)
        hs_type = payload[5]
        if hs_type != 0x01:
            return out

        idx = 9  # skip record(5) + handshake type(1) + handshake len(3)
        client_version = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2
        idx += 32  # random
        # session id
        sid_len = payload[idx]
        idx += 1 + sid_len
        # cipher suites
        cs_len = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            c = struct.unpack("!H", payload[idx + i:idx + i + 2])[0]
            if c not in _GREASE:
                ciphers.append(c)
        idx += cs_len
        # compression methods
        comp_len = payload[idx]
        idx += 1 + comp_len

        sni = ""
        extensions_list = []
        curves = []
        point_formats = []

        if idx + 2 <= len(payload):
            ext_total = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2
            end = min(len(payload), idx + ext_total)
            while idx + 4 <= end:
                ext_type = struct.unpack("!H", payload[idx:idx + 2])[0]
                ext_len = struct.unpack("!H", payload[idx + 2:idx + 4])[0]
                idx += 4
                ext_data = payload[idx:idx + ext_len]
                idx += ext_len
                if ext_type not in _GREASE:
                    extensions_list.append(ext_type)
                if ext_type == 0x0000 and len(ext_data) >= 5:  # SNI
                    # server_name_list len(2), type(1)=0 host_name, name len(2)
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    sni = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")
                elif ext_type == 0x000a and len(ext_data) >= 2:  # supported_groups
                    glen = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(0, glen, 2):
                        g = struct.unpack("!H", ext_data[2 + i:4 + i])[0]
                        if g not in _GREASE:
                            curves.append(g)
                elif ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
                    plen = ext_data[0]
                    point_formats = list(ext_data[1:1 + plen])

        ja3_str = "{},{},{},{},{}".format(
            client_version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in extensions_list),
            "-".join(str(c) for c in curves),
            "-".join(str(p) for p in point_formats),
        )
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        out.update({
            "is_client_hello": True,
            "sni": sni,
            "version": _tls_version_name(client_version),
            "ciphers": ciphers,
            "ja3": ja3_str,
            "ja3_hash": ja3_hash,
        })
    except Exception:
        return {"is_client_hello": False}
    return out


def _tls_version_name(v: int) -> str:
    return {
        0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
        0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
    }.get(v, f"0x{v:04x}")


# A tiny best-effort JA3 -> client table (illustrative, not exhaustive).
_JA3_KNOWN = {
    "e7d705a3286e19ea42f587b344ee6865": "Chrome/Chromium",
    "579ccef312d18482fc42e2b822ca2430": "Firefox",
}


def classify_ja3(ja3_hash: str) -> str:
    return _JA3_KNOWN.get(ja3_hash, "")


# --------------------------------------------------------------------------- #
#  p0f-style passive OS guess from IP TTL + TCP window                        #
# --------------------------------------------------------------------------- #
def guess_os_from_ttl(ttl: int) -> str:
    """Initial-TTL heuristic. Hops reduce TTL, so we round up to the nearest
    common initial value (64 = *nix/Android, 128 = Windows, 255 = network gear).
    """
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux/Unix/Android"
    if ttl <= 128:
        return "Windows"
    return "Network Device"


def p0f_guess(ttl: int, window: int) -> str:
    """Combine TTL and TCP window size for a slightly sharper OS guess."""
    base = guess_os_from_ttl(ttl)
    if window in (65535, 64240, 64800):
        if "Windows" in base:
            return "Windows 10/11"
    if window in (29200, 14600, 5840):
        return "Linux"
    if window == 65535 and "Linux" in base:
        return "macOS/iOS"
    return base


# --------------------------------------------------------------------------- #
#  MAC address helpers                                                         #
# --------------------------------------------------------------------------- #
def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit (bit 1 of the first octet) is set — i.e. a randomised
    / locally-assigned MAC rather than a real vendor-burned OUI."""
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except (ValueError, IndexError):
        return False


def is_multicast_mac(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x01)
    except (ValueError, IndexError):
        return False


# --------------------------------------------------------------------------- #
#  Shannon entropy (used by DNS-tunneling heuristic)                          #
# --------------------------------------------------------------------------- #
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())
