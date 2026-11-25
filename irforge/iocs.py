"""IOC extraction from events and decoding of PowerShell -EncodedCommand payloads."""
import base64
import ipaddress
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|me|tk|cc)\b", re.I)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
ENC_RE = re.compile(r"\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_powershell(b64):
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        return raw.decode("utf-16-le")
    except Exception:
        return None


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _public_ip(s):
    """True for routable addresses. Documentation ranges count as public so synthetic samples work."""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if any(ip in n for n in DOC_NETS):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def extract(events):
    """Return a dict of sorted lists: ips, urls, domains, hashes, decoded (PowerShell payloads)."""
    out = {"ips": set(), "urls": set(), "domains": set(), "hashes": set(), "decoded": set()}
    for e in events:
        blobs = [e.command_line, e.target, e.raw.get("hashes", "")]
        for blob in blobs:
            if not blob:
                continue
            for m in ENC_RE.finditer(blob + " "):
                dec = decode_powershell(m.group(1))
                if dec:
                    out["decoded"].add(dec)
                    blobs.append(dec)
            out["urls"].update(URL_RE.findall(blob))
            out["hashes"].update(h.lower() for h in HASH_RE.findall(blob))
            for ip in IP_RE.findall(blob):
                if _public_ip(ip):
                    out["ips"].add(ip)
            for d in DOMAIN_RE.findall(blob):
                out["domains"].add(d.lower())
        if e.event_id == 3 and e.target:
            ip = e.target.rsplit(":", 1)[0]
            if _public_ip(ip):
                out["ips"].add(ip)
        if e.event_id == 22 and e.target:
            out["domains"].add(e.target.lower())
    return {k: sorted(v) for k, v in out.items()}
