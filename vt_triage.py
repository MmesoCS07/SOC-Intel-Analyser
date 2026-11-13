#!/usr/bin/env python3


import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui"

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Verdict thresholds (tune these to your organisation's risk appetite)
MALICIOUS_THRESHOLD = 5     # engines flagging as malicious -> MALICIOUS
SUSPICIOUS_THRESHOLD = 1    # >=1 malicious or >=3 suspicious -> SUSPICIOUS


# --------------------------------------------------------------------------- #
# IOC handling
# --------------------------------------------------------------------------- #
def refang(ioc: str) -> str:
    """Convert a defanged IOC (hxxp://evil[.]com) back to its live form."""
    ioc = ioc.strip().strip("<>\"'")
    ioc = re.sub(r"^hxxp", "http", ioc, flags=re.IGNORECASE)
    for old, new in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[://]", "://")):
        ioc = ioc.replace(old, new)
    return ioc


def classify(ioc: str) -> str:
    """Return one of: ip, hash, url, domain, unknown."""
    if re.match(r"^https?://", ioc, re.IGNORECASE):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(ioc):
        return "hash"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


def is_private_ip(ioc: str) -> bool:
    addr = ipaddress.ip_address(ioc)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


def endpoint_for(ioc: str, kind: str):
    """Return (api_url, gui_url) for an IOC."""
    if kind == "ip":
        return f"{API_BASE}/ip_addresses/{ioc}", f"{GUI_BASE}/ip-address/{ioc}"
    if kind == "domain":
        return f"{API_BASE}/domains/{ioc}", f"{GUI_BASE}/domain/{ioc}"
    if kind == "hash":
        return f"{API_BASE}/files/{ioc.lower()}", f"{GUI_BASE}/file/{ioc.lower()}"
    # URLs are addressed by unpadded url-safe base64 of the URL itself
    url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    return f"{API_BASE}/urls/{url_id}", f"{GUI_BASE}/url/{url_id}"


# --------------------------------------------------------------------------- #
# VirusTotal client
# --------------------------------------------------------------------------- #
class VTClient:
    def __init__(self, api_key: str, min_interval: float = 15.0, max_retries: int = 3):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json"})
        self.min_interval = min_interval  # free tier = 4 req/min -> 15s
        self.max_retries = max_retries
        self._last_call = 0.0

    def _throttle(self):
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def get(self, url: str) -> dict:
        """GET with throttling, 429 back-off and basic error handling."""
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                resp = self.session.get(url, timeout=30)
            except requests.RequestException as exc:
                if attempt == self.max_retries:
                    return {"_error": f"network error: {exc}"}
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return {"_not_found": True}
            if resp.status_code == 401:
                sys.exit("[!] VirusTotal rejected the API key (401). Check VT_API_KEY.")
            if resp.status_code == 429:
                time.sleep(60)  # quota hit: wait out the window
                continue
            return {"_error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        return {"_error": "rate limited after retries"}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def verdict_from_stats(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    if total == 0:
        return "NO DATA"
    if malicious >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if malicious >= SUSPICIOUS_THRESHOLD or suspicious >= 3:
        return "SUSPICIOUS"
    return "CLEAN"


def enrich(client: VTClient, ioc: str, kind: str) -> dict:
    api_url, gui_url = endpoint_for(ioc, kind)
    result = {
        "ioc": ioc, "type": kind, "verdict": "", "malicious": 0, "suspicious": 0,
        "harmless": 0, "undetected": 0, "reputation": "", "context": "",
        "last_analysed": "", "vt_link": gui_url, "note": "",
    }
    data = client.get(api_url)

    if data.get("_not_found"):
        result.update(verdict="NOT FOUND", note="Not in VirusTotal (never submitted)")
        return result
    if data.get("_error"):
        result.update(verdict="ERROR", note=data["_error"])
        return result

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    result.update(
        verdict=verdict_from_stats(stats),
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        reputation=attrs.get("reputation", ""),
    )

    ts = attrs.get("last_analysis_date")
    if ts:
        result["last_analysed"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Type-specific context useful when writing up a ticket
    if kind == "ip":
        result["context"] = f"{attrs.get('as_owner', 'n/a')} | {attrs.get('country', 'n/a')}"
    elif kind == "domain":
        result["context"] = f"registrar: {attrs.get('registrar', 'n/a')} | categories: " \
                            f"{', '.join(sorted(set(attrs.get('categories', {}).values()))) or 'n/a'}"
    elif kind == "hash":
        result["context"] = f"{attrs.get('meaningful_name', 'n/a')} | {attrs.get('type_description', 'n/a')}"
    elif kind == "url":
        result["context"] = f"title: {attrs.get('title', 'n/a')}"
    return result


# --------------------------------------------------------------------------- #
# Input / output
# --------------------------------------------------------------------------- #
def load_iocs(args) -> list:
    raw = list(args.iocs)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            raw += [ln for ln in fh.read().splitlines() if ln.strip() and not ln.startswith("#")]
    if not sys.stdin.isatty() and not raw:
        raw += [ln for ln in sys.stdin.read().splitlines() if ln.strip()]
    seen, ordered = set(), []
    for item in raw:
        clean = refang(item)
        if clean and clean not in seen:
            seen.add(clean)
            ordered.append(clean)
    return ordered


COLOURS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "CLEAN": "\033[92m"}
RESET = "\033[0m"


def print_result(r: dict, colour: bool):
    tag = r["verdict"]
    if colour and tag in COLOURS:
        tag = f"{COLOURS[tag]}{tag}{RESET}"
    ratio = f"{r['malicious']}/{r['malicious'] + r['suspicious'] + r['harmless'] + r['undetected']}"
    print(f"[{tag}] {r['ioc']} ({r['type']})  detections: {ratio}")
    for label, key in (("context", "context"), ("last scan", "last_analysed"),
                       ("note", "note"), ("link", "vt_link")):
        if r.get(key):
            print(f"    {label:<9}: {r[key]}")


def write_csv(path: str, results: list):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)


def main():
    p = argparse.ArgumentParser(description="Triage IOCs against VirusTotal (API v3).")
    p.add_argument("iocs", nargs="*", help="IOCs: IPs, domains, URLs, hashes (defanged OK)")
    p.add_argument("-f", "--file", help="File with one IOC per line (# for comments)")
    p.add_argument("--csv", help="Write results to a CSV file")
    p.add_argument("--json", dest="json_out", help="Write results to a JSON file")
    p.add_argument("--rate", type=float, default=15.0,
                   help="Seconds between API calls (default 15 = free tier; use 0.25 for premium)")
    p.add_argument("--no-colour", action="store_true", help="Disable coloured output")
    args = p.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        sys.exit("[!] Set your key first:  export VT_API_KEY='your_key_here'")

    iocs = load_iocs(args)
    if not iocs:
        p.print_help()
        sys.exit(1)

    client = VTClient(api_key, min_interval=args.rate)
    results = []
    print(f"[*] Triage started: {len(iocs)} unique IOC(s)\n")

    for ioc in iocs:
        kind = classify(ioc)
        if kind == "unknown":
            print(f"[SKIP] {ioc}: unrecognised IOC format\n")
            continue
        if kind == "ip" and is_private_ip(ioc):
            print(f"[SKIP] {ioc}: private/reserved address, nothing to look up\n")
            continue
        result = enrich(client, ioc, kind)
        results.append(result)
        print_result(result, colour=sys.stdout.isatty() and not args.no_colour)
        print()

    if results:
        counts = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print("[*] Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        if args.csv:
            write_csv(args.csv, results)
            print(f"[*] CSV written to {args.csv}")
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
            print(f"[*] JSON written to {args.json_out}")
        # Non-zero exit if anything malicious: handy for SOAR/pipeline use
        sys.exit(2 if counts.get("MALICIOUS") else 0)


if __name__ == "__main__":
    main()
