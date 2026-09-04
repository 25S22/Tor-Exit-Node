#!/usr/bin/env python3
import argparse
import bisect
import ipaddress
import json
import os
import sys
import time
from datetime import date
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

try:
    import pandas as pd
    from openpyxl.styles import PatternFill, Font
    from openpyxl.utils import get_column_letter
except ImportError:
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs): return iterable

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "")

INPUT_FILE_PATH = "ips.txt"
OUTPUT_FILE_PATH = "ip_reputation_report.xlsx"

HTTP = requests.Session()
if SSL_CERT_PATH and Path(SSL_CERT_PATH).exists():
    HTTP.verify = SSL_CERT_PATH
else:
    HTTP.verify = True

BASE_DIR = Path(__file__).resolve().parent
CHECKPOINT_FILE = BASE_DIR / "checkpoint.json"
QUOTA_FILE = BASE_DIR / "quota_tracker.json"
BLOCKLIST_CACHE_DIR = BASE_DIR / "blocklist_cache"
BLOCKLIST_MAX_AGE_HOURS = 12

DAILY_QUOTAS = {
    "abuseipdb_check": 950,
    "abuseipdb_blacklist": 4,
    "virustotal": 480,
}

BLOCKLIST_SOURCES = {
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
    "feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "cins_army": "http://cinsscore.com/list/ci-badguys.txt",
}

VT_SLEEP_SECONDS = 16
ABUSEIPDB_SLEEP_SECONDS = 0.3
INTERNETDB_CONCURRENCY = 20
CHECKPOINT_SAVE_EVERY = 50

def load_quota():
    today = str(date.today())
    if QUOTA_FILE.exists():
        data = json.loads(QUOTA_FILE.read_text())
        if data.get("date") == today:
            return data
    return {"date": today, "used": {k: 0 for k in DAILY_QUOTAS}}

def save_quota(quota):
    QUOTA_FILE.write_text(json.dumps(quota, indent=2))

def quota_remaining(quota, key):
    return DAILY_QUOTAS[key] - quota["used"].get(key, 0)

def quota_consume(quota, key, n=1):
    quota["used"][key] = quota["used"].get(key, 0) + n

def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        return json.loads(CHECKPOINT_FILE.read_text())
    return {}

def save_checkpoint(checkpoint):
    CHECKPOINT_FILE.write_text(json.dumps(checkpoint, indent=2))

def download_blocklists():
    BLOCKLIST_CACHE_DIR.mkdir(exist_ok=True)
    for name, url in BLOCKLIST_SOURCES.items():
        cache_file = BLOCKLIST_CACHE_DIR / f"{name}.txt"
        if cache_file.exists():
            age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
            if age_hours < BLOCKLIST_MAX_AGE_HOURS:
                continue
        try:
            resp = HTTP.get(url, timeout=30, headers={"User-Agent": "ip-recon/1.0"})
            resp.raise_for_status()
            cache_file.write_text(resp.text)
        except Exception:
            pass

def build_blocklist_index():
    ranges = []
    for name in BLOCKLIST_SOURCES:
        cache_file = BLOCKLIST_CACHE_DIR / f"{name}.txt"
        if not cache_file.exists():
            continue
        for line in cache_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            token = line.split()[0]
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            ranges.append((int(net.network_address), int(net.broadcast_address), name))
    ranges.sort(key=lambda r: r[0])
    starts = [r[0] for r in ranges]
    return ranges, starts

def check_local_blocklists(ip, ranges, starts):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if addr.version != 4:
        return []
    ip_int = int(addr)
    matches = []
    idx = bisect.bisect_right(starts, ip_int) - 1
    i = idx
    while i >= 0 and ranges[i][0] <= ip_int:
        start, end, source = ranges[i]
        if start <= ip_int <= end:
            matches.append(source)
        i -= 1
        if idx - i > 5000:
            break
    return matches

def pull_abuseipdb_blacklist(quota):
    if not ABUSEIPDB_API_KEY:
        return {}
    if quota_remaining(quota, "abuseipdb_blacklist") <= 0:
        return {}
    try:
        resp = HTTP.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 75, "limit": 10000},
            timeout=30,
        )
        quota_consume(quota, "abuseipdb_blacklist")
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return {row["ipAddress"]: row["abuseConfidenceScore"] for row in data}
    except Exception:
        return {}

def check_internetdb(ip):
    try:
        resp = HTTP.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        data = resp.json()
        return {
            "found": True,
            "ports": data.get("ports", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
        }
    except Exception:
        return {"error": True}

def run_internetdb_tier(ips, checkpoint):
    todo = [ip for ip in ips if "internetdb" not in checkpoint.get(ip, {})]
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=INTERNETDB_CONCURRENCY) as pool:
        futures = {pool.submit(check_internetdb, ip): ip for ip in todo}
        count = 0
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Shodan"):
            ip = futures[fut]
            checkpoint.setdefault(ip, {})["internetdb"] = fut.result()
            count += 1
            if count % CHECKPOINT_SAVE_EVERY == 0:
                save_checkpoint(checkpoint)
    save_checkpoint(checkpoint)

def check_abuseipdb(ip):
    resp = HTTP.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=15,
    )
    resp.raise_for_status()
    d = resp.json()["data"]
    return {
        "score": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
    }

def run_abuseipdb_tier(ips, checkpoint, quota, known_bad):
    if not ABUSEIPDB_API_KEY:
        return
    needs_lookup = [ip for ip in ips if not checkpoint.get(ip, {}).get("blocklist_hits") and ip not in known_bad]
    todo = [ip for ip in needs_lookup if "abuseipdb" not in checkpoint.get(ip, {})]
    remaining = quota_remaining(quota, "abuseipdb_check")
    batch = todo[:remaining]
    for i, ip in enumerate(tqdm(batch, desc="AbuseIPDB API")):
        try:
            checkpoint.setdefault(ip, {})["abuseipdb"] = check_abuseipdb(ip)
        except Exception as exc:
            checkpoint.setdefault(ip, {})["abuseipdb"] = {"error": str(exc)}
        quota_consume(quota, "abuseipdb_check")
        if i % CHECKPOINT_SAVE_EVERY == 0:
            save_checkpoint(checkpoint)
            save_quota(quota)
        time.sleep(ABUSEIPDB_SLEEP_SECONDS)
    save_checkpoint(checkpoint)
    save_quota(quota)

def check_virustotal(ip):
    resp = HTTP.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_API_KEY},
        timeout=15,
    )
    resp.raise_for_status()
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

def run_virustotal_tier(unresolved_ips, checkpoint, quota):
    todo = [ip for ip in unresolved_ips if "virustotal" not in checkpoint.get(ip, {})]
    remaining = quota_remaining(quota, "virustotal")
    batch = todo[:remaining]
    for i, ip in enumerate(tqdm(batch, desc="VirusTotal")):
        try:
            checkpoint.setdefault(ip, {})["virustotal"] = check_virustotal(ip)
        except Exception as exc:
            checkpoint.setdefault(ip, {})["virustotal"] = {"error": str(exc)}
        quota_consume(quota, "virustotal")
        if i % CHECKPOINT_SAVE_EVERY == 0:
            save_checkpoint(checkpoint)
            save_quota(quota)
        time.sleep(VT_SLEEP_SECONDS)
    save_checkpoint(checkpoint)
    save_quota(quota)

def compute_verdict(row):
    blocklist_hits = row.get("blocklist_hits") or []
    blacklist_score = row.get("abuseipdb_blacklist_score")
    abuseipdb = row.get("abuseipdb") or {}
    vt = row.get("virustotal") or {}

    if blocklist_hits or (blacklist_score is not None and blacklist_score >= 90):
        return "Malicious"
    if abuseipdb.get("score") is not None and abuseipdb["score"] >= 75:
        return "Malicious"
    if vt.get("malicious", 0) >= 3:
        return "Malicious"

    if (blacklist_score is not None and blacklist_score >= 25) \
            or (abuseipdb.get("score") is not None and 25 <= abuseipdb["score"] < 75) \
            or (0 < vt.get("malicious", 0) < 3) \
            or vt.get("suspicious", 0) > 0:
        return "Suspicious"

    have_any_data = any([
        blacklist_score is not None,
        abuseipdb.get("score") is not None,
        "malicious" in vt,
    ])
    if have_any_data:
        return "Not Malicious"
    return "Unknown / Not Checked Yet"

VERDICT_COLORS = {
    "Malicious": "FFC7CE",
    "Suspicious": "FFEB9C",
    "Not Malicious": "C6EFCE",
    "Unknown / Not Checked Yet": "D9D9D9",
}

def export_excel(ips, checkpoint, blacklist_map, output_path):
    rows = []
    for ip in ips:
        rec = dict(checkpoint.get(ip, {}))
        rec["abuseipdb_blacklist_score"] = blacklist_map.get(ip)
        verdict = compute_verdict(rec)

        internetdb = rec.get("internetdb") or {}
        abuseipdb = rec.get("abuseipdb") or {}
        vt = rec.get("virustotal") or {}

        rows.append({
            "IP": ip,
            "IP Version": "IPv6" if ":" in ip else "IPv4",
            "Verdict": verdict,
            "Blocklist Sources": ", ".join(rec.get("blocklist_hits") or []),
            "AbuseIPDB Blacklist Score": rec.get("abuseipdb_blacklist_score"),
            "AbuseIPDB Score": abuseipdb.get("score"),
            "AbuseIPDB Reports": abuseipdb.get("reports"),
            "AbuseIPDB Country": abuseipdb.get("country"),
            "AbuseIPDB ISP": abuseipdb.get("isp"),
            "AbuseIPDB Usage Type": abuseipdb.get("usage_type"),
            "AbuseIPDB Is Tor": abuseipdb.get("is_tor"),
            "VT Malicious": vt.get("malicious"),
            "VT Suspicious": vt.get("suspicious"),
            "VT Harmless": vt.get("harmless"),
            "Shodan Open Ports": ", ".join(str(p) for p in internetdb.get("ports", []) or []),
            "Shodan Known CVEs": ", ".join(internetdb.get("vulns", []) or []),
            "Shodan Tags": ", ".join(internetdb.get("tags", []) or []),
        })

    df = pd.DataFrame(rows)
    df.to_excel(output_path, index=False, sheet_name="IP Reputation")

    import openpyxl
    wb = openpyxl.load_workbook(output_path)
    ws = wb["IP Reputation"]
    ws.freeze_panes = "A2"
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill

    verdict_col_idx = df.columns.get_loc("Verdict") + 1
    for row_idx in range(2, ws.max_row + 1):
        verdict = ws.cell(row=row_idx, column=verdict_col_idx).value
        color = VERDICT_COLORS.get(verdict)
        if color:
            fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
            for col_idx in range(1, ws.max_column + 1):
                ws.cell(row=row_idx, column=col_idx).fill = fill

    for col_idx, col_name in enumerate(df.columns, start=1):
        max_len = max([len(str(col_name))] + [len(str(v)) for v in df[col_name].astype(str)])
        ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 2, 45)
    wb.save(output_path)

def load_ip_list(path):
    ips = []
    seen = set()
    if not Path(path).exists():
        sys.exit(1)
    with open(path) as f:
        for line in f:
            token = line.strip()
            if not token:
                continue
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            if token not in seen:
                seen.add(token)
                ips.append(token)
    return ips

def apply_blocklist_tier(ips, checkpoint):
    download_blocklists()
    ranges, starts = build_blocklist_index()
    todo = [ip for ip in ips if "blocklist_hits" not in checkpoint.get(ip, {})]
    for ip in tqdm(todo, desc="Blocklists"):
        checkpoint.setdefault(ip, {})["blocklist_hits"] = check_local_blocklists(ip, ranges, starts)
    save_checkpoint(checkpoint)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=INPUT_FILE_PATH)
    parser.add_argument("--output", default=OUTPUT_FILE_PATH)
    args = parser.parse_args()

    ips = load_ip_list(args.input)
    checkpoint = load_checkpoint()
    quota = load_quota()

    apply_blocklist_tier(ips, checkpoint)
    blacklist_map = pull_abuseipdb_blacklist(quota)
    save_quota(quota)

    run_internetdb_tier(ips, checkpoint)
    run_abuseipdb_tier(ips, checkpoint, quota, blacklist_map)

    unresolved_ips = []
    for ip in ips:
        rec = dict(checkpoint.get(ip, {}))
        rec["abuseipdb_blacklist_score"] = blacklist_map.get(ip)
        if compute_verdict(rec) == "Unknown / Not Checked Yet":
            unresolved_ips.append(ip)

    if unresolved_ips and VT_API_KEY:
        ans = input(f"\n[?] {len(unresolved_ips)} IPs remain unverified after Shodan and AbuseIPDB.\nDo you want to query VirusTotal for these? (y/n): ").strip().lower()
        if ans == 'y':
            run_virustotal_tier(unresolved_ips, checkpoint, quota)

    export_excel(ips, checkpoint, blacklist_map, args.output)

if __name__ == "__main__":
    main()
