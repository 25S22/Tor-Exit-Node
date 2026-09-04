#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import date
from pathlib import Path
import requests

try:
    import pandas as pd
    from openpyxl.styles import PatternFill, Font
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Error: Missing required packages. Run: pip install requests pandas openpyxl tqdm")
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

DAILY_QUOTAS = {
    "abuseipdb_check": 950,
    "virustotal": 480,
}

SHODAN_SLEEP_SECONDS = 1.0
ABUSEIPDB_SLEEP_SECONDS = 0.3
VT_SLEEP_SECONDS = 15.5
CHECKPOINT_SAVE_EVERY = 25

SHODAN_MALICIOUS_TAGS = {"malware", "compromised", "c2", "botnet", "miner", "ransomware"}
SHODAN_SUSPICIOUS_TAGS = {"vpn", "tor", "proxy", "scanner", "anonymizer", "tunnel"}

def load_quota():
    today = str(date.today())
    if QUOTA_FILE.exists():
        try:
            data = json.loads(QUOTA_FILE.read_text())
            if data.get("date") == today:
                return data
        except Exception:
            pass
    return {"date": today, "used": {k: 0 for k in DAILY_QUOTAS}}

def save_quota(quota):
    QUOTA_FILE.write_text(json.dumps(quota, indent=2))

def quota_remaining(quota, key):
    return DAILY_QUOTAS[key] - quota["used"].get(key, 0)

def quota_consume(quota, key, n=1):
    quota["used"][key] = quota["used"].get(key, 0) + n

def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        try:
            return json.loads(CHECKPOINT_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_checkpoint(checkpoint):
    CHECKPOINT_FILE.write_text(json.dumps(checkpoint, indent=2))

def check_shodan_host(ip):
    if not SHODAN_API_KEY:
        return {"skipped": True}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        resp = HTTP.get(url, params={"key": SHODAN_API_KEY, "minify": "true"}, timeout=15)
        if resp.status_code == 404:
            return {"found": False}
        if resp.status_code == 429:
            time.sleep(2)
            resp = HTTP.get(url, params={"key": SHODAN_API_KEY, "minify": "true"}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return {
            "found": True,
            "ports": data.get("ports") or [],
            "tags": data.get("tags") or [],
            "vulns": list(data.get("vulns") or []),
            "org": data.get("org", ""),
            "asn": data.get("asn", ""),
            "hostnames": data.get("hostnames") or [],
        }
    except Exception as exc:
        return {"error": str(exc)}

def run_shodan_tier(ips, checkpoint):
    if not SHODAN_API_KEY:
        return
    todo = [ip for ip in ips if "shodan" not in checkpoint.get(ip, {})]
    for i, ip in enumerate(tqdm(todo, desc="Shodan API")):
        checkpoint.setdefault(ip, {})["shodan"] = check_shodan_host(ip)
        if (i + 1) % CHECKPOINT_SAVE_EVERY == 0:
            save_checkpoint(checkpoint)
        time.sleep(SHODAN_SLEEP_SECONDS)
    save_checkpoint(checkpoint)

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"skipped": True}
    resp = HTTP.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=15,
    )
    resp.raise_for_status()
    d = resp.json().get("data") or {}
    return {
        "score": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
    }

def run_abuseipdb_tier(ips, checkpoint, quota):
    if not ABUSEIPDB_API_KEY:
        return
    todo = [ip for ip in ips if "abuseipdb" not in checkpoint.get(ip, {})]
    remaining = quota_remaining(quota, "abuseipdb_check")
    batch = todo[:remaining]
    for i, ip in enumerate(tqdm(batch, desc="AbuseIPDB API")):
        try:
            checkpoint.setdefault(ip, {})["abuseipdb"] = check_abuseipdb(ip)
        except Exception as exc:
            checkpoint.setdefault(ip, {})["abuseipdb"] = {"error": str(exc)}
        quota_consume(quota, "abuseipdb_check")
        if (i + 1) % CHECKPOINT_SAVE_EVERY == 0:
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
    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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
    for i, ip in enumerate(tqdm(batch, desc="VirusTotal API")):
        try:
            checkpoint.setdefault(ip, {})["virustotal"] = check_virustotal(ip)
        except Exception as exc:
            checkpoint.setdefault(ip, {})["virustotal"] = {"error": str(exc)}
        quota_consume(quota, "virustotal")
        if (i + 1) % CHECKPOINT_SAVE_EVERY == 0:
            save_checkpoint(checkpoint)
            save_quota(quota)
        time.sleep(VT_SLEEP_SECONDS)
    save_checkpoint(checkpoint)
    save_quota(quota)

def compute_verdict(row):
    shodan = row.get("shodan") or {}
    abuseipdb = row.get("abuseipdb") or {}
    vt = row.get("virustotal") or {}

    shodan_tags = set(t.lower() for t in (shodan.get("tags") or []))
    shodan_vulns = shodan.get("vulns") or []

    if bool(shodan_tags & SHODAN_MALICIOUS_TAGS):
        return "Malicious"
    if abuseipdb.get("score") is not None and abuseipdb["score"] >= 75:
        return "Malicious"
    if vt.get("malicious", 0) >= 3:
        return "Malicious"

    if bool(shodan_tags & SHODAN_SUSPICIOUS_TAGS) \
            or len(shodan_vulns) >= 2 \
            or (abuseipdb.get("score") is not None and 20 <= abuseipdb["score"] < 75) \
            or (0 < vt.get("malicious", 0) < 3) \
            or vt.get("suspicious", 0) > 0:
        return "Suspicious"

    has_data = any([
        shodan.get("found") is True,
        abuseipdb.get("score") is not None,
        "malicious" in vt,
    ])
    if has_data:
        return "Not Malicious"
    return "Unknown / Not Checked Yet"

VERDICT_COLORS = {
    "Malicious": "FFC7CE",
    "Suspicious": "FFEB9C",
    "Not Malicious": "C6EFCE",
    "Unknown / Not Checked Yet": "D9D9D9",
}

def export_excel(ips, checkpoint, output_path):
    rows = []
    for ip in ips:
        rec = dict(checkpoint.get(ip, {}))
        verdict = compute_verdict(rec)

        shodan = rec.get("shodan") or {}
        abuseipdb = rec.get("abuseipdb") or {}
        vt = rec.get("virustotal") or {}

        rows.append({
            "IP": ip,
            "IP Version": "IPv6" if ":" in ip else "IPv4",
            "Verdict": verdict,
            "AbuseIPDB Score": abuseipdb.get("score"),
            "AbuseIPDB Reports": abuseipdb.get("reports"),
            "AbuseIPDB Country": abuseipdb.get("country"),
            "AbuseIPDB ISP": abuseipdb.get("isp"),
            "AbuseIPDB Usage Type": abuseipdb.get("usage_type"),
            "AbuseIPDB Is Tor": abuseipdb.get("is_tor"),
            "Shodan Open Ports": ", ".join(str(p) for p in (shodan.get("ports") or [])),
            "Shodan Tags": ", ".join(shodan.get("tags") or []),
            "Shodan Vulns": ", ".join(shodan.get("vulns") or []),
            "Shodan Org": shodan.get("org", ""),
            "VT Malicious": vt.get("malicious"),
            "VT Suspicious": vt.get("suspicious"),
            "VT Harmless": vt.get("harmless"),
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
        print(f"Error: The input file '{path}' was not found.")
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=INPUT_FILE_PATH)
    parser.add_argument("--output", default=OUTPUT_FILE_PATH)
    args = parser.parse_args()

    ips = load_ip_list(args.input)
    if not ips:
        print("No valid IPs found to process. Exiting.")
        return

    checkpoint = load_checkpoint()
    quota = load_quota()

    run_shodan_tier(ips, checkpoint)
    run_abuseipdb_tier(ips, checkpoint, quota)

    unresolved_ips = []
    for ip in ips:
        rec = dict(checkpoint.get(ip, {}))
        if compute_verdict(rec) == "Unknown / Not Checked Yet":
            unresolved_ips.append(ip)

    if unresolved_ips and VT_API_KEY:
        ans = input(f"\n[?] {len(unresolved_ips)} IPs remain unverified after Shodan and AbuseIPDB.\nDo you want to query VirusTotal for these? (y/n): ").strip().lower()
        if ans == "y":
            run_virustotal_tier(unresolved_ips, checkpoint, quota)

    export_excel(ips, checkpoint, args.output)
    print(f"Report exported to: {args.output}")

if __name__ == "__main__":
    main()
