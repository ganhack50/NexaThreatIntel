import io
import os
import zipfile
import requests

print("[*] Starting Incremental Threat Intel Harvester (N-1 Resilient + Auth-Key Mode)...")

# Directory structure
CACHE_DIR = "cache/raw"
NETWORK_FEED_DIR = "feeds/network"
DISK_FEED_DIR = "feeds/disk"

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(NETWORK_FEED_DIR, exist_ok=True)
os.makedirs(DISK_FEED_DIR, exist_ok=True)

# Read optional abuse.ch Auth-Key from environment variable (GitHub Secrets)
ABUSECH_API_KEY = os.environ.get("ABUSECH_API_KEY", "").strip()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "*/*",
}
if ABUSECH_API_KEY:
    HEADERS["Auth-Key"] = ABUSECH_API_KEY
    print("[+] ABUSECH_API_KEY detected in environment.")
else:
    print("[!] No ABUSECH_API_KEY set. Using public endpoints + keyless SHA-256 mirrors.")

IPS_FILE = os.path.join(NETWORK_FEED_DIR, "ip_blocks.txt")
TRACKERS_FILE = os.path.join(NETWORK_FEED_DIR, "trackers.txt")
MALWARE_FILE = os.path.join(NETWORK_FEED_DIR, "malware.txt")
HASHES_FILE = os.path.join(DISK_FEED_DIR, "hashes.txt")


def load_existing_feed(filepath):
    """Loads N-1 IOCs from existing feed files so historical IOCs are never lost."""
    items = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip().lower()
                    if clean and not clean.startswith("#"):
                        items.add(clean)
        except Exception as e:
            print(f"[-] Warning: Could not read {filepath}: {e}")
    return items


def fetch_to_cache(url, cache_filename, min_bytes=200, timeout=45, params=None):
    """Downloads upstream feed into cache/raw/ first, falling back to N-1 cache on error."""
    cache_path = os.path.join(CACHE_DIR, cache_filename)
    try:
        res = requests.get(url, headers=HEADERS, params=params, timeout=timeout)
        if res.status_code == 200 and len(res.content) >= min_bytes:
            # Reject HTML login walls pretending to be HTTP 200 text/zip feeds
            if not res.content[:150].lstrip().lower().startswith((b"<!doctype html", b"<html")):
                tmp_cache = cache_path + ".tmp"
                with open(tmp_cache, "wb") as f:
                    f.write(res.content)
                os.replace(tmp_cache, cache_path)
                print(f"    [+] Cached {cache_filename} ({len(res.content):,} bytes)")
                return res.content
            else:
                print(f"    [!] {cache_filename} returned an HTML login/challenge page. Skipping.")
        else:
            print(f"    [!] {cache_filename} returned HTTP {res.status_code} ({len(res.content)} bytes).")
    except Exception as e:
        print(f"    [!] Error fetching {cache_filename}: {e}")

    if os.path.exists(cache_path):
        print(f"    [*] Falling back to N-1 cached {cache_filename}")
        with open(cache_path, "rb") as f:
            return f.read()
    return None


def is_valid_sha256(s):
    if len(s) != 64:
        return False
    return all(c in "0123456789abcdef" for c in s)


def atomic_write_feed(filepath, data_iterable):
    tmp_path = filepath + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(data_iterable))
    os.replace(tmp_path, filepath)


# =====================================================================
# STAGE 1: LOAD N-1 FEEDS
# =====================================================================
ips = load_existing_feed(IPS_FILE)
trackers = load_existing_feed(TRACKERS_FILE)
malware_domains = load_existing_feed(MALWARE_FILE)
hashes = {h for h in load_existing_feed(HASHES_FILE) if is_valid_sha256(h)}

n1_counts = (len(ips), len(trackers), len(malware_domains), len(hashes))
print(f"[*] N-1 Baseline: {n1_counts[0]:,} IPs | {n1_counts[1]:,} Trackers | {n1_counts[2]:,} Malware Domains | {n1_counts[3]:,} Hashes")

# =====================================================================
# STAGE 2: HARVEST IPs, TRACKERS, MALWARE DOMAINS & HASHES
# =====================================================================

# 1. Fetch IPs (FireHOL Level 1 + EmergingThreats)
print("[*] Syncing IP blocklists...")
ip_sources = [
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "firehol_level1.netset"),
    ("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "emerging_block_ips.txt"),
]
for url, cache_name in ip_sources:
    raw_ips = fetch_to_cache(url, cache_name, min_bytes=500)
    if raw_ips:
        for line in raw_ips.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "/", ";")):
                ip = line.split("/")[0].strip()
                if ip.count(".") == 3:
                    ips.add(ip)

# 2. Fetch Trackers & Ad Domains (StevenBlack)
print("[*] Syncing tracker & ad blocklist...")
raw_trackers = fetch_to_cache(
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "stevenblack_hosts.txt",
    min_bytes=10000,
)
if raw_trackers:
    for line in raw_trackers.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower().strip(".")
                if domain and domain != "localhost" and "." in domain:
                    trackers.add(domain)

# 3. Fetch Malicious Domains (URLhaus + DigiSide + OpenPhish)
print("[*] Syncing malicious domain blocklists...")
auth_params = {"auth-key": ABUSECH_API_KEY} if ABUSECH_API_KEY else None
malware_sources = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus_hostfile.txt", auth_params),
    ("https://urlhaus.abuse.ch/downloads/text/", "urlhaus_text.txt", auth_params),
    ("https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "digitalside_domains.txt", None),
    ("https://openphish.com/feed.txt", "openphish_feed.txt", None),
]
for url, cache_name, params in malware_sources:
    raw_malware = fetch_to_cache(url, cache_name, min_bytes=200, params=params)
    if raw_malware:
        for line in raw_malware.decode("utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("127.0.0.1", "0.0.0.0")):
                parts = line.split()
                if len(parts) >= 2:
                    line = parts[1]
            for prefix in ("http://", "https://", "ftp://"):
                if line.startswith(prefix):
                    line = line[len(prefix):]
            domain = line.split("/")[0].split("?")[0].split(":")[0].strip(".")
            if domain and domain != "localhost" and "." in domain:
                if all(p.isdigit() for p in domain.split(".")):
                    ips.add(domain)
                else:
                    malware_domains.add(domain)

# 4. Fetch SHA-256 Hashes (MalwareBazaar Auth + Keyless Community Mirrors)
print("[*] Syncing SHA-256 hash database...")

# 4A: MalwareBazaar Full ZIP & Recent (with Auth-Key query param if available)
mb_zip_sources = [
    ("https://bazaar.abuse.ch/export/txt/sha256/full/", "malwarebazaar_full.zip", auth_params),
]
for url, cache_name, params in mb_zip_sources:
    raw_zip = fetch_to_cache(url, cache_name, min_bytes=1000, timeout=90, params=params)
    if raw_zip and raw_zip.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
                for filename in z.namelist():
                    if filename.endswith(".txt"):
                        with z.open(filename) as f:
                            for line in f:
                                h = line.decode("utf-8", errors="ignore").strip().lower()
                                if is_valid_sha256(h):
                                    hashes.add(h)
        except Exception as e:
            print(f"    [-] ZIP extraction error: {e}")

# 4B: MalwareBazaar API v1 (Query recent 100 samples directly via POST if Auth-Key is set)
if ABUSECH_API_KEY:
    try:
        api_res = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers=HEADERS,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
        )
        if api_res.status_code == 200:
            json_data = api_res.json()
            for item in json_data.get("data", []):
                h = item.get("sha256_hash", "").strip().lower()
                if is_valid_sha256(h):
                    hashes.add(h)
            print(f"    [+] Pulled recent hashes via MalwareBazaar API v1")
    except Exception as e:
        print(f"    [!] MalwareBazaar API v1 error: {e}")

# 4C: High-Volume Keyless SHA-256 Feeds (Guarantees 100k+ hashes even without API key)
plain_hash_sources = [
    ("https://bazaar.abuse.ch/export/txt/sha256/recent/", "malwarebazaar_recent.txt", auth_params),
    ("https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt", "marcoux_sha256_aa.txt", None),
    ("https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-ab.txt", "marcoux_sha256_ab.txt", None),
    ("https://osint.digitalside.it/Threat-Intel/lists/latesthashes.txt", "digitalside_hashes.txt", None),
    ("https://www.botvrij.eu/data/ioclist.sha256.raw", "botvrij_sha256.txt", None),
]
for url, cache_name, params in plain_hash_sources:
    raw_txt = fetch_to_cache(url, cache_name, min_bytes=200, timeout=45, params=params)
    if raw_txt:
        for line in raw_txt.decode("utf-8", errors="ignore").splitlines():
            h = line.strip().lower()
            if is_valid_sha256(h):
                hashes.add(h)

# =====================================================================
# STAGE 3: DEDUPLICATE, CAP & ATOMICALLY WRITE FEEDS
# =====================================================================
ips.add("198.51.100.50")
trackers.add("tracker-test.nexasecurity.local")
malware_domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# Ensure malware domains are never silenced by tracker list
trackers.difference_update(malware_domains)

MAX_HASHES = 500000
final_hashes = sorted(hashes)[:MAX_HASHES]

atomic_write_feed(IPS_FILE, sorted(ips))
atomic_write_feed(TRACKERS_FILE, sorted(trackers))
atomic_write_feed(MALWARE_FILE, sorted(malware_domains))
atomic_write_feed(HASHES_FILE, final_hashes)

print("\n[+] Harvest Complete:")
print(f"    - {len(ips):,} IPs (+{len(ips) - n1_counts[0]:,} new)")
print(f"    - {len(trackers):,} Tracker Domains (+{len(trackers) - n1_counts[1]:,} net)")
print(f"    - {len(malware_domains):,} Malware Domains (+{len(malware_domains) - n1_counts[2]:,} new)")
print(f"    - {len(final_hashes):,} File Hashes (+{len(final_hashes) - n1_counts[3]:,} new)")
