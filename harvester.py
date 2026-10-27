import io
import os
import zipfile
import requests

print("[*] Starting Incremental Threat Intel Harvester (N-1 Resilient Mode)...")

# Directory structure
CACHE_DIR = "cache/raw"
NETWORK_FEED_DIR = "feeds/network"
DISK_FEED_DIR = "feeds/disk"

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(NETWORK_FEED_DIR, exist_ok=True)
os.makedirs(DISK_FEED_DIR, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/plain,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Paths for final feeds
IPS_FILE = os.path.join(NETWORK_FEED_DIR, "ip_blocks.txt")
TRACKERS_FILE = os.path.join(NETWORK_FEED_DIR, "trackers.txt")
MALWARE_FILE = os.path.join(NETWORK_FEED_DIR, "malware.txt")
HASHES_FILE = os.path.join(DISK_FEED_DIR, "hashes.txt")


def load_existing_feed(filepath):
    """Loads N-1 IOCs from the existing feed file so we never lose historical data."""
    items = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip().lower()
                    if clean and not clean.startswith("#"):
                        items.add(clean)
        except Exception as e:
            print(f"[-] Warning: Could not read existing {filepath}: {e}")
    return items


def fetch_to_cache(url, cache_filename, min_bytes=256, timeout=30):
    """
    Downloads upstream feed to a separate raw cache folder.
    If download fails or is blocked/empty, falls back to the cached N-1 raw file.
    """
    cache_path = os.path.join(CACHE_DIR, cache_filename)
    try:
        res = requests.get(url, headers=HEADERS, timeout=timeout)
        if res.status_code == 200 and len(res.content) >= min_bytes:
            tmp_cache = cache_path + ".tmp"
            with open(tmp_cache, "wb") as f:
                f.write(res.content)
            os.replace(tmp_cache, cache_path)
            print(f"    [+] Cached fresh upstream payload -> {cache_path} ({len(res.content):,} bytes)")
            return res.content
        else:
            print(f"    [!] Upstream {url} returned HTTP {res.status_code} ({len(res.content)} bytes). Using cache fallback.")
    except Exception as e:
        print(f"    [!] Network error fetching {url}: {e}. Using cache fallback.")

    # Fallback to N-1 raw cache if available
    if os.path.exists(cache_path):
        print(f"    [*] Loaded N-1 cached payload from {cache_path}")
        with open(cache_path, "rb") as f:
            return f.read()
    return None


def atomic_write_feed(filepath, data_iterable):
    """Writes to a temporary file first and atomically replaces the target feed."""
    tmp_path = filepath + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(data_iterable))
    os.replace(tmp_path, filepath)


# =====================================================================
# STAGE 1: LOAD EXISTING (N-1) FEEDS INTO MEMORY
# =====================================================================
ips = load_existing_feed(IPS_FILE)
trackers = load_existing_feed(TRACKERS_FILE)
malware_domains = load_existing_feed(MALWARE_FILE)
hashes = load_existing_feed(HASHES_FILE)

n1_counts = (len(ips), len(trackers), len(malware_domains), len(hashes))
print(f"[*] Loaded N-1 Baseline: {n1_counts[0]:,} IPs | {n1_counts[1]:,} Trackers | {n1_counts[2]:,} Malware Domains | {n1_counts[3]:,} Hashes")


# =====================================================================
# STAGE 2: DOWNLOAD TO RAW CACHE & PARSE INCREMENTALLY
# =====================================================================

# 1. Fetch IPs (FireHOL Level 1 + EmergingThreats fallback)
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
            if line and not line.startswith("#") and not line.startswith("/") and not line.startswith(";"):
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

# 3. Fetch Malicious Domains (URLhaus + ThreatFox / OpenPhish Mirrors)
print("[*] Syncing malicious domain blocklists...")
malware_sources = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus_hostfile.txt"),
    ("https://urlhaus.abuse.ch/downloads/text/", "urlhaus_text.txt"),
    ("https://openphish.com/feed.txt", "openphish_feed.txt"),
]
for url, cache_name in malware_sources:
    raw_malware = fetch_to_cache(url, cache_name, min_bytes=200)
    if raw_malware:
        for line in raw_malware.decode("utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # Handle hostfile format ("127.0.0.1 evil.com") or URL format ("http://evil.com/path")
            if line.startswith("127.0.0.1") or line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 2:
                    line = parts[1]
            for prefix in ("http://", "https://", "ftp://"):
                if line.startswith(prefix):
                    line = line[len(prefix):]
            domain = line.split("/")[0].split("?")[0].split(":")[0].strip(".")
            # Ignore raw IPs in domain list (send them to ips set instead)
            if domain and domain != "localhost" and "." in domain:
                if all(p.isdigit() for p in domain.split(".")):
                    ips.add(domain)
                else:
                    malware_domains.add(domain)

# 4. Fetch Hashes (MalwareBazaar Full ZIP + Recent Text Fallback)
print("[*] Syncing SHA-256 hash database...")
raw_zip = fetch_to_cache(
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
    "malwarebazaar_full.zip",
    min_bytes=1000,
    timeout=90,
)
if raw_zip and raw_zip.startswith(b"PK\x03\x04"):
    try:
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
            for filename in z.namelist():
                if filename.endswith(".txt"):
                    with z.open(filename) as f:
                        for line in f:
                            h = line.decode("utf-8", errors="ignore").strip().lower()
                            if len(h) == 64 and not h.startswith("#"):
                                hashes.add(h)
    except Exception as e:
        print(f"[-] Error extracting cached ZIP: {e}")

# Also pull recent SHA-256 text feed in case full ZIP endpoint rate-limits
raw_recent_hashes = fetch_to_cache(
    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "malwarebazaar_recent.txt",
    min_bytes=500,
    timeout=30,
)
if raw_recent_hashes:
    for line in raw_recent_hashes.decode("utf-8", errors="ignore").splitlines():
        h = line.strip().lower()
        if len(h) == 64 and not h.startswith("#"):
            hashes.add(h)


# =====================================================================
# STAGE 3: DEDUPLICATE, CAP & ATOMICALLY WRITE INCREMENTAL FEEDS
# =====================================================================

# Guaranteed test baselines
ips.add("198.51.100.50")
trackers.add("tracker-test.nexasecurity.local")
malware_domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# CRITICAL: Remove any malware domain from trackers so Malware Alerts are NEVER silenced!
trackers.difference_update(malware_domains)

# Cap hashes at 500,000 to stay safely below GitHub's 100MB file size limit (~32.5MB)
MAX_HASHES = 500000
final_hashes = sorted(hashes)[:MAX_HASHES]

atomic_write_feed(IPS_FILE, sorted(ips))
atomic_write_feed(TRACKERS_FILE, sorted(trackers))
atomic_write_feed(MALWARE_FILE, sorted(malware_domains))
atomic_write_feed(HASHES_FILE, final_hashes)

print("\n[+] Incremental Harvest Complete:")
print(f"    - IPs:             {len(ips):,} (+{len(ips) - n1_counts[0]:,} new)")
print(f"    - Tracker Domains: {len(trackers):,} (+{len(trackers) - n1_counts[1]:,} net)")
print(f"    - Malware Domains: {len(malware_domains):,} (+{len(malware_domains) - n1_counts[2]:,} new)")
print(f"    - File Hashes:     {len(final_hashes):,} (+{len(final_hashes) - n1_counts[3]:,} new)")
                
