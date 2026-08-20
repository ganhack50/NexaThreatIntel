import io
import os
import zipfile
import requests

print("[*] Fetching MASSIVE global threat intel feeds...")

ips = set()
trackers = set()
malware_domains = set()
hashes = set()

# 1. Fetch IPs (FireHOL)
try:
    print("[*] Downloading IP blocklist...")
    res = requests.get(
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        timeout=15,
    )
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("/"):
                ip = line.split("/")[0]
                if ip.count(".") == 3:
                    ips.add(ip)
except Exception as e:
    print(f"[-] Error fetching IPs: {e}")

# 2. Fetch Trackers & Ad Domains (StevenBlack) - Silent Drop List
try:
    print("[*] Downloading tracker & ad blocklist...")
    res = requests.get(
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        timeout=15,
    )
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    trackers.add(parts[1].lower())
except Exception as e:
    print(f"[-] Error fetching trackers: {e}")

# 3. Fetch Malicious Domains (URLhaus) - High-Fidelity Alert List
try:
    print("[*] Downloading malicious domain blocklist (URLhaus)...")
    res = requests.get(
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        timeout=15,
    )
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    malware_domains.add(parts[1].lower())
except Exception as e:
    print(f"[-] Error fetching malware domains: {e}")

# 4. Fetch Hashes (MalwareBazaar)
try:
    print("[*] Bypassing pagination: Downloading FULL zipped hash database...")
    res = requests.get(
        "https://bazaar.abuse.ch/export/txt/sha256/full/",
        timeout=60,
    )
    if res.status_code == 200:
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            for filename in z.namelist():
                if filename.endswith(".txt"):
                    print(f"[*] Extracting {filename} from zip...")
                    with z.open(filename) as f:
                        for line in f:
                            line = line.decode("utf-8").strip().lower()
                            if line and not line.startswith("#") and len(line) == 64:
                                hashes.add(line)
except Exception as e:
    print(f"[-] Error fetching bulk hashes: {e}")

# Guaranteed safety baselines
ips.add("198.51.100.50")
trackers.add("tracker-test.nexasecurity.local")
malware_domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# Cap hashes to prevent GitHub 100MB file limit errors
MAX_HASHES = 500000
final_hashes = list(hashes)[:MAX_HASHES]

# Ensure output directories exist
os.makedirs("feeds/network", exist_ok=True)
os.makedirs("feeds/disk", exist_ok=True)

# 1. Save Network IPs
with open("feeds/network/ip_blocks.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(ips)))

# 2. Save Tracker Domains (Silent UI Dropping)
with open("feeds/network/trackers.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(trackers)))

# 3. Save Malicious Domains (Threat Alert List)
with open("feeds/network/malware.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(malware_domains)))

# 4. Save Disk AV Hashes
with open("feeds/disk/hashes.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(final_hashes)))

print("[+] Harvest Complete:")
print(f"    - {len(ips):,} IPs")
print(f"    - {len(trackers):,} Tracker Domains")
print(f"    - {len(malware_domains):,} Malware Domains")
print(f"    - {len(final_hashes):,} File Hashes")
                
