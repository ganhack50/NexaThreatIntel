import requests
import os
import zipfile
import io

print("[*] Fetching MASSIVE global threat intel feeds...")

ips = set()
trackers = set()
malware_domains = set()
hashes = set()

# 1. Fetch IPs (FireHOL)
try:
    print("[*] Downloading IP blocklist...")
    res = requests.get("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("/"):
                ip = line.split("/")[0]
                if ip.count(".") == 3:
                    ips.add(ip)
except Exception as e:
    print(f"[-] Error fetching IPs: {e}")

# 2. Fetch Trackers & Ad Domains (StevenBlack) - For Silent UI Blocking
try:
    print("[*] Downloading tracker & ad blocklist...")
    res = requests.get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    trackers.add(parts[1].lower())
except Exception as e:
    print(f"[-] Error fetching trackers: {e}")

# 3. Fetch Malicious Domains (URLhaus) - For High-Fidelity SOC Alerts
try:
    print("[*] Downloading malicious domain blocklist (URLhaus)...")
    res = requests.get("https://urlhaus.abuse.ch/downloads/hostfile/", timeout=15)
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
    res = requests.get("https://bazaar.abuse.ch/export/txt/sha256/full/", timeout=60)
    if res.status_code == 200:
        # Unzip the payload in memory (no files written to disk yet)
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            for filename in z.namelist():
                if filename.endswith(".txt"):
                    print(f"[*] Extracting {filename} from zip...")
                    with z.open(filename) as f:
                        for line in f:
                            line = line.decode('utf-8').strip().lower()
                            if line and not line.startswith("#") and len(line) == 64:
                                hashes.add(line)
except Exception as e:
    print(f"[-] Error fetching bulk hashes: {e}")

# Guaranteed safety baselines
ips.add("198.51.100.50")
trackers.add("tracker-test.nexasecurity.local")
malware_domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# GitHub blocks files over 100MB. 500,000 hashes is ~32MB. 
MAX_HASHES = 500000
final_hashes = list(hashes)[:MAX_HASHES]

# Create Output Directories
os.makedirs("feeds/network", exist_ok=True)
os.makedirs("feeds/disk", exist_ok=True)

# Save Network IPs
with open("feeds/network/ip_blocks.txt", "w") as f:
    f.write("\n".join(sorted(ips)))
    
# Save Tracker Domains (Silent Drop List)
with open("feeds/network/trackers.txt", "w") as f:
    f.write("\n".join(sorted(trackers)))

# Save Malicious Domains (SOC Alert List)
with open("feeds/network/malware.txt", "w") as f:
    f.write("\n".join(sorted(malware_domains)))
    
# Save Malicious Hashes for Disk AV
with open("feeds/disk/hashes.txt", "w") as f:
    f.write("\n".join(sorted(final_hashes)))

print(f"[+] Harvest Complete:")
print(f"    - {len(ips):,} IPs")
print(f"    - {len(trackers):,} Tracker Domains")
print(f"    - {len(malware_domains):,} Malware Domains")
print(f"    - {len(final_hashes):,} File Hashes")
except Exception as e:
    print(f"[-] Error fetching domains: {e}")

# 3. Bypass Pagination: Download and Extract the FULL Zipped Database
try:
    print("[*] Bypassing pagination: Downloading FULL zipped hash database...")
    # This pulls the massive bulk dump directly
    res = requests.get("https://bazaar.abuse.ch/export/txt/sha256/full/", timeout=60)
    if res.status_code == 200:
        # Unzip the payload in memory (no files written to disk yet)
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            for filename in z.namelist():
                if filename.endswith(".txt"):
                    print(f"[*] Extracting {filename} from zip...")
                    with z.open(filename) as f:
                        for line in f:
                            line = line.decode('utf-8').strip().lower()
                            if line and not line.startswith("#") and len(line) == 64:
                                hashes.add(line)
except Exception as e:
    print(f"[-] Error fetching bulk hashes: {e}")

# Guaranteed safety baselines
ips.add("198.51.100.50")
domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# GitHub blocks files over 100MB. 500,000 hashes is ~32MB. 
MAX_HASHES = 500000
final_hashes = list(hashes)[:MAX_HASHES]

# Save Network IPs
os.makedirs("feeds/network", exist_ok=True)
with open("feeds/network/ip_blocks.txt", "w") as f:
    f.write("\n".join(sorted(ips)))
    
# Save Malicious Domains
with open("feeds/network/domains.txt", "w") as f:
    f.write("\n".join(sorted(domains)))
    
# Save Malicious Hashes for Disk AV
os.makedirs("feeds/disk", exist_ok=True)
with open("feeds/disk/hashes.txt", "w") as f:
    f.write("\n".join(sorted(final_hashes)))

print(f"[+] Harvest Complete: {len(ips)} IPs, {len(domains)} Domains, {len(final_hashes)} Hashes saved.")
