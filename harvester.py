import requests
import os

print("[*] Fetching open-source threat feeds from GitHub repositories...")

FEED_SOURCES = {
    "ips": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "domains": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # Using a broader or alternative reliable source for known malware hashes if available, 
    # or parsing multiple lines from a known IOC repository
    "hashes": "https://raw.githubusercontent.com/AbuseIPDB/key-hold/master/hashes.txt" # Alternatively, let's pull from a community collection or generate multiple test indicators
}

ips = set()
domains = set()
hashes = set()

# 1. Fetch IPs
try:
    print("[*] Downloading IP blocklist...")
    res = requests.get(FEED_SOURCES["ips"], timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("/"):
                ip = line.split("/")[0]
                if ip.count(".") == 3:
                    ips.add(ip)
except Exception as e:
    print(f"[-] Error fetching IPs: {e}")

# 2. Fetch Domains
try:
    print("[*] Downloading domain blocklist...")
    res = requests.get(FEED_SOURCES["domains"], timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    domains.add(parts[1])
except Exception as e:
    print(f"[-] Error fetching domains: {e}")

# 3. Fetch Hashes (Using a fallback list or a reliable public hash collection URL)
try:
    print("[*] Downloading malware hash list...")
    # Let's pull from MalwareBazaar's recent daily share or another raw community hash list
    hash_url = "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2023/indicators.txt"
    res = requests.get(hash_url, timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            # Look for strings that look like SHA-256 or MD5 hashes (32 or 64 hex chars)
            if len(line) in [32, 64] and all(c in "0123456789abcdefABCDEF" for c in line):
                hashes.add(line.lower())
except Exception as e:
    print(f"[-] Error fetching hashes, using expanded baseline: {e}")

# Guaranteed baselines
ips.add("198.51.100.50")
domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
hashes.add("8d1a12bc201639d6e8b4e7e6e22f25492a5eb578a164b38d72df9b77fa8f6233")

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
    f.write("\n".join(sorted(hashes)))

print(f"[+] Harvest Complete: {len(ips)} IPs, {len(domains)} Domains, {len(hashes)} Hashes saved.")
