import requests
import os

print("[*] Fetching threat intel feeds...")

ips = set()
domains = set()
hashes = set()

# 1. Fetch IPs from FireHOL
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

# 2. Fetch Domains from StevenBlack hosts
try:
    print("[*] Downloading domain blocklist...")
    res = requests.get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    domains.add(parts[1])
except Exception as e:
    print(f"[-] Error fetching domains: {e}")

# 3. Fetch Real Malware Hashes from MalwareBazaar (Recent SHA-256 text feed)
try:
    print("[*] Downloading malware hash feed...")
    hash_url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    res = requests.get(hash_url, timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            # Skip comment lines starting with #
            if line and not line.startswith("#"):
                if len(line) == 64:  # Valid SHA-256 length
                    hashes.add(line.lower())
except Exception as e:
    print(f"[-] Error fetching hashes: {e}")

# Guaranteed safety baselines
ips.add("198.51.100.50")
domains.add("malware-test.nexasecurity.local")
hashes.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

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
