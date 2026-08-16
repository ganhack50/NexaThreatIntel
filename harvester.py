import requests
import os

print("[*] Fetching open-source threat feeds from GitHub repositories...")

# Example trusted public threat feed sources (raw text files)
# You can replace or add any public raw GitHub URLs here
FEED_SOURCES = {
    "ips": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "domains": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "hashes": "https://raw.githubusercontent.com/yolosec/malware-hashes/main/hashes.txt" # Or any public hash list
}

ips = set()
domains = set()
hashes = set()

# 1. Fetch IPs (filtering out comment lines)
try:
    print("[*] Downloading IP blocklist...")
    res = requests.get(FEED_SOURCES["ips"], timeout=15)
    if res.status_code == 200:
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("/"):
                # Basic cleanup if it's CIDR or raw IP
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
            # Standard hosts file format: "0.0.0.0 domain.com"
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    domains.add(parts[1])
except Exception as e:
    print(f"[-] Error fetching domains: {e}")

# Add guaranteed test baselines so feeds are never blank
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
