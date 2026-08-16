import requests
import os

print("[*] Fetching comprehensive IOCs from ThreatFox...")
url = "https://threatfox-api.abuse.ch/api/v1/"
# Increase limit or use recent ID queries to pull a rich set of data
payload = {"query": "get_iocs", "days": 7}

try:
    response = requests.post(url, json=payload).json()
    ips = set()
    domains = set()
    hashes = set()
    
    data_list = response.get("data", [])
    print(f"[*] Total raw entries pulled from API: {len(data_list)}")
    
    if response.get("query_status") == "ok":
        for entry in data_list:
            ioc_type = str(entry.get("ioc_type", "")).lower()
            ioc_value = str(entry.get("ioc", "")).strip()
            
            if not ioc_value:
                continue
                
            # Capture IP addresses (handles both ip:port and raw ip)
            if "ip" in ioc_type:
                ip = ioc_value.split(":")[0]
                if count_dots := ip.count(".") == 3: # Basic IPv4 validation
                    ips.add(ip)
            # Capture domains
            elif "domain" in ioc_type:
                domains.add(ioc_value)
            # Capture any hash type (sha256, md5, etc.)
            elif "hash" in ioc_type or len(ioc_value) in [32, 64]:
                hashes.add(ioc_value)
                
    # Add robust test baselines
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
        
    print(f"[+] Harvest Success: {len(ips)} IPs, {len(domains)} Domains, {len(hashes)} Hashes saved.")
except Exception as e:
    print(f"[-] Error during harvest: {e}")
