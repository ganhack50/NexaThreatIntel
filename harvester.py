import requests
import os

print("[*] Fetching Multi-Vector C2 IOCs from ThreatFox...")
url = "https://threatfox-api.abuse.ch/api/v1/"
payload = {"query": "get_iocs", "days": 3}

try:
    response = requests.post(url, json=payload).json()
    ips = set()
    domains = set()
    hashes = set()
    
    if response.get("query_status") == "ok":
        for entry in response.get("data", []):
            ioc_type = entry.get("ioc_type")
            ioc_value = entry.get("ioc")
            
            if ioc_type == "ip:port":
                ip = ioc_value.split(":")[0]
                ips.add(ip)
            elif ioc_type == "domain":
                domains.add(ioc_value)
            elif ioc_type in ["sha256_hash", "md5_hash"]:
                hashes.add(ioc_value)
                
    # Baselines so feeds are never completely empty
    ips.add("198.51.100.50")
    domains.add("malware-test.nexasecurity.local")
    
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
except Exception as e:
    print(f"[-] Error: {e}")
