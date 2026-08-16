import requests
import os
import re

print("[*] Fetching Global C2 IPs from ThreatFox...")
url = "https://threatfox-api.abuse.ch/api/v1/"
# Grab ALL active threats from the last 3 days instead of relying on one tag
payload = {"query": "get_iocs", "days": 3}

try:
    response = requests.post(url, json=payload).json()
    ips = set()
    
    if response.get("query_status") == "ok":
        for entry in response.get("data", []):
            if entry.get("ioc_type") == "ip:port":
                ip = entry["ioc"].split(":")[0]
                ips.add(ip)
                
    # Always add a test IP so the file is never blank and the firewall has a baseline
    ips.add("198.51.100.50") 
                
    os.makedirs("feeds/network", exist_ok=True)
    with open("feeds/network/ip_blocks.txt", "w") as f:
        f.write("\n".join(sorted(ips)))
        
    print(f"[+] Harvest Complete. Saved {len(ips)} active C2 IPs.")
except Exception as e:
    print(f"[-] Error: {e}")
