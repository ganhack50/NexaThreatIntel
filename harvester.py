import requests
import os

print("[*] Fetching Android C2 IPs from ThreatFox...")
url = "https://threatfox-api.abuse.ch/api/v1/"
payload = {"query": "taginfo", "tag": "android", "limit": 1000}

try:
    response = requests.post(url, json=payload).json()
    ips = set()
    
    if response.get("query_status") == "ok":
        for entry in response["data"]:
            if entry["ioc_type"] == "ip:port":
                # Extract just the IP, drop the port
                ip = entry["ioc"].split(":")[0]
                ips.add(ip)
                
    os.makedirs("feeds/network", exist_ok=True)
    with open("feeds/network/ip_blocks.txt", "w") as f:
        f.write("\n".join(sorted(ips)))
        
    print(f"[+] Harvest Complete. Saved {len(ips)} active Android C2 IPs.")
except Exception as e:
    print(f"[-] Error: {e}")
