import requests
import sys

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

headers = {
    "x-apikey": API_KEY
}

def check_ip(ip_address):
    url = BASE_URL + ip_address
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("Error fetching data from VirusTotal")
        return

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    print("\n🔍 Threat Intelligence Report")
    print("----------------------------")
    print(f"IP Address   : {ip_address}")
    print(f"Malicious    : {malicious}")
    print(f"Suspicious   : {suspicious}")

    if malicious > 0:
        print("⚠️  Verdict   : HIGH RISK")
    elif suspicious > 0:
        print("⚠️  Verdict   : SUSPICIOUS")
    else:
        print("✅ Verdict   : CLEAN")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python threat_checker.py <IP_ADDRESS>")
    else:
        check_ip(sys.argv[1])
