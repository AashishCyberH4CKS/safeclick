import requests
import re
import socket
from urllib.parse import urlparse

# 🔐 Your actual VirusTotal API Key
VT_API_KEY = "7a69cc645e21d9a796ae77bdf8bd68f2f899d93333dd39bf2b3ab39096920871"

# 🌈 Yellow + Orange mix text color
def yellow_orange(text):
    return f"\033[93m{text}\033[0m"

# 🧾 Banner Display
def show_banner():
    banner = """

░██████╗░█████╗░███████╗███████╗░░░░░░░█████╗░██╗░░░░░██╗░█████╗░██╗░░██╗
██╔════╝██╔══██╗██╔════╝██╔════╝░░░░░░██╔══██╗██║░░░░░██║██╔══██╗██║░██╔╝
╚█████╗░███████║█████╗░░█████╗░░█████╗██║░░╚═╝██║░░░░░██║██║░░╚═╝█████═╝░
░╚═══██╗██╔══██║██╔══╝░░██╔══╝░░╚════╝██║░░██╗██║░░░░░██║██║░░██╗██╔═██╗░
██████╔╝██║░░██║██║░░░░░███████╗░░░░░░╚█████╔╝███████╗██║╚█████╔╝██║░╚██╗
╚═════╝░╚═╝░░╚═╝╚═╝░░░░░╚══════╝░░░░░░░╚════╝░╚══════╝╚═╝░╚════╝░╚═╝░░╚═╝
"""
    print(yellow_orange(banner))
    print(yellow_orange("Version 1.0 | Created By Aashish_Cyber_H4CKS\n"))

# 🧠 Detect phishing-style keywords
def is_phishing(url):
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'free', 'bonus']
    return any(word in url.lower() for word in keywords)

# 🌐 Extract domain + resolve IP
def get_domain_info(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unable to resolve"
    return domain, ip

# 🔬 Scan with VirusTotal
def scan_with_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.post(api_url, headers=headers, data={"url": url})
        if response.status_code != 200:
            return "Error sending to VirusTotal"

        scan_id = response.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        result = requests.get(report_url, headers=headers).json()

        stats = result['data']['attributes']['stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']

        if malicious > 0 or suspicious > 0:
            return f"⚠️ Detected: {malicious} malicious, {suspicious} suspicious"
        else:
            return "✅ Clean according to VirusTotal"

    except Exception as e:
        return f"Error: {str(e)}"

# 🚀 Main Program
if __name__ == "__main__":
    show_banner()
    url = input("🔗 Enter URL to scan: ")

    if not re.match(r'^https?:/{2}\w.+$', url):
        print("❌ Invalid URL format.")
        exit()

    domain, ip = get_domain_info(url)
    print(f"\n🌍 Domain: {domain}")
    print(f"📡 IP Address: {ip}")

    phishing = is_phishing(url)
    print(f"🚨 Phishing Pattern Detected: {'Yes' if phishing else 'No'}")

    print("\n🔬 Scanning with VirusTotal...")
    vt_result = scan_with_virustotal(url)
    print(f"🧪 VirusTotal Result: {vt_result}")
