import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_virustotal(ip):
    """Query VirusTotal for IP reputation data."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "community_score": attributes.get("reputation", 0),
                "tags": attributes.get("tags", []),
                "country": attributes.get("country", "Unknown"),
                "owner": attributes.get("as_owner", "Unknown"),
            }
        else:
            return {"source": "VirusTotal", "error": f"Status {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_domain_virustotal(domain):
    """Query VirusTotal for domain reputation data."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "community_score": attributes.get("reputation", 0),
                "tags": attributes.get("tags", []),
                "registrar": attributes.get("registrar", "Unknown"),
                "creation_date": attributes.get("creation_date", "Unknown"),
            }
        else:
            return {"source": "VirusTotal", "error": f"Status {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_hash_virustotal(file_hash):
    """Query VirusTotal for file hash reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "file_type": attributes.get("type_description", "Unknown"),
                "file_size": attributes.get("size", 0),
                "tags": attributes.get("tags", []),
                "names": attributes.get("names", [])[:3],
            }
        else:
            return {"source": "VirusTotal", "error": f"Status {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}