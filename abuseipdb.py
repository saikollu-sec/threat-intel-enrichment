import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_abuseipdb(ip):
    """Query AbuseIPDB for IP abuse reports."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "distinct_users": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "last_reported": data.get("lastReportedAt", "Never"),
            }
        else:
            return {"source": "AbuseIPDB", "error": f"Status {response.status_code}"}

    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}