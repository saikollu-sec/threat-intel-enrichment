import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def check_ip_otx(ip):
    """Query AlienVault OTX for IP threat intelligence."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        general = requests.get(
            f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general",
            headers=headers, timeout=20
        ).json()

        pulses = general.get("pulse_info", {}).get("pulses", [])

        # Safely extract only string values
        malware_families = list(set([
            str(m) for pulse in pulses
            for m in pulse.get("malware_families", [])
            if isinstance(m, str)
        ]))[:5]

        tags = list(set([
            str(t) for pulse in pulses
            for t in pulse.get("tags", [])
            if isinstance(t, str)
        ]))[:5]

        threat_types = list(set([
            pulse.get("name", "")
            for pulse in pulses
            if isinstance(pulse.get("name", ""), str)
        ]))[:3]

        return {
            "source": "AlienVault OTX",
            "pulse_count": general.get("pulse_info", {}).get("count", 0),
            "malware_families": malware_families,
            "tags": tags,
            "threat_types": threat_types,
            "country": general.get("country_name", "Unknown"),
        }

    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}


def check_domain_otx(domain):
    """Query AlienVault OTX for domain threat intelligence."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        general = requests.get(
            f"{OTX_BASE_URL}/indicators/domain/{domain}/general",
            headers=headers, timeout=10
        ).json()

        return {
            "source": "AlienVault OTX",
            "pulse_count": general.get("pulse_info", {}).get("count", 0),
            "malware_families": list(set([
                tag for pulse in general.get("pulse_info", {}).get("pulses", [])
                for tag in pulse.get("malware_families", [])
            ]))[:5],
            "tags": list(set([
                tag for pulse in general.get("pulse_info", {}).get("pulses", [])
                for tag in pulse.get("tags", [])
            ]))[:5],
            "alexa_rank": general.get("alexa", "Unknown"),
        }

    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}