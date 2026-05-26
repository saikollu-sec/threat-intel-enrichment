# 🛡️ AI-Powered Threat Intelligence Enrichment Tool

A Python-based SOC analyst tool that automates IOC enrichment by querying 
multiple threat intelligence sources and generating AI-powered analyst 
reports using Claude AI.

Built by a cybersecurity analyst to reduce manual IOC triage time from 
~15 minutes to under 30 seconds.

---

## 🔍 What It Does

Takes any **IP address, domain, or file hash** as input and automatically:

1. Queries **VirusTotal** — malicious detections, engine scores, tags
2. Queries **AbuseIPDB** — abuse score, report history, ISP details
3. Queries **AlienVault OTX** — threat pulses, malware families, TTPs
4. Feeds all enrichment data into **Claude AI** to generate a structured 
   SOC analyst report including:
   - Threat assessment narrative
   - MITRE ATT&CK technique mapping
   - Risk verdict (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)
   - Prioritised recommended SOC actions
   - Confidence level with reasoning

---

## 📊 Sample Output# threat-intel-enrichment
🔍 Analyzing IP: 185.220.101.45
⏳ Querying VirusTotal...
⏳ Querying AbuseIPDB...
⏳ Querying AlienVault OTX...
RAW ENRICHMENT DATA
VirusTotal:
malicious           : 18
suspicious          : 1
total_engines       : 91
community_score     : -21
tags                : ['tor']
country             : DE
owner               : Stiftung Erneuerbare Freiheit
AbuseIPDB:
abuse_score         : 100
total_reports       : 114
distinct_users      : 67
is_tor              : True
isp                 : Network for Tor-Exit traffic
============================================================
AI ANALYST REPORT
THREAT ASSESSMENT
This IP address is a known Tor exit node operated by "Stiftung
Erneuerbare Freiheit" in Germany. While Tor infrastructure itself
serves legitimate anonymization purposes, this specific exit node
has been weaponized for malicious activity, evidenced by an AbuseIPDB
score of 100/100 with 114 reports from 67 distinct users.
MITRE ATT&CK MAPPING

T1090.003: Proxy - Multi-hop Proxy
T1071.001: Application Layer Protocol - Web Protocols
T1583.003: Acquire Infrastructure - Virtual Private Server
T1110: Brute Force
T1595.002: Active Scanning - Vulnerability Scanning

RISK VERDICT
VERDICT: HIGH
RECOMMENDED SOC ACTIONS

Immediate Threat Hunt — Query SIEM for connections to this IP
Endpoint Investigation — Identify internal hosts communicating
with this IP
Firewall Rule Implementation — Block at perimeter firewall
Access Review — Review affected user accounts
Policy Enforcement — Escalate if legitimate business use claimed

CONFIDENCE LEVEL
CONFIDENCE: High
Multiple independent sources with strong consensus on malicious activity.
---

## 🏗️ Architecture
Input (IP / Domain / Hash)
↓
┌────────────────────────────┐
│      Enrichment Layer      │
│  VirusTotal + AbuseIPDB    │
│  + AlienVault OTX          │
└────────────────────────────┘
↓
┌────────────────────────────┐
│     AI Analysis Layer      │
│  Claude AI (Anthropic)     │
│  → Threat narrative        │
│  → MITRE ATT&CK mapping    │
│  → Risk verdict            │
│  → Recommended actions     │
│  → Confidence score        │
└────────────────────────────┘
↓
┌────────────────────────────┐
│       Output Layer         │
│  Terminal display          │
│  + JSON report saved       │
│  + Text report saved       │
└────────────────────────────┘

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.x | Core language |
| VirusTotal API | Malware/reputation intelligence |
| AbuseIPDB API | IP abuse reporting |
| AlienVault OTX API | Threat pulse intelligence |
| Anthropic Claude API | AI analyst report generation |
| python-dotenv | Secure API key management |

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/saikollu-sec/threat-intel-enrichment.git
cd threat-intel-enrichment
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
```

### 3. Install dependencies
```bash
pip install requests python-dotenv anthropic
```

### 4. Configure API keys
Create a `.env` file in the root directory:
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

Get free API keys from:
- [VirusTotal](https://virustotal.com)
- [AbuseIPDB](https://abuseipdb.com)
- [AlienVault OTX](https://otx.alienvault.com)
- [Anthropic](https://console.anthropic.com)

---

## 🚀 Usage

**Analyze an IP address:**
```bash
python enrich.py --ioc 185.220.101.45
```

**Analyze a domain:**
```bash
python enrich.py --ioc malicious-domain.com
```

**Analyze a file hash:**
```bash
python enrich.py --ioc 44d88612fea8a8f36de82e1278abb02f
```

Reports are automatically saved to the `reports/` directory as both 
JSON and text files.

---

## 📁 Project Structure
threat-intel-enrichment/
│
├── enrich.py          # Main entry point
├── virustotal.py      # VirusTotal API connector
├── abuseipdb.py       # AbuseIPDB API connector
├── otx.py             # AlienVault OTX connector
├── ai_analyst.py      # Claude AI report generator
├── report.py          # Report saving and formatting
├── reports/           # Auto-generated reports (gitignored)
├── .env               # API keys (gitignored)
└── .gitignore

---

## 💡 Use Cases

- **Alert triage** — Quickly assess IOCs from SIEM alerts
- **Incident response** — Rapid enrichment during active incidents
- **Threat hunting** — Bulk IOC investigation
- **SOC automation** — Integrate into SOAR playbooks

---

## 👤 Author

**Sai Kollu** — Cybersecurity Analyst | Detection Engineer  
[LinkedIn](https://linkedin.com/in/sai-kollu-629773377) | 
[GitHub](https://github.com/saikollu-sec)

3+ years experience in enterprise SOC and MSSP environments.  
Microsoft Sentinel | CrowdStrike | MITRE ATT&CK | AZ-500 Certified