import anthropic
import os
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def generate_analyst_report(ioc, ioc_type, enrichment_data):
    """Use Claude to generate a SOC analyst report from enrichment data."""

    prompt = f"""
You are a senior SOC analyst writing a threat intelligence report.

Analyze the following enrichment data for this IOC and produce a professional SOC report.

IOC: {ioc}
IOC Type: {ioc_type}

ENRICHMENT DATA:
{enrichment_data}

Write a structured SOC analyst report with these exact sections:

THREAT ASSESSMENT
Write 3-4 sentences summarizing what this IOC is, how dangerous it is, and what threat activity it is associated with. Be specific and technical.

MITRE ATT&CK MAPPING
List the most relevant MITRE ATT&CK techniques this IOC is associated with based on the threat data. Format as:
- TXXXX: Technique Name — brief explanation

RISK VERDICT
State one of: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
Then explain why in 1-2 sentences.

RECOMMENDED SOC ACTIONS
List 4-5 specific, prioritized actions a SOC analyst should take right now. Be specific and actionable.

CONFIDENCE LEVEL
State: High / Medium / Low
Explain briefly why based on data quality and source agreement.

Keep the tone professional, technical, and concise. Write as an experienced L2/L3 SOC analyst would.
"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"