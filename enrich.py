import argparse
import json
from virustotal import check_ip_virustotal, check_domain_virustotal, check_hash_virustotal
from abuseipdb import check_ip_abuseipdb
from otx import check_ip_otx, check_domain_otx
from ai_analyst import generate_analyst_report
from report import save_report


def detect_ioc_type(ioc):
    """Auto-detect whether input is IP, domain, or hash."""
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "hash"
    else:
        return "domain"


def enrich_ioc(ioc):
    """Main enrichment function — pulls from all sources and generates AI report."""

    ioc_type = detect_ioc_type(ioc)
    print(f"\n🔍 Analyzing {ioc_type.upper()}: {ioc}")
    print("=" * 60)

    enrichment_data = []

    # Pull from all relevant sources
    if ioc_type == "ip":
        print("⏳ Querying VirusTotal...")
        enrichment_data.append(check_ip_virustotal(ioc))

        print("⏳ Querying AbuseIPDB...")
        enrichment_data.append(check_ip_abuseipdb(ioc))

        print("⏳ Querying AlienVault OTX...")
        enrichment_data.append(check_ip_otx(ioc))

    elif ioc_type == "domain":
        print("⏳ Querying VirusTotal...")
        enrichment_data.append(check_domain_virustotal(ioc))

        print("⏳ Querying AlienVault OTX...")
        enrichment_data.append(check_domain_otx(ioc))

    elif ioc_type == "hash":
        print("⏳ Querying VirusTotal...")
        enrichment_data.append(check_hash_virustotal(ioc))

    # Display raw enrichment
    print("\n📊 RAW ENRICHMENT DATA")
    print("-" * 60)
    for source in enrichment_data:
        print(f"\n{source.get('source', 'Unknown')}:")
        for key, value in source.items():
            if key != "source":
                print(f"  {key:<20}: {value}")

    # Generate AI analyst report
    print("\n🤖 Generating AI Analyst Report...")
    print("-" * 60)
    ai_report = generate_analyst_report(
        ioc,
        ioc_type,
        json.dumps(enrichment_data, indent=2)
    )

    # Display AI report
    print("\n" + "=" * 60)
    print("AI ANALYST REPORT")
    print("=" * 60)
    print(ai_report)

    # Save reports
    save_report(ioc, ioc_type, enrichment_data, ai_report)


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Threat Intelligence Enrichment Tool"
    )
    parser.add_argument(
        "--ioc",
        required=True,
        help="IP address, domain, or file hash to analyze"
    )
    args = parser.parse_args()
    enrich_ioc(args.ioc)


if __name__ == "__main__":
    main()