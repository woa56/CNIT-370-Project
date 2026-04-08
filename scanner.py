"""
Text File Sensitivity Scanner
Uses Microsoft Presidio to detect PII and classify files as High, Medium, or Low sensitivity.

Setup:
    pip install presidio-analyzer
    python -m spacy download en_core_web_lg
"""

import os
import sys
from presidio_analyzer import AnalyzerEngine

# PII entities grouped by sensitivity tier
HIGH_SENSITIVITY = {
    "US_SSN",
    "CREDIT_CARD",
    "US_BANK_NUMBER",
    "MEDICAL_LICENSE",
    "US_ITIN",
    "US_PASSPORT",       # passport = high
    "IN_AADHAAR",
    "IN_PAN",
    "SG_NRIC_FIN",
    "AU_TFN",
    "AU_MEDICARE",
}

MEDIUM_SENSITIVITY = {
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "DATE_TIME",
    "NRP",               # Nationality / Religion / Political group
    "DRIVER_ID",
    "IP_ADDRESS",
    "IBAN_CODE",
    "CRYPTO",
    "UK_NHS",
    "ES_NIF",
    "IT_FISCAL_CODE",
    "IT_DRIVER_LICENSE",
    "IT_PASSPORT",
    "IT_IDENTITY_CARD",
    "PL_PESEL",
    "FI_PERSONAL_IDENTITY_CODE",
    "IN_VEHICLE_REGISTRATION",
}

# Anything else detected (PERSON, LOCATION, URL, ORG, etc.) = LOW


def classify_findings(detected_entities: set[str]) -> str:
    """Return High / Medium / Low based on the most sensitive entity found."""
    if detected_entities & HIGH_SENSITIVITY:
        return "High"
    if detected_entities & MEDIUM_SENSITIVITY:
        return "Medium"
    if detected_entities:
        return "Low"
    return "Low"  # no PII detected → low risk


def scan_file(path: str, analyzer: AnalyzerEngine) -> dict:
    """Scan a single text file and return its classification report."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    results = analyzer.analyze(text=text, language="en")

    detected = {r.entity_type for r in results}
    classification = classify_findings(detected)

    return {
        "file": path,
        "classification": classification,
        "entities_found": sorted(detected),
        "total_hits": len(results),
    }


def scan_directory(directory: str, analyzer: AnalyzerEngine) -> list[dict]:
    """Recursively scan all .txt files in a directory."""
    reports = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".txt"):
                filepath = os.path.join(root, filename)
                reports.append(scan_file(filepath, analyzer))
    return reports


def print_report(reports: list[dict]) -> None:
    """Print a formatted summary of scan results."""
    if not reports:
        print("No .txt files found.")
        return

    # Sort: High first, then Medium, then Low
    order = {"High": 0, "Medium": 1, "Low": 2}
    reports.sort(key=lambda r: order[r["classification"]])

    print(f"\n{'='*60}")
    print(f"  SENSITIVITY SCAN REPORT  ({len(reports)} file(s) scanned)")
    print(f"{'='*60}\n")

    for r in reports:
        label = r["classification"]
        label_fmt = f"[{label.upper():^6}]"
        print(f"{label_fmt}  {r['file']}")
        if r["entities_found"]:
            print(f"           Entities : {', '.join(r['entities_found'])}")
            print(f"           Hits     : {r['total_hits']}")
        else:
            print(f"           No PII detected")
        print()

    # Summary counts
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in reports:
        counts[r["classification"]] += 1

    print(f"{'='*60}")
    print(f"  Summary: High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}")
    print(f"{'='*60}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scanner.py <file_or_directory> [file_or_directory ...]")
        print("\nExample:")
        print("  python scanner.py documents/")
        print("  python scanner.py report.txt notes.txt")
        sys.exit(1)

    print("Initializing Presidio Analyzer...")
    analyzer = AnalyzerEngine()

    reports = []
    for target in sys.argv[1:]:
        if os.path.isdir(target):
            reports.extend(scan_directory(target, analyzer))
        elif os.path.isfile(target) and target.endswith(".txt"):
            reports.append(scan_file(target, analyzer))
        else:
            print(f"Skipping '{target}' (not a .txt file or directory)")

    print_report(reports)


if __name__ == "__main__":
    main()
