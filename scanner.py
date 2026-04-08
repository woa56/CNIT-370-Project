"""
Text File Sensitivity Scanner
Uses Microsoft Presidio to detect PII and classify files as High, Medium, or Low sensitivity.

Setup:
    pip install presidio-analyzer
    python -m spacy download en_core_web_lg

Sensitivity Levels
------------------
Low    — Public, harmless, or operational data. No PII, credentials, financial,
         health, or confidential content. General non-personal / routine information.

Medium — Personal or internal information that is not immediately damaging on its own.
         Basic identity, contact info, usernames, employment details, internal
         non-confidential data. No credentials, financial, or health data.

High   — Data that could cause serious harm if exposed: fraud, identity theft,
         unauthorized access, legal issues, or security compromise. Strong personal
         identifiers, financial data, credentials, secrets, health records.
"""

import os
import sys
from presidio_analyzer import AnalyzerEngine

# ---------------------------------------------------------------------------
# Entity sets
# ---------------------------------------------------------------------------

# Strong personal identifiers, financial, health, credentials → HIGH
HIGH_SENSITIVITY = {
    "US_SSN",
    "CREDIT_CARD",
    "US_BANK_NUMBER",
    "MEDICAL_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "DRIVER_ID",          # strong personal identifier
    "IN_AADHAAR",
    "IN_PAN",
    "SG_NRIC_FIN",
    "AU_TFN",
    "AU_MEDICARE",
    "UK_NHS",             # health data
}

# Basic personal info, contact info, internal identifiers → MEDIUM
# DATE_TIME, ORG, and other low-risk entities fall through to LOW
MEDIUM_SENSITIVITY = {
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "NRP",                # Nationality / Religion / Political group
    "IP_ADDRESS",
    "IBAN_CODE",
    "CRYPTO",
    "URL",
    "ES_NIF",
    "IT_FISCAL_CODE",
    "IT_DRIVER_LICENSE",
    "IT_PASSPORT",
    "IT_IDENTITY_CARD",
    "PL_PESEL",
    "FI_PERSONAL_IDENTITY_CODE",
    "IN_VEHICLE_REGISTRATION",
}

# ---------------------------------------------------------------------------
# Feature flags per sensitivity level
# ---------------------------------------------------------------------------

LOW_FLAGS = {
    "contains_pii": 0,
    "contains_credentials": 0,
    "contains_financial": 0,
    "contains_health": 0,
    "contains_confidential_business": 0,
    "contains_secrets": 0,
    "risk_score": 0,
}

MEDIUM_FLAGS = {
    "contains_pii": 1,
    "contains_basic_identity": 1,
    "contains_contact_info": 1,
    "contains_internal_only": 1,
    "contains_credentials": 0,
    "contains_financial": 0,
    "contains_health": 0,
    "contains_secrets": 0,
}

HIGH_FLAGS = {
    "contains_sensitive_pii": 1,
    "contains_financial": 1,
    "contains_credentials": 1,
    "contains_secrets": 1,
    "contains_health": 1,
    "contains_confidential_business": 1,
    "high_risk_pattern_match": 1,
}

FLAGS_BY_LEVEL = {
    "Low": LOW_FLAGS,
    "Medium": MEDIUM_FLAGS,
    "High": HIGH_FLAGS,
}


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def classify_findings(detected_entities: set[str]) -> str:
    """Return High / Medium / Low based on the most sensitive entity found."""
    if detected_entities & HIGH_SENSITIVITY:
        return "High"
    if detected_entities & MEDIUM_SENSITIVITY:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Email classification helpers
# ---------------------------------------------------------------------------

# Role/function addresses that are public-facing and carry no personal identity.
PUBLIC_EMAIL_PREFIXES = {
    "support", "help", "info", "contact", "hello", "hi",
    "sales", "marketing", "billing", "payments", "invoices",
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "admin", "administrator", "webmaster", "postmaster",
    "security", "privacy", "legal", "compliance",
    "hr", "careers", "jobs", "recruiting",
    "press", "media", "pr", "news",
    "feedback", "survey",
    "abuse", "spam",
    "team", "general", "office",
}


def is_public_email(email_text: str) -> bool:
    """Return True if the email looks like a public/role address rather than a personal one."""
    local = email_text.split("@")[0].lower().strip()
    return local in PUBLIC_EMAIL_PREFIXES


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_file(path: str, analyzer: AnalyzerEngine) -> dict:
    """Scan a single text file and return its classification report."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    results = analyzer.analyze(text=text, language="en")

    # Split EMAIL_ADDRESS hits into public vs personal so public support
    # addresses (e.g. support@company.com) don't inflate the sensitivity level.
    personal_email_found = False
    for r in results:
        if r.entity_type == "EMAIL_ADDRESS":
            email_text = text[r.start:r.end]
            if not is_public_email(email_text):
                personal_email_found = True
                break

    detected = set()
    for r in results:
        if r.entity_type == "EMAIL_ADDRESS" and not personal_email_found:
            continue  # all emails in this file are public role addresses
        detected.add(r.entity_type)

    classification = classify_findings(detected)

    return {
        "file": path,
        "classification": classification,
        "entities_found": sorted(detected),
        "total_hits": len(results),
        "feature_flags": FLAGS_BY_LEVEL[classification],
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


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(reports: list[dict]) -> None:
    """Print a formatted summary of scan results."""
    if not reports:
        print("No .txt files found.")
        return

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
        print(f"           Flags    : {r['feature_flags']}")
        print()

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in reports:
        counts[r["classification"]] += 1

    print(f"{'='*60}")
    print(f"  Summary: High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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
