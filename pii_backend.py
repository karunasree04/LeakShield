# -*- coding: utf-8 -*-
"""
pii_backend.py
==============
Core PII detection engine with context-aware confidence logic.

Layers:
  1. Regex        → Structural detection (email, phone, Aadhaar, SSN, address)
  2. spaCy NER    → Contextual enrichment (PERSON, GPE/LOC entities)
  3. Confidence   → Context-aware scoring (not just format validity)
  4. Severity     → Risk classification

NEW in this version:
  5. GitHub README fetcher → fetch_github_readme(url)
"""

import re
import requests

# ── Optional spaCy (gracefully skipped if not installed) ─────────────────────
try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    spacy = None
    SPACY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 ─ REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)

PHONE_PATTERN = re.compile(
    r'(?:\+?[\d]{1,3}[\s\-\.]?)?(?:\(?[\d]{2,4}\)?[\s\-\.]?)[\d]{3,5}[\s\-\.]?[\d]{4,5}'
)

# Aadhaar: 12-digit Indian UID, starts 2-9, optional space/hyphen separators
AADHAAR_PATTERN = re.compile(
    r'\b[2-9][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
)

# SSN: AAA-BB-CCCC — excludes invalid prefixes 000, 666, 9xx
SSN_PATTERN = re.compile(
    r'\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b'
)

# Address: house number + street name + road-type keyword anchor
ADDRESS_PATTERN = re.compile(
    r'''
    \b
    (?:No\.?\s*)?
    \d{1,5}[A-Za-z]?
    [,\s]+
    [A-Za-z0-9\s\.\-]{3,40}
    (?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|
       Nagar|Colony|Hills|Layout|Enclave|Cross|Main|Block|Sector|Phase|
       Place|Pl|Circle|Court|Ct|Way|Marg|Chowk|Bazaar|Galli|Peth)
    (?:[,\s]+[A-Za-z\s]{2,30})?
    \b
    ''',
    re.VERBOSE | re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 ─ CONTEXT-AWARE CONFIDENCE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

LOG_CONTEXT_KEYWORDS = {
    "error", "code", "exception", "log", "transaction",
    "id", "ref", "request", "status", "trace", "debug",
    "ticket", "order", "invoice", "batch", "session", "event"
}

AADHAAR_CONTEXT_KEYWORDS = {
    "aadhaar", "aadhar", "uid", "uidai", "enrollment",
    "dob", "biometric", "identity", "verification"
}

SSN_CONTEXT_KEYWORDS = {
    "ssn", "social", "security", "taxpayer", "irs",
    "federal", "ein", "tin", "w2", "w-2"
}

ADDRESS_CONTEXT_KEYWORDS = {
    "address", "residence", "residing", "lives", "located",
    "home", "office", "flat", "apartment", "house", "plot",
    "door", "building", "floor", "near", "opposite", "behind"
}


def _get_surrounding_words(text: str, match_start: int, match_end: int, window: int = 80) -> str:
    """Extract a text window around a match to assess context."""
    start = max(0, match_start - window)
    end   = min(len(text), match_end + window)
    return text[start:end].lower()


def _has_log_context(surrounding: str) -> bool:
    words = re.findall(r'[a-z]+', surrounding)
    return bool(LOG_CONTEXT_KEYWORDS.intersection(words))


def _has_keyword_context(surrounding: str, keyword_set: set) -> bool:
    words = re.findall(r'[a-z]+', surrounding)
    return bool(keyword_set.intersection(words))


def classify_email(value: str, person_present: bool) -> dict:
    """
    High   → strict email format + PERSON entity in text
    Medium → valid format, no PERSON detected
    Severity: Low
    """
    strict_match = re.fullmatch(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        value.strip()
    )
    if not strict_match:
        confidence = "Medium"
    elif person_present:
        confidence = "High"
    else:
        confidence = "Medium"

    return {
        "type":       "Email",
        "value":      value.strip(),
        "confidence": confidence,
        "severity":   "Low",
        "reason":     "Valid email format" if strict_match else "Partial email match"
    }


def classify_phone(value: str, surrounding: str, person_present: bool) -> dict:
    """
    Low    → log/system keywords in surrounding text
    Low    → digit count < 10
    Medium → valid format, no PERSON entity
    High   → valid format + PERSON present
    Severity: Medium
    """
    digits = re.sub(r'\D', '', value)

    if _has_log_context(surrounding):
        confidence = "Low"
        reason     = "Numeric value found in log/error/system context"
    elif len(digits) < 10:
        confidence = "Low"
        reason     = "Digit count below standard phone number length"
    elif not person_present:
        confidence = "Medium"
        reason     = "Valid format but no PERSON entity detected in text"
    else:
        confidence = "High"
        reason     = "Valid phone format with PERSON entity present in text"

    return {
        "type":       "Phone",
        "value":      value.strip(),
        "confidence": confidence,
        "severity":   "Medium",
        "reason":     reason
    }


def classify_aadhaar(value: str, surrounding: str, person_present: bool) -> dict:
    """
    High   → Aadhaar keyword in context OR PERSON entity present
    Medium → format match only
    Severity: High (government-issued ID)
    """
    has_ctx = _has_keyword_context(surrounding, AADHAAR_CONTEXT_KEYWORDS)
    if has_ctx or person_present:
        confidence = "High"
        reason = "Aadhaar keyword in context" if has_ctx else "12-digit ID with PERSON entity present"
    else:
        confidence = "Medium"
        reason = "12-digit number matching Aadhaar format (no contextual confirmation)"

    return {
        "type":       "Aadhaar",
        "value":      value.strip(),
        "confidence": confidence,
        "severity":   "High",
        "reason":     reason
    }


def classify_ssn(value: str, surrounding: str, person_present: bool) -> dict:
    """
    High   → SSN keyword in context OR PERSON entity present
    Medium → format match only
    Severity: High (government-issued ID)
    """
    has_ctx = _has_keyword_context(surrounding, SSN_CONTEXT_KEYWORDS)
    if has_ctx or person_present:
        confidence = "High"
        reason = "SSN keyword in surrounding context" if has_ctx else "SSN format with PERSON entity present"
    else:
        confidence = "Medium"
        reason = "Matches SSN format (AAA-BB-CCCC), no contextual confirmation"

    return {
        "type":       "SSN",
        "value":      value.strip(),
        "confidence": confidence,
        "severity":   "High",
        "reason":     reason
    }


def classify_address(value: str, surrounding: str, person_present: bool, location_present: bool) -> dict:
    """
    High   → address keyword context + PERSON or LOCATION entity
    Medium → address keyword context OR person/location entity (not both)
    Low    → regex match only
    Severity: Medium
    """
    has_addr_ctx = _has_keyword_context(surrounding, ADDRESS_CONTEXT_KEYWORDS)
    has_nlp      = person_present or location_present

    if has_addr_ctx and has_nlp:
        confidence = "High"
        reason     = "Address keyword context + NLP entity (PERSON/LOCATION) present"
    elif has_addr_ctx or has_nlp:
        confidence = "Medium"
        reason = (
            "Address keyword found in context" if has_addr_ctx
            else "PERSON/LOCATION entity supports address pattern"
        )
    else:
        confidence = "Low"
        reason = "Street keyword pattern matched but no contextual confirmation"

    return {
        "type":       "Address",
        "value":      value.strip(),
        "confidence": confidence,
        "severity":   "Medium",
        "reason":     reason
    }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 ─ spaCy NER LAYER
# ─────────────────────────────────────────────────────────────────────────────

def extract_nlp_entities(text: str) -> dict:
    """
    Run spaCy NER. Returns PERSON and GPE/LOC entities.
    Loaded lazily to avoid Streamlit crash on import.
    Falls back to safe empty defaults if unavailable.
    """
    if not SPACY_AVAILABLE:
        return {"persons": [], "locations": [], "has_person": False,
                "has_location": False, "spacy_available": False}

    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        return {"persons": [], "locations": [], "has_person": False,
                "has_location": False, "spacy_available": False}

    doc     = nlp(text)
    persons = list({ent.text for ent in doc.ents if ent.label_ == "PERSON"})
    locs    = list({ent.text for ent in doc.ents if ent.label_ in ("GPE", "LOC")})

    return {
        "persons":         persons,
        "locations":       locs,
        "has_person":      len(persons) > 0,
        "has_location":    len(locs) > 0,
        "spacy_available": True
    }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 ─ MASTER SCAN FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def scan_text(text: str) -> dict:
    """
    Full pipeline:
      Step 1 → spaCy NER  (contextual signal — runs FIRST)
      Step 2 → Regex detection: email, Aadhaar, SSN, phone, address
      Step 3 → Context-aware classification per type
    Returns: { pii_results: [...], nlp_entities: {...} }
    """
    nlp_data       = extract_nlp_entities(text)
    person_found   = nlp_data["has_person"]
    location_found = nlp_data.get("has_location", False)

    results = []
    seen    = set()

    # Emails
    for match in EMAIL_PATTERN.finditer(text):
        val = match.group().strip()
        if val not in seen:
            seen.add(val)
            results.append(classify_email(val, person_present=person_found))

    # Aadhaar (before phone — prevents 12-digit IDs being mis-tagged as phones)
    for match in AADHAAR_PATTERN.finditer(text):
        val    = match.group().strip()
        digits = re.sub(r'\D', '', val)
        if len(digits) != 12 or val in seen:
            continue
        seen.add(val)
        surrounding = _get_surrounding_words(text, match.start(), match.end())
        results.append(classify_aadhaar(val, surrounding, person_present=person_found))

    # SSN
    for match in SSN_PATTERN.finditer(text):
        val = match.group().strip()
        if val not in seen:
            seen.add(val)
            surrounding = _get_surrounding_words(text, match.start(), match.end())
            results.append(classify_ssn(val, surrounding, person_present=person_found))

    # Phone numbers
    for match in PHONE_PATTERN.finditer(text):
        val    = match.group().strip()
        digits = re.sub(r'\D', '', val)
        if len(digits) < 7 or val in seen:
            continue
        if any(val in r["value"] for r in results if r["type"] == "Email"):
            continue
        seen.add(val)
        surrounding = _get_surrounding_words(text, match.start(), match.end())
        results.append(classify_phone(val, surrounding, person_present=person_found))

    # Addresses
    for match in ADDRESS_PATTERN.finditer(text):
        val = re.sub(r'\s+', ' ', match.group().strip())
        if val not in seen:
            seen.add(val)
            surrounding = _get_surrounding_words(text, match.start(), match.end())
            results.append(classify_address(
                val, surrounding,
                person_present=person_found,
                location_present=location_found
            ))

    return {"pii_results": results, "nlp_entities": nlp_data}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 ─ GITHUB README FETCHER  (NEW)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_github_readme(repo_url: str) -> dict:
    """
    Fetches ONLY the README.md from a public GitHub repository URL.

    Supports URL formats:
      https://github.com/owner/repo
      https://github.com/owner/repo/
      https://github.com/owner/repo/tree/main  (branch ignored, always fetches default)

    Steps:
      1. Parse owner/repo from the URL
      2. Try to fetch README.md via raw.githubusercontent.com
         (tries both main and master branches)
      3. Return the raw text content on success

    Constraints:
      - No authentication, no tokens
      - No recursive crawling — README.md only
      - Read-only HTTP GET
      - Graceful error handling

    Returns:
      { "success": True,  "text": "...", "url": "...", "error": None }
      { "success": False, "text": "",   "url": "",    "error": "reason" }
    """
    try:
        # ── Step 1: Parse owner/repo from URL ────────────────────────────────
        # Strip trailing slashes and split by /
        parts = repo_url.rstrip("/").replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return {"success": False, "text": "", "url": "",
                    "error": "Invalid GitHub URL. Expected: https://github.com/owner/repo"}

        owner = parts[0].strip()
        repo  = parts[1].strip()

        if not owner or not repo:
            return {"success": False, "text": "", "url": "",
                    "error": "Could not parse owner/repo from the provided URL."}

        # ── Step 2: Try main branch, then master ──────────────────────────────
        for branch in ["main", "master"]:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
            try:
                response = requests.get(raw_url, timeout=8)
                if response.status_code == 200:
                    return {
                        "success": True,
                        "text":    response.text,
                        "url":     raw_url,
                        "error":   None
                    }
            except requests.exceptions.Timeout:
                return {"success": False, "text": "", "url": "",
                        "error": "Request timed out. Check your internet connection."}
            except requests.exceptions.ConnectionError:
                return {"success": False, "text": "", "url": "",
                        "error": "Connection error. Check your internet connection."}

        # Neither branch had a README
        return {
            "success": False, "text": "", "url": "",
            "error": f"README.md not found in {owner}/{repo} (tried main and master branches)."
        }

    except Exception as e:
        return {"success": False, "text": "", "url": "", "error": str(e)}
