import json
import datetime
import streamlit as st
import pandas as pd

from pii_backend import scan_text, fetch_github_readme, SPACY_AVAILABLE


st.set_page_config(
    page_title="PII Leakage Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
/* ── Global font & background ── */
html, body, [class*="css"] {
    font-family: 'Inter', 'Segoe UI', sans-serif;
    background-color: #0f1117;
    color: #e0e0e0;
}

/* ── Top banner / hero ── */
.hero-banner {
    background: linear-gradient(135deg, #1a1f2e 0%, #0d1b2a 60%, #0a2540 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 32px 36px 24px 36px;
    margin-bottom: 28px;
}
.hero-title {
    font-size: 2.1rem;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: -0.5px;
    margin: 0 0 6px 0;
}
.hero-subtitle {
    font-size: 0.95rem;
    color: #8eaacc;
    margin: 0;
    line-height: 1.6;
}
.hero-badge {
    display: inline-block;
    background: #0d3b66;
    color: #63b3ed;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    border: 1px solid #1e5a9c;
    margin-right: 6px;
    margin-top: 10px;
    letter-spacing: 0.4px;
    text-transform: uppercase;
}

/* ── Section headers ── */
.section-header {
    font-size: 1.05rem;
    font-weight: 700;
    color: #63b3ed;
    letter-spacing: 0.3px;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid #1e3a5f;
}

/* ── PII type color pills ── */
.pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.pill-email   { background:#0d3b66; color:#63b3ed; border:1px solid #1e5a9c; }
.pill-phone   { background:#064e3b; color:#6ee7b7; border:1px solid #065f46; }
.pill-aadhaar { background:#4c1d1d; color:#fca5a5; border:1px solid #7f1d1d; }
.pill-ssn     { background:#4c1d1d; color:#fca5a5; border:1px solid #7f1d1d; }
.pill-address { background:#312e81; color:#c4b5fd; border:1px solid #4338ca; }

/* ── Confidence badges ── */
.conf-high   { background:#052e16; color:#4ade80; border:1px solid #166534; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }
.conf-medium { background:#422006; color:#fbbf24; border:1px solid #92400e; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }
.conf-low    { background:#1c1917; color:#94a3b8; border:1px solid #374151; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }

/* ── Severity badges ── */
.sev-high   { background:#4c0519; color:#f87171; border:1px solid #991b1b; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }
.sev-medium { background:#422006; color:#fb923c; border:1px solid #92400e; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }
.sev-low    { background:#0c2340; color:#7dd3fc; border:1px solid #0369a1; padding:2px 8px; border-radius:8px; font-size:0.78rem; font-weight:700; }

/* ── Alert banners ── */
.alert-critical {
    background: linear-gradient(90deg, #4c0519, #1c0a0a);
    border: 1px solid #dc2626;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 14px 0;
    color: #fecaca;
    font-weight: 600;
    font-size: 0.95rem;
}
.alert-warn {
    background: linear-gradient(90deg, #422006, #1c1200);
    border: 1px solid #d97706;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 14px 0;
    color: #fde68a;
    font-weight: 500;
    font-size: 0.9rem;
}
.alert-safe {
    background: linear-gradient(90deg, #052e16, #021a0e);
    border: 1px solid #16a34a;
    border-left: 4px solid #22c55e;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 14px 0;
    color: #bbf7d0;
    font-weight: 500;
    font-size: 0.9rem;
}

/* ── Metric cards ── */
.metric-card {
    background: #1a1f2e;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 16px 12px;
    text-align: center;
    margin-bottom: 10px;
}
.metric-card .metric-val {
    font-size: 2rem;
    font-weight: 800;
    color: #63b3ed;
    line-height: 1.1;
}
.metric-card .metric-lbl {
    font-size: 0.75rem;
    color: #8eaacc;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 4px;
}

/* ── PII result table row ── */
.pii-row {
    background: #141824;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    display: flex;
    gap: 12px;
    align-items: flex-start;
    flex-wrap: wrap;
}
.pii-row:hover { border-color: #2d5a9e; }
.pii-value { font-family: monospace; font-size: 0.9rem; color: #e2e8f0; }
.pii-reason { font-size: 0.78rem; color: #64748b; margin-top: 4px; }

/* ── Insight cards ── */
.insight-card {
    background: #141824;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-size: 0.88rem;
    color: #cbd5e1;
    line-height: 1.6;
}

/* ── Source selector tabs look ── */
div[data-testid="stRadio"] > div { gap: 8px; }
div[data-testid="stRadio"] label {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 8px;
    padding: 6px 16px;
    font-size: 0.85rem;
    cursor: pointer;
    color: #a0aec0;
}

/* ── Inputs ── */
textarea, input[type="text"] {
    background: #141824 !important;
    border-color: #2d3748 !important;
    color: #e2e8f0 !important;
    border-radius: 8px !important;
    font-family: monospace !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #1d4ed8, #1e40af) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    padding: 10px 0 !important;
    letter-spacing: 0.3px !important;
    transition: opacity 0.2s;
}
.stButton > button:hover { opacity: 0.9 !important; }

/* ── Download buttons ── */
.stDownloadButton > button {
    background: #1e3a5f !important;
    color: #63b3ed !important;
    border: 1px solid #2d5a9e !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}

/* ── Expander ── */
details {
    background: #141824 !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 8px !important;
}
summary { color: #63b3ed !important; font-weight: 600 !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e3a5f;
}

/* ── Divider ── */
hr { border-color: #1e2d40 !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0f1117; }
::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🔒 PII Leakage Scanner")
    st.markdown("---")

    if SPACY_AVAILABLE:
        st.markdown("🟢 **spaCy NLP** — Active")
    else:
        st.markdown("🔴 **spaCy NLP** — Offline")
        st.caption("Run: `pip install spacy && python -m spacy download en_core_web_sm`")

    st.markdown("---")
    st.markdown("**Detects:**")
    st.markdown("""
- 📧 Email addresses
- 📱 Phone numbers
- 🆔 Aadhaar numbers
- 🇺🇸 SSN (US)
- 🏠 Physical addresses
    """)
    st.markdown("---")
    st.markdown("**Severity Scale:**")
    st.markdown("""
<span class="pill pill-aadhaar">🔴 High</span> Aadhaar · SSN  
<span class="pill pill-phone">🟡 Medium</span> Phone · Address  
<span class="pill pill-email">🔵 Low</span> Email  
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.caption("Ethical · Read-only · No external API calls")
    st.caption("Hackathon Prototype — v2.0")


# ─────────────────────────────────────────────────────────────────────────────
# HERO BANNER
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero-banner">
  <div class="hero-title">🔒 LeakShield : Automated PII Leakage Scanner</div>
  <div class="hero-subtitle">
    Detect personally identifiable information across public text, GitHub repositories,
    and simulated data sources. Context-aware confidence scoring powered by Regex + spaCy NER.
  </div>
  <span class="hero-badge">Regex Detection</span>
  <span class="hero-badge">spaCy NER</span>
  <span class="hero-badge">Context-Aware Confidence</span>
  <span class="hero-badge">Alert Reports</span>
  <span class="hero-badge">Digital Footprint</span>
  <span class="hero-badge">Export CSV/JSON</span>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SIMULATED PASTEBIN DATA
# ─────────────────────────────────────────────────────────────────────────────

PASTEBIN_SAMPLES = {
    "Paste #1 — Credential dump": (
        "username: johndoe | email: john.doe@example.com | phone: 9876543210\n"
        "username: janesmith | email: jane.smith@corp.org | phone: +91-98765-43210\n"
        "admin contact: support@helpdesk.in | hotline: 080-23456789"
    ),
    "Paste #2 — Identity data leak": (
        "Name: Robert Brown | Aadhaar: 3456 7890 1234 | DOB: 12/03/1990\n"
        "SSN: 123-45-6789 | Email: robert.brown@mail.com | Phone: +1 (800) 555-0199\n"
        "Address: 12, Greenwood Avenue, Banjara Hills"
    ),
    "Paste #3 — System log (false positive test)": (
        "ERROR [2024-01-15 10:23:45] Transaction failed. Error code: 9988776655\n"
        "Exception ref: 1122334455 at batch session. Request ID: 5566778899\n"
        "Contact support@helpdesk.in to resolve."
    ),
}

MANUAL_SAMPLES = {
    "Select a sample...": "",
    "All PII types — personal context (High confidence)": (
        "Dear John Doe, residing at 45B, MG Road, Jubilee Hills, Hyderabad. "
        "Email: john.doe@example.com | Phone: +91-9876543210 | "
        "Aadhaar: 2345 6789 0123 | SSN: 321-45-6789. "
        "Colleague Jane Smith: jane.smith@company.org | +1 (800) 555-0199."
    ),
    "Log / Error context — phones (Low confidence)": (
        "Error code: 9876543210 occurred during transaction processing. "
        "Exception ref: 080-23456789 at session batch ID 1234567. "
        "Contact support@helpdesk.in for status."
    ),
    "Mixed context — varied confidence": (
        "Dear Alice Johnson, account alert triggered. "
        "Error code 9988776655 logged at session start. "
        "Call Alice at +1 (800) 555-0199 or email alice@domain.com. "
        "Home: 12, Greenwood Avenue, Banjara Hills."
    ),
    "Aadhaar + SSN — government IDs": (
        "Identity verification for Robert Brown. "
        "Aadhaar: 3456 7890 1234. SSN: 123-45-6789 (US tax). "
        "Email: robert.brown@mail.com | Phone: +91-9988776655."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE SELECTOR + INPUT
# ─────────────────────────────────────────────────────────────────────────────

st.markdown('<div class="section-header">📡 DATA SOURCE</div>', unsafe_allow_html=True)

source_type = st.radio(
    "",
    ["Manual Text", "GitHub Repository", "Pastebin (Simulated)"],
    horizontal=True,
    label_visibility="collapsed"
)

input_text   = ""
source_label = "Manual"

if source_type == "Manual Text":
    source_label = "Manual"
    selected = st.selectbox("Quick sample:", list(MANUAL_SAMPLES.keys()), label_visibility="visible")
    input_text = st.text_area(
        "Paste text to scan:",
        value=MANUAL_SAMPLES[selected],
        height=150,
        placeholder="Paste any text — emails, logs, reports, messages...",
        label_visibility="visible"
    )

elif source_type == "GitHub Repository":
    source_label = "GitHub"
    st.info("ℹ️ Fetches **README.md only** from any public GitHub repository. No token required.")
    github_url = st.text_input(
        "Public GitHub repository URL:",
        placeholder="https://github.com/owner/repo"
    )
    if github_url:
        with st.spinner("Fetching README.md..."):
            result = fetch_github_readme(github_url)
        if result["success"]:
            st.success(f"✅ Fetched: `{result['url']}`")
            with st.expander("📄 README preview (first 1000 chars)"):
                st.code(result["text"][:1000] + ("..." if len(result["text"]) > 1000 else ""), language="markdown")
            input_text = result["text"]
        else:
            st.error(f"❌ {result['error']}")

elif source_type == "Pastebin (Simulated)":
    source_label = "Pastebin (Simulated)"
    st.warning("⚠️ **Simulated data** — No live Pastebin scraping (ethical constraint). Preset samples used.")
    selected_paste = st.selectbox("Select simulated paste:", list(PASTEBIN_SAMPLES.keys()))
    input_text = PASTEBIN_SAMPLES[selected_paste]
    st.text_area("Paste preview (read-only):", value=input_text, height=100, disabled=True)

st.markdown("<br>", unsafe_allow_html=True)
scan_clicked = st.button("🔍 Scan for PII Leakage", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# SCAN PIPELINE + RESULTS
# ─────────────────────────────────────────────────────────────────────────────

if scan_clicked:
    if not input_text.strip():
        st.error("⚠️ No text to scan. Please provide input above.")
        st.stop()

    with st.spinner("Running PII detection pipeline..."):
        output    = scan_text(input_text)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pii_items = output["pii_results"]
    nlp_data  = output["nlp_entities"]
    persons   = nlp_data.get("persons", [])
    locations = nlp_data.get("locations", [])

    high_conf  = [r for r in pii_items if r["confidence"] == "High"]
    med_conf   = [r for r in pii_items if r["confidence"] == "Medium"]
    low_conf   = [r for r in pii_items if r["confidence"] == "Low"]
    high_sev   = [r for r in pii_items if r["severity"]   == "High"]

    st.markdown("---")

    # ── ALERT BANNER ─────────────────────────────────────────────────────────

    st.markdown('<div class="section-header">🚨 ALERT STATUS</div>', unsafe_allow_html=True)

    if high_conf:
        st.markdown(f"""
        <div class="alert-critical">
        ⚠️ &nbsp;<strong>POTENTIAL PII LEAKAGE DETECTED — IMMEDIATE REVIEW RECOMMENDED</strong><br>
        <span style="font-weight:400; font-size:0.88rem;">
        {len(high_conf)} High-confidence PII item(s) detected
        {f"including {len(high_sev)} High-severity government ID(s) (Aadhaar/SSN)" if high_sev else ""}.
        Source: <strong>{source_label}</strong> &nbsp;|&nbsp; Scanned: <strong>{timestamp}</strong>
        </span>
        </div>
        """, unsafe_allow_html=True)
    elif pii_items:
        st.markdown(f"""
        <div class="alert-warn">
        🔔 &nbsp;<strong>PII Detected — Review Recommended</strong><br>
        <span style="font-weight:400; font-size:0.88rem;">
        {len(pii_items)} item(s) detected at Medium/Low confidence.
        Source: <strong>{source_label}</strong> &nbsp;|&nbsp; Scanned: <strong>{timestamp}</strong>
        </span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="alert-safe">
        ✅ &nbsp;<strong>No PII Detected</strong><br>
        <span style="font-weight:400; font-size:0.88rem;">
        The scanned text appears clean. Source: <strong>{source_label}</strong>
        </span>
        </div>
        """, unsafe_allow_html=True)

    # ── SUMMARY METRICS ───────────────────────────────────────────────────────

    if pii_items:
        st.markdown('<div class="section-header" style="margin-top:20px;">📊 RISK SUMMARY</div>', unsafe_allow_html=True)

        c1, c2, c3, c4, c5 = st.columns(5)
        def metric_card(col, val, label):
            col.markdown(f"""
            <div class="metric-card">
              <div class="metric-val">{val}</div>
              <div class="metric-lbl">{label}</div>
            </div>
            """, unsafe_allow_html=True)

        metric_card(c1, len(pii_items),  "Total PII")
        metric_card(c2, len(high_conf),  "🔴 High Conf.")
        metric_card(c3, len(med_conf),   "🟡 Medium Conf.")
        metric_card(c4, len(low_conf),   "⚪ Low Conf.")
        metric_card(c5, len(high_sev),   "🆔 Govt. IDs")

    # ── NLP CONTEXT ───────────────────────────────────────────────────────────

    with st.expander("🧠 NLP Context Analysis — spaCy Named Entity Recognition", expanded=bool(persons or locations)):
        nlp_col1, nlp_col2 = st.columns(2)
        with nlp_col1:
            st.markdown("**👤 PERSON entities detected:**")
            if persons:
                for p in persons:
                    st.markdown(f"&nbsp;&nbsp;`{p}`")
            else:
                st.markdown("_None detected_")
        with nlp_col2:
            st.markdown("**📍 LOCATION entities detected:**")
            if locations:
                for loc in locations:
                    st.markdown(f"&nbsp;&nbsp;`{loc}`")
            else:
                st.markdown("_None detected_")
        st.info(
            "**How NLP influences confidence:** A detected PERSON boosts phone/email/Aadhaar/SSN "
            "confidence to High. LOCATION + address keywords → High address confidence. "
            "No entities → confidence capped at Medium or Low."
        )

    # ── PII DETECTION TABLE ───────────────────────────────────────────────────

    if pii_items:
        st.markdown(f'<div class="section-header" style="margin-top:20px;">🛡️ DETECTED PII — {len(pii_items)} ITEM(S) &nbsp;|&nbsp; SOURCE: {source_label.upper()}</div>', unsafe_allow_html=True)

        PILL_MAP = {
            "Email":   "pill-email",
            "Phone":   "pill-phone",
            "Aadhaar": "pill-aadhaar",
            "SSN":     "pill-ssn",
            "Address": "pill-address",
        }
        CONF_MAP = {"High": "conf-high", "Medium": "conf-medium", "Low": "conf-low"}
        SEV_MAP  = {"High": "sev-high",  "Medium": "sev-medium",  "Low": "sev-low"}

        for item in pii_items:
            type_cls = PILL_MAP.get(item["type"], "pill-email")
            conf_cls = CONF_MAP.get(item["confidence"], "conf-low")
            sev_cls  = SEV_MAP.get(item["severity"],    "sev-low")
            st.markdown(f"""
            <div class="pii-row">
              <span class="pill {type_cls}">{item["type"]}</span>
              <div style="flex:1; min-width:180px;">
                <div class="pii-value">{item["value"]}</div>
                <div class="pii-reason">ℹ️ {item["reason"]}</div>
              </div>
              <span class="pill {conf_cls}">Conf: {item["confidence"]}</span>
              <span class="pill {sev_cls}">Sev: {item["severity"]}</span>
            </div>
            """, unsafe_allow_html=True)

        # Per-type counts row
        st.markdown("<br>", unsafe_allow_html=True)
        t1, t2, t3, t4, t5 = st.columns(5)
        for col, ptype in zip([t1, t2, t3, t4, t5],
                               ["Email", "Phone", "Aadhaar", "SSN", "Address"]):
            count = sum(1 for r in pii_items if r["type"] == ptype)
            col.markdown(f"""
            <div class="metric-card">
              <div class="metric-val" style="font-size:1.5rem;">{count}</div>
              <div class="metric-lbl">{ptype}</div>
            </div>
            """, unsafe_allow_html=True)

    # ── DIGITAL FOOTPRINT ANALYSIS ────────────────────────────────────────────

    if pii_items:
        import re
        st.markdown('<div class="section-header" style="margin-top:20px;">🌐 DIGITAL FOOTPRINT ANALYSIS</div>', unsafe_allow_html=True)

        insights = []

        if persons:
            insights.append(
                f"👤 <strong>{len(persons)} named individual(s)</strong> detected: "
                + ", ".join(f"<code>{p}</code>" for p in persons)
                + ". Multiple identifiers linked to one person significantly amplify exposure risk."
            )

        emails = [r["value"] for r in pii_items if r["type"] == "Email"]
        if emails:
            domains = {}
            for e in emails:
                d = e.split("@")[-1] if "@" in e else "unknown"
                domains[d] = domains.get(d, 0) + 1
            domain_str = ", ".join(
                f"<code>{d}</code> ({c} address{'es' if c > 1 else ''})"
                for d, c in domains.items()
            )
            insights.append(
                f"📧 <strong>Email domains:</strong> {domain_str}. "
                "Corporate domain addresses carry elevated organisational breach risk."
            )

        phones = [r["value"] for r in pii_items if r["type"] == "Phone"]
        if phones:
            codes = {}
            for ph in phones:
                if ph.startswith("+91"):   code = "+91 (India)"
                elif ph.startswith("+1"):  code = "+1 (US/Canada)"
                elif ph.startswith("+"):   code = ph[:3] + " (International)"
                else:                      code = "Local / unspecified"
                codes[code] = codes.get(code, 0) + 1
            code_str = ", ".join(f"<code>{c}</code> ×{n}" for c, n in codes.items())
            insights.append(
                f"📱 <strong>Phone country codes:</strong> {code_str}. "
                "Cross-border exposure triggers multi-jurisdiction compliance obligations (GDPR, DPDP Act)."
            )

        aadhaars = [r for r in pii_items if r["type"] == "Aadhaar"]
        ssns     = [r for r in pii_items if r["type"] == "SSN"]
        if aadhaars or ssns:
            gov_ids = []
            if aadhaars: gov_ids.append(f"{len(aadhaars)} Aadhaar number(s)")
            if ssns:     gov_ids.append(f"{len(ssns)} SSN(s)")
            insights.append(
                f"🆔 <strong>Government-issued IDs:</strong> {' and '.join(gov_ids)} detected. "
                "Exposure of national identity numbers constitutes a <strong>Critical-level data breach</strong> "
                "under DPDP Act 2023 and US Privacy laws."
            )

        addresses = [r for r in pii_items if r["type"] == "Address"]
        if addresses:
            insights.append(
                f"🏠 <strong>{len(addresses)} physical address(es)</strong> detected. "
                "Location data combined with identity information enables real-world targeting and stalking."
            )

        pii_types_found = {r["type"] for r in pii_items}
        if len(pii_types_found) >= 3:
            insights.append(
                f"⚡ <strong>Combined PII risk:</strong> {len(pii_types_found)} distinct PII types found "
                f"({', '.join(sorted(pii_types_found))}). "
                "Aggregated PII dramatically increases identity theft, fraud, and social engineering risk."
            )

        for ins in insights:
            st.markdown(f'<div class="insight-card">{ins}</div>', unsafe_allow_html=True)

        if not insights:
            st.markdown('<div class="insight-card">No significant footprint patterns identified.</div>', unsafe_allow_html=True)

    # ── EXPORT ────────────────────────────────────────────────────────────────

    if pii_items:
        st.markdown('<div class="section-header" style="margin-top:20px;">📥 EXPORT CLASSIFICATION REPORT</div>', unsafe_allow_html=True)

        export_rows = [{
            "Source":     source_label,
            "Timestamp":  timestamp,
            "Type":       r["type"],
            "Value":      r["value"],
            "Confidence": r["confidence"],
            "Severity":   r["severity"],
            "Reason":     r["reason"],
        } for r in pii_items]

        export_df  = pd.DataFrame(export_rows)
        ts_safe    = timestamp.replace(" ", "_").replace(":", "-")
        csv_data   = export_df.to_csv(index=False).encode("utf-8")
        json_data  = json.dumps(export_rows, indent=2).encode("utf-8")

        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                "⬇️ Download CSV Report",
                data=csv_data,
                file_name=f"pii_report_{ts_safe}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with dl2:
            st.download_button(
                "⬇️ Download JSON Report",
                data=json_data,
                file_name=f"pii_report_{ts_safe}.json",
                mime="application/json",
                use_container_width=True
            )
        st.caption(f"Report timestamp: `{timestamp}` &nbsp;|&nbsp; Source: `{source_label}` &nbsp;|&nbsp; {len(pii_items)} PII items")

    
    

# ── FOOTER ────────────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown(
    '<div style="text-align:center; color:#4a5568; font-size:0.78rem; padding:8px 0;">'
    '🔒 Automated PII Leakage Scanner &nbsp;|&nbsp; Hackathon Prototype v2.0 &nbsp;|&nbsp; '
    'Ethical · Read-only · Explainable'
    '</div>',
    unsafe_allow_html=True
)
