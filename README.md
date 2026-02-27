# 🔍 Automated PII Leakage Scanner (LeakShield)

An AI-powered system that detects and classifies exposed Personally Identifiable Information (PII) from publicly available text using Regex and Natural Language Processing (NLP).

---

## 📌 Problem Statement

Sensitive personal information such as phone numbers, email addresses, Aadhaar numbers, and physical addresses are frequently exposed on public platforms like GitHub repositories, paste sites, and forums. These leaks can lead to identity theft, fraud, and privacy violations.

Manual detection is impractical at scale, and simple pattern-based tools often generate false positives without understanding context.

---

## 💡 Solution Overview

LeakShield is an **automated, context-aware PII leakage scanner** that:

1. Collects publicly available text (manual input or GitHub repository README)
2. Detects potential PII using **Regex**
3. Uses **NLP (spaCy NER)** to understand contextual clues (e.g., PERSON, LOCATION)
4. Assigns **confidence levels** (Low / Medium / High)
5. Classifies **risk severity**
6. Generates a clear, explainable detection report

The system is **read-only**, ethical, and does **not verify, store, or track identities**.

---

## 🚀 Key Features

- ✅ Detects multiple PII types:
  - Email addresses
  - Phone numbers
  - Aadhaar numbers
  - SSN (US)
  - Physical addresses
- 🧠 Context-aware confidence scoring using NLP
- 🛡️ Severity-based risk classification
- 🌐 GitHub repository README scanning (safe, read-only)
- 📊 Interactive Streamlit frontend
- 📖 Explainable output (reason for each detection)

---

## 🧠 How It Works (Architecture)

**Layer 1 — Regex Detection**  
Identifies PII patterns using optimized regular expressions.

**Layer 2 — NLP Context (spaCy)**  
Extracts PERSON and LOCATION entities to validate whether detected data is likely personal.

**Layer 3 — Confidence Scoring**  
Adjusts confidence based on:
- Presence of PERSON/LOCATION entities
- Log/system context (e.g., error codes)
- Keyword-based contextual validation

**Layer 4 — Severity Classification**  
Assigns risk level based on PII sensitivity.

---

## 🧪 Example Use Cases

- Detect accidental Aadhaar leakage in public GitHub READMEs
- Identify phone numbers exposed in logs or documentation
- Reduce false positives from numeric IDs or error codes
- Demonstrate PII risk assessment in cybersecurity workflows

---

## 🖥️ Tech Stack

- **Backend**: Python
- **NLP**: spaCy (`en_core_web_sm`)
- **Detection**: Regex
- **Frontend**: Streamlit
- **Data Fetching**: Requests (GitHub raw content)

---

## 📦 Installation & Setup

```bash
# Clone repository
git clone <your-repo-url>
cd LeakShield

# Create and activate virtual environment
python3.11 -m venv pii-env
source pii-env/bin/activate   # macOS/Linux
# pii-env\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Download NLP model
python -m spacy download en_core_web_sm

# Run the app
streamlit run app.py
