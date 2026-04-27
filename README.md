# 🎣 EdgeIQ Phishing Kit Detector

**Detect phishing kit artifacts, brand impersonation, and credential harvesting infrastructure.**

Analyzes live URLs or local HTML dumps to identify phishing kit clones, stolen branding, suspicious form actions, obfuscated JavaScript, and credential harvesting infrastructure.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Detects phishing kit artifacts by analyzing URL structure, HTML content, JavaScript behavior, and infrastructure fingerprints. Identifies brand impersonation, credential harvesting forms, and suspicious redirect chains.

> ⚠️ **Legal Notice:** Only analyze domains you own or have explicit written authorization to audit.

---

## Key Features

- **Phishing artifact detection** — form action URLs, hidden fields, autocomplete
- **Brand impersonation analysis** — detects copied logos, CSS frameworks, imagery
- **Infrastructure fingerprinting** — shared/free hosting, suspicious TLDs
- **JavaScript analysis** — credential harvesting scripts, keyloggers, redirects
- **Stolen branding detection** — fake trust seals, SSL badges
- **URL structure analysis** — phishing-specific path patterns
- **JSON export** — structured forensic report

---

## Prerequisites

- Python 3.8+
- `requests` library

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-phishing-kit-detector.git
cd edgeiq-phishing-kit-detector
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Scan a suspicious URL
python3 phishing_detector.py --url "https://suspicious-site.com/login"

# Scan a local HTML file
python3 phishing_detector.py --file ./phishing_page.html

# JSON forensic report
python3 phishing_detector.py --url "https://fake-bank.com/" --format json --output report.json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 5 scans/month, basic detection |
| **Lifetime** | $39 one-time | Unlimited scans, full JS analysis, brand detection |
| **Monthly** | $7/mo | All Lifetime features, billed monthly |

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-phishing-kit-detector/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
