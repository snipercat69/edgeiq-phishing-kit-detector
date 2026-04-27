# Phishing Kit Detector — CLI Setup

Detect phishing kit artifacts, brand impersonation, form action URLs, stolen CSS/images, and suspicious page structure. Analyze live phishing pages or offline phishing kit dumps.

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-phishing-kit-detector.git
cd edgeiq-phishing-kit-detector
```

## Quick Start

```bash
# Analyze a suspected phishing URL
python3 phishing_detector.py --url "https://fake-paypal-login.com"

# Analyze local phishing page (HTML dump)
python3 phishing_detector.py --file /path/to/phishing_page.html --pro

# Deep scan with brand impersonation check
python3 phishing_detector.py --url "https://fake-amazon.com" --brands paypal,amazon,apple --pro

# Full analysis + JSON report
python3 phishing_detector.py --url "https://phishing-site.net" --bundle --output report.json
```

## Features

- **Phishing kit artifact detection** — form action URLs, credential capture endpoints, fake login fields
- **Brand impersonation analysis** — detects use of brand logos, CSS, and imagery
- **Infrastructure fingerprinting** — shared hosting patterns, free hosting providers, suspicious TLDs
- **JavaScript analysis** — credential harvesting scripts, redirect chains, keyloggers
- **Stolen branding elements** — detects references to legitimate brand assets
- **URL structure analysis** — path patterns common in phishing kits

## ⚠️ Legal Notice

- Only analyze domains you own or have explicit written authorization to audit
- Not for unauthorized reconnaissance of third-party sites

## Licensing

Free tier: 5 URL/file scans.

Pro ($19/mo) or Bundle ($39/mo): [buy.stripe.com/aFa00l9i3bxrcUs18c7wA0k](https://buy.stripe.com/aFa00l9i3bxrcUs18c7wA0k)