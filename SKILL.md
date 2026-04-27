# Phishing Kit Detector

**Skill Name:** `phishing-kit-detector`
**Version:** `1.0.0`
**Category:** Security / Phishing / OSINT
**Price:** **Lifetime: $39** / Optional Monthly: $7/mo (includes all Pro features permanently)
**Author:** EdgeIQ Labs
**OpenClaw Compatible:** Yes — Python 3, pure stdlib, WSL + Linux

---

## What It Does

Detects phishing kit artifacts, brand impersonation, form action URLs, stolen branding, suspicious JavaScript, and credential harvesting infrastructure. Analyzes live URLs or local HTML dumps to determine if a page is a phishing kit clone.

> ⚠️ **Legal Notice:** Only analyze domains you own or have explicit written authorization to audit. Not for unauthorized scanning of third-party sites.

---

## Features

- **Phishing artifact detection** — form action URLs pointing to credential capture endpoints, hidden fields, credential autocomplete
- **Brand impersonation analysis** — detects brand logos, CSS frameworks, and imagery copied from legitimate sites
- **Infrastructure fingerprinting** — shared/free hosting detection, suspicious TLDs, URL path patterns
- **JavaScript analysis** — credential harvesting scripts, redirect chains, keyloggers, obfuscated callbacks
- **Stolen branding detection** — references to legitimate brand assets, fake SSL badges, trust seals
- **URL structure analysis** — phishing-specific URL path patterns (login, account, verify, secure)
- **JSON export** — structured forensic report

---

## Tier Comparison

| Feature | Free | **Lifetime ($39)** | Optional Monthly ($7/mo) |
|---------|------|----------------|----------------------|
| URL scan | ✅ (5 scans) | ✅ (unlimited) | ✅ (unlimited) |
| Local file scan | ✅ | ✅ | ✅ |
| Brand impersonation check | ✅ | ✅ | ✅ |
| JS analysis | ✅ | ✅ | ✅ |
| Infrastructure fingerprinting | ✅ | ✅ | ✅ |
| Stolen branding detection | ✅ | ✅ | ✅ |
| JSON export | ✅ | ✅ | ✅ |

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/phishing-kit-detector ~/.openclaw/skills/phishing-kit-detector
```

---

## Usage

### Basic URL scan (free tier)

```bash
python3 phishing_detector.py --url "https://suspicious-site.com/login"
```

### Local HTML file scan (Pro)

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 phishing_detector.py \
  --file /path/to/phishing_page.html --pro
```

### Brand impersonation check (Pro)

```bash
python3 phishing_detector.py --url "https://fake-paypal.com" \
  --brands paypal,amazon,apple --pro
```

### Full bundle analysis + JSON export

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 phishing_detector.py \
  --url "https://phishing-site.net" --bundle --output report.json
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | string | — | Phishing URL to analyze |
| `--file` | string | — | Path to local HTML file |
| `--brands` | string | — | Comma-separated brand list (paypal,amazon,apple,google,microsoft,facebook,instagram,twitter,netflix,linkedin) |
| `--pro` | flag | False | Enable Pro features |
| `--bundle` | flag | False | Enable Bundle features |
| `--output` | string | — | Write JSON report to file |

---

## Brand List

Supported brands for impersonation detection:
`paypal` · `amazon` · `apple` · `google` · `microsoft` · `facebook` · `instagram` · `twitter` · `netflix` · `linkedin` · `ebay` · `salesforce` · `dropbox` · `slack` · `zoom` · `steam` · `epic games` · `steam` · `yahoo` · `cnn` · `chase` · `bank of america` · `wells fargo` · `capital one`

---

## Output Example

```
=== Phishing Kit Detector ===
Analyzing: https://fake-paypal.com/account/verify

  🔴 PHISHING KIT DETECTED (98% confidence)
  
  Artifact Analysis:
    Form action → credential harvest endpoint detected
    Hidden field → password re-entry field (credential capture)
    Credential autocomplete → enabled on sensitive fields
    Multiple forms → login + payment + PIN entry

  Brand Impersonation:
    Detected: PayPal (logo, CSS framework, brand colors)
    Stolen assets: 3 CSS files, 2 images from paypal.com
    Fake SSL badge detected

  Infrastructure:
    Free hosting provider detected (Freenom .tk domain)
    Suspicious TLD: .tk — commonly used in phishing
    Redirect chain: 2 hops before landing page
    Shared hosting IP — multiple malicious sites on same IP

  JavaScript Findings:
    Credential harvester script detected
    Keylogger injection found
    Redirect to: paypal.com.legit-site.ru

  Threat Level: CRITICAL — Sophisticated phishing kit with credential harvesting + keylogger
```

---

## Pro Upgrade

Full phishing kit analysis + brand impersonation + JS analysis + infrastructure fingerprinting:

👉 [Buy Lifetime — $39](https://buy.stripe.com/9B6fZjdyjfNH1bK8AE7wA0Y)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/00w00l1PBbxr5s04ko7wA18)

---

## Support

Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com)

---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
