# PhishShield Datasets & Provenance Documentation

Verified on: **October 10, 2026**

---

## 1. Primary Datasets Used for URL Model Training

### 1. Tranco Top Sites List
- **Source:** https://tranco-list.eu/top-1m.csv.zip
- **License / Terms:** Research use / Open public research ranking.
- **Role:** Legitimate web traffic baseline.
- **Preprocessing:** Top 3,000 domains were sampled. To avoid synthetic path bias (where models associate the mere presence of a path with phishing), a balanced mix of bare homepages and realistic legitimate paths (`/about`, `/contact`, `/services`, `/login`, `/privacy`) were constructed.

### 2. URLhaus Active Malicious Feed
- **Source:** abuse.ch URLhaus (https://urlhaus.abuse.ch/downloads/csv_online/)
- **License / Terms:** Creative Commons CC0 / abuse.ch Open Threat Intelligence.
- **Role:** Active real-world malicious and malware distribution URLs.
- **Count:** 2,500 active URLs sampled and normalized.

### 3. OpenPhish Community Phishing Feed
- **Source:** OpenPhish (https://openphish.com/feed.txt)
- **License / Terms:** Free for non-commercial / research use.
- **Role:** Live verified phishing URLs collected from honeypots.
- **Count:** 300 active URLs sampled and normalized.

### 4. Hard-Negative Legitimate Login Set
- **Source:** Curated in-house from `data/reference/brand_domains.csv`.
- **Role:** Realistic login, portal, verification, and KYC paths (`/login`, `/auth/signin`, `/netbanking`, `/personal-banking/login`) for official banks (SBI, HDFC, ICICI), global platforms (Google, Microsoft, Amazon), and Indian government portals (UIDAI Aadhaar, Income Tax).
- **Purpose:** Prevents lexical tokens like "login" or "verify" from triggering false positives on official brand domains.

### 5. Targeted Synthetic Kit-Like Phishing Patterns
- **Role:** Generates coverage of modern deceptive patterns:
  - Tunnel hosts with brand subdomains (`sbi-secure.trycloudflare.com`, `hdfc-login.loca.lt`)
  - Packed decimal and hex IP addresses (`http://3232235777/`)
  - Userinfo tricks (`http://sbi.co.in@evil.xyz/`)
  - IDN Punycode homographs (`https://xn--instgram-e1a.com/`)

---

## 2. Dataset Quality Summary (`reports/data_quality.json`)

- **Total Cleaned Unique Records:** 6,316 URLs
- **Legitimate Count:** 3,424
- **Phishing Count:** 2,892
- **Class Balance:** 45.8% Phishing / 54.2% Legitimate
- **Unique Registrable Domains:** > 3,500
- **Missing Feature Values:** 0 (all 43 features strictly computed)

---

## 3. Reference Datasets

- `data/reference/brand_domains.csv`: 45+ verified brands across banking, payments, social media, government, e-commerce, and telecom with official registrable domains.
- `data/reference/tunnel_hosts.csv`: 30+ verified tunnel, free-tier, and serverless hosting suffixes (Cloudflare Tunnels, Localhost.run, Serveo, Ngrok, Pages.dev, Workers.dev).
- `data/reference/sms_sender_reference.csv`: Verified Indian TRAI DLT alphanumeric header registrations (HDFCBK, SBIINB, ICICIB, AMAZON, AADHAR, ITDEFL).
- `data/reference/apk_rules.yaml`: Static APK rule configuration.
