# 🛡️ Centinela — Automated Web Security & Legitimacy Analyzer

[![Version](https://img.shields.io/badge/version-2.4.0-blue.svg?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg?style=flat-square)](#)
[![Security: SSRF Hardened](https://img.shields.io/badge/Security-SSRF%20Hardened-cyan.svg?style=flat-square)](#)
[![Zero Synthetic Data](https://img.shields.io/badge/Data%20Policy-100%25%20Live%20Dynamic%20Data-purple.svg?style=flat-square)](#)

**Centinela** is an independent, automated cybersecurity assessment platform engineered to audit the security posture, cryptography, infrastructure, and legal legitimacy of any website or domain.

👉 **Live Platform**: [https://centinela.azagra.dev](https://centinela.azagra.dev)

---

## 🎯 Core Objectives

Centinela evaluates two fundamental security vectors for any domain:

> 1. **⚙️ Technical Security Posture**: How hardened and compliant are the site's cryptographic ciphers, transport layers, DNS records, HTTP security headers, cookies, and email defenses?
> 2. **🏛️ Domain Legitimacy & Trust**: What independent cryptographic and public registry evidence proves that this domain is genuine, established, and legally authenticated rather than an unauthenticated proxy or impersonation attack?

```text
⚠️ Cybersecurity Axiom:
🔒 HTTPS ≠ Safe
📜 Valid DV Certificate ≠ Legitimate Company
🧹 No Malware Detected ≠ Trusted Domain
🛠️ Good Technical Security ≠ Genuine Identity
```

---

## 🔍 Domain Security & Legitimacy Audit (What Tests Are Performed)

When you query a domain, Centinela executes parallel, non-intrusive security audits across ten specialized cybersecurity vectors:

```
                      [ User Input: Domain / URL ]
                                   │
       ┌───────────────────────────┴───────────────────────────┐
       ▼                                                       ▼
⚙️ Technical Posture Audits                             🏛️ Legitimacy & PKI Evidence
 ├── 1. TLS/SSL & Cipher Suites                          ├── 7. Domain Age & RDAP Lifecycle
 ├── 2. DNS Infrastructure & DNSSEC                      ├── 8. Tech Fingerprinting & CVEs
 ├── 3. HTTP Security Headers & CSP                      ├── 9. Dynamic PKI & Legal Identity
 ├── 4. Cookie Scope & Attributes                        └── 10. Redirect Flow & Subdomains
 ├── 5. Email Defenses (SPF/DMARC)
 └── 6. Threat Intel & Blocklists
```

---

### 🔒 1. Transport Layer Security & TLS / SSL Deep Inspection
* **📜 Live Certificate Lifecycle Tracking**:
  * 🏢 **Issuing Authority**: Direct extraction of the issuing CA (Google Trust Services, DigiCert, Apple Inc., Let's Encrypt, Sectigo, etc.).
  * ⏳ **Validity Window**: Live socket extraction of issuance (`notBefore`) and expiration (`notAfter`) timestamps with countdown of remaining days.
* **🔐 Protocol Compliance**:
  * ✅ **TLS 1.3 & TLS 1.2**: Modern cryptographic transport protocol verification.
  * 🚫 **Legacy Protocols**: Detects and flags obsolete protocols (**TLS 1.0**, **TLS 1.1**, **SSLv3**).
* **🛡️ Cipher Suites & Cryptographic Hardening**:
  * 🔄 **Perfect Forward Secrecy (PFS)**: Ephemeral key exchange (ECDHE/DHE) auditing.
  * 🔑 **Key Algorithm & Length**: RSA (>= 2048-bit) and ECDSA curve validation.
  * 🩻 **Vulnerability Auditing**: Checks immunity against historic cryptographic attacks (**Heartbleed** CVE-2014-0160, **POODLE**, **FREAK**).

---

### 🌐 2. DNS Infrastructure, DNSSEC & Secure SNI (ECH)
* **📋 Authoritative Record Resolution**:
  * 📍 **`A` & `AAAA` Records**: IPv4 and IPv6 dual-stack readiness mapping.
  * 🔀 **`CNAME` & `SOA`**: Canonical aliasing and zone authority details.
  * 📬 **`MX` Records**: Mail exchange routing validation.
  * 🏷️ **`TXT` Records**: Verification tokens and policy records.
  * 🔐 **`HTTPS` (Type 65 / RFC 9460)**: Audits published ECH configurations and ALPN parameters for Encrypted Client Hello.
* **🔐 DNSSEC Signature Chain**:
  * 🔗 **`DS` & `DNSKEY` Verification**: Validates parent TLD delegation signer records and cryptographic integrity (`AD` flag).
* **🛡️ Certificate Authority Authorization (CAA)**:
  * 📜 Audits CAA policies to prevent unauthorized certificate issuance.

---

### 🛡️ 3. HTTP Security Headers & Content Security Policy (CSP)
* **🔒 Strict-Transport-Security (HSTS)**:
  * Verifies `max-age` directives (recommending >= 31,536,000s / 1 year), `includeSubDomains`, and `preload` readiness.
* **🛡️ Content Security Policy (CSP) Deep Evaluator**:
  * 🚫 `unsafe-inline`: Flags inline script injection risks.
  * 🚫 `unsafe-eval`: Flags string-to-code execution risks.
  * 🌐 Wildcard (`*`) source origins detection.
  * 📦 Directive coverage (`default-src`, `script-src`, `frame-ancestors`).
* **🖼️ Anti-Clickjacking (X-Frame-Options)**: Validates `DENY` or `SAMEORIGIN` framing policies.
* **🎭 MIME-Sniffing Defense (X-Content-Type-Options)**: Confirms `nosniff` enforcement.
* **👁️ Privacy Policies**: `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`, and `COEP`.

---

### 🍪 4. Cookie Security & Scope Auditing
* 🔒 **`Secure` Flag**: Enforces HTTPS-only transmission.
* 🛡️ **`HttpOnly` Flag**: Blocks client-side JavaScript access to prevent session hijacking via XSS.
* 🚪 **`SameSite` Attribute**: Audits `Strict` and `Lax` policies against CSRF.
* 🏷️ **Security Prefixes**: Verifies `__Secure-` and `__Host-` prefix compliance.

---

### 📧 5. Email Authentication & Anti-Spoofing Defenses
* 📜 **SPF (Sender Policy Framework)**: Parses `v=spf1` TXT records and authorized sending IPs.
* 📬 **DMARC**: Evaluates policy enforcement:
  * 🔴 `p=none` *(Permissive / Monitoring only)*.
  * 🟡 `p=quarantine` *(Moderate — routes spoofed mail to spam)*.
  * 🟢 `p=reject` *(Strongest — blocks unauthorized mail)*.
* 🔐 **MTA-STS & TLS-RPT**: SMTP transport encryption policies and reporting.

---

### ☣️ 6. Threat Intelligence & Real-Time Blocklists
* 🪱 **URLhaus (Abuse.ch)**: Active malware payload distribution tracking.
* 🤖 **ThreatFox (Abuse.ch)**: Botnet Command & Control (C2) IOC tracking.
* 🚫 **Spamhaus DBL**: Global spam, phishing, and malware domain blocklists.
* 🎣 **OpenPhish / Community Feeds**: Active credential harvesting feeds.
* 🔍 **Google Safe Browsing v4**: Enterprise detection (selective opt-in checkbox).
* 🛡️ **VirusTotal v3**: Multi-engine antivirus scanning (selective opt-in checkbox).

---

### 📅 7. Domain Age & RDAP Lifecycle Intelligence
* ⏳ **Domain Age Calculation**: Exact live calculation in days and years from official ICANN/RDAP registration events.
* ⚠️ **Recent Domain Risk Indicator**: Flags domains registered less than 30 days ago.
* 🏢 **Registrar & Status**: Identifies the sponsoring registrar and operational status.

---

### 🐛 8. Technology Fingerprinting & Known CVE Auditing
* 🏷️ **Technology Discovery**: Passive identification from HTTP response banners and server headers.
* 🚨 **Known CVE Matching**: Correlates disclosed software versions against public Common Vulnerabilities and Exposures (CVE) databases with CVSS scoring and remediation advice.

---

### 🏛️ 9. Domain Legitimacy & Legal Identity Audit (100% Dynamic PKI)
* **📜 PKI Identity Verification (OV/EV Certificates)**:
  * Inspects X.509 Subject Organization attributes (`O=`) issued by audited Certificate Authorities.
* **📧 BIMI & VMC Protocol**:
  * Audits DNS `default._bimi.<domain>` records for Verified Mark Certificates.
* **🔗 DNS Authority & Infrastructure**:
  * Evaluates self-authoritative nameservers, dedicated root CAs, and longevity.
* **🎭 Heuristic Anti-Impersonation**:
  * Detects brand name spoofing and phishing keywords (`login`, `secure`, `verify`, `bank`).
* **🛑 Confidence Ceilings**:
  * Applies mathematical confidence caps (e.g. 90/100 for anonymous DV certificates).

---

### 🔀 10. Hop-by-Hop Redirect Flow & Passive Subdomains
* 🧭 **Redirect Chain Flowchart**: Traces each hop with HTTP status codes (`301`, `302`, `307`, `308`, `200`), response latency, destination URLs, and loop detection.
* 🌐 **Passive Subdomain Discovery**: Discovers indexed subdomains from Certificate Transparency (CT) logs (`crt.sh`).

---

## 📊 Results, Scoring & Trust Classification (What Output You Obtain)

Every assessment generates a structured diagnostic report with actionable insights, numerical scoring, and trust certifications:

### 1. Executive Tri-Metric Summary

| Metric | Score Range | Description |
| :--- | :---: | :--- |
| **⚙️ Technical Security** | `0 – 100` | Mathematical evaluation of TLS, DNS, HTTP Headers, CSP, Cookies, and Email defenses. |
| **🏛️ Legitimacy Evidence** | `0 – 100` | Evidence-based score evaluating domain age, PKI organizational identity, and threat history. |
| **🌐 Global Trust Level** | Category | Synthesis classification: `VERY HIGH`, `HIGH`, `MODERATE`, `LOW`, or `CRITICAL RISK`. |

---

### 2. Trust Seals Matrix

| Seal | Badge | Meaning |
| :--- | :---: | :--- |
| 🟢 **★ VERIFIED LEGITIMATE** | `VERIFIED` | Cryptographically verified legal organization (OV/EV, BIMI) with strong technical posture. |
| 🔵 **SAFE** | `SAFE` | Solid technical posture with zero threat blocklist detections (Standard DV). |
| 🟡 **CAUTION** | `CAUTION` | Moderate configuration weaknesses, permissive policies, or newly created domain (<30d). |
| 🟠 **SUSPICIOUS** | `SUSPICIOUS` | High risk profile, multiple misconfigurations, or potential brand impersonation. |
| 🔴 **DANGEROUS** | `DANGEROUS` | Active threat detection: malware distribution, phishing, or blacklisted infrastructure. |

---

### 3. Unique Scan IDs & Historical Comparison
* **Unique Scan ID**: Every audit generates a permanent identifier (e.g. `cnt-6a9154b7-e8fed5`).
* **Shareable Permalinks**: Direct links (`https://centinela.azagra.dev/?id=cnt-...`) allow 1-click sharing of exact point-in-time assessments.
* **Historical Evolution Engine**: Re-scanning a domain automatically compares the new results with past scans, highlighting score improvements (`+15 pts Improvement`), category score deltas, and resolved security findings.

---

### 4. Zero-Trust Backend Architecture
* **🛑 Anti-SSRF & DNS Rebinding Guard**: All target hostnames and redirect hops are validated against comprehensive private subnet filters (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, RFC 6598 `100.64.0.0/10`, loopbacks `127.0.0.0/8`, link-local `169.254.0.0/16`, and IPv6 `fc00::/7`).
* **⚖️ 100% Live Dynamic Data Policy**: Zero synthetic or mock data in production. Every metric is computed in real time from authoritative registries and direct protocol handshakes.
* **📐 Fully Explainable Scoring**: Every point added or deducted is accompanied by technical evidence, security impact, and recommendations.

---

## 🖥️ Client Browser Security Diagnostics (Your Connection Privacy)

In addition to auditing remote domains, Centinela includes a real-time **Client Browser & Connection Diagnostics Engine** to audit the visitor's local connection privacy and cryptographic transport:

* 🛡️ **DNSSEC Validation**: Verifies whether your DNS resolver enforces cryptographic signature validation (`DS` / `DNSKEY` with `AD` Authenticated Data bit) to prevent DNS spoofing and cache poisoning.
* 🔒 **Secure DNS (DoH / DoT)**: Detects whether your browser/operating system transmits DNS queries via encrypted **DNS-over-HTTPS (RFC 8484)**, shielding browsing destinations from ISP inspection and wiretapping.
* ⚡ **TLS 1.3 Protocol Engine**: Audits whether your client browser supports the modern **TLS 1.3** transport protocol with Perfect Forward Secrecy (PFS).
* 🔐 **Secure SNI / Encrypted Client Hello (ECH RFC 9460)**: Verifies if your browser negotiates encrypted Server Name Indication (`sni=encrypted`) to conceal target domain names from on-path network observers.

---

### 🧪 Terminal Verification & Local Diagnostic Commands

You can verify your connection's cryptography, DoH capabilities, DNSSEC enforcement, and ECH support directly from your terminal using standard tools:

#### 1. 🔍 Test ECH (Encrypted Client Hello) Type 65 DNS Records
To verify if your DoH resolver delivers modern **DNS Type 65 (`HTTPS`)** records with the public ECH key (`ech=...`):

```bash
curl -s -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=crypto.cloudflare.com&type=HTTPS" | jq .
```

**Expected Response**:
```json
{
  "Status": 0,
  "AD": true,
  "Answer": [
    {
      "name": "crypto.cloudflare.com",
      "type": 65,
      "TTL": 300,
      "data": "1 . alpn=h2 ipv4hint=162.159.135.79,162.159.136.79 ech=AEX+DQBBVgAg... ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f"
    }
  ]
}
```
* **`"AD": true`**: Authenticates that DNSSEC validation succeeded.
* **`"type": 65`**: Delivers the RFC 9460 HTTPS record.
* **`ech=AEX+...`**: Delivers the public encryption key required by the browser to encrypt the SNI.

---

#### 2. 📡 Inspect Live Cloudflare Cryptographic Telemetry
Check your current client TLS protocol and SNI encryption status:

```bash
curl -s "https://crypto.cloudflare.com/cdn-cgi/trace"
```

Look for the following keys in the output:
```text
tls=TLSv1.3        # Modern transport protocol active
sni=encrypted      # ECH active (or 'sni=plaintext' if standard)
warp=off           # Cloudflare WARP status
```

---

#### 3. 🛡️ Test DNSSEC Signature Verification
Verify if recursive resolvers return the Authenticated Data (`AD`) flag for DNSSEC-signed zones:

```bash
curl -s -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A&do=true" | jq '{Status: .Status, AD: .AD, IP: .Answer[0].data}'
```

---

### ⚙️ Browser Configuration & Troubleshooting Guide

#### 🚀 Enabling DoH and ECH (Encrypted Client Hello)

**In Google Chrome / Brave / Microsoft Edge:**
1. Navigate to `chrome://settings/security` (or *Settings > Privacy and Security > Security*).
2. Enable **"Use secure DNS"** (*Usar DNS seguro*).
3. Select **Cloudflare (1.1.1.1)** or **Google (Public DNS)**.
4. Navigate to `chrome://flags/#encrypted-client-hello` and set **Encrypted Client Hello** to **`Enabled`**.
5. Restart your browser.

**In Mozilla Firefox:**
1. Navigate to `about:config` and verify:
   * `network.dns.echconfig.enabled` ➔ **`true`**
   * `network.dns.use_https_rr_as_alpn` ➔ **`true`**
2. In *Settings > Privacy & Security > DNS over HTTPS*:
   * Select **"Increased Protection"** or **"Max Protection"** (with Cloudflare or NextDNS).
3. Restart Firefox.

---

#### 🧹 Flushing Internal Browser DNS Cache

If you recently enabled DoH or ECH, your browser may retain previous unencrypted IP records in its memory cache:

* **Chrome / Brave / Edge**: Open `chrome://net-internals/#dns` and click **"Clear host cache"**, then `chrome://net-internals/#sockets` and click **"Flush socket pools"**.
* **Mozilla Firefox**: Open `about:networking#dns` and click **"Clear DNS Cache"**.

---

#### ❓ Why Can ECH Fail Even When Enabled?

1. **Missing DoH**: Browsers **strictly disable ECH** if DoH is inactive, because the browser cannot securely fetch the Type 65 `ech=` DNS record over unencrypted UDP/53.
2. **Antivirus HTTPS Inspection**: Antivirus software (Bitdefender, ESET, Kaspersky, Avast) with SSL/TLS web scanning acts as a local Man-in-the-Middle proxy, forcing fallback to plaintext SNI (`sni=plaintext`).
3. **ISP / Router Canary Domain Blocking**: Some ISPs block `use-application-dns.net`, signaling browsers to disable DoH.
4. **Unsupported Resolvers**: Custom DNS servers or outdated Pi-hole instances that strip or drop DNS Type 65 queries.

---

## 📄 License

MIT License · Centinela 2026.
