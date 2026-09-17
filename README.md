# Phishing Email Analyzer

A fully client-side web application that analyzes suspicious emails for phishing indicators. All parsing, scoring, and analysis happens locally in your browser — your email data never leaves your machine unless you explicitly choose to look up an IOC with your own API key.

**Live: https://boode-hub.github.io/Phishing-Analyzer/**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)

## Features

- **Header Analysis** — Parses email headers, extracts authentication results (SPF/DKIM/DMARC), and detects domain alignment issues
- **Body Analysis** — Extracts plain text and HTML content, and flags deceptive links — link text that shows one address while pointing to another
- **IOC Extraction** — Finds URLs (including tracking pixels and other remote resources), domains, IP addresses, email addresses, and attachments with risk flagging. Links rewritten by Microsoft Safe Links or Proofpoint are unwrapped, and the real destination is analysed as an IOC of its own
- **URL Decoders** — Under every URL: unwrap Safe Links / Proofpoint v1–v3 / Google / Barracuda / Cisco / open redirects, multi-layer URL decoding, Base64, punycode (reveals lookalike characters), HTML entities, hex and `\u`/`\x` escapes, or everything at once
- **File Hashing** — Decodes every file part in the message, attachments and inline images alike, and shows SHA-256 and MD5 for each so any of them can be checked against VirusTotal in one click
- **Sender IP** — States the originating IP (where the message entered the mail system) separately from the last relay, each with VirusTotal and AbuseIPDB lookup buttons
- **Language Analysis** — Detects urgency, authority/fear, financial fraud, and credential-harvesting language patterns with inline highlighting
- **Risk Scoring** — Composite score based on authentication failures, IOC risk flags, and language analysis, with every point explained. Warns when the evidence is too thin to trust a low score (forwarded messages, missing authentication headers)
- **VirusTotal Integration** — Optional per-IOC lookup for URLs, domains, IPs, and file hashes (requires your own API key)
- **AbuseIPDB Integration** — Optional per-IOC IP reputation lookup (requires your own API key)
- **Defang/Copy** — One-click defanging for safe sharing, and copy-to-clipboard for any IOC

## Privacy

This tool runs entirely in your browser. Nothing is uploaded or transmitted, except IOCs you explicitly submit to VirusTotal/AbuseIPDB using your own API key. See the Settings panel to configure API keys.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/boode-hub/Phishing-Analyzer.git
cd Phishing-Analyzer

# Start the local server
node server.js

# Open http://localhost:8080 in your browser
# Port taken or refused (Windows reserves some ranges)? PORT=3000 node server.js
```

## Usage

1. **Paste** the raw message source into the text area, or **upload** a `.eml` file. Use the original message, not a forward — a forward's headers describe the forward

2. Click **Analyze Email**
3. Review the panels:
   - **Quick Summary** — Key signals at a glance
   - **Analysis Result** — Risk tier, score breakdown, and reasons
   - **Email Authentication** — SPF/DKIM/DMARC results and domain alignment
   - **Indicators of Compromise (IOCs)** — Extracted URLs, domains, IPs, emails, attachments
   - **Body & Language Analysis** — Plain text, HTML preview, and highlighted suspicious phrases
   - **Email Headers** — Structured header table
4. (Optional) Add VirusTotal/AbuseIPDB API keys in **Settings** to enable per-IOC enrichment

## Project Structure

```
/
├── index.html              # App shell
├── favicon.svg             # App icon (+ favicon-32.png, apple-touch-icon.png)
├── styles/
│   └── main.css            # Design system & styling
├── scripts/
│   ├── main.js             # App init, event wiring, API lookups
│   ├── parse-headers.js    # Header extraction & unfolding
│   ├── parse-auth.js       # SPF/DKIM/DMARC, alignment, received chain, sender IP
│   ├── parse-body.js       # MIME tree parsing, links, remote resources
│   ├── extract-iocs.js     # IOC extraction + risk flagging
│   ├── url-decode.js       # URL unwrapping and decoders
│   ├── ip-utils.js         # IP validation and extraction
│   ├── analyze-language.js # Urgency/fraud keyword scoring
│   ├── score.js            # Composite verdict scoring
│   ├── render.js           # DOM rendering for all panels
│   └── hash-utils.js       # SHA-256 & MD5 (byte-accurate) for file hashing
├── tests/                  # Plain node test suites (see Tests)
├── sample-data/            # Test .eml files
│   ├── legitimate-email.eml
│   ├── phishing-spoofed.eml
│   └── phishing-urgency.eml
├── .github/workflows/      # Runs the tests, then deploys to GitHub Pages
├── server.js               # Local server + API relay
└── README.md
```

## Tech Stack

- Pure HTML5 + CSS3 + vanilla JavaScript (ES modules)
- No build step required
- No external libraries or CDN dependencies
- Web Crypto API for SHA-256 hashing
- LocalStorage for API key persistence

## API Integrations (Optional)

### VirusTotal

- URL lookup via `/api/v3/urls/{url_id}`
- Domain lookup via `/api/v3/domains/{domain}`
- IP lookup via `/api/v3/ip_addresses/{ip}`
- File hash lookup via `/api/v3/files/{sha256}`
- Auto-submits URLs for analysis if not found

### AbuseIPDB

- IP reputation check via `/api/v2/check`
- Shows abuse confidence score, total reports, country, ISP

### Where lookups work

**Run locally and an API key is all you need.**

```bash
node server.js
# Open http://localhost:8080, paste your keys in Settings, done.
```

`server.js` serves the page *and* relays the API calls, so both are same-origin
and nothing else has to be configured.

**Lookups cannot work from GitHub Pages, and no client-side code can change
that.** Neither vendor sends CORS headers — AbuseIPDB rejects the preflight with
`405 Method Not Allowed`, and VirusTotal answers the preflight without an
`Access-Control-Allow-Origin` header — so the browser discards the response
before the page ever sees it. An API key does not help; the block is on the
response, not on authentication. Everything else (parsing, scoring, IOC
extraction, file hashing) runs fine on Pages. The Settings panel says which
situation you are in.

If you specifically need lookups from a hosted page, the only route is to put
something you control in front of the vendors:

**Cloudflare Worker (optional, hosted deployments only)**
1. Go to [workers.cloudflare.com](https://workers.cloudflare.com/) and create a free account
2. Create a new Worker and paste the code from [`cors-worker.js`](cors-worker.js)
3. Save and deploy - copy your worker URL (e.g., `https://your-worker.your-subdomain.workers.dev`)
4. In the Phishing Analyzer app, open **Settings** and paste the worker URL in the **CORS Proxy URL** field
5. The worker URL should end with `?url=` (e.g., `https://your-worker.workers.dev?url=`)

**Why a proxy is needed:** VirusTotal and AbuseIPDB APIs don't send `Access-Control-Allow-Origin` headers, so browsers reject responses from GitHub Pages. A CORS proxy adds these headers. The Cloudflare Worker template provided forwards all headers (including your API keys) securely.

## Sample Data

Three synthetic `.eml` files are included for testing:

| File                   | Description                                    | Expected Result |
| ---------------------- | ---------------------------------------------- | --------------- |
| `legitimate-email.eml` | Clean email with passing auth                  | Low Risk        |
| `phishing-spoofed.eml` | Spoofed domain, auth failures, domain mismatch | High Risk       |
| `phishing-urgency.eml` | Urgency/financial language, passing auth       | Low Risk †      |

† The message authenticates correctly, and language alone is deliberately not
enough to raise the tier — urgent wording is common in legitimate mail. The
language findings are still listed in the verdict.


## Tests

```bash
node tests/runner.mjs            # module unit tests
node tests/auth.test.mjs         # SPF/DKIM/DMARC parsing + alignment + scoring
node tests/attachments.test.mjs  # MIME extraction + file hashing
node tests/ip.test.mjs           # IP validation, extraction, private ranges
node tests/url-decode.test.mjs   # URL unwrapping and decoders
node tests/links.test.mjs        # link/IOC extraction, summary and verdict rendering
```

Attachment hashes are asserted against `node:crypto`, not against values this
codebase produced, so a self-consistent wrong hash cannot pass.

## License

MIT
