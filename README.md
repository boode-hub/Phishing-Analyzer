# Phishing Email Analyzer

A browser-based analyzer for suspicious emails. Paste the raw message or upload an `.eml` file, and it checks the sender's authentication, traces the route the message took, extracts and decodes every indicator of compromise, reads the wording for fraud patterns, and gives a scored verdict with the reasons behind it — then exports a defanged report.

All analysis runs locally in your browser. Nothing is uploaded; the only data that ever leaves your machine is an indicator you explicitly send to VirusTotal or AbuseIPDB with your own API key.

**Live: https://boode-hub.github.io/Phishing-Analyzer/**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)

---

## Contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [How to use it](#how-to-use-it)
- [Features](#features)
  - [Quick Summary](#quick-summary)
  - [Sender identity](#sender-identity)
  - [Verdict and scoring](#verdict-and-scoring)
  - [Email authentication](#email-authentication)
  - [Sender IP and route](#sender-ip-and-route)
  - [Indicators of compromise](#indicators-of-compromise)
  - [URL decoders](#url-decoders)
  - [Attachments and file hashes](#attachments-and-file-hashes)
  - [Live DNS and WHOIS](#live-dns-and-whois)
  - [Batch analysis](#batch-analysis)
  - [Language analysis](#language-analysis)
  - [Body preview](#body-preview)
  - [Email headers](#email-headers)
  - [Report export](#report-export)
  - [VirusTotal and AbuseIPDB lookups](#virustotal-and-abuseipdb-lookups)
  - [Theme colour](#theme-colour)
  - [Mobile](#mobile)
- [Security of the tool itself](#security-of-the-tool-itself)
- [Privacy and security](#privacy-and-security)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Testing and deployment](#testing-and-deployment)
- [Sample data](#sample-data)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Highlights

- **Authentication done the way receiving servers do it** — SPF, DKIM and DMARC read from the header your own mail server wrote, forged headers flagged, and DMARC-style domain alignment explained in plain terms.
- **Finds what the link is hiding** — unwraps Microsoft Safe Links, Proofpoint and open redirects, decodes Base64, punycode and more, and analyses the real destination as an indicator of its own.
- **Every indicator in one place** — URLs (including tracking pixels), domains, IPs, email addresses, attachments and inline images with SHA-256/MD5, and deceptive links.
- **Checks who it claims to be** — display names that carry another address or a brand they do not own, lookalike and mixed-alphabet sending domains, and replies pointed at free webmail.
- **Looks inside attachments** — the real file type from its first bytes, so "Invoice.pdf" that is actually a program is caught, along with HTML smuggling.
- **Reads the wording** — urgency, fear, financial fraud, credential harvesting, and Business Email Compromise / payment fraud, matched by pattern as well as by phrase.
- **Asks your own machine, not a service** — live DNS (SPF, DMARC, MX) and WHOIS/registration for every domain and IP, resolved locally with no API key.
- **A verdict you can explain** — every point of the score has a reason, and the tool says when the evidence is too thin to trust a low score.
- **Report in one click** — a styled, self-contained HTML report, a CSV and a JSON file for tooling, with every indicator defanged, plus a one-click copy of all indicators.
- **A whole batch at once** — select many files and every message is scored and listed worst first.
- **Private by design** — no uploads, no tracking, and the message's own HTML preview cannot phone home.
- **Works on phones.**

---

## Quick start

### Use it online

Open **https://boode-hub.github.io/Phishing-Analyzer/** — no install. Everything works there except the VirusTotal/AbuseIPDB lookups (see [why](#where-lookups-work)).

### Run it locally

Requires [Node.js](https://nodejs.org/). There are no dependencies to install and no build step.

```bash
git clone https://github.com/boode-hub/Phishing-Analyzer.git
cd Phishing-Analyzer
node server.js
```

Open **http://localhost:8080**. Running locally also makes the VirusTotal and AbuseIPDB lookups work with nothing more than your API key.

If port 8080 is taken or refused — Windows reserves some port ranges — choose another:

```bash
PORT=3000 node server.js
```

---

## How to use it

1. **Get the original message source.** A forwarded copy is not good enough: a forward's headers describe the forward, not the original sender.
   - **Gmail:** open the message → ⋮ → **Show original** → copy it, or **Download original** for an `.eml` file.
   - **Outlook on the web:** open the message → ⋯ → **View** → **View message source**.
   - **Outlook desktop:** **File → Properties** shows the Internet headers. Headers alone are enough for the authentication and routing analysis; body, links and attachments need the full source.
2. **Paste** it into the input box, or **upload** the `.eml` / `.txt` file.
3. Click **Analyze Email**.
4. Read the **Quick Summary** first, then drill into the panels below it.
5. Optionally add **VirusTotal / AbuseIPDB API keys** in **Settings** to look indicators up in place.
6. **Export** an HTML report and/or a CSV from the bar above the results.

Text that is not an email is refused rather than given a verdict. `.msg` files are not supported yet — save or convert the message to `.eml`.

---

## Features

### Quick Summary

The first panel answers "is this phishing?" and shows the evidence at a glance.

| Card | Shows |
|---|---|
| **Verdict** | Risk tier, score out of 100, the top three reasons, and any caveats about the evidence |
| **Authentication** | SPF, DKIM and DMARC results and whether the domains align |
| **IOCs found** | Counts of URLs, domains, IPs, emails and files, highlighted when any is high-risk |
| **Sender** | From address and domain, and whether DMARC verifies it — shown as **Not verified — fails DMARC** for a spoofed sender |
| **Reply-To** | The real Reply-To header, if any, and whether replies go to a different domain |
| **Message** | Decoded subject, date and mailer |
| **Sender IP** | The sender's public originating IP and the last relay, each with Copy, VirusTotal and AbuseIPDB buttons |
| **Language** | Every suspicious phrase found, grouped by category and colour-coded by severity |

### Verdict and scoring

The score combines three categories, each capped at 100 **before** weighting so that a large number of minor findings cannot outweigh a clean authentication result:

| Category | Weight | What raises it |
|---|---|---|
| **Authentication** | 60% | SPF/DKIM/DMARC failures, missing records, domain misalignment, a differing Reply-To, forged or duplicated headers |
| **Indicators** | 25% | Deceptive links, raw-IP links, punycode domains, URL shorteners, executable or double-extension attachments, disposable email addresses |
| **Language** | 15% | Phrases in the language categories — deliberately the weakest signal, since urgent wording is common in legitimate mail |

| Score | Tier |
|---|---|
| 60–100 | **High Risk** |
| 30–59 | **Suspicious** |
| 0–29 | **Low Risk** |

- A message where SPF, DKIM and DMARC all fail on a misaligned domain reaches **High Risk** on authentication alone.
- Repeated low-severity findings have diminishing returns — the twentieth shortened link adds almost nothing.
- **Every point comes with a reason**, listed under its category in the **Analysis Result** panel.
- **Caveats** warn when a low score is not a clean result:
  - the subject starts with `Fw:` / `Fwd:` — likely a forward whose headers describe the forward;
  - no authentication or routing headers were found at all;
  - no SPF, DKIM or DMARC result was recorded.

### Email authentication

**SPF, DKIM and DMARC**

- Results are taken from the **topmost `Authentication-Results` header** — the one your own receiving server wrote. Lower headers can be forged by the sender; if one claims a pass that the receiving server did not record, it is flagged.
- Headers are parsed clause by clause, so text inside comments is never mistaken for a result.
- Microsoft 365's format, which omits the server name and writes `smtp.mailfrom` as a bare domain, is handled.
- `Received-SPF` is read in both the standard form and Microsoft's.
- **SPF is shown from both headers side by side** — `Authentication-Results` and `Received-SPF` — each with the IP it evaluated and the identity it checked. If they disagree on the result or the IP, it is flagged; `Authentication-Results` decides the verdict.
- Every result state is kept distinct: pass, fail, softfail, neutral, none, temperror, permerror, and "signed but unverified" for DKIM.

**Domain alignment**

Alignment follows DMARC and is spelled out as a comparison, for example:

> **SPF** · Return-Path `em6908.spglobal.com` = From `spglobal.com` · **Aligned — relaxed, both under spglobal.com**

- **SPF alignment** compares the envelope sender (Return-Path) with From; **DKIM alignment** compares the signing domain with From.
- **Strict** means identical domains; **relaxed** means the same organizational domain (`mail.example.com` and `example.com`), recognising multi-part suffixes such as `co.uk` and `com.au`.
- DMARC is satisfied when **either** SPF or DKIM both passes and aligns; alignment without a passing check does not count, and the table says so.
- **Reply-To is not a DMARC input.** A differing Reply-To is shown as informational and priced as a caution, not a failure.

**Header trust warnings**

- A lower `Authentication-Results` header contradicting the receiving server's result.
- More than one `From`, `Subject`, `Reply-To`, `Return-Path`, `Date` or `To` header.

### Sender IP and route

- **Received chain** — every hop in order of travel (hop 1 is where the message started), with sending host, receiving host, IP and timestamp. Hops with a private origin or timestamps running backwards are flagged.
- The sending IP is read **only from each hop's `from` clause**, never from the `by` clause, which names the server that received it.
- **Originating IP** — the sender's public address. When the first hop records a private address (a workstation behind NAT, an internal relay), it is kept for the record and the analyzer walks outward to the first public address.
- **Last relay** — the server that delivered the message to you.
- Every address is **validated** — IPv4 octets within range and without ambiguous leading zeros, IPv6 including compressed and IPv4-mapped forms. Queue IDs and version strings that merely look like addresses are discarded.
- Private and reserved addresses are labelled and are **not offered for reputation lookups**, since the services hold no data on them.

### Indicators of compromise

| Indicator | Where it is found | Risk flags |
|---|---|---|
| **URLs** | Plain text, link targets, and remote resources that load when the message is opened (tracking pixels, remote images, scripts, frames) | Deceptive link, raw IP address, punycode, URL shortener |
| **Real destinations** | Unwrapped from Safe Links, Proofpoint and redirect links, and listed as URLs of their own | Every URL check runs on the real destination too |
| **Domains** | Every URL, every unwrapped destination, the From / Reply-To / Return-Path addresses, the Message-ID | Punycode |
| **IP addresses** | Received headers, `X-Originating-IP`, the message body | Originating IP (can be spoofed), private/reserved |
| **Email addresses** | From, Reply-To, Return-Path, the message body | Disposable email provider |
| **Attachments** | Every file part, including inline images and parts with a Content-ID | Double extension, risky executable extension |
| **Deceptive links** | Links whose visible text shows one address while pointing to another | — |

**How the flags decide**

- A link is **deceptive** only when its visible text itself looks like a URL or domain and points to a different organization — compared *after* unwrapping, so a Safe Links rewrite of the same site is not flagged, but a rewrite hiding a different domain is. Ordinary link text such as "View invoice" is never flagged.
- **URL shortener** and **disposable email** checks match the exact domain or its subdomains, so `t.co` does not match `microsoft.com`.
- **Risky extensions:** `.exe .scr .js .hta .vbs .bat .cmd .pif .msi .com .dll .ps1 .sh .bash .jar .app .dmg`, plus double extensions such as `.pdf.exe`.

**On every indicator row:** **Copy**, **Defang** (switches between the live and defanged value), and **VirusTotal** / **AbuseIPDB** lookup buttons where they apply. Email addresses also get a lookup for their domain. Long tables show the first 50 rows with a **Show all** button.

### URL decoders

Every URL has a **Decode URL** section. It is highlighted with the encodings it detected, and each decoder runs with one click:

| Decoder | What it does |
|---|---|
| **Decode all** | Applies every reversible layer until the URL stops changing, then reports any hidden Base64/hex payloads and the punycode display form |
| **Unwrap Safe Links / redirect** | Recovers the real destination from Microsoft Defender Safe Links, Proofpoint URL Defense v1, v2 and v3, Google and Facebook redirects, Barracuda Link Protection, Cisco Secure Email, and any redirect parameter holding a URL — recursively, when wrappers are nested. Mimecast links say plainly that the destination is held on Mimecast's servers and cannot be recovered |
| **URL %XX** | Percent-decoding, including multiple layers, which are flagged as an evasion technique |
| **Base64** | Decodes Base64 and Base64URL tokens that produce readable text, and flags a hidden email address — usually the targeted recipient |
| **Punycode** | Shows how an `xn--` domain actually displays and names the lookalike characters, e.g. `pаypal.com` with a Cyrillic `а` (U+0430) |
| **HTML entities** | `&amp;`, `&#x2F;` and similar |
| **Hex** | Hex runs that decode to readable text; hashes and random IDs are ignored |
| **\u \x escapes** | JavaScript-style escape sequences |

### Attachments and file hashes

- Every MIME part is decoded to its exact bytes — nested multipart messages, Base64 and quoted-printable encodings, and encoded filenames included.
- **Inline images and embedded files are collected too**, not only parts marked as attachments.
- **SHA-256 and MD5** are shown for each file, with its type, size and whether it is inline.
- The VirusTotal button on a file looks up its hash.

### Language analysis

Phrases are matched as **whole words** (so "first" never matches "IRS", nor "courtesy" match "court") in five categories:

| Category | Examples | Severity |
|---|---|---|
| **Urgency** | act now, within 24 hours, account will be suspended, final warning | Caution |
| **Authority / Fear** | legal action, law enforcement, IRS, unauthorized access, final notice | Caution |
| **Financial / Fraud** | wire transfer, gift card, bitcoin, banking details, payment request | High |
| **Credential harvesting** | click here to verify, confirm your password, reset your password | High |
| **BEC / Payment fraud** | new or updated bank details, change of beneficiary, wire instructions, direct-deposit changes, overdue invoice, process the payment, proof of payment, "are you available", "I'm in a meeting", keep this confidential, purchase gift cards and send the codes | High |

- The **Quick Summary** lists the phrases found, grouped by category, with repeated phrases shown once with a count (`Act now ×2`).
- The **Body & Language Analysis** panel shows the full breakdown and highlights every phrase inline, coloured by category.

### Body preview

- **Plain text** view with suspicious phrases highlighted.
- **HTML preview** in a fully sandboxed frame with a content security policy that blocks every remote request — the message's tracking pixels and remote images do not load, so opening the preview never tells the sender you looked.

### Sender identity

Authentication answers "did this domain really send it". It cannot answer "is this domain who the reader thinks it is" — and most real phishing passes every check. The **Sender identity** card appears directly under the verdict whenever any of these hold:

- the display name carries a different address than the real sender (`"PayPal Service <service@paypal.com>" <attacker@gmail.com>`);
- the display name claims a brand the sending domain does not belong to;
- the sending domain imitates a brand — `paypa1.com` (reads the same), `micorsoft.com` (one edit away), or `paypal.secure-login.test` (the brand used as a word);
- a domain label mixes Latin with Cyrillic or Greek letters, which is how lookalike domains are built;
- replies would go to a personal webmail account on another domain.

The same lookalike check runs over every link, so a link to `paypa1-verify.com` is flagged even when its text is innocent. Links are also flagged for embedded credentials (`https://accounts.paypal.com@evil.test`), `javascript:` and `data:` schemes, non-standard ports, direct downloads of programs or archives, and heavily abused domain endings such as `.zip`.

### Live DNS and WHOIS

Both run **on your own machine**, through the app's server (`node server.js`). No third-party API, no key, and nothing about the message is sent anywhere.

- **WHOIS & registration** sits under every domain and IP, and under the sender's IP in the summary. It shows the registrar or network owner, the registrant, country, name servers, status and the abuse contact — with a badge when a domain was **registered days ago**, which is the most reliable sign of a throwaway phishing domain. An unregistered domain is reported as such.
- **Published policy** in the Authentication panel resolves what the From domain publishes right now: its SPF record and whether it ends in `-all` or only `~all`, its DMARC policy (`p=reject`, `p=quarantine` or the decorative `p=none`), and its MX records — a domain with no MX is not set up to receive mail at all.

RDAP is used where registries support it, with classic WHOIS on port 43 as the fallback. On a hosted copy there is no local server, and the panels say so instead of failing quietly.

### Batch analysis

Select several files in the upload box and every message is parsed, scored and listed **worst first**, with its verdict, sender and subject. Clicking **Open** loads that message into the full view. Everything stays local, and one bad message in a wave of twenty does not get missed.

### Email headers

The **Email Headers** panel has two collapsible views:

- **Key headers first** — important headers on top, then everything else.
- **Original order** — every header numbered, exactly as it appears in the email. Each `Received` header is labelled with its hop (**hop 1 · origin** through **last**) and authentication headers are marked. **Copy raw headers** copies the original header block verbatim.

### Report export

The **Export IOC report** bar above the results downloads any combination of the three formats, and **Copy IOCs** puts every indicator on the clipboard (defanged, or raw for tooling).

**HTML report** — a single self-contained file in the app's own design:

- Verdict with score meter, subject, sender and indicator counts.
- Message details; a score card per category with its reasons; authentication with SPF by header and domain alignment; sender path and the received chain; and every indicator — URL cards with their real destinations nested inside, tables for domains, IPs and emails, and attachment cards with click-to-select hashes.
- Includes any VirusTotal / AbuseIPDB lookups already run.
- **Opens offline and makes no network request** — no web fonts, images or scripts; a content security policy blocks anything from loading or running.
- Adapts to phones, and **prints cleanly** to a light layout — use **Print → Save as PDF** for a PDF.

**CSV** — one indicator per row, for SIEMs, blocklists and spreadsheets:

| Column | Contents |
|---|---|
| `type` | `url`, `domain`, `ip`, `email`, `filename`, `sha256`, `md5`, `deceptive_link` |
| `indicator` | The defanged value (hashes and filenames unchanged) |
| `source` | Where it was found |
| `risk_flags` | Flags, separated by `;` |
| `details` | Context — e.g. the wrapper a URL was unwrapped from, a file's type and size |
| `virustotal` / `abuseipdb` | Lookup results, if run |
| `indicator_raw` | Optional — the live value, for importing into tooling |

- UTF-8 with a byte-order mark and CRLF line endings, so it opens correctly in Excel.
- Cells that would start with `= + - @` are prefixed so spreadsheets cannot execute them as formulas.

**Defanging** (both formats)

| Original | Defanged |
|---|---|
| `https://evil.com/path` | `hxxps[://]evil[.]com/path` |
| `evil.com` | `evil[.]com` |
| `203.0.113.5` | `203[.]0[.]113[.]5` |
| `2001:db8::1` | `2001[:]db8[:][:]1` |
| `user@evil.com` | `user[@]evil[.]com` |

Domains hidden inside a URL's query — such as the destination carried by a Safe Links wrapper — are defanged too, because chat tools auto-link bare domains. Hashes and filenames are never altered. Files are named `phishing-report_<date>_<subject>.html` / `.csv`.

### VirusTotal and AbuseIPDB lookups

Optional. Add your API keys in **Settings**; they are stored in this browser only and sent only to the service when you click a lookup button.

**VirusTotal**

- Look up **URLs, domains, IPs and file hashes** from any indicator row or the Sender IP card.
- Shows the verdict (malicious / suspicious / clean), engine counts, last analysis date, reputation, and metadata such as AS owner, country and file name.
- A URL VirusTotal has never seen is submitted for analysis automatically.
- **Rescan** requests a fresh analysis; **Open in VT** opens the full report.

**AbuseIPDB**

- Look up **IP addresses**. Shows abuse confidence score, total reports, country, ISP, domain, usage type and last report date.

**Both**

- Results are cached for the session, so re-opening a result does not spend quota.
- Key formats are checked before any request is made. Malformed IP addresses are refused, and private or reserved addresses get no lookup buttons.
- Invalid-key, permission, rate-limit and timeout errors are explained; connectivity failures also offer a link to the vendor's web report.

#### Where lookups work

**Run locally (`node server.js`) and an API key is all you need.** The local server serves the app and relays the API calls, so there is nothing else to configure; **Settings** confirms "Lookups are ready".

**From GitHub Pages, lookups cannot work — and no client-side code can change that.** Neither service allows browsers on other websites to read its API responses (AbuseIPDB rejects the browser's preflight check outright; VirusTotal answers it without permission), so the browser discards the response. An API key does not help; the block is on the response, not on authentication. **Settings** says so when you are on a hosted copy. Everything else works on Pages.

If you need lookups from a hosted copy, put a relay you control in front of the services — a template for a free **Cloudflare Worker** is included:

1. Create a free account at [workers.cloudflare.com](https://workers.cloudflare.com/).
2. Create a Worker and paste in [`cors-worker.js`](cors-worker.js).
3. Deploy it and copy its URL.
4. In the app's **Settings**, enter it in **CORS Proxy URL**, ending with `?url=` — e.g. `https://your-worker.your-subdomain.workers.dev?url=`.

Note that a relay sees the indicators and API keys that pass through it — use only one you operate.

### Theme colour

**Settings → Theme colour** opens your browser's colour picker. The choice recolours only the green accent — buttons, pass badges, focus rings and the logo — while backgrounds and the red/amber severity colours stay fixed so they keep their meaning. It applies instantly, is remembered in this browser, and **Reset** returns to the default `#9fef00`. Exported reports always use the default colours.

### Mobile

The whole app is usable on a phone:

- Tables become stacked cards — no sideways scrolling.
- Buttons and toggles are at least 40px tall, and no text is smaller than 11px.
- Side-by-side cards stack; the header keeps the title on one line.
- The exported HTML report adapts the same way.

---

## Security of the tool itself

The app parses hostile input, so it is built to stay harmless even if the parsing is wrong:

- A strict **Content-Security-Policy**: `default-src 'self'`, `script-src 'self'` with no `unsafe-inline`, and `object-src`, `base-uri` and `form-action` set to `'none'`. An escaping mistake cannot become code execution.
- **No inline event handlers anywhere.** Every result button carries a `data-act` attribute and is handled by one delegated listener; nothing is exposed on `window`.
- **Fonts ship with the app.** Nothing is fetched from Google or any other third party at load time.
- **The local server binds `127.0.0.1` only**, so the analyzer and its API relay are not reachable from the rest of the network. It also:
  - serves only known file types, and never a dot-directory such as `.git`;
  - refuses paths containing null bytes or control characters, and survives them — one such request used to crash it;
  - answers the relay and the local lookups **only for the app's own origin**, so a page you happen to be visiting cannot use your machine as a DNS, WHOIS or VirusTotal proxy;
  - sends `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, and hands out no CORS permission at all;
  - catches any unexpected error per request instead of exiting.
- **The optional Cloudflare relay forwards to VirusTotal and AbuseIPDB over HTTPS only** — without that allow-list, anyone who learned the worker URL could route their own traffic through your account.
- **API keys do not have to be stored.** Settings can keep them in memory for the tab instead of in this browser's storage.
- The message's own HTML is previewed in a sandboxed frame with its own blocking policy, and exported reports carry `default-src 'none'` and no script.

`tests/security.test.mjs` and `tests/server.test.mjs` check each of these against a real running server, so none of them can be lost by accident.

## Privacy and security

**What leaves your machine**

- Nothing, by default. Parsing, decoding, hashing, scoring and report generation all run in your browser.
- An indicator is sent to VirusTotal or AbuseIPDB **only** when you click its lookup button, together with your API key.
- API keys are kept in your browser's local storage and can be cleared from **Settings**.

**Handling hostile content** — every email is treated as attacker-controlled:

- All message content is escaped before display.
- The HTML preview runs in a fully sandboxed frame with remote loading blocked, so it cannot run scripts or reveal that you opened the message.
- Exported HTML reports carry a content security policy that blocks all loading and script execution, and contain no clickable links to indicators — only in-page navigation.
- CSV cells cannot run as spreadsheet formulas.
- The local server only serves files inside the project folder.

---

## How it works

A pure HTML, CSS and JavaScript application — ES modules, no framework, no build step, no dependencies. The Web Crypto API provides SHA-256.

```
Raw email
  │
  ├─ parse-headers.js   headers (original order and by name), addresses, decoded subject
  │     └─ refuses input with no email headers
  ├─ parse-auth.js      SPF / DKIM / DMARC, domain alignment, header trust,
  │                     received chain, sender's public IP
  ├─ parse-body.js      MIME tree → text, HTML, links, remote resources, file bytes
  ├─ extract-iocs.js    URLs (+ unwrapped destinations), domains, IPs, emails,
  │                     attachments, risk flags
  ├─ hash-utils.js      SHA-256 / MD5 of every file
  ├─ analyze-language.js phrase detection in five categories
  ├─ score.js           capped, weighted score · tier · reasons · caveats
  │
  ├─ render.js          all panels, URL decoders, header views
  └─ report.js          HTML and CSV export, defanging
```

`url-decode.js` provides the unwrapping and decoding used by both the IOC extraction and the decoder panels; `ip-utils.js` provides address validation throughout.

---

## Project structure

```
/
├── index.html                  App shell
├── favicon.svg                 App icon (+ favicon-32.png, apple-touch-icon.png)
├── styles/
│   └── main.css                Design system and all styles
├── scripts/
│   ├── main.js                 Start-up, analysis flow, lookups, export controls
│   ├── parse-headers.js        Header parsing and unfolding
│   ├── parse-auth.js           Authentication, alignment, received chain, sender IP
│   ├── parse-body.js           MIME parsing, links, remote resources, attachments
│   ├── extract-iocs.js         Indicator extraction and risk flags
│   ├── url-decode.js           URL unwrapping and decoders
│   ├── ip-utils.js             IP validation and extraction
│   ├── analyze-language.js     Phrase detection
│   ├── score.js                Scoring, reasons and caveats
│   ├── render.js               Rendering for every panel
│   ├── report.js               HTML / CSV report export and defanging
│   ├── hash-utils.js           Byte-accurate SHA-256 and MD5
│   ├── analyze-identity.js     Display-name and lookalike-domain analysis
│   ├── file-type.js            Attachment content sniffing and HTML smuggling
│   └── theme.js                Accent colour picker palette
├── lookup-local.js             DNS and WHOIS/RDAP performed by this machine
├── fonts/                      Self-hosted Inter and JetBrains Mono
├── tests/                      Test suites (see below)
├── sample-data/                Example .eml files
├── server.js                   Local server and API relay
├── cors-worker.js              Optional Cloudflare Worker relay for hosted copies
├── test-api.html               Stand-alone page that checks whether a browser can reach the lookup APIs
├── phishing-analyzer-master-prompt_v3.md   Complete build prompt: rebuild the whole platform from this one document
├── phishing-analyzer-master-prompt_v2.md   Original build specification (historical; superseded by v3)
└── .github/workflows/pages.yml Test, then deploy to GitHub Pages
```

---

## Testing and deployment

The test suites are plain Node.js scripts with no test framework. Where a result can be checked against an independent source, it is — hashes against `node:crypto`, punycode against `node:url`, Proofpoint decoding against Proofpoint's published examples.

```bash
node tests/runner.mjs            # module unit tests and end-to-end sample checks
node tests/auth.test.mjs         # SPF/DKIM/DMARC parsing, alignment, scoring
node tests/attachments.test.mjs  # MIME extraction and file hashing
node tests/ip.test.mjs           # IP validation, extraction, sender IP resolution
node tests/url-decode.test.mjs   # URL unwrapping and decoders
node tests/links.test.mjs        # link and IOC extraction, summary and verdict rendering
node tests/report.test.mjs       # report export: defanging, safety, well-formed output
node tests/headers.test.mjs      # original header order view
node tests/language.test.mjs     # whole-word matching, BEC / payment-fraud phrases
node tests/theme.test.mjs        # accent colour palette, apply and reset
node tests/security.test.mjs     # CSP, no inline handlers, no third-party assets, relay allow-list
node tests/detection.test.mjs    # identity, link shapes, file content, ARC, anomalies, BEC floor
node tests/server.test.mjs       # traversal, null bytes, dot-files, cross-origin use of the local endpoints
node tests/imports.test.mjs      # every cross-module call is imported
```

| Suite | Tests |
|---|---|
| runner | 92 |
| auth | 37 |
| url-decode | 26 |
| ip | 24 |
| report | 19 |
| links | 17 |
| attachments | 9 |
| language | 7 |
| headers | 6 |
| detection | 25 |
| server | 11 |
| security | 10 |
| theme | 3 |
| imports | 1 |
| **Total** | **287** |

**Deployment:** every push to `master` runs all suites in GitHub Actions and deploys to GitHub Pages only if they pass. A broken build never reaches the live site. After a deploy, browsers may keep the previous version for a few minutes — press **Ctrl+F5** to load the latest.

---

## Sample data

| File | Description | Result |
|---|---|---|
| `legitimate-email.eml` | Clean message, all authentication passing | Low Risk (0) |
| `phishing-spoofed.eml` | Spoofed domain, authentication failures, misaligned domain | High Risk (68) |
| `phishing-urgency.eml` | Urgent and financial wording, authentication passing | Low Risk (6) † |

† The message authenticates correctly, and wording alone is deliberately not enough to raise the tier. The language findings are still listed in the summary and the verdict.

---

## Known limitations

- **Lookups need the local server** (or a relay you run) — see [Where lookups work](#where-lookups-work).
- **Wording alone cannot raise the risk tier.** This prevents false alarms from urgent-sounding legitimate mail, but it means a Business Email Compromise message sent from a genuine, compromised account can score **Low Risk** while its BEC phrases are listed. Always verify payment or bank-detail changes by phone using a known number.
- **Language detection is English-only.**
- **Relaxed alignment uses a compact list of multi-part domain suffixes**, not the full Public Suffix List; unusual country suffixes may be judged by their last two labels.
- **Attachments are hashed, not scanned** — look the hash up to learn about the file.
- **Mimecast-rewritten links cannot be unwrapped**, because Mimecast keeps the destination on its servers.
- **`.msg` files are not supported** — convert to `.eml` or paste the source.

---

## License

MIT
