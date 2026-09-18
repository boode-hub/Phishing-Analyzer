# Security review and test report

**Subject:** Phishing Email Analyzer (this repository)
**Date:** 18 September 2026
**Reviewed version:** commit at the time of writing, deployed to `https://boode-hub.github.io/Phishing-Analyzer/`
**Question asked:** does everything work, and is the platform safe to host publicly?

**Answer:** yes, with four issues found and fixed during the review (listed below). The hosted copy is a static site that keeps no secrets, accepts no uploads to any server, and has no server-side code at all. The parts that could be attacked are the parsing of hostile email and the local helper server; both were probed directly.

---

## 1. What was tested and how

| Area | Method |
|---|---|
| Unit and integration behaviour | 15 automated suites, 287 checks, run on every push through GitHub Actions |
| Whole-app behaviour | Driven in a real browser: input handling, every panel, decoders, exports, settings, theme, batch, mobile widths |
| Hostile email handling | A message carrying `<script>`, `onerror=`, `javascript:` and `svg/onload` payloads in **every** header and in the body, plus a fake PDF that is really a Windows program |
| Robustness | Empty input, 5 KB of raw binary, 10 000 `Received` headers, a 1 MB body with 5 000 links, 60 levels of nested MIME, 500 KB of text, deliberately pathological URLs |
| Local server | Direct HTTP probes: traversal, encoded traversal, null bytes, dot-files, unknown types, cross-origin use, relay abuse, injection into the DNS/WHOIS parameters |
| Exported files | Generated reports opened in a browser and inspected for scripts, remote loads and live indicators |
| Hosted copy | Framing test against the live site; asset and policy checks over HTTPS |

---

## 2. Functional results

All 15 automated suites pass (287 checks). Browser testing confirmed:

| Feature | Result |
|---|---|
| Junk text refused; empty input refused; stale results cleared | Correct messages, all panels hidden |
| Headers-only message | Analysed, body panel correctly hidden |
| Full message | Summary, verdict, authentication, IOCs, body, headers all rendered |
| Sender identity | Display-name and lookalike findings shown and scored |
| Sender IP | Walks past a private hop (`10.0.0.5`) to the public one (`198.51.100.7`) and explains it |
| Header views | Both views, hop tags, copy buttons |
| URL decoders | Panel opens lazily, decoders run, Safe Links destination extracted as its own indicator |
| Large result sets | 113 indicators, capped at 50 rows with a working "Show all" |
| Attachments | SHA-256/MD5 shown; a `.pdf` containing a Windows executable is flagged |
| Live DNS | SPF/DMARC/MX resolved locally and explained (`p=reject` versus `p=none`, `-all` versus `~all`) |
| WHOIS | Registrar, registrant, dates, status, abuse contact; recent-registration badge; unregistered domains reported |
| Reputation lookups | With a key: results in page. Without: links to the vendor's own page |
| Exports | HTML, CSV and JSON download together; CSV keeps its fixed columns; JSON parses |
| Batch | Several files scored and sorted worst-first; opening one loads it |
| Theme colour | Applies live, persists, resets |
| Key storage toggle | With "remember" off, nothing is written to browser storage |
| Mobile at 320 px | No sideways scrolling, tables become cards, smallest text 11 px, smallest tap target 40 px |

Performance (worst cases, on a normal laptop):

| Input | Time |
|---|---|
| 10 000 `Received` headers | 58 ms |
| 1 MB body, 5 000 links | 672 ms |
| 500 KB of text through language analysis | 57 ms |
| 6 pathological URLs × 8 decoders | 233 ms |
| 60 levels of nested MIME | 2 ms |

Nothing hangs, and no input caused a crash after the fixes below.

---

## 3. Findings

Four issues were found. All four are fixed, tested and deployed.

### 3.1 A visited web page could crash the local server — fixed

**Severity:** medium (local availability)
**What happened:** `GET /index.html%00.png` made `fs.readFile` throw on the null byte. Nothing caught it, so the Node process exited. Because any website can send a cross-origin request to `http://127.0.0.1:<port>`, merely visiting a hostile page could kill an analyst's running tool mid-investigation.
**Fix:** paths containing null bytes or control characters are refused with 400, and every request is wrapped so one bad request can never take the process down.

### 3.2 The local server published the whole project directory — fixed

**Severity:** low (local information exposure)
**What happened:** any file under the project root was served, including `.git/` and source files.
**Fix:** only known file types are served, and no path component may begin with a dot. `.git/config` and `.env` now return 403.

### 3.3 Any website could use the local lookups and relay — fixed

**Severity:** medium (local exposure / abuse of the analyst's machine)
**What happened:** `/lookup/dns`, `/lookup/whois` and `/proxy/*` answered with `Access-Control-Allow-Origin: *`, so a page the analyst happened to be visiting could run DNS and WHOIS queries from their machine, relay calls to VirusTotal and AbuseIPDB, and read the answers.
**Fix:** those endpoints serve the app's own origin only — a request carrying any other `Origin` is refused — and no endpoint sends CORS permission at all. This also blunts DNS rebinding.

### 3.4 The hosted copy could be framed — fixed

**Severity:** low (clickjacking)
**What happened:** GitHub Pages cannot send `X-Frame-Options`, and `frame-ancestors` is ignored inside a `<meta>` policy, so the live site could be placed in an invisible frame on another site.
**Fix:** the app refuses to run unless it is the top-level window, and shows a link to open it directly. Verified against the live site. The local server additionally sends `X-Frame-Options: DENY`.

---

## 4. Verified safe

Each of these was actively attacked, not merely reviewed.

| Attack | Result |
|---|---|
| Stored XSS through headers (From, Reply-To, Subject, X-Mailer, Message-ID, Received, Authentication-Results), body HTML and attachment filenames | No payload executed. The live DOM contains **zero** `on*` attributes; payloads appear only as escaped text |
| Script injection into the page | Blocked by CSP: inline script and a remote `<script>` were both refused by the browser |
| Tracking pixels and remote images in the message | Never loaded, including with the HTML preview open. The preview frame is fully sandboxed with its own `default-src 'none'` policy |
| `javascript:` and `data:` links | Captured, flagged as indicators, never followed or made clickable |
| XSS through the exported HTML report | Report opened in a browser: no scripts, no images, no external requests, payload inert, all indicators defanged |
| Spreadsheet formula injection in CSV | Cells starting with `= + - @` are prefixed, quoting is RFC 4180, BOM and CRLF present |
| JSON export | Valid JSON; payloads carried as string data only |
| Path traversal, encoded and Windows-style | 403/404, contained inside the project directory |
| SSRF through the relay | The target host is fixed in code; no path or query moved it. The optional Cloudflare worker allows only VirusTotal and AbuseIPDB over HTTPS |
| Command injection into DNS/WHOIS (`; whoami`, `\|cat /etc/passwd`, newlines, over-long labels, URLs) | Refused: only a bare domain or IP is accepted |
| Prototype pollution through header names (`__proto__`, `constructor`) | `Object.prototype` untouched; header names stay data |
| Denial of service through huge or pathological input | See the timings above; nothing hangs |
| API key handling | Keys stay in the browser, are sent only to the vendor on an explicit click, and can be kept out of storage entirely |

---

## 5. Residual risks to be aware of

These are inherent to what the tool does, not defects:

1. **Whatever you look up, you share.** Clicking a VirusTotal or AbuseIPDB button sends that indicator to that company. A WHOIS or DNS lookup tells the registry and your DNS resolver which domain you are investigating. Analysis, scoring and reports involve no network traffic at all.
2. **A custom CORS relay sees your traffic.** If you configure one in Settings, the indicators and your API key pass through it. Use only a relay you operate — the bundled worker is written to be that.
3. **API keys live in the browser.** Anything that can run script on the page could read them. That is why the page has a strict policy, no inline handlers and no third-party code — and why the "remember my keys" option exists for shared machines.
4. **Reports contain the attacker's text.** Indicators are defanged and the file is inert, but the wording in a report is still attacker-written. Treat it as evidence, not instructions.
5. **The local server is a developer tool.** It is bound to `127.0.0.1`, serves only the app, and should not be exposed to a network or run as an administrator.
6. **Detection is heuristic.** A high score is evidence, not proof; a low score with a caveat means the headers were not enough to judge.

---

## 6. Conclusion

The platform is **safe to host publicly as a static site**. It stores nothing, authenticates no one, has no server-side code and no database, keeps every secret in the visitor's own browser, and treats every part of an email as hostile data. The four issues found in this review — all in the optional local helper server, except the framing one — have been fixed, covered by tests, and deployed.

Re-run the checks at any time with:

```bash
for f in tests/*.mjs; do node "$f" || break; done
```
