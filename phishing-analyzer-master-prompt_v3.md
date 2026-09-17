# Master Build Prompt v3: Phishing Email Analyzer

> Give this whole document to an AI coding assistant (Claude, GPT, or similar) as the task. It describes the finished product as it exists at `boode-hub/Phishing-Analyzer`: every module, rule, constant, UI panel, security control, and test the app depends on. Build it exactly as written. Where this document gives a list, a number, or a message, use it word for word.
>
> v2 (`phishing-analyzer-master-prompt_v2.md`) is the original, superseded spec. v3 records every accuracy fix and feature added since.

---

## 0. How to work

1. Build in the order given in §4. After each step, run that step's tests and make them pass before moving on.
2. Every rule below exists because a naive version gave a wrong verdict. The "Why" notes explain each one. Do not simplify them away.
3. Use no frameworks, no bundler and no npm dependencies. Use plain HTML, CSS and vanilla JavaScript ES modules. Tests are plain Node scripts using `node:assert/strict`.
4. When input is incomplete or malformed, return partial output that names what is missing. Do not throw or return a blank result.
5. Escape every value that came from an email before writing it into HTML. The whole email is written by the attacker.

---

## 1. Product summary

The app is a single-page tool that runs entirely client-side. An analyst pastes a raw email (headers only, or the full source) or uploads a `.eml` file. The app then does the following:

- It parses the headers and the full MIME body tree.
- It evaluates SPF, DKIM and DMARC the way a receiving server would, including DMARC domain alignment and a header-forgery trust check.
- It walks the Received chain to find the sender's real public IP.
- It extracts IOCs: URLs (including the real destination behind Safe Links or Proofpoint wrappers), domains, IPs, email addresses, and attachments/inline images with SHA-256 and MD5.
- It offers eight URL decoders.
- It flags manipulative language in five categories, including BEC/payment fraud.
- It computes an explainable 0–100 risk score. Every point added carries a reason, and caveats appear when the evidence is too thin to judge.
- It offers opt-in VirusTotal and AbuseIPDB lookups, using the analyst's own API keys and only on an explicit click.
- It exports a defanged, self-contained HTML report and a CSV.
- It lets the analyst change the green accent colour in Settings, with a Reset button.

Deployment and hosting:

- **Live:** GitHub Pages at `https://boode-hub.github.io/Phishing-Analyzer/`. Analysis works there, but lookups do not, because of CORS (see §12).
- **Local:** run `node server.js`, which serves the app and relays the lookups.

---

## 2. Hard constraints

1. **Analysis is local.** Parsing, scoring, hashing, decoding, rendering and report generation make no network request. There is no telemetry and no CDN JavaScript. The only allowed external load is the Google Fonts stylesheet: Inter 400–800 and JetBrains Mono 400–700.
2. **There is no build step.** `index.html` loads `scripts/main.js` as `type="module"`.
3. **Lookups are opt-in.** A request goes to VirusTotal or AbuseIPDB only when the user has saved a key and clicks a lookup button for a specific IOC. Keys are stored in `localStorage` only.
4. **Viewing an email must never contact the sender.** The HTML preview is sandboxed and a CSP blocks remote loads (§11.6).
5. **Exported files are inert.** The HTML report has a CSP of `default-src 'none'`, no scripts, no external loads, and every indicator defanged (§13).
6. **Browser storage can be blocked.** Wrap every `localStorage` access in try/catch; the app must keep working without it.

---

## 3. File structure

```
/index.html                  app shell (all panels, settings modal, inline themable logo)
/favicon.svg                 Glitch Tomoe mark (§15.2)
/favicon-32.png              32×32 raster of the mark
/apple-touch-icon.png        180×180 raster of the mark
/styles/main.css             design system + every component + responsive rules
/scripts/main.js             init, event wiring, analysis pipeline, lookups, export, settings
/scripts/parse-headers.js    header unfolding, ordered list, address extraction, RFC 2047
/scripts/parse-auth.js       SPF/DKIM/DMARC, alignment, trust, Received chain, sender IP
/scripts/ip-utils.js         strict IPv4/IPv6 validation, private ranges, IP extraction
/scripts/parse-body.js       recursive MIME tree, byte-exact decoding, links, deception rule
/scripts/extract-iocs.js     IOC extraction, unwrapped destinations, risk flags, dedup
/scripts/url-decode.js       8 URL decoders + registry
/scripts/analyze-language.js keyword categories, whole-word matching, highlighting
/scripts/score.js            composite score, reasons, reason groups, caveats
/scripts/render.js           DOM rendering for every result panel
/scripts/report.js           defanging, HTML report, CSV report, filename
/scripts/hash-utils.js       SHA-256 (Web Crypto) and hand-written MD5 over bytes
/scripts/theme.js            accent colour palette, apply/load/save
/server.js                   static server + API relay (Node stdlib only)
/cors-worker.js              optional Cloudflare Worker relay
/test-api.html               standalone page to test API connectivity/keys
/sample-data/legitimate-email.eml
/sample-data/phishing-spoofed.eml
/sample-data/phishing-urgency.eml
/tests/*.mjs                 11 plain-Node suites (§17)
/.github/workflows/pages.yml test → deploy pipeline (§16)
/README.md
```

---

## 4. Build order (each step ends green)

1. `ip-utils.js` with `ip.test.mjs` (the validation part).
2. `parse-headers.js` with `headers.test.mjs`.
3. `parse-auth.js` with `auth.test.mjs` (auth part) and the sender-IP tests in `ip.test.mjs`.
4. `url-decode.js` with `url-decode.test.mjs`.
5. `parse-body.js` and `hash-utils.js` with `attachments.test.mjs` and `links.test.mjs` (the parsing part).
6. `extract-iocs.js` with `links.test.mjs` and the IOC tests in `ip.test.mjs`.
7. `analyze-language.js` with `language.test.mjs`.
8. `score.js` with the scoring tests in `auth.test.mjs`, then `runner.mjs` (end-to-end on the three samples).
9. `render.js` and `index.html` + `main.css`, with the renderer smoke tests.
10. `main.js`: pipeline, lookups, settings.
11. `report.js` with `report.test.mjs`.
12. `theme.js` with `theme.test.mjs`; `imports.test.mjs`.
13. `server.js`, `cors-worker.js`, the workflow, and the README.

---

## 5. `ip-utils.js`

Why this module exists: header text is full of dotted-quad lookalikes (message IDs, queue IDs, version strings). One real bug let `15.21.360.10` reach the UI and AbuseIPDB. Nothing becomes an IP without passing validation here.

Exports:

- **`isValidIPv4(v)`**
  - `v` must be a string with exactly 4 dot-separated parts.
  - Each part matches `^\d{1,3}$` and is ≤ 255.
  - Reject leading zeros (`"010"`); some resolvers read them as octal, a known obfuscation trick.
- **`isValidIPv6(v)`**
  - Must contain `:`.
  - A trailing dotted-quad is allowed if it is valid IPv4, and counts as 2 groups.
  - At most one `::`.
  - Every group matches `^[0-9a-f]{1,4}$`.
  - With `::`, the total group count must be ≤ 7; without it, exactly 8.
- **`isValidIP(v)`:** v4 or v6.
- **`isPrivateIP(v)`:** returns false for invalid input.
  - IPv6: `::1`, `::`, `fc`/`fd` (unique local) and `fe8`–`feb` (link local) are private. For an IPv4-mapped address, judge the embedded IPv4.
  - IPv4: `10/8`, `127/8`, `0/8`, `172.16–31`, `192.168`, `169.254` (link local), `100.64–127` (carrier-grade NAT), and `≥224` (multicast/reserved).
- **`isRoutableIP(v)`:** valid and not private. This decides whether an address is worth a reputation lookup.
- **`receivedFromIP(header)`:** the sending host's address from one Received header.
  - Take only the from-clause: `/\bfrom\b([\s\S]*?)(?=\bby\b|\bwith\b|;|$)/i`.
  - Prefer the first valid `[bracketed]` value, with any `IPv6:` prefix stripped.
  - Otherwise use the first valid bare IP in that clause. Microsoft writes `(1.2.3.4)` in parentheses.
  - *Why:* searching the whole header reported the receiving server's by-clause IP as the sender.
- **`findIPs(text)`:** every valid IP, de-duplicated, in order of appearance.
  - IPv4 candidates: `/(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g`.
  - IPv6 candidates: `/(?:IPv6:)?\b([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})/gi`.
  - Every candidate is validated before it is returned.

---

## 6. `parse-headers.js`

`parseHeaders(rawInput)` returns:

```js
{
  raw,              // header block exactly as given (folding intact)
  all,              // { lowercased-name: string | string[] }  (repeats become arrays)
  ordered,          // [{ name (case preserved), value }] in original top-to-bottom order
  from, replyTo, returnPath, to,   // { raw, email (lowercased), name } | null
  subject,          // RFC 2047 decoded
  date, messageId, contentType, xMailer, xOriginatingIp,   // topmost occurrence
  received, authenticationResults, receivedSpf, dkimSignature,  // ALWAYS arrays, topmost first
  xHeaders,         // every x-* header
  duplicated,       // [{ header, count }] for from, subject, reply-to, return-path, date, to when >1
  domains,          // [{ source: From|Reply-To|Return-Path|DKIM, domain, email? }]
}
```

Rules:

- **Header/body boundary:** the first `\r\n\r\n` or `\n\n`, whichever comes earlier. If neither exists, fall back to the first blank line that follows a line containing `:`.
- **Unfolding:** replace `/\r?\n[ \t]+/g` with a single space.
- **`ordered`:**
  - Skip lines with no colon at index > 0.
  - The name must match `/^[\x21-\x39\x3b-\x7e]+$/`, which keeps body lines containing a colon out of the list.
  - Values are trimmed.
- **Single-value headers** use the topmost occurrence, because that is what the mail client displays. A second From or Subject is a forgery signal and is reported through `duplicated`.
- **`extractAddress`:**
  1. Strip parenthesised comments.
  2. Try `Name <email>` first, validated by `/^[^\s<>]+@[^\s<>]+\.[^\s<>]+$/`.
  3. Then a plain address.
  4. Then the fallback `/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/`.
  5. If nothing matches, return `{ raw, email: null, name: null }`.

  Emails are lowercased.
- **RFC 2047 decoding:** `=?charset?B|Q?text?=`.
  - B is base64.
  - Q replaces `_` with a space and decodes `=HH`.
  - Decode the resulting bytes with `TextDecoder(charset)`.
  - On any failure, keep the original text.

---

## 7. `parse-auth.js`: authentication (the core of accuracy)

### 7.1 Design rules (put these in the file header comment)

1. **Only the topmost Authentication-Results header is trusted.** Relays prepend headers, so index 0 was written by your own receiving MTA. Lower headers were supplied upstream and can be forged by the sender.
2. **Read results per clause, never by scanning the whole header.** A bare `/spf=(\w+)/` picks up `spf=pass` from inside a DKIM clause's comment.
3. **Received-SPF's result is the first token** (RFC 7208 §9.1). `result=pass` is a Microsoft form that is also accepted.
4. **Alignment follows DMARC** (RFC 7489 §3.1):
   - SPF aligns the envelope domain with From.
   - DKIM aligns `d=` with From.
   - Relaxed mode compares organizational domains.
   - Reply-To is not a DMARC input and is informational only.

### 7.2 Authentication-Results parsing

- **`splitClauses(s)`:** split on `;` only at the top level. Track `(…)` comment depth and `"…"` quotes, honouring `\"` escapes.
- **`stripComments(s)`:** remove nested `(…)`.
- **authserv-id:** if the first segment, after comments are stripped, does not match `/^[a-z][a-z0-9-]*\s*=/i`, it is the authserv-id; take its first token and shift it off. Otherwise there is no authserv-id. *Why:* Microsoft omits the id and starts with `spf=pass (…)`, and treating that clause as the id silently dropped the SPF result.
- **Each remaining clause:**
  1. Strip comments.
  2. Match `/^([a-z][a-z0-9-]*)\s*=\s*([a-z]+)/i` to get the method and result, both lowercased.
  3. Read properties with `/\b([a-z]+)\.([a-z0-9-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi`. Keys are lowercased as `ptype.prop` (for example `smtp.mailfrom`, `header.d`); quotes are stripped from values.
  4. Store the result as `methods[method] = [{ result, props, raw }]`. It is a list because a message can carry two DKIM results.
- **`normalizeAuthStatus`:** keep `pass, fail, softfail, neutral, none, temperror, permerror, policy` distinct; anything else becomes `unknown`. *Why:* a temporary DNS error is not a pass, and a broken record is not a forged sender.

### 7.3 Received-SPF

- **Result:**
  - The leading token, if it is one of `pass fail softfail neutral none temperror permerror`.
  - Otherwise `result=` read from the comment-stripped text.
  - With neither, the header is ignored.
- **Other fields, from the comment-stripped text:**
  - `client-ip`: `/client-ip\s*=\s*"?([^\s;"]+)/i`
  - `envelope-from`
  - `helo`

### 7.4 DKIM-Signature

Split on `;` and parse `k=v` tags (keys lowercased). A signature without `d=` is ignored. Each returns `{ domain (lowercased), selector: s, algorithm: a, identity: i, raw }`.

### 7.5 SPF resolution: keep both sources

`spf.sources` holds up to two entries.

**Entry 1: Authentication-Results** (the first `spf` clause of the authoritative header)

- `identity`: `smtp.mailfrom`, falling back to `smtp.helo`.
- `ip`: the first valid value of `smtp.remote-ip` or `smtp.client-ip`; otherwise the first IP from `findIPs(clause.raw)`. Microsoft writes `(sender IP is 1.2.3.4)` and Google writes `(… designates 1.2.3.4 as permitted sender)`.
- `domain`: `identityDomain(identity)`.
- `server`: the authserv-id.

**Entry 2: Received-SPF** (the topmost one)

- `ip`: `client-ip` if valid, else the first IP found in the header.
- `identity`: `envelope-from`, falling back to `helo`.
- `domain`: `identityDomain(envelope-from)`.

**Result**

- With no sources:
  - `status: "unknown"`
  - `details: "No SPF result published by the receiving server"`
  - `resultsAgree` and `ipsAgree` are `null`.
- Otherwise the primary is `sources[0]`, and the result is:
  - `status`, `rawResult`, `identity` from the primary.
  - `domain`: the primary's domain **only**. *Why:* a forged Received-SPF must not decide which domain alignment checks.
  - `ip` and `clientIp`: the primary's IP, else any source's IP.
  - `source`: `"Authentication-Results (authserv)"` or the header name.
  - `resultsAgree`: set when both sources exist.
  - `ipsAgree`: set when both sources have an IP.
  - `details`: `[rawResult, "IP x", identity].join(" — ")`.

`identityDomain(identity)`: if it contains `@`, take the domain part; otherwise the identity is already a bare domain (Microsoft's form), so strip `<>`, spaces, `;` and `,` and lowercase it.

### 7.6 DKIM resolution

- **The authoritative header has `dkim` clauses:**
  - Choose the first passing clause, else the first clause.
  - `domain`: `realDomain(header.d)`, else `realDomain(header.i without its leading @)`, else the first signature's domain.
  - `domains`: every clause's `realDomain(header.d)`.
  - `signatureCount`, `source: "Authentication-Results (id)"`.
  - `details`: `"result — d=domain"`.
  - `realDomain(v)` returns null for `none|null|n/a|-|unknown` or any value without a dot. *Why:* Microsoft writes `header.d=none`, which produced a bogus "DKIM domain (none) is not aligned" finding.
- **No clauses, but signatures present:**
  - `status: "unverified"`
  - `details: "Signature present (d=x) but no verification result"`
- **Neither:**
  - `status: "none"`
  - `details: "Message carries no DKIM signature"`

### 7.7 DMARC resolution

- **A `dmarc` clause exists:**
  - `status`: the normalised result.
  - `policy`: `header.p`.
  - `fromDomain`: `header.from`.
  - `details`: `"result — header.from=x, p=y"`.
- **Otherwise:**
  - `status: "unknown"`
  - `details: "No DMARC result published by the receiving server"`

### 7.8 Organizational domain (`orgDomain`, exported)

1. Lowercase the name, strip any trailing dot, and split into labels.
2. With 2 or fewer labels, return them joined.
3. If the last two labels are in `MULTI_PART_SUFFIXES`, return the last three.
4. Otherwise return the last two.

Mark this with a `ponytail:` comment: it is a compact list, not the full Public Suffix List. The exact 101 entries:

```
co.uk org.uk ac.uk gov.uk net.uk sch.uk me.uk ltd.uk
com.au net.au org.au edu.au gov.au id.au
co.nz net.nz org.nz govt.nz ac.nz
co.za org.za net.za gov.za ac.za
co.jp ne.jp or.jp ac.jp go.jp ad.jp
com.br net.br org.br gov.br edu.br
com.cn net.cn org.cn gov.cn edu.cn ac.cn
co.in net.in org.in gen.in firm.in ind.in gov.in
com.mx com.ar com.co com.pe com.ve com.ec com.uy
com.sg com.hk com.tw com.my com.ph com.vn com.bd
com.tr com.pl com.ua com.ru org.ru net.ru
co.kr or.kr ne.kr go.kr
co.il org.il net.il ac.il gov.il
co.th in.th ac.th go.th
co.id or.id ac.id go.id web.id
com.sa com.eg com.ng com.pk com.kw com.qa
co.ke co.tz co.ug
com.es com.pt com.gr com.ro com.hr com.cy
```

### 7.9 Domain alignment

Inputs:

- `fromDomain`: the domain part of `headers.from.email`.
- `fromOrg`: `orgDomain(fromDomain)`.

Entries:

- **SPF entry:** `source "Return-Path"`, domain = `spf.domain` or the Return-Path domain, `dmarcRelevant: true`, `mechanismPassed: spf.status === "pass"`, note `"SPF alignment: the envelope sender DMARC checks against From"`.
- **DKIM entries:** one per unique domain in `dkim.domains`, falling back to the signature domains.
  - Source is `"DKIM"`, or `"DKIM (selector|domain)"` when there are several.
  - `dmarcRelevant: true`, `mechanismPassed: dkim.status === "pass"`.
  - Note: `"DKIM alignment: the signing domain DMARC checks against From"`.
- **Reply-To entry:** `dmarcRelevant: false`, `mechanismPassed: false`, note `"Not used by DMARC — informational only"`.

`buildAlignment` returns `{ source, domain, orgDomain, strict, relaxed, aligned, mode, dmarcRelevant, mechanismPassed, note }`:

- `strict`: the domain equals `fromDomain`, case-insensitive.
- `relaxed`: both org domains exist and are equal. This is symmetric: a subdomain in From with the org domain in the envelope still aligns.
- `aligned`: strict or relaxed.
- `mode`: `strict`, `relaxed` or `none`.

The function returns:

- `fromDomain`, `fromOrgDomain`, `entries`, `domains`, `aligned`.
- `mismatches`: one line per DMARC-relevant entry that did not align: `"<source> domain (<domain>) is not aligned with From domain (<fromDomain>)"`.
- **`dmarcAligned`:** `null` if there are no DMARC-relevant entries. Otherwise true when **some entry is both aligned and has `mechanismPassed`**. Alignment alone proves nothing.
- `replyToMismatch`: true when the Reply-To entry exists and is not aligned.
- `replyToDomain`.
- `mismatchWarning`: `"Domain alignment failure: …"` when there are mismatches.

### 7.10 Header trust

- **Forged lower header:** when there are two or more A-R headers, check spf, dkim and dmarc. If a lower header's first result for a method normalises to `pass` while the top one does not, warn: ``A lower Authentication-Results header claims ${M}=${claim} while the receiving server recorded ${M}=${top}. Lower headers can be forged by the sender.``
- **Duplicates:** for each `headers.duplicated` entry, warn ``${count} ${Formatted-Name} headers present — a message should carry only one.``
- **Return value:** `{ authservId, authResultsCount, usedTopmost, warnings }`.

`crossCheckSpf(spf, senderIp)` adds two more possible warnings:

- **Results differ:** ``SPF headers disagree: Authentication-Results says ${AR} but Received-SPF says ${RS}. Authentication-Results is written by the receiving server and is the one used.``
- **IPs differ:** ``SPF headers evaluated different IPs: Authentication-Results checked ${a}, Received-SPF checked ${b}.``

It also sets `spf.senderPublicIp`, and `spf.matchesSenderIp` (true, false, or null). A different sender IP is **not** a warning, because ESPs and forwarding legitimately evaluate a relay.

### 7.11 Received chain

`parseReceivedChain(received[])`: index 0 is the last hop (your server); the last element is the origin. For each header:

- `number = total - index`, so hop 1 is the origin.
- `isOrigin`: this is the last element.
- `raw`.
- `ip`: `receivedFromIP`.
- `from`: `/\bfrom\s+([^\s;()\[\]]+)/i`; `by` uses the same pattern with `by`.
- `date`: the text after the last `;`; `timestamp` is `Date.parse` of it, or null.
- `privateIp`.

Warnings (only these two; *why:* the old heuristic flagged every non-.com relay):

- The origin hop has a private IP and the chain has more than 1 hop: `"Message originated from a private/reserved IP address"`.
- The next-received hop's timestamp is more than 60 s earlier than this hop's: `"Timestamp is later than the hop that follows it"`.

`suspicious` is true when a hop has any warning.

### 7.12 Sender IP (`resolveSenderIp`, exported)

Walk from the origin (the end of the array) toward the receiver, skipping hops without a valid IP:

- The first valid IP becomes `originIp`; if it is private, also `privateIp`.
- Each later private IP increments `privateHopsSkipped`.
- The first routable IP becomes `publicIp` and `publicHop`; stop there.

This returns `{ publicIp, publicHop, privateIp, originIp, privateHopsSkipped }` and never throws. A non-array input returns all nulls.

*Why:* the origin hop is often a NAT'd workstation or an internal relay, and a private address identifies nobody.

### 7.13 Overall status

- **failures** (one per condition): SPF fail; DKIM fail; DMARC fail; `dmarcAligned === false` (the mismatch lines are added to issues).
- **softIssues:**
  - SPF softfail, permerror or none;
  - DKIM none or permerror;
  - DMARC none;
  - `replyToMismatch`;
  - each trust warning.
- **Issue only:** temperror adds an issue but no count.

The level is:

- `fail` if failures ≥ 2;
- `suspicious` if failures = 1, softIssues ≥ 2, or any issue exists;
- otherwise `pass`.

### 7.14 `parseAuth(headers)` returns

`{ mechanisms: { spf|dkim|dmarc: { status, details, source } }, spf, dkim, dmarc, signatures, domainAlignment, receivedChain, senderIp, trust, overallStatus }`

---

## 8. `url-decode.js`

Each decoder takes a string and returns `{ output, note }`, or `null` when it has nothing to do. None makes a network request. `MAX_LAYERS = 5`.

- **`percentDecode`**
  - Loop while `/%[0-9a-f]{2}/i` matches, up to 5 layers.
  - Use `decodeURIComponent`; if it throws on malformed UTF-8, replace each `%HH` byte-wise.
  - Stop when nothing changes.
  - Note when more than 1 layer: ``${n} layers of encoding — multi-encoding is a filter-evasion technique``.
- **`unwrapRedirect`**
  - Repeat `unwrapOnce` up to 5 times, collecting a chain of `via` labels.
  - If a step is `partial`, return immediately: `{ output: step.url, note: "<chain joined ' → '>. <partial text>" }`. This check comes **before** the unchanged-URL check.
  - Stop when the URL no longer changes.
  - Otherwise the note is ``Unwrapped: a → b``.
  - `unwrapOnce` (parse with `new URL`; `null` if it fails):
    - **Microsoft Defender Safe Links:** host ends with `safelinks.protection.outlook.com`; target in the `url` param.
    - **Proofpoint URL Defense v3:** host `urldefense.com`, path starts `/v3/__` (algorithm below).
    - **Proofpoint URL Defense v2:** host ends `urldefense.proofpoint.com`, path `/v2/`. Take param `u`, replace `-`→`%` and `_`→`/`, then decode.
    - **Proofpoint URL Defense v1:** path `/v1/`; decode param `u`.
    - **Google redirect:** host matches `/(^|\.)google\.[a-z.]+$/`, path `/url`; target in param `q` or `url`.
    - **Facebook link shim:** host `/^l[m]?\.facebook\.com$/`, path `/l.php`; param `u`.
    - **Barracuda Link Protection:** host `linkprotect.cudasvc.com`; param `a`.
    - **Cisco Secure Email:** host `secure-web.cisco.com`; the last path segment, decoded, must start `http(s)://`.
    - **Mimecast URL Protect:** host `/(^|\.)mimecast\.com$/`, path contains `/s/`. Return `{ url, via, partial: "The destination is held on Mimecast's servers and cannot be recovered from the link itself." }`.
    - **Generic open redirect:** any query value matching `/^(https?:\/\/|www\.)/i` that differs from the URL. `via` is ``redirect parameter "${key}" on ${host}``.
  - **Proofpoint v3 algorithm:**
    1. Match `/v3\/__(.+?)__;(.*?)!/`.
    2. The URL part is `decodeURIComponent(m[1])`.
    3. `m[2]` is base64url of the removed characters; decode it as UTF-8 and spread into a character array.
    4. Replace `/\*\*(.)|\*/g` from left to right:
       - `**X` takes the next `indexOf(X in "A–Z a–z 0–9 - _") + 2` characters;
       - a single `*` takes the next 1 character (or stays `*` if none are left).
- **`base64Decode`**
  - Percent-decode first.
  - Split on `[/?&=#;,:.]+`.
  - Keep tokens of length ≥ 8 matching `^[A-Za-z0-9+/_-]+={0,2}$` that contain a digit or mixed case.
  - Decode as base64url and keep only `readableText` results. Output lines are `token  →  text`.
  - Note when the decoded text contains `@`: `"An email address was hidden in the link — typically the targeted recipient"`.
  - `readableText(bytes)`:
    - strict UTF-8 decode;
    - length ≥ 4;
    - ≥ 95% printable (≥ 0x20, not 0x7f, not 0x80–0x9f);
    - contains `[a-z]{3}` (case-insensitive).
  - The base64 decoder rejects a length where `len % 4 === 1`.
- **`hexDecode`:** percent-decode first; find runs matching `/(?:[0-9a-f]{2}){6,}/gi` and keep the readable ones. A hash is not readable, so it is not reported.
- **`htmlEntityDecode`:**
  - Numeric entities: `&#N;` and `&#xH;` (code point > 0 and ≤ 0x10FFFF).
  - Named entities: `amp lt gt quot apos nbsp sol colon period commat quest equals`.
- **`escapeDecode`:** `\u{H…}`, `\uHHHH`, `\xHH`.
- **`punycodeDecode`**
  - Applies to a URL host containing `xn--` labels.
  - Decode each label with a hand-written RFC 3492 decoder (base 36, tMin 1, tMax 26, skew 38, damp 700, initial n 128, bias 72). Browsers expose no toUnicode.
  - Output: the URL with the Unicode host.
  - Note: ``Displays as ${host} — non-ASCII characters: а U+0430, …``.
- **`decodeAll`**
  1. Up to 5 passes, applying in order `unwrap`, `HTML entities`, `escapes`, `URL %XX`, and recording each step that changed the value.
  2. Then append `Base64 inside:\n…`, `Hex inside:\n…`, and the punycode note.
  3. Return `null` if nothing was found.
  4. Otherwise the note is ``Applied: step → step``.
- **`URL_DECODERS` registry** (order and labels exact):
  - `all` "Decode all"
  - `unwrap` "Unwrap Safe Links / redirect"
  - `percent` "URL %XX"
  - `base64` "Base64"
  - `punycode` "Punycode"
  - `html` "HTML entities"
  - `hex` "Hex"
  - `escape` "\u \x escapes"
- `detectEncodings(url)`: the ids (excluding `all`) whose `safeRun` returns non-null. `safeRun(fn, url)` is a try/catch that returns null on error.

---

## 9. `parse-body.js` and `hash-utils.js`

### 9.1 MIME

`parseBody(raw)` returns `{ text, html, raw, contentType, attachments, links }`.

- **Boundary:** the first `\r\n\r\n` (+4) or `\n\n` (+2).
- **`parseMimePart(headers, body)`:** recursive. Each part has:
  - `mime` (lowercased type),
  - `charset` (default utf-8),
  - `encoding` (default 7bit),
  - `dispositionType`,
  - `filename`: the RFC 2047-decoded `filename` from Content-Disposition, else `name` from Content-Type,
  - `contentId` (with `<>` stripped).

  A `multipart/*` part is split on `--boundary`: skip the preamble, stop at the `--` epilogue, strip the leading newline, split head from body, and recurse. A leaf gets `bytes = decodeToBytes(body, encoding)`.
- **`decodeToBytes`:**
  - base64: strip non-base64 characters, `atob`, then latin1 to bytes (on failure, use the raw latin1).
  - quoted-printable: remove soft breaks `=\r?\n`, decode `=HH` byte-wise, and take other characters as `& 0xff`.
  - Anything else: latin1 to bytes.

  *Why bytes:* running `atob` output back through TextEncoder corrupts every byte above 0x7F, so every image or executable hash was wrong.
- **File parts:**
  - A part is a file when it is:
    - disposition `attachment`;
    - any part with a filename or Content-ID;
    - any non-root leaf that is not `text/*`.

    *Why:* inline images and tracking pixels are exactly what the analyst wants hashed.
  - Each file is recorded as `{ filename, contentType, size, bytes, contentId, inline }`.
  - `filename` falls back to `inline-<cid>`, or `unnamed-part.<subtype>`.
  - `inline` is true for disposition inline, or when a Content-ID is present.
- **Text parts:**
  - Decode with `TextDecoder(charset)`, falling back to utf-8.
  - `text/html` is appended to `html`, and its links are extracted.
  - Other `text/*` is appended to `text`, and plain URLs are extracted.
  - If `text` is empty, `text = stripHtml(html)`, so an HTML-only message still gets language analysis.
  - `stripHtml` removes script and style blocks and tags, decodes the basic entities, and collapses whitespace.

### 9.2 Links

- **Anchors:** `/<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi`.
  - Use `[\s\S]*?` so anchors wrapping other markup are captured.
  - The href is entity-decoded with `htmlEntityDecode`.
  - The text is `stripHtml` of the inner markup.
  - Each is recorded as `{ href, text: text || href, isMismatch }`.
- **Remote resources:** `/<(?:img|script|iframe|embed|source|input|body|table|td)\b[^>]*?\b(?:src|background)\s*=\s*["'](https?:\/\/[^"']+)["']/gi`, recorded as `{ href, text: "", isMismatch: false, resource: true }`.
- **Plain text:** `/https?:\/\/[^\s<>"]+/gi`.
- **Deception rule (`isDeceptiveLink(text, href)`):** a link is deceptive **only** when all of these hold:
  - the visible text itself looks like a URL or domain (`hostOf(text)` is non-null);
  - the href is not `mailto:`, `tel:` or `#`;
  - the org domain of the text's host differs from the org domain of the href's host **after `unwrapRedirect`**.

  `hostOf` accepts `http(s)://…` or a bare `(www.)?label(.label)+(/…)?`, and strips `www.`.

  *Why:* flagging "View invoice" made every newsletter look like phishing, and a Safe Links rewrite of the same destination is not deception.

### 9.3 Hashing

- **`sha256(str)`:** TextEncoder, then `sha256Bytes`.
- **`sha256Bytes(bytes)`:** `crypto.subtle.digest`, output as lowercase hex.
- **`md5(str)` and `md5Bytes(bytes)`:** a hand-written RFC 1321 MD5 over bytes, output as lowercase hex. Tests compare both against `node:crypto`.

---

## 10. `extract-iocs.js`

`extractIOCs(headers, body)` returns `{ urls, domains, ips, emails, attachments, mismatchedLinks }`.

### 10.1 From headers

- **Emails:** From, Reply-To and Return-Path, with that `source`.
- **IPs:**
  - `X-Originating-IP` (every value from `findIPs`) and `receivedFromIP` of each Received header.
  - Merge by value into `{ value, source, allSources }`; source is `X-Originating-IP` if present, else `Received`.
- **Message-ID domain:** `@([^>]+)`, source `Message-ID`.

### 10.2 From the body

- **URLs:** `/https?:\/\/[^\s<>"')\]]+/gi` over the text (source `Body`).
- **Link merging:** for each `body.links` entry, merge it into an existing URL (OR the `isMismatch` flags; a resource sets source `"Remote resource (loads on open)"`), or add it with `text` and `isMismatch`. Mismatched links are also pushed to `mismatchedLinks` as `{ text, href }`.
- **Emails:** `/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g`, lowercased.
- **IPs:** `findIPs(text)`, source `Body`.
- **Attachments:** `{ value: filename, contentType, size, source: Inline|Attachment, inline, contentId, bytes }`. `main.js` adds `sha256` and `md5` later.

### 10.3 Unwrapped destinations

For each URL where `unwrapRedirect` yields a different `http(s)` output that is not already listed, add:

```
{ value: output, source: note with "Unwrapped: " replaced by "Unwrapped via ", isMismatch: false, unwrappedFrom: original }
```

*Why:* otherwise every risk check ran against the gateway host and never saw the punycode or raw-IP destination. `isMismatch` stays false so the deception is not scored twice.

### 10.4 Domains

Collect domains from the From, Reply-To and Return-Path addresses, and from every URL hostname (source `URL`, or `Unwrapped URL`). Lowercase them, strip trailing dots, and skip IP literals and dotless names.

### 10.5 Dedup and flags

- Every IOC gets `riskFlags: [{ type: high|medium|low, label }]` and `risks: [{ type, level, message }]`.
- `defang(v)` replaces `http` with `hxxp` and `.` with `[.]`.
- The helper **`isDomainOrSubdomain(host, domain)`** matches when `host === domain` or `host.endsWith("." + domain)`. *Why:* a substring test made `t.co` match `microsoft.com`.

**URLs** (dedup by value):

| Check | Flag label | Level | risk type / message |
|---|---|---|---|
| host is/under a shortener | `URL Shortener` | medium | `url-shortener` / "URL uses a URL shortener service" |
| `xn--` in host | `Punycode` | high | `punycode` / "Domain contains punycode (possible homograph attack)" |
| host is valid IPv4, or `[IPv6]` | `IP URL` | high | `ip-url` / "URL uses raw IP address instead of domain" |
| `isMismatch` | `Mismatch` | high | `mismatch` / "Link text doesn't match actual URL" |

Shorteners (26): `bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly adf.ly j.mp tr.im tiny.cc lnkd.in db.tt qr.ae cur.lv ity.im q.gs po.st su.pr fire.to bit.do mcaf.ee link.tl go.usa.gov go2.me shorl.com`

**Domains** (dedup): `xn--` gives `Punycode` high, with the message "Domain contains punycode".

**IPs** (dedup):

- Source `X-Originating-IP` gets the medium flag `Originating IP` ("X-Originating-IP header (may be spoofed)").
- `private = isPrivateIP(value)`. When true, add the low flag `Private/Reserved`, and the renderer offers no lookup buttons.

**Emails** (dedup): a disposable domain (matched with `isDomainOrSubdomain`) gets the medium flag `Disposable` ("Uses disposable email domain").

Disposable domains (12): `tempmail.com 10minutemail.com guerrillamail.com mailinator.com throwaway.email temp-mail.org fakeinbox.com trashmail.com yopmail.com sharklasers.com guerrillamail.info grr.la`

**Attachments:**

- A double extension (any pattern, case-insensitive) gets the high flag `Double Extension`: `\.pdf\.exe \.doc\.exe \.xls\.exe \.zip\.exe \.pdf\.scr \.doc\.scr \.xls\.scr \.jpg\.exe \.png\.exe \.gif\.exe \.txt\.exe`.
- A risky last extension gets the high flag ``Risky: ${ext}``: `.exe .scr .js .hta .vbs .bat .cmd .pif .msi .com .dll .ps1 .sh .bash .jar .app .dmg`.
- Either sets `risky = true`.

---

## 11. `analyze-language.js`

### 11.1 Categories (weights, labels, exact keywords)

| key | label | weight |
|---|---|---|
| urgency | Urgency | 1.0 |
| authority | Authority/Fear | 1.2 |
| financial | Financial/Fraud | 1.1 |
| credential | Credential Harvesting | 1.3 |
| bec | BEC / Payment Fraud | 1.4 |

**urgency (29):** act now, immediately, urgent, as soon as possible, right away, within 24 hours, within 48 hours, deadline, expires soon, account will be suspended, account will be locked, account will be closed, verify now, confirm now, update now, limited time, time sensitive, action required, immediate action, respond immediately, your account expires, final warning, last chance, don't delay, hurry, act fast, time running out, expires today, expires in

**authority (21):** legal action, lawsuit, court, attorney, law enforcement, irs, tax authority, government, federal, official notice, your account has been compromised, unauthorized access, security breach, suspicious activity, final notice, cease and desist, penalty, violation, compliance required, mandatory, obligatory

**financial (27):** wire transfer, bank transfer, swift, iban, gift card, itunes gift card, amazon gift card, cryptocurrency, bitcoin, btc, wallet address, invoice payment, payment request, outstanding payment, banking details, account details, routing number, update your payment information, payment method expired, credit card expired, billing information, refund, reimbursement, compensation, transaction, payment confirmation, order confirmation

**credential (18):** click here to verify, click here to confirm, verify your account, confirm your password, confirm your identity, login to secure, login to verify, sign in to verify, update your password, reset your password, validate your account, authenticate your account, security check, account verification, confirm login details, update account information, verify credentials, secure your account now

**bec (79):** new bank details, updated bank details, change of bank details, change in bank details, bank details have changed, bank details has changed, our bank account has changed, changed our bank, new bank account, new account details, updated account details, change of payment details, updated payment details, new payment details, new remittance details, update the beneficiary, new beneficiary, beneficiary details, beneficiary account, wire instructions, wiring instructions, payment instructions, sort code, ach transfer, direct deposit, update my direct deposit, change my direct deposit, payroll change, payroll update, overdue invoice, past due invoice, unpaid invoice, outstanding invoice, overdue payment, process the payment, process this payment, release the payment, settle the invoice, proof of payment, remittance advice, pro forma invoice, proforma invoice, same day payment, same-day payment, transfer the funds, wire the funds, urgent wire, urgent payment, vendor payment, are you available, are you at your desk, are you in the office, quick favor, quick favour, quick task, i need a favor, i need a favour, can you handle a task, keep this confidential, keep this between us, strictly confidential, confidential transaction, confidential matter, sensitive transaction, do not discuss this, don't discuss this, don't mention this, i'm in a meeting, i am in a meeting, can't talk right now, cannot talk right now, reply by email only, send me your cell, send me your mobile number, purchase gift cards, buy gift cards, scratch the back, send me the codes, send the codes

Do **not** include "fine": it matches "define" and legal boilerplate.

### 11.2 Matching

- **Whole words only.** For each keyword, use `new RegExp("(?<![\\w])" + escapeRegExp(keyword) + "(?![\\w])", "gi")`. *Why:* substring matching turned "first" into `irs`, "courtesy" into `court` and "swiftly" into `swift`.
- **Per category:**
  - de-duplicate by `index-phrase`;
  - `score = min(count × weight × 10, 100)`, rounded;
  - store `{ label, score, matches: [{ phrase, index, length }], matchCount, weight }`.
- **`analyzeLanguage(text)` returns** `{ categories, totalScore (sum capped at 100), detectedLanguage, languageMismatch: false, highlightedText, summary, matches (all, with category) }`. Empty input returns empty categories and `summary: "No text provided for analysis"`.
- **`detectLanguage`:** a word-frequency check over en, es, fr and de stop-word lists. Thresholds: en 0.2, the others 0.25. With fewer than 10 words, return `unknown`.
- **`highlightedText`:**
  - Sort matches and merge any that overlap.
  - Escape the text between matches.
  - Wrap each match as `<mark class="highlight-<category>" title="<label>">`.
  - Labels: Urgency indicator, Authority/Fear tactic, Financial fraud indicator, Credential harvesting attempt, BEC / payment fraud indicator.
- **`summary`:** `"Detected: 2 urgency phrases, 1 bec / payment fraud phrase."`, or `"No suspicious language patterns detected."` when nothing matched.

---

## 12. `score.js`

`calculateScore(auth, iocs, languageAnalysis, headers?)` returns:

```js
{ tier, score, reasons (unique), reasonGroups: { auth, iocs, language },
  caveats, breakdown: { auth, authentication /* alias */, iocs, language } }
```

**Two rules to state in the file header:**

1. Cap each sub-score to 0–100 **before** weighting. *Why:* 20 newsletter shortener links (160 raw points) pushed a fully authenticated message into Suspicious.
2. **Every point added emits a reason.**

**Total:** `round(min(auth×0.6 + iocs×0.25 + lang×0.15, 100))`. Tiers: **≥ 60 High Risk**, **≥ 30 Suspicious**, otherwise **Low Risk**. Language alone can never reach a tier.

### 12.1 Authentication points (with exact reasons)

**SPF**

| Status | Points | Reason |
|---|---|---|
| fail | 30 | "SPF failed — the sending server is not authorized for this domain" |
| softfail | 18 | "SPF soft-failed — the sending server is not authorized" |
| permerror | 8 | "The sending domain's SPF record is malformed" |
| neutral | 5 | "The sending domain's SPF record makes no assertion" |
| none | 5 | "The sending domain publishes no SPF record" |
| temperror | 2 | "SPF could not be evaluated (temporary DNS error)" |
| unknown | 2 | "No SPF result was recorded by the receiving server" |

**DKIM**

| Status | Points | Reason |
|---|---|---|
| fail | 25 | "DKIM signature failed verification — the message was altered or forged" |
| permerror | 8 | "DKIM signature is malformed" |
| unverified | 4 | "The message is signed but the receiving server did not verify it" |
| none | 5 | "The message carries no DKIM signature" |
| unknown | 2 | "No DKIM result was recorded by the receiving server" |

**DMARC**

| Status | Points | Reason |
|---|---|---|
| fail | 35 | "DMARC failed — the message does not authenticate as its From domain" |
| none | 5 | "The sending domain publishes no DMARC policy" |
| unknown | 2 | "No DMARC result was recorded by the receiving server" |

**Other adjustments**

- `dmarcAligned === false`: +30, with each mismatch line as a reason.
- `replyToMismatch`: +8, reason ``Reply-To points at a different domain (${replyToDomain}) than From``.
- Each trust warning: +12, with the warning as its reason.
- SPF, DKIM and DMARC all pass **and** `dmarcAligned === true`: −10. The auth score never goes below 0.

### 12.2 IOC points

`diminishing(count, first, rest) = count ≤ 0 ? 0 : first + min(count−1, 4) × rest`

- **URLs with a high risk:** `diminishing(n, 25, 12)`.
- **URLs with medium but no high:** `diminishing(n, 8, 4)`.
- **URL reasons**, each added once if any URL qualifies:
  - mismatch: "A link's display text does not match its actual destination"
  - ip-url: "A link points at a raw IP address instead of a domain"
  - punycode: "A link uses a punycode domain (possible homograph attack)"
  - medium URLs present: ``${n} link(s) use(s) a URL shortener, hiding the destination``
- **High-risk attachments:** `diminishing(n, 30, 15)`, reason ``Executable or double-extension attachment: a, b, c`` (first 3 names).
- **Punycode domains:** `diminishing(n, 20, 10)`, reason "A punycode domain was found in the message".
- **Any disposable email:** +10, reason "A disposable email address appears in the message".

### 12.3 Language points

- Weights: urgency 0.5, authority 0.5, financial 0.8, credential 0.8, bec 1.0 (other 0.5).
- Sum `category.score × weight` and round.
- Each category with matches adds a reason ``${n} ${label}${n>1?"s":""} detected``, where the labels are: `urgency phrase`, `authority/fear phrase`, `financial/fraud phrase`, `credential-harvesting phrase`, `BEC / payment-fraud phrase`.

### 12.4 Caveats (a low score means "cannot judge", not "safe")

- **Forwarded message** (subject matches `/^\s*(fw|fwd)\s*:/i`): "This looks like a forwarded message. Its headers describe the forward, not the original — attach or paste the original message source for a reliable verdict."
- **No auth** (no A-R headers and no SPF sources) **and no Received chain:** "No authentication or routing headers were found, so sender authenticity could not be checked. A low score here is not a clean result."
- **Otherwise, no auth only:** "No SPF, DKIM or DMARC results were recorded, so sender authenticity could not be verified."

### 12.5 Expected sample outcomes

- `legitimate-email.eml` → Low Risk.
- `phishing-spoofed.eml` → High Risk.
- `phishing-urgency.eml` → score > 0.

---

## 13. `report.js`: exports

### 13.1 Defanging (exported)

- **`defangUrl(v)`:**
  - Split into scheme, host and rest.
  - The scheme `http…` becomes `hxxp…`, and `ftp` becomes `fxp`.
  - Output: `scheme[://]` + `defangHost(host)` + `defangText(rest)`.
  - The rest is defanged too, because Safe Links carries the real domain in its query and chat tools auto-link bare domains.
  - A value that is not a URL goes through `defangText` instead.
- **`defangHost`:** `@`→`[@]`; colons inside `[ipv6]` become `[:]`; dots outside brackets become `[.]`.
- **`defangDomain`:** `.`→`[.]`.
- **`defangIp`:** IPv6 `:`→`[:]`, otherwise `.`→`[.]`.
- **`defangEmail`:** `local[@]domain[.]tld`.
- **`defangText(v)`:** a single regex pass over URLs, then emails, dotted quads, and domains (`/\b(?:https?|ftp):\/\/[^\s<>"'\`)\]]+|[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi`).
  - Leave these tokens as they are:
    - auth property names matching `/^(header|smtp|policy|body)\.[a-z-]+$/i`;
    - tokens ending in a file extension from: `exe pdf doc docx docm xls xlsx xlsm ppt pptx rar 7z gz tar cab js vbs vbe wsf hta html htm iso img lnk scr bat cmd ps1 dll jar msi txt csv png jpg jpeg gif svg eml msg ics json xml py sh`.
  - `.zip`, `.mov` and `.one` are real TLDs and are deliberately absent from that list.
- **Hashes are never defanged.**

### 13.2 `reportFilename(analysis, ext, now)`

The name is `phishing-report_YYYY-MM-DD_<slug>.<ext>`.

1. Build the slug from the subject: NFKD normalise, drop non-ASCII, lowercase, and turn each non-alphanumeric run into `-`.
2. Trim any leading or trailing `-`.
3. Cut to 40 characters at a word boundary.
4. If the slug ends up empty, use `email`.

### 13.3 `buildHtmlReport(analysis, { lookups: Map, now })`

A single self-contained HTML file in the app's visual style.

**Head**

- `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`
- `<meta name="referrer" content="no-referrer">`
- Inline `<style>` only. No scripts, fonts or images; the logo is inline SVG with the default green.

**Escaping:** every value is escaped with `&<>"'`. Every indicator is defanged.

**Meters:** every meter width goes through `percent()` (a finite number clamped to 0–100, rounded; otherwise 0).

**Structure**

1. **Header:** the logo, "Phishing Email Analyzer" / "IOC report", and "Generated YYYY-MM-DD HH:MM UTC".
2. **Hero:**
   - Tone: bad (High Risk), warn (Suspicious) or good (Low Risk).
   - Tier, score/100 and a meter.
   - The defanged subject and From.
   - Count chips for URL, Domain, IP, Email, File, and Deceptive link (only when present), with zero counts dimmed.
3. **TOC:** in-page anchors only, to `#message #verdict #authentication #sender-path #indicators`.
4. **Defang note:** explains `hxxp[://] [.] [@] [:]`, says to re-fang before using the values in tooling, and that hashes are unmodified.
5. **Message:** a key/value list of Subject, From, Reply-To ("None — replies go to From" when absent), Return-Path, To, Date, Message-ID and Mailer.
6. **"Why it scored this way":** caveat callouts, then three score cards (Authentication, Indicators, Language), each with its number, a meter coloured by severity (≥ 60 bad, ≥ 30 warn) and its reason list ("Nothing found" when empty).
7. **Authentication:**
   - Mechanism cards with status pills.
   - An "SPF by header" table (Header, Result, Evaluated IP, Identity) plus an agree/disagree callout.
   - A "Domain alignment" table (Check, Comparison `X (d) = From (d)`, Result pill: Aligned · strict / Aligned · relaxed + "both under org" / Not aligned / for Reply-To Same domain or Differs) with "but SPF/DKIM did not pass" when relevant, then the dmarcAligned callout.
   - "Header trust" warnings.
8. **Sender path:**
   - Cards for Originating IP (primary), First hop (private) and Last relay, each with any VT or AbuseIPDB lookup summary.
   - A "Received chain" table sorted by hop number (Hop, From, By, IP, Time).
9. **Indicators of compromise:**
   - **URLs:** URL cards grouped with `groupUrls`, which nests unwrapped destinations under their wrapper as "Real destination" instead of listing them twice.
   - **Domains, IPs, Emails:** tables. The VirusTotal and AbuseIPDB columns appear only when at least one row has a lookup result.
   - **Attachments:** file cards with name, inline pill, flags, Type, Size, SHA-256, MD5, and VT if looked up.
   - **Deceptive links:** a table of Displays → Actually goes to.
10. **Footer:** "Generated locally by Phishing Email Analyzer — no data left the analyst's browser. This file loads nothing and runs no scripts."

**Report CSS**

- Tokens:
  - `--bg:#0d1117; --panel:#161b22; --elev:#21262d; --surface:#30363d; --border:#30363d`
  - `--text:#e6edf3; --text2:#8b949e; --muted:#6e7681`
  - `--accent/--good:#9fef00`, `--bad:#ff7b72`, `--warn:#d29922`, each with `-bg` (≈ .08–.1 alpha) and `-border` (≈ .25–.3 alpha)
  - `--radius:10px`
  - System font stacks with Inter and JetBrains Mono first; no web fonts are loaded.
- Tables become labelled cards on mobile (`td[data-label]`).
- `@media (max-width:720px)`: grids go to one column, and tables turn into cards with `td::before{content:attr(data-label)}`.
- `@media print`: switch to a light palette (white panels, `--text:#1f2328`, darker good/bad/warn) with `print-color-adjust: exact`.

### 13.4 `buildCsvReport(analysis, { lookups, includeRaw })`

- **Columns, fixed:** `type, indicator, source, risk_flags, details, virustotal, abuseipdb`, plus `indicator_raw` only when `includeRaw` is set.
- **Rows:**
  - `url`: details `unwrapped from <defanged>`.
  - `domain`.
  - `ip`: details `private/reserved address`.
  - `email`.
  - `filename`: details `type; size; inline`.
  - `sha256` and `md5`: details `file: name`, looked up by filename.
  - `deceptive_link`: risk `Mismatch`, details `displays: <defanged text>`.
- **Format:**
  - Flags are joined with `; `.
  - The file starts with a UTF-8 BOM `﻿` and uses CRLF line endings.
  - RFC 4180 quoting: quote a cell containing `" , \r \n` or leading/trailing whitespace, and double any `"`.
- **Formula injection guard:** prefix `'` to any cell starting with `= + - @ \t \r`.

---

## 14. UI: `index.html`, `render.js`, `main.js`

### 14.1 Page layout (top to bottom)

1. **Trust banner:** a shield icon and "All analysis runs locally in your browser. Nothing is uploaded unless you explicitly use VirusTotal/AbuseIPDB with your own API key."
2. **Header:**
   - `<h1>` with the **inline** Glitch Tomoe SVG (class `app-logo`, 30×30, `fill`/`stroke="currentColor"`, `color: var(--accent)`, ids prefixed `logo-`). It is inline so it follows the theme colour.
   - Then "Phishing Email Analyzer".
   - A Settings button (gear icon + `<span class="btn-label">Settings</span>`, `aria-label="Settings"`).
3. **Email Input panel:**
   - A textarea `#email-input` with placeholder "Paste raw email headers or full .eml source here...".
   - A file input `#file-upload` accepting `.eml,.txt,.msg`, with the hint ".eml and .txt supported. .msg coming soon."
   - Buttons "Analyze Email" (primary, search icon) and "Clear".
   - A `#input-status` message.
4. **Export bar** `#export-section` (hidden until results exist):
   - Download icon, "Export IOC report" and "All indicators defanged · generated locally · includes any lookups you ran".
   - Chips for HTML report `.html` and CSV `.csv`, both checked.
   - A checkbox "Raw values column in CSV", enabled only when CSV is checked.
   - A Download button, disabled when neither format is chosen.
   - `#export-status` (role=status, aria-live). Its message clears after 4 s.
5. **Result panels** (all hidden until analysis): Quick Summary, Analysis Result, Email Authentication, Indicators of Compromise, Body & Language Analysis (only for a full email with a body), Email Headers.
6. **Settings modal** (§14.8).

### 14.2 Analysis pipeline (`handleAnalyze`)

1. **Empty input:** hide results and show "Please paste an email or upload a file first."
2. **`parseHeaders`**, then refuse non-email input. If none of these headers exist — `from to subject date received message-id return-path authentication-results received-spf dkim-signature reply-to mime-version content-type` — hide results and show "No email headers found — this doesn't look like an email. Paste the full raw message source (headers and body), or upload the .eml file." *Why:* arbitrary text used to come back Low Risk.
3. **`parseAuth`.**
4. **Body:**
   - `isFullEmail` is true when a blank line exists.
   - Otherwise it is true when lines longer than 50 characters that are not header-like outnumber header lines.
   - When full, run `parseBody`.
5. **`extractIOCs`.**
6. **Hash** every attachment with bytes: `sha256Bytes` and `md5Bytes`. Keep the bytes in `attachmentContentMap`.
7. **Language:** `analyzeLanguage(body.text)` when there is text.
8. **Score:** `calculateScore(auth, iocs, lang, headers)`.
9. **Render** every panel and show the export bar. Status "Analysis complete!"
10. **On any exception:** hide results and show ``Error analyzing email: ${message}``. *Why:* a stale verdict must never sit under a new error.

**Clear** empties the input and the file field, hides results, and clears the status.

**File upload:** read the file as text into the textarea and show ``Loaded: name``. A `.msg` file is rejected with ".msg files are not yet supported. Please convert to .eml or paste the raw source."

### 14.3 Quick Summary (`renderSummary`)

1. **Verdict strip:**
   - Class `tier-high`, `tier-medium` or `tier-low`.
   - Tier and `score/100`.
   - The top 3 reasons.
   - Caveats with ⚠.
2. **Top row** (2 columns):
   - **Authentication card:** pills for SPF, DKIM, DMARC and alignment. Alignment reads ALIGNED (pass) / MISMATCHED (fail) / NO DATA (none), based on `dmarcAligned`.
   - **IOCs Found card:** counts for URLs, Domains, IPs, Emails and Files, with non-zero counts only. URLs is marked `high` when any URL has a high flag; Files is `high` when a risky extension or a double extension is present. When everything is zero, show "0 None".
3. **Bottom row** (3 columns, each card with a risk border):
   - **Sender:** From (truncated to 40, full value in the title) and Domain (`suspicious` when it starts with `xn--` or a digit).
     - Authenticity reads:
       - "Not verified — fails DMARC" (malicious) when DMARC fails or `dmarcAligned === false`;
       - "Verified by DMARC" (verified) when DMARC passes and is aligned;
       - otherwise "Could not be verified".
     - Border: high if spoofed or a lookalike, low if verified, else medium.
   - **Reply-To:** only a real Reply-To header, never Return-Path.
     - When present: the address, plus "Replies go to a different domain" (amber) or "Same domain as From".
     - When absent: "None — replies go to From".
     - Border: medium when the domains differ, otherwise neutral.
   - **Message:** Subject (truncated to 60), Date, and Mailer when X-Mailer exists.
4. **Split row** `.summary-split` (2 equal columns):
   - **Sender IP card** (`data-lookup-scope`):
     - "Originating IP (the sender's public address)" shows `senderIp.publicIp`, or "No public IP recorded in these headers" (muted). Add lookup buttons and the public hop's hostname.
     - If `privateIp` is set: "First hop recorded X, a private address (plus N more private hops). Walked outward to the first public address above." or "No public address appears anywhere in the chain."
     - "Last relay (the server that delivered to you)": the first chain hop with a valid IP, shown when it differs from both the origin and the private IP, with its own buttons.
     - A `.lookup-result-content` box.
     - Border: high when a chain exists but no public IP was found.
   - **Language card:**
     - Groups the phrases by category, de-duplicated case-insensitively, with `×N` counts.
     - Header total: "N phrase(s)".
     - Tone: credential, financial and bec are `bad` (red); urgency and authority are `warn` (amber).
     - Border: high if any bad category has matches, else medium.
     - With no matches: "No suspicious language detected." (low border).
     - With no body: "No message body to analyze."

**IP lookup buttons** (`ipLookupButtons`):

- Invalid IP: nothing.
- Private IP: Copy + "private/reserved — not published in reputation data".
- Otherwise: Copy, VT and AbuseIPDB. Without a key, the button gets class `disabled` and `onclick=promptSettings()`, with title "Add a … API key in Settings".

### 14.4 Analysis Result (`renderVerdict`)

- A verdict box with the tier, "Score: N/100" and caveats.
- Three score columns (Authentication, Indicators, Language), each with its value and a bar filled to `value%` and coloured by severity (≥ 60 high, ≥ 30 medium, else low), plus that category's reason list ("Nothing found" when empty). *Why:* a full green bar read as "all good".
- A Language Flags section with category name and count.

### 14.5 Email Authentication (`renderAuth`)

- **Source note:** "Results reported by `authserv` — N Authentication-Results headers present, only the topmost is trusted."
- **Mechanism cards:**
  - Left border and status colour: pass `var(--green)`, fail `#ef4444`, softfail/permerror/unverified `#f59e0b`, others `#9ca3af`.
  - **SPF** shows both sources side by side: header name, raw result, "IP x" or "not recorded", "for identity".
  - The SPF agreement line reads:
    - "Only <header> is present — nothing to cross-check.", or
    - "✓ Both headers agree on <ip>", or
    - "⚠ Headers disagree — results differ and checked different IPs. Authentication-Results decides the status above."
  - Then "Sender public IP x", with either "✓ same IP SPF checked" or "≠ SPF checked a relay, not the origin (normal for ESPs and forwarding)".
  - DKIM and DMARC show their details and "via source".
- **Header Trust:** a ⚠ list, shown when warnings exist.
- **Domain Alignment:**
  - Verdict sentence:
    - "Domain alignment satisfied — at least one authenticated mechanism matches the From domain."
    - "No authenticated mechanism aligns with the From domain."
    - "Not enough information to evaluate alignment."
  - Table columns: Check / Comparison / Result.
    - **Check:** "SPF — envelope sender vs From", "DKIM — signing domain vs From", or "Reply-To — not a DMARC input".
    - **Comparison:** `Source (domain) = / ≠ From (domain)`.
    - **Result:**
      - "✓ ALIGNED — strict — identical domains";
      - "✓ ALIGNED — relaxed — both under org";
      - "✗ NOT ALIGNED — organizational domains differ: a ≠ b" (red if DMARC-relevant, muted otherwise);
      - plus "but SPF/DKIM did not pass, so this does not satisfy DMARC" when aligned but not passed.
    - Rows that are relevant but misaligned get class `mismatch-row`.
- **Received Chain:** hop cards with number, From (+ `origin` tag), By, IP, date, and ⚠ warnings. Suspicious hops are highlighted.

### 14.6 Indicators of Compromise (`renderIOCs`)

- **Sections, in order:** URLs, Domains, IP Addresses, Email Addresses, Attachments, then Mismatched Links. Each heading is `Title (N)`, followed by a table of Value / Risk / Actions.
- **Row limit:** `IOC_ROW_LIMIT = 50`. The rest sit behind a "Show all N" button with "M more not shown". Section data is stored in a Map so `showAllIOCs(id)` re-renders one section.
- **Value cell:**
  - The original value, plus a hidden defanged copy.
  - **Attachments:** SHA-256 and MD5 lines (or "no decodable content"), then `type · size · inline`.
  - **URLs:**
    - A `<details class="url-decode" data-url ontoggle="renderDecoders(this)">` summary "Decode URL", plus the hint "encoded: <labels>" when `detectEncodings` finds something.
    - The panel body is filled lazily on first open, with decoder buttons. `all` and any applicable decoders get class `applies`.
    - `runDecoder` marks the clicked button `active` and shows the note, a `<pre>` output and Copy. With no result it shows "Label: nothing to decode in this URL."
- **Risk cell:** risk tags coloured by level.
- **Actions:**
  - Copy (copies whichever form is visible).
  - Defang/Original toggle.
  - VT button (`data-value`, `data-type`, and `data-sha256` for attachments). Disabled when there is no key.
  - Emails also get "VT Domain".
  - IPs also get AbuseIPDB.
  - A **private IP gets no lookup buttons.** Declare `lookupUseless` before the button code; a TDZ bug once lived there.
- **Lookup results** render into a hidden `<tr class="lookup-result-row">` directly after the IOC row.

### 14.7 Body & Language

- Tabs "Plain Text" and "HTML Preview".
- **Plain text:** escaped, with each language match wrapped in `<mark class="lang-highlight <category>">`.
- **HTML preview:**
  - The note "Remote images and scripts are blocked. Nothing in this preview contacts the sender."
  - `<iframe class="html-preview" sandbox referrerpolicy="no-referrer">` (sandbox with **no** allow-list).
  - `srcdoc = withBlockingCSP(html)`: insert `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">` right after `<head…>`, or prepend it.
- **Language Analysis panel:** the summary, plus per-category count and up to 5 phrases.

### 14.8 Email Headers (`renderHeaders`)

Two `<details>`, both collapsed by default:

1. **"Key headers first":** "N headers · important ones on top". The table starts with From, Reply-To, Return-Path, To, Subject, Date, Message-ID, Authentication-Results, Received-SPF, DKIM-Signature, Content-Type, X-Mailer and X-Originating-IP, then every other header. Names are Title-Cased. The "Copy headers" button copies `Name: value` lines.
2. **"Original order":** "N headers · exactly as in the email".
   - A note that the chain reads bottom-up.
   - The "Copy raw headers" button copies `headers.raw` byte-for-byte, trimmed at the end.
   - Table columns: # / Header / Value.
   - Received rows get tag `hop N`, with `· origin` on hop 1 and `· last` on the first Received when there are more than 1. Their class is `hdr-received`.
   - Auth headers (`authentication-results`, `received-spf`, `dkim-signature`, `arc-*`) get class `hdr-auth`.

Copy buttons show "Copied!" or "Copy failed" for 2 s.

### 14.9 Settings modal

- **Opening and closing:** opened by the Settings button or `promptSettings()`. Closed by ×, a backdrop click, or Escape.
- **Note:** "API keys are stored in this browser only. They are sent only to VirusTotal/AbuseIPDB when you click a lookup button."
- **`#api-availability`:**
  - **On localhost or 127.0.0.1:** class `ok`. "**Lookups are ready.** This page is served by `server.js`, which relays VirusTotal and AbuseIPDB calls for you. Paste your API keys below and the lookup buttons will work — no proxy setup, no other configuration." Also hide the proxy field.
  - **Elsewhere:** "**Lookups cannot run from this address.** VirusTotal and AbuseIPDB do not send CORS headers, so your browser blocks their responses on any page they do not serve themselves. An API key alone cannot change that. To use lookups, run the app locally — clone the repo, then `node server.js` and open `http://localhost:8080`. Your keys work immediately there. Everything else on this page (parsing, scoring, hashing) is unaffected and runs fine right here."
- **Fields:**
  - VirusTotal API Key (password): "Used for URL, domain, IP, and file hash lookups".
  - AbuseIPDB API Key (password): "Used for IP address reputation lookups".
  - `#proxy-field` "CORS Proxy URL (optional)", placeholder `https://your-worker.workers.dev?url=`, with a link to cors-worker.js.
  - **Theme colour** (§14.10).
- **Buttons:**
  - **Save Settings** stores or removes `vt-api-key`, `abuseipdb-api-key` and `cors-proxy-url`, closes the modal, and shows "Settings saved!".
  - **Clear Saved Keys** (danger) empties the key fields and their storage and shows "API keys cleared.".
  - Saving does not re-render existing result buttons; the new keys apply to the next analysis.

### 14.10 Theme colour (`theme.js`)

- **Markup:**
  - `<label for="accent-color">Theme colour</label>`
  - A `.theme-row` holding `<input type="color" id="accent-color" value="#9fef00">` (the native full colour panel), `<code id="accent-value">#9fef00</code>` and `<button id="reset-accent" class="btn btn-secondary" type="button">Reset</button>`.
  - The hint "Changes the green accent only. Applied instantly and saved in this browser."
- **Scope:** only the green family changes. Backgrounds, text, red, yellow, blue and purple stay fixed so severity colours keep their meaning.
- **Exports:** `DEFAULT_ACCENT = "#9fef00"`, `normalizeHex` (accepts `#?RRGGBB` only), `accentPalette(hex)`, `applyAccent(hex, root = document.documentElement)`, `loadAccent()`, `saveAccent(hex)`.
- **`accentPalette`** sets:
  - `--accent`, `--green`, `--border-hover` = hex
  - `--accent-hover` = mix toward white by 20%
  - `--accent-dim` = mix toward black by 33%
  - `--accent-bg` and `--green-bg` = rgba .08
  - `--accent-border` and `--green-border` = rgba .25
  - `--accent-glow` = rgba .15
  - `--accent-contrast` = `#0d1117` when relative luminance > 0.35, otherwise `#ffffff`
- **`applyAccent`:** always removes all 11 properties from the inline style first. If the value is the default or invalid, it stops there, so the stylesheet values apply. Otherwise it sets them. It returns the applied hex.
- **Storage:**
  - `loadAccent` reads `localStorage["accent-color"]` in a try/catch.
  - `saveAccent` removes the key for the default or invalid values, and stores it otherwise.
- **Wiring in `main.js`:**
  - Call `applyAccent(loadAccent())` at module top level, before first render.
  - `setupThemePicker()` syncs the input and label.
  - On `input`: apply and save (a live preview while dragging).
  - Reset: apply and save the default.
- **CSS requirements:**
  - Never hard-code a green. The three former literals become `color-mix(in srgb, var(--accent) 3%, transparent)` (background glow), `var(--accent-glow)` (rescan hover) and `color-mix(in srgb, var(--accent) 50%, transparent)` (decoder "applies" border).
  - Text on accent backgrounds (`.btn-primary`, `.decode-btn.active`) uses `var(--accent-contrast, #0d1117)`.
  - Status "pass" colours use `var(--green)`, never `#22c55e`.
- The exported report keeps the default green; it is a fixed document.

### 14.11 Lookups (`main.js`)

**Endpoints**

- On localhost or 127.0.0.1, use **relative** paths so any port works:
  - `/proxy/vt` + path
  - `/proxy/vt-submit`
  - `/proxy/vt-analyse` + path
  - `/proxy/abuseipdb` + query
- Elsewhere, call the real URL through `viaProxy(url) = proxy ? proxy + encodeURIComponent(url) : url`. The target must be encoded; *why:* AbuseIPDB's `&maxAgeInDays=90` was otherwise parsed as a proxy parameter.
- `VT_BASE = https://www.virustotal.com`, `ABUSE_BASE = https://api.abuseipdb.com/api/v2`.

**VirusTotal** (`lookupVirusTotal(btn)`)

- Find the result target: the next `tr`'s `.lookup-result-content`, or the closest `[data-lookup-scope]` box.
- **Validation:**
  - For IPs, the IP must be valid.
  - The key must match `^[a-f0-9]{64}$`; otherwise show "Invalid VirusTotal API key format. Key should be 64 hex characters. Check Settings."
- **Cache:** key `vt:type:value`. Only successful results are cached; errors stay retryable.
- **Request path by type:**
  - Attachment: `/api/v3/files/<sha256>`, using the hash from `data-sha256`, else computed from the byte map, else the error "Cannot compute hash: this part carried no decodable content. The pasted source may be truncated."
  - IP: `/api/v3/ip_addresses/<enc>`.
  - Domain: `/api/v3/domains/<enc>`.
  - URL: `/api/v3/urls/<sha256 of the URL string>`. `vtUrlId = sha256(value)`; *why:* `btoa` produced invalid path characters and threw on non-ASCII.
- **Request:** GET with headers `x-apikey` and `Accept: application/json`, and a 15 s AbortController timeout.
- **Responses:**
  - **URL 404:** "URL not found in VirusTotal. Submitting for analysis...", then POST `url=<enc>` (form-urlencoded) to submit. On success: "URL submitted to VirusTotal for analysis. Check back in a few minutes."
  - **Other 404:** "Not found in VirusTotal database."
  - **Errors:** 401 "API key is invalid or missing.", 429 "Rate limited. Wait a moment and try again.", 403 "API key lacks required permissions.", followed by the API message.
  - **Success:**
    - Reputation: MALICIOUS (malicious > 0), SUSPICIOUS, or CLEAN.
    - Stats: malicious, suspicious, harmless, undetected.
    - Created (`creation_date` or `registration_date`, as a date), Last analyzed, Reputation, AS Owner, Country, Name.
    - A **Rescan** button carrying `data-url` and calling `rescanVT(analysePath, btn)`, with analyse path `…/analyse`. VirusTotal uses the British spelling; `/analyze` returns 404.
    - An "Open in VT ↗" link.
    - Record in `lookupResults`: `vt:<value>` → `"Malicious|Suspicious|Clean — X/Y engines flagged"`.
- **Network failure:** show "API UNAVAILABLE" and a hint. For timeouts: "Request timed out. Try again or check your network." For "Failed to fetch", on localhost: "Is the server running? Start it with: node server.js"; otherwise: "CORS error. Configure a CORS proxy in Settings or run locally with: node server.js". Add an "Open in VirusTotal ↗" link to the matching GUI page:
  - `gui/file/<hash>`
  - `gui/ip-address/<ip>`
  - `gui/domain/<d>`
  - `gui/search/<v>`
- **`rescanVT`:**
  - POST to the analyse endpoint. On 204 or ok: "Queued", plus "Analysis queued. Click VT again in ~30s for fresh results."
  - When a URL rescan fails, resubmit the URL instead: "URL resubmitted for analysis."
  - Otherwise show "Failed" for 3 s, with the error in the title.

**AbuseIPDB** (`lookupAbuseIPDB(btn)`)

- **Validation:**
  - An invalid IP gets an error.
  - A private IP gets "X is a private or reserved address. Reputation services hold no data for it."
  - A key shorter than 20 characters gets "Invalid AbuseIPDB API key format. Check Settings."
- **Cache:** `abuse:ip`.
- **Request:** GET `/check?ipAddress=<enc>&maxAgeInDays=90` with headers `Key` and `Accept`.
- **Success display:**
  - Class by score: ≥ 50 malicious ("⚠ HIGH RISK"), ≥ 25 suspicious ("⚡ ELEVATED"), else clean ("✓ LOW RISK").
  - Stats: Abuse Score %, Total Reports, Country, ISP.
  - Domain, Usage, and Last reported.
- **Record:** `abuse:ip` → `"N% abuse confidence · R reports · CC · ISP"`.
- **Errors:** follow the VirusTotal pattern, with a link to `https://www.abuseipdb.com/check/<ip>`.

**Other**

- `window` globals for the inline handlers: `lookupVirusTotal, lookupAbuseIPDB, copyIOC, toggleDefang, promptSettings, rescanVT, showAllIOCs, renderDecoders, runDecoder, copyText`.
- `esc` in `main.js` uses DOM `textContent` → `innerHTML`.
- Downloads: Blob plus a temporary `<a download>`. With two files, stagger them 350 ms apart (browsers drop a second download in the same tick), then revoke the object URL after 1 s. The status reads "Downloaded the HTML report and CSV." or "Downloaded <name>".

### 14.12 Hidden signature

- `<!-- BOoDe -->` directly after the doctype.
- `<meta name="author" content="BOoDe">`.
- On init, `console.log("%cBOoDe", "color:#9fef00;font:700 14px monospace")`.

---

## 15. Design system

### 15.1 Tokens (`:root` in main.css)

```css
--bg-deep:#0d1117; --bg-base:#161b22; --bg-elevated:#21262d; --bg-surface:#30363d; --bg-overlay:rgba(13,17,23,.85);
--accent:#9fef00; --accent-hover:#b3ff33; --accent-dim:#6b9e00;
--accent-bg:rgba(159,239,0,.08); --accent-border:rgba(159,239,0,.25); --accent-glow:rgba(159,239,0,.15);
--green:#9fef00; --green-bg:rgba(159,239,0,.08); --green-border:rgba(159,239,0,.25);
--red:#ff7b72; --red-bg:rgba(255,123,114,.08); --red-border:rgba(255,123,114,.25);
--yellow:#d29922; --yellow-bg:rgba(210,153,34,.08); --yellow-border:rgba(210,153,34,.25);
--blue:#58a6ff; --blue-bg:rgba(88,166,255,.08); --blue-border:rgba(88,166,255,.25);
--purple:#bc8cff; --purple-bg:rgba(188,140,255,.08); --purple-border:rgba(188,140,255,.25);
--text:#e6edf3; --text-secondary:#8b949e; --text-muted:#6e7681;
--border:#30363d; --border-light:#21262d; --border-hover:#9fef00;
--radius-sm:4px; --radius-md:6px; --radius-lg:8px; --radius-xl:12px; --radius-full:9999px;
--transition:.15s ease-in-out; --transition-slow:.25s ease-in-out;
```

- **Fonts:** Inter for the UI, JetBrains Mono for values, hashes and headers.
- **Look:** a dark, HTB-inspired theme with a soft radial accent glow at the top of the page (`width: min(800px, 100vw)`, 400 px high, pointer-events none).
- **Language category colours:** urgency and authority amber, credential and financial red, **bec purple** (`--purple`), for both `.lang-highlight.bec` and `.highlight-bec`.

### 15.2 Logo: Glitch Tomoe (`favicon.svg`)

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="-5 -5 110 110">
  <defs>
    <g id="eye">
      <circle cx="50" cy="50" r="48" fill="#000"/>
      <circle cx="50" cy="50" r="46.5" fill="none" stroke="#9fef00" stroke-width="2.5"/>
      <g id="t" fill="#9fef00">
        <path d="M50 12A38 38 0 0 1 81 28Q69 22 50 26Z"/>
        <circle cx="50" cy="19" r="7"/>
      </g>
      <use href="#t" transform="rotate(120 50 50)"/>
      <use href="#t" transform="rotate(240 50 50)"/>
      <circle cx="50" cy="50" r="8" fill="#9fef00"/>
    </g>
    <clipPath id="s1"><rect x="-10" y="22" width="120" height="7"/></clipPath>
    <clipPath id="s2"><rect x="-10" y="47" width="120" height="5"/></clipPath>
    <clipPath id="s3"><rect x="-10" y="70" width="120" height="6"/></clipPath>
  </defs>
  <!-- The whole eye, then three horizontal slices of it shifted sideways. -->
  <use href="#eye"/>
  <g clip-path="url(#s1)"><use href="#eye" x="7"/></g>
  <g clip-path="url(#s2)"><use href="#eye" x="-6"/></g>
  <g clip-path="url(#s3)"><use href="#eye" x="5"/></g>
</svg>
```

- The **head** links `favicon-32.png` (32×32, PNG first for browsers without SVG favicon support), `favicon.svg` (type image/svg+xml) and `apple-touch-icon.png`.
- The header uses an **inline** copy with `currentColor` and `logo-` ids (§14.1).
- The report uses an inline copy with `lg-` ids and fixed green.

### 15.3 Responsive and mobile rules

Verify the layout at 320, 375, 768 and 1280 px.

- **No horizontal page scroll at any width.** Grid children get `min-width: 0`. Long mono values use `word-break: break-all`, but the decode hint uses `word-break: normal`. Mismatched-link cells wrap.
- **≤ 768 px:**
  - The summary rows, split row, verdict strip and score breakdown collapse to one column.
  - IOC, alignment and header tables turn into stacked cards (`thead` hidden, rows as bordered elevated cards).
  - In IOC tables each `td[data-label]` shows its label above the value, the actions wrap, and empty cells are hidden.
  - The export controls go full width.
  - Tap targets are at least **40 px** high.
  - No text is smaller than **11 px**.
- **≤ 480 px:**
  - The Settings button becomes icon-only (hide `.btn-label`, min-width 40 px).
  - The `h1` stays on one line with an ellipsis.
  - The trust banner drops to 11 px.
  - Body text is 12 px.
- **Wide tables** otherwise scroll inside a `.table-scroll` wrapper, never the page.

---

## 16. Server, relay and deploy

### 16.1 `server.js` (Node stdlib: http, https, fs, path)

- **Port:** `const PORT = Number(process.env.PORT) || 8080`. On `EACCES` or `EADDRINUSE`, print ``Port ${PORT} is unavailable (${code}). Pick another, e.g.:\n  PORT=3000 node server.js`` and exit 1. *Why:* Windows reserves dynamic port ranges that can include 8080.
- **OPTIONS:** 204 with Allow-Origin `*`, methods `GET, POST, OPTIONS`, headers `Content-Type, x-apikey, Key`.
- **Proxy routes:**
  - `GET /proxy/vt/<path>` → `https://www.virustotal.com/<path>`, forwarding `x-apikey`.
  - `POST /proxy/vt-submit` → `https://www.virustotal.com/api/v3/urls`, form body.
  - `POST /proxy/vt-analyse/<path>` → VirusTotal, with `Content-Type` only when there is a body.
  - `GET /proxy/abuseipdb<query>` → `https://api.abuseipdb.com/api/v2<query>`, forwarding `Key`.
- **`proxyRequest`:** parse with the WHATWG `new URL` (not the deprecated `url.parse`). Pipe the upstream status and content-type, with Allow-Origin `*`. On error, return 502 JSON `{ error: "Proxy error: …" }`.
- **Static files:**
  - Strip `?` and `#`, then `decodeURIComponent` (a malformed escape returns 400).
  - Resolve with `path.join(__dirname, path)`; `/` maps to `index.html`.
  - **Return 403 unless the path is inside `__dirname`** (path-traversal guard).
  - MIME types: html, js (`text/javascript`), css, json, eml (`message/rfc822`), txt, svg, png, ico; anything else `application/octet-stream`.
  - Return 404 for ENOENT or EISDIR, 500 for other errors.

### 16.2 `cors-worker.js` (Cloudflare Worker, optional)

- Reads the target from `?url=`; without it, returns 400.
- Forwards the method, the headers (minus host and origin) and the body (except for GET/HEAD).
- Adds CORS headers to every response, answers the OPTIONS preflight, and returns 502 on error.
- The header comment contains the setup steps.
- The Settings "CORS Proxy URL" field takes `https://worker…/?url=`.

### 16.3 `test-api.html`

A standalone page for pasting keys and testing VirusTotal and AbuseIPDB connectivity directly.

### 16.4 GitHub Actions: `.github/workflows/pages.yml`

- **Triggers:** push to `master`, and `workflow_dispatch`.
- **Permissions:** `contents: read`, `pages: write`, `id-token: write`.
- **Concurrency:** group `pages`, with `cancel-in-progress: false`.
- **Job `test`** (ubuntu, `actions/setup-node@v4` with Node 22): run every suite with `node tests/<suite>`. There is no install step.
- **Job `deploy`:**
  - `needs: test`, environment `github-pages`.
  - Steps: checkout, `configure-pages@v5`, `upload-pages-artifact@v3` with `path: .`, and `deploy-pages@v4` (id `deployment`).

---

## 17. Tests (plain Node, no framework)

Each suite:

- defines a small `test(name, fn)` that counts passes and collects failures;
- prints `N passed, M failed`;
- exits 1 on any failure.

`runner.mjs` is an older assert-style suite ending in "All tests passed!". The renderer tests run without a DOM by giving `renderX` a fake `{ innerHTML: "" }` container.

The required regression cases below are the behaviour the product depends on; each suite must contain at least these.

**`ip.test.mjs` (24)**

- Validation:
  - `15.21.360.10` is rejected;
  - octet edges (0, 255, 256) are enforced;
  - malformed shapes are rejected;
  - zero-padded octets are rejected;
  - valid and invalid IPv6 forms;
  - private ranges;
  - an invalid IP is never private or routable.
- Extraction:
  - `findIPs` returns only real addresses;
  - an invalid bracketed IP never reaches the chain or the IOCs;
  - a hop whose only candidate is invalid reports no IP;
  - private IOCs are marked;
  - IPv6 in Received is captured;
  - a by-clause IP is never the sender's;
  - Microsoft's bare parenthesised IPs are read.
- Sender walk:
  - a private origin walks outward;
  - several private hops are skipped and counted;
  - a public origin is used as-is;
  - an all-private chain gives no public IP;
  - invalid IPs are skipped;
  - an empty chain returns nulls.
- Renderer smoke tests:
  - `renderIOCs` builds every section;
  - a private IP row has no lookup buttons.

**`headers.test.mjs` (6)**

- Original order is kept, with repeats in place.
- Unfolding works and name case is preserved.
- Repeated values keep their order.
- Body lines containing a colon are not headers.
- The original-order view shows hop labels.
- Values are escaped.

**`auth.test.mjs` (37)**

- Multiple A-R headers do not throw.
- The topmost A-R wins over a forged lower one.
- Multiple DKIM signatures are parsed.
- Duplicate From is flagged.
- Received-SPF: the first-token result, and Microsoft's `result=` form.
- A-R takes precedence over Received-SPF.
- `spf=` inside a DKIM comment is not read.
- Semicolons inside comments do not split clauses.
- permerror and temperror stay distinct; neutral is not downgraded.
- A signature without a result is "unverified".
- Microsoft A-R without an authserv-id keeps its SPF clause.
- The SPF IP is read from the comment.
- Both SPF headers are kept: agree, disagree on result, disagree on IP, and compared with the sender IP.
- A forged Received-SPF cannot choose the alignment domain.
- `header.d=none` is ignored.
- `renderAuth` shows both SPF sources and the spelled-out comparison.
- Relaxed alignment is symmetric.
- Multi-part suffixes resolve correctly.
- A differing Reply-To is not a DMARC failure.
- DMARC passes when DKIM aligns but SPF does not.
- A real spoof is caught.
- A mismatch reaches `overallStatus`.
- Non-.com relays are not flagged.
- Hop 1 is the origin.
- Many shortener links cannot outweigh full authentication.
- The breakdown key is `auth`.
- A spoofed sender scores High Risk.
- Every point has a reason.
- A no-evidence caveat, a forwarded-message caveat, and no caveat when fully authenticated.
- `reasonGroups` exist.

**`url-decode.test.mjs` (26)**

- Percent: single layer, multi-layer flagged, malformed input does not throw, plain URL returns null.
- Wrappers:
  - Safe Links;
  - Proofpoint v2 (published example);
  - Proofpoint v3 (`*` and `**X` runs);
  - Google;
  - nested wrappers;
  - generic redirect;
  - Mimecast is honest;
  - an ordinary URL is not a wrapper.
- Base64:
  - a victim email in the fragment;
  - base64 behind percent-encoding;
  - base64url;
  - path words are not base64.
- Other decoders:
  - hex text is found but a hash is not;
  - entities;
  - escapes;
  - punycode equals `node:url` `domainToUnicode`;
  - the punycode note names the characters;
  - an ASCII host has no punycode.
- Registry:
  - `decodeAll` surfaces a hidden email;
  - `detectEncodings` lists only applicable decoders;
  - no decoder throws on hostile input.

**`attachments.test.mjs` (9)**

- Binary bytes survive decoding.
- SHA-256 and MD5 equal `node:crypto`.
- A real PNG hashes correctly.
- A Content-ID inline image is collected.
- Nested multipart is traversed.
- Quoted-printable bytes are correct.
- RFC 2047 filenames are decoded.
- An HTML-only message yields text.
- No attachments reports none.

**`links.test.mjs` (17)**

- Deception:
  - ordinary text is not a mismatch;
  - a URL text pointing elsewhere is a mismatch;
  - a bare domain text counts;
  - the same org is not a mismatch;
  - Safe Links to the same destination is not a mismatch, but to a different domain is.
- Extraction:
  - anchors wrapping markup are captured;
  - entities in href are decoded;
  - pixels and remote images become IOCs.
- IOCs:
  - the unwrapped destination becomes a flagged IOC;
  - no double-counted mismatch;
  - domains come from URLs, unwrapped URLs and senders;
  - shortener and disposable checks match whole domains;
  - IP hosts are not domains.

**`language.test.mjs` (7)**

- Whole-word matching (benign text containing first, courtesy, define, swiftly scores 0).
- The real words still match (IRS, court, SWIFT).
- Punctuated keywords match.
- Invoice fraud, CEO fraud and payroll diversion phrases are detected.
- The BEC label appears in the score reasons.

**`report.test.mjs` (19)**

- Defanging: URL, IP, email and domain; filenames and auth properties are untouched; one pass over free text.
- HTML report:
  - no live indicators;
  - cannot load or run anything (CSP, no `<script`, no `src=http`, only `#` hrefs);
  - attacker content is escaped;
  - hashes are intact;
  - every section is present;
  - the markup is well-formed;
  - meters are clamped;
  - unwrapped destinations are nested;
  - lookup columns appear only when there are results.
- CSV:
  - BOM, CRLF and fixed columns;
  - no live indicators;
  - formula guard;
  - opt-in raw column;
  - hashes tied to their file.
- Filename format.

**`theme.test.mjs` (3)**

- Hex validation.
- Every palette token derives from one colour, only accent/green tokens are touched, and contrast is picked correctly.
- Apply, then reset or invalid input, clears back to the stylesheet.

**`imports.test.mjs`**

A static check. For every `scripts/*.js`, any call to a function exported by another module must be imported or defined locally. *Why:* `main.js` once called `sha256()` without importing it, so every VirusTotal URL lookup failed with "sha256 is not defined".

**`runner.mjs` (92)**

Broad unit coverage plus end-to-end runs on the three samples (§12.5).

**Test-writing pitfall:** inside a JS template literal, `\s` becomes `s`. Build regexes from normal strings with `\\s`, or use regex literals.

---

## 18. Pitfalls this product already hit (do not reintroduce)

| Wrong | Right |
|---|---|
| Scan the whole A-R header with `/spf=(\w+)/` | Split into clauses, strip comments |
| Trust any A-R header | Only the topmost; warn on a forged lower pass |
| Treat Microsoft's first `spf=` clause as the authserv-id | Detect `method=` first |
| Take the alignment domain from Received-SPF | Only from the authoritative source |
| `header.d=none` as a domain | `realDomain` filter |
| "aligned" = alignment alone | aligned **and** mechanism passed |
| Reply-To mismatch = DMARC failure | Informational, +8 |
| Substring shortener or disposable match (`t.co` in `microsoft.com`) | Exact domain or subdomain |
| Substring keyword match (`irs` in "first") | Whole-word lookarounds |
| Loose IPv4 regex | Strict validation everywhere |
| Sender IP from the whole Received header | From-clause only; walk past private hops |
| Hash `atob` output via TextEncoder | Hash raw bytes |
| Only `Content-Disposition: attachment` counts as a file | Inline and Content-ID parts count too |
| Flag every link whose text ≠ href | Only URL-like text whose org domain differs after unwrap |
| Check the gateway host only | Add unwrapped destinations as IOCs |
| Weight the uncapped IOC score | Cap then weight; diminishing returns |
| `btoa` VT URL id | SHA-256 of the URL |
| `/analyze` | `/analyse` |
| Hard-coded `http://localhost:8080` endpoints | Relative `/proxy/...` |
| Proxy target not encoded | `encodeURIComponent(target)` |
| Preview iframe loading remote images | `sandbox` + blocking CSP |
| Stale verdict under a new error | `hideResults()` on refuse or error |
| Arbitrary text → "Low Risk" | Refuse input with no email headers |
| Mimecast unwrap never returned | Check `partial` before the unchanged check |
| Report leaked the domain inside a Safe Links query | `defangText` the path and query |
| `width:NaN%` meter | `percent()` clamp |
| Fixed 800px glow → sideways scroll on phones | `min(800px, 100vw)` |
| A variable used before declaration in `renderIOCs` (TDZ) | Declare first; smoke test |
| Missing import only failing on click | `imports.test.mjs` |
| Hard-coded greens | Everything via `--accent`/`--green` |
| `url.parse` in server | WHATWG `URL` |
| `"." + req.url` static serving | Resolve and contain within `__dirname` |

---

## 19. Final acceptance checklist

- [ ] `for t in tests/*.mjs; do node $t || exit 1; done` passes (11 suites).
- [ ] The three samples give Low Risk, High Risk, and a score > 0 respectively.
- [ ] Pasting plain prose is refused with the "No email headers found" message, and no stale panels remain.
- [ ] A header-only paste renders Summary, Verdict, Auth, IOCs and Headers, with no Body panel.
- [ ] The HTML preview makes zero network requests (check DevTools).
- [ ] Private IPs show no lookup buttons; public IPs show Copy, VT and AbuseIPDB.
- [ ] With `node server.js` and a dummy 64-hex VT key, a URL lookup returns VirusTotal's 401 message, not "API UNAVAILABLE".
- [ ] On GitHub Pages, Settings explains why lookups cannot run there.
- [ ] Export downloads both files. The HTML report opens offline with no requests, and every indicator is defanged. The CSV opens in Excel with no formulas executed.
- [ ] Settings theme colour: the picker recolours every green (buttons, pass badges, logo, focus rings) live; base and severity colours do not change; the choice persists across reload; Reset returns to `#9fef00` and clears storage.
- [ ] No horizontal scroll at 320 / 375 / 768 / 1280 px; tables become cards at ≤ 768 px; tap targets ≥ 40 px; text ≥ 11 px.
- [ ] A push to `master` runs every test before deploying to Pages.
