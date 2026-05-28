# its-over-8k

Polls SEC EDGAR for new 8-K filings disclosing cybersecurity incidents and extracts indicators of compromise (IOCs) — IPs, domains, URLs, hashes, CVEs, threat actor names, malware families — into structured JSON Lines.

Built around the observation that 8-Ks have no IOC standard, so a two-layered extractor (precision regex + local LLM) handles the prose-heavy reality of these disclosures.

## How it works

```text
EDGAR full-text search  ─►  fetch filing bundle  ─►  strip HTML
                                                          │
                                                          ▼
                                          keyword-window narrowing
                                                          │
                                                          ▼
                                      ┌─ high-precision regex (hashes/CVE/BTC/ATT&CK)
                                      └─ local LLM (domains/IPs/threat actors/etc.)
                                                          │
                                                          ▼
                                                 merged JSONL / STIX / TAXII
```

1. **Search** — EDGAR full-text search (`efts.sec.gov`) for 8-Ks matching Item 1.05 + voluntary 8.01 cyber-disclosure language.
2. **Fetch** — pulls every HTML document in the accession bundle (primary doc + exhibits), skipping SEC's auto-generated SGML wrapper files.
3. **Narrow** — paragraphs are filtered to those containing cyber keywords (plus immediate neighbors for prose context). This is what gets fed to the extractors.
4. **Extract** — regex handles things with rigid grammars (`sha256`, `CVE-YYYY-NNNN`, BTC, ATT&CK IDs). The LLM handles contextual indicators (named threat actors, malware families, attacker-controlled domains) because in 8-K prose, raw domain/IP regex is >95% IR-boilerplate noise.
5. **Emit** — JSONL by default; STIX 2.1 bundles to a file and/or TAXII collection optionally.
6. **Checkpoint** — accession numbers go into a state file, so polls are idempotent.

On **first run** (empty state file), the script automatically backfills the past `--backfill-days` of filings before entering normal polling cadence. Subsequent runs only process filings newer than the state checkpoint.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The LLM is optional but recommended. Any OpenAI-compatible server works (mlx_lm.server, llama.cpp server, LM Studio, vLLM, Ollama). Model is auto-detected via `/v1/models`.

## Usage

Run once (backfills past year on first run, then exits):

```bash
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --llm-url http://127.0.0.1:8080 \
  --output filings.jsonl
```

Run as a continuous poller (every hour):

```bash
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --llm-url http://127.0.0.1:8080 \
  --output filings.jsonl \
  --interval 3600
```

Skip the first-run backfill (only process new filings going forward):

```bash
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --llm-url http://127.0.0.1:8080 \
  --output filings.jsonl \
  --backfill-days 0 \
  --interval 3600
```

Regex-only (no LLM):

```bash
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --no-llm \
  --output filings.jsonl
```

### Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--user-agent` | *required* | EDGAR requires a real name + contact email. Browser strings get blocked. |
| `--query` | Item 1.05 + cyber keywords | EDGAR full-text query string. |
| `--lookback-days` | `2` | Window each poll covers. State dedupes across polls. |
| `--backfill-days` | `365` first run only | When passed explicitly, forces a backfill at the given depth on every run (widens an existing run's window without deleting state). When omitted, the default `365` applies only on first run (empty state). `0` disables backfill. |
| `--llm-url` | — | OpenAI-compatible base URL. Omit to disable LLM extraction. |
| `--llm-model` | auto | Auto-detected via `/v1/models` if omitted. |
| `--no-llm` | false | Force regex-only even if `--llm-url` is set. |
| `--clean-start` | false | Delete the state file plus any output files this invocation would write to (`--output`, `--text-output`, `--stix-output`), then run normally. Prompts for confirmation unless `--yes` is set. Useful for re-running a backfill from scratch. |
| `--yes`, `-y` | false | Skip the `--clean-start` confirmation prompt. |
| `--interval` | `0` | Seconds between polls. `0` = run once and exit. |
| `--state-file` | `8k_state.json` | Accession dedupe store. Delete to re-trigger first-run backfill. |
| `--output` | stdout | Append-mode JSONL output. |
| `--text-output` | — | Append-mode human-readable per-filing report. |
| `--stix-output` | — | Append-mode STIX 2.1 bundles (NDJSON: one bundle per line). |
| `--taxii-url` | — | TAXII 2.1 API root URL. Must be set with `--taxii-collection`. |
| `--taxii-collection` | — | TAXII collection id to push bundles into. |
| `--taxii-user`, `--taxii-pass` | — | TAXII basic auth credentials. |
| `--taxii-token` | — | TAXII bearer token (alternative to basic auth). |
| `--log-file` | `run.log` | Append run logs (banner + per-filing lines + warnings/errors) to this file. Plain text, no ANSI colour, full ISO timestamps. |
| `--no-log-file` | false | Disable file logging entirely. |
| `--no-banner` | false | Suppress the ASCII startup banner. |
| `--no-color` | false | Force-disable ANSI colour. Also honours `NO_COLOR=1` env. |
| `-v`, `--verbose` | — | Debug logging. |

You can use any combination of outputs. Common setups:

```bash
# JSONL + plaintext + STIX file, no TAXII
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --llm-url http://127.0.0.1:8080 \
  --output filings.jsonl \
  --text-output filings.txt \
  --stix-output filings.stix.ndjson \
  --interval 3600

# Push directly to a TAXII 2.1 server
.venv/bin/python run.py \
  --user-agent "Your Name your@email.example" \
  --llm-url http://127.0.0.1:8080 \
  --output filings.jsonl \
  --taxii-url https://taxii.example/api/ \
  --taxii-collection 4f7e6f2a-... \
  --taxii-token YOUR_BEARER_TOKEN \
  --interval 3600
```

## How the keyword filter works

8-K filings are mostly forward-looking statements, risk-factor boilerplate, and signature blocks. The actual incident discussion is usually only a few paragraphs. Running the LLM (or noisy regexes) over the whole filing wastes tokens and surfaces false positives from unrelated cover-page and footer text.

After HTML stripping, the script splits the filing into single-newline-delimited paragraphs and keeps only paragraphs matching a cyber-keyword regex — plus one neighbor on either side, so prose flow around the hit is preserved. Both regex and LLM extraction then operate on this narrowed window.

The keyword set (`_RE_CYBER` in the script) covers the EDGAR query terms plus common synonyms:

- `item 1.05`
- `cyber` / `cybersecurity` / `cyberattack`
- `ransom` / `ransomware`
- `unauthorized access`
- `data breach`
- `threat actor`
- `intrusion`
- `malware`
- `exfiltrat*`
- `compromis*`
- `security incident`
- `encrypt*` (`encrypted` / `encryption`)
- `phish*`

If no paragraph in a filing matches (which shouldn't happen — the filing got returned by an EDGAR query with matching terms), the script logs at debug level and falls back to extracting from the full text.

Net effect: typical LLM input drops from ~24k clipped chars to a few thousand chars of actual incident discussion.

## The LLM prompt

The system prompt sent to the local LLM is the `LLM_SYSTEM` constant in `run.py`:

```text
You extract indicators of compromise (IOCs) from SEC 8-K cybersecurity disclosures.

Return STRICT JSON with one key "iocs" whose value is a list of objects:
  {"type": str, "value": str, "context": str}

Allowed type values:
  ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve, attack_pattern,
  threat_actor, malware_family, vulnerability, btc, monero, filename,
  mutex, registry_key, tool_name.

Rules:
- Only return indicators tied to the disclosed incident.
- Do NOT return the filer's own corporate name, ticker symbol, SEC URLs,
  CIK / file numbers, monetary figures, or generic legal boilerplate.
- "threat_actor" / "malware_family" should be the named group or family
  (e.g. "Scattered Spider", "LockBit", "ALPHV").
- If nothing applies, return {"iocs": []}.
- Output JSON only — no prose, no markdown fences.
```

Request shape sent to `POST /v1/chat/completions`:

| Field | Value |
|-------|-------|
| `model` | `--llm-model`, or first id from `/v1/models` |
| `temperature` | `0.0` (deterministic) |
| system message | the prompt above |
| user message | the keyword-windowed filing text, clipped to 24,000 chars |
| `response_format` | `{"type": "json_object"}` — most OpenAI-compatible servers will constrain decoding to valid JSON when this is set |

The expected response shape is `{"iocs": [{"type": "...", "value": "...", "context": "..."}, ...]}`. An empty list (`{"iocs": []}`) is the correct response for filings that disclose an incident without naming any concrete indicators — which is most of them. Non-JSON output or HTTP errors are logged at warning level and treated as zero IOCs from the LLM; regex output still ships.

## Output

**JSONL** (`--output`): one record per filing, including filings with zero IOCs (kept as negative-result evidence that the script saw the filing).

**Plain text** (`--text-output`): same content as JSONL, formatted for human reading.

**STIX 2.1** (`--stix-output`, `--taxii-url`): one bundle per filing, **only when `ioc_count > 0`**. A bundle with no indicators is just an identity + report stub, which clutters downstream feeds without adding signal.

**Run log** (`--log-file`, default `run.log`): all log lines (DEBUG/INFO/WARNING/ERROR plus tracebacks) with full ISO timestamps and no ANSI colour. Appended each run.

JSONL record shape:

```json
{
  "accession": "0001193125-26-147772",
  "cik": "0001901799",
  "filer": "Example Corp (XMPL) (CIK 0001901799)",
  "filed": "2026-04-08",
  "form": "8-K",
  "url": "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=1901799&type=8-K",
  "filing_index": "https://www.sec.gov/Archives/edgar/data/1901799/000119312526147772/0001193125-26-147772-index.htm",
  "iocs": [
    {"type": "threat_actor", "value": "Scattered Spider", "context": "..."},
    {"type": "sha256", "value": "ab12...", "context": "..."}
  ],
  "ioc_count": 2,
  "extracted_at": "2026-04-08T14:32:11+00:00"
}
```

## Design notes

- **Why not just a browser UA?** EDGAR's fair-access policy requires a descriptive UA with a contact email. Spoofing a browser gets you IP-blocked.
- **Why high-precision regex only when LLM is on?** Bare domain/IP/email regex catches investor-relations URLs and press-wire addresses in nearly every 8-K. The LLM has the context to know `lockbit-victims.onion` in the breach paragraph is an IOC and `ir.companyname.com` in the footer is not. With the LLM off, the regex layer falls back to running all types.
- **Why a keyword window before the LLM?** Token cost and false-positive cost. LLMs over a full 8-K spend most of their context on legal boilerplate; narrowing to incident paragraphs makes the prompt focused and the output cleaner.
- **Why automatic backfill on first run?** A fresh state file with no history means no historical IOCs in your output stream. The 1-year default gives most users a useful starting corpus without having to think about it — set `--backfill-days 0` to opt out.
- **Why skip the STIX bundle for zero-IOC filings?** A bundle with no indicators contains only an identity SDO for the filer and a report SDO pointing at the filing — no actionable signal for a TIP. JSONL/text outputs still record these as negative-result evidence so you can audit what the script saw and rejected.
- **Why a persistent HTTP session for the LLM?** The LLM endpoint gets a POST per filing during backfill. A shared `requests.Session` keeps the TCP connection alive (HTTP keep-alive), so each call after the first skips the handshake. Same for the EDGAR client.

## Known limitations

- **EDGAR full-text search caps at 1000 results per query window.** A year-long backfill could silently truncate if the cyber-keyword query returns more than 1000 hits. Volume has historically been well under this for cybersecurity-disclosure 8-Ks, but if you see exactly `1000 candidate filings` logged during backfill, that's the cap — narrow `--backfill-days` and run multiple times, or chunk the query.
- **8-Ks rarely contain hard IOCs.** Most cyber-incident 8-Ks describe what happened in narrative form without naming malware/IPs/hashes. Expect `ioc_count: 0` on the majority of real disclosures. Press-release exhibits (Ex. 99.1) sometimes carry more detail and are included in the bundle fetcher.
- **LLM input is clipped at 24,000 characters** even after keyword narrowing, as a safety net for outlier filings. In practice the keyword window keeps things well under this, but a filing with many cyber-flagged paragraphs could still have content past the clip ignored by the LLM (regex still runs on the full window).
- **Keyword filter drift.** If you customize `--query` to terms not covered by `_RE_CYBER`, the narrower may drop the only relevant paragraphs and fall back to full-text extraction. Run with `-v` to see when this happens; update `_RE_CYBER` in the script to match.
- **EDGAR's search endpoint occasionally returns HTTP 500** for arbitrary date ranges even when the same query works moments later. The client retries on 5xx with exponential backoff.
- **Rate limit.** The client holds ~150 ms between EDGAR requests (well under SEC's 10 req/s ceiling). A year-long backfill of ~hundreds of filings, each with ~3–5 documents to fetch, plus a local LLM call per filing, can take 30+ minutes. This is expected.
- **State file grows unbounded** with accession numbers. At ~30k 8-Ks/year industry-wide and ~hundreds of cyber-relevant ones, it stays small for many years.
- **No HTML/XBRL fidelity.** The HTML stripper is `html.parser`-based and intentionally simple. Tables collapse to whitespace-separated runs, which is usually fine for IOC extraction but can lose tabular structure (e.g. a hash/filename table flattens into a single line).
- **TAXII push is fire-and-forget.** Failures are logged as warnings but don't block JSONL/STIX file output. If you need guaranteed delivery, run a separate consumer against the `--stix-output` file.

## License

See `LICENSE`.
