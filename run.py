#!/usr/bin/env python3
"""Monitor SEC EDGAR for new 8-K filings and extract IOCs.

Polls EDGAR's full-text search for 8-Ks matching cybersecurity keywords,
fetches each new filing's documents + exhibits, and extracts indicators of
compromise via regex and (optionally) an OpenAI-compatible local LLM. Output
is JSON Lines; state is checkpointed by accession number so reruns are
incremental.

Usage:
  python run.py \\
      --user-agent "Your Name your@email.example" \\
      --llm-url http://127.0.0.1:8080 \\
      --output filings.jsonl \\
      --interval 3600

  # Emit STIX 2.1 bundles to a file and/or push to a TAXII 2.1 collection:
  python run.py \\
      --user-agent "Your Name your@email.example" \\
      --stix-output bundles.jsonl \\
      --taxii-url https://taxii.example/api/ \\
      --taxii-collection 00000000-0000-0000-0000-000000000000 \\
      --taxii-token YOUR_BEARER_TOKEN
      # or: --taxii-user USER --taxii-pass PASS
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import IO

import requests

log = logging.getLogger("8k")

# ─── Banner / TTY chrome ──────────────────────────────────────────────────────

BANNER = r"""
 ___ _____ ____    _____     _____ ____    ___  _  __
|_ _|_   _/ ___|  / _ \ \   / / ____|  _ \ ( _ )| |/ /
 | |  | | \___ \ | | | \ \ / /|  _| | |_) |/ _ \| ' /
 | |  | |  ___) || |_| |\ V / | |___|  _ <| (_) | . \
|___| |_| |____/  \___/  \_/  |_____|_| \_\\___/|_|\_\
        S E C   8 - K   →   I O C   M O N I T O R
       »  SCOUTER READING:  "IT'S OVER 8,000!"  «
            [ Item 1.05 Disclosure Wiretap ]
"""

# ANSI colour codes — only emitted when stderr is a real tty (and NO_COLOR
# isn't set). Falls back to bare text in pipes/CI.
class C:
    RESET = "\033[0m"
    DIM   = "\033[2m"
    BOLD  = "\033[1m"
    RED   = "\033[31m"
    GRN   = "\033[32m"
    YEL   = "\033[33m"
    BLU   = "\033[34m"
    MAG   = "\033[35m"
    CYA   = "\033[36m"


_USE_COLOR = False  # set in main() once we know tty/flag state


def _c(code: str, s: str) -> str:
    return f"{code}{s}{C.RESET}" if _USE_COLOR else s


class _HackerFormatter(logging.Formatter):
    """Old-school [*] / [+] / [!] prefixes per log level.

    ``colored=False`` skips ANSI codes and emits a full ISO-ish timestamp
    suitable for log files (terminal output stays short-form HH:MM:SS).
    """
    SIGIL = {
        logging.DEBUG:    ("[.]", C.DIM),
        logging.INFO:     ("[*]", C.CYA),
        logging.WARNING:  ("[!]", C.YEL),
        logging.ERROR:    ("[x]", C.RED),
        logging.CRITICAL: ("[X]", C.RED + C.BOLD),
    }

    def __init__(self, colored: bool = True) -> None:
        super().__init__()
        self.colored = colored

    def format(self, record: logging.LogRecord) -> str:
        sigil, colour = self.SIGIL.get(record.levelno, ("[*]", ""))
        if self.colored and _USE_COLOR:
            ts = _c(C.DIM, datetime.now().strftime("%H:%M:%S"))
            tag = _c(colour, sigil)
        else:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            tag = sigil
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"{ts} {tag} {msg}"


def print_banner(stream: IO[str]) -> None:
    if _USE_COLOR:
        # Green-on-black phosphor terminal vibe.
        stream.write(C.GRN + BANNER + C.RESET + "\n")
    else:
        stream.write(BANNER + "\n")
    stream.flush()


# ─── EDGAR ────────────────────────────────────────────────────────────────────

EDGAR_SEARCH = "https://efts.sec.gov/LATEST/search-index"
EDGAR_ARCHIVES = "https://www.sec.gov/Archives/edgar/data"

# Item 1.05 (effective Dec 2023) is the dedicated cybersecurity-incident item
# and catches most current disclosures. But filers also voluntarily disclose
# under Item 8.01 to avoid the implicit materiality assertion 1.05 carries,
# and pre-2024 incidents were filed under 8.01 / 7.01 entirely. Cast the
# search net wide; the strong-keyword paragraph gate + LLM gate downstream
# reject risk-factor boilerplate that merely mentions these terms.
DEFAULT_QUERY = (
    '"Item 1.05" OR "cybersecurity incident" '
    'OR "ransomware attack" OR "unauthorized access to" '
    'OR "data breach" OR "threat actor"'
)


# ─── IOC patterns ─────────────────────────────────────────────────────────────

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
RE_URL = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
RE_MD5 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
RE_SHA1 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
RE_SHA256 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RE_BTC = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)
RE_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Boilerplate that shows up in nearly every filing — drop to cut FP noise.
DOMAIN_BLOCKLIST = {
    "sec.gov", "www.sec.gov", "edgar.sec.gov", "investor.gov",
    "prnewswire.com", "businesswire.com", "globenewswire.com",
}
EMAIL_DOMAIN_BLOCKLIST = {"sec.gov"}


def refang(text: str) -> str:
    """Restore defanged IOCs (1.2.3[.]4 → 1.2.3.4, hxxp → http, etc.)."""
    for bad, good in (
        ("[.]", "."), ("(.)", "."), ("{.}", "."),
        ("[:]", ":"), ("[/]", "/"),
        ("hxxp", "http"), ("hXXp", "http"), ("HXXP", "HTTP"),
        ("[@]", "@"), ("(@)", "@"), ("[at]", "@"), ("[AT]", "@"),
    ):
        text = text.replace(bad, good)
    return text


class _Stripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


_RE_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_RE_NL_RUNS = re.compile(r"\s*\n\s*")
_RE_HTAB_RUNS = re.compile(r"[ \t]+")


def html_to_text(html: str) -> str:
    # SEC's filing wrapper embeds documents inside a top-level <!--<SEC-HEADER>...-->
    # comment, and the inlined Workiva docs each begin with <!--xfrm--> /
    # <!--r:UUID,d:UUID--> markers. html.parser mis-handles the nesting and lets
    # these leak into handle_data (where their hash-like substrings match our
    # MD5/SHA regexes). Pre-strip all comments to make extraction robust.
    html = _RE_HTML_COMMENT.sub(" ", html)
    p = _Stripper()
    try:
        p.feed(html)
    except Exception:
        pass
    text = " ".join(p.parts)
    text = _RE_NL_RUNS.sub("\n", text)
    return _RE_HTAB_RUNS.sub(" ", text).strip()


# ─── EDGAR client ─────────────────────────────────────────────────────────────

class Edgar:
    """Rate-limited EDGAR client.

    EDGAR enforces 10 req/s and requires a descriptive User-Agent with a
    contact email. We hold a ~150ms gap to stay well under the limit.
    """

    def __init__(self, user_agent: str) -> None:
        self.session = requests.Session()
        # Headers required/expected by SEC fair-access policy. Do NOT swap the
        # UA for a fake browser string — SEC will block you for that.
        # Do NOT pin a Host header — requests sets it per-URL, and EDGAR uses
        # multiple hosts (efts.sec.gov for search, www.sec.gov for archives).
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        })
        self._last = 0.0

    def _wait(self) -> None:
        delta = time.monotonic() - self._last
        if delta < 0.15:
            time.sleep(0.15 - delta)
        self._last = time.monotonic()

    def get(self, url: str, allow: tuple[int, ...] = (), **kw) -> requests.Response:
        """GET with retry/backoff on transient 403/429/5xx from SEC's edge.

        Status codes in ``allow`` are returned without raising — used by
        ``search()`` because EDGAR's search endpoint returns 404 + a valid
        empty-results JSON body when zero hits match.
        """
        backoffs = (1.0, 3.0, 8.0)
        last_exc: requests.RequestException | None = None
        for attempt, delay in enumerate((0.0,) + backoffs):
            if delay:
                log.debug("retrying %s in %.1fs (attempt %d)", url, delay, attempt)
                time.sleep(delay)
            self._wait()
            try:
                resp = self.session.get(url, timeout=30, **kw)
            except requests.RequestException as e:
                last_exc = e
                continue
            if resp.status_code in allow:
                return resp
            if resp.status_code in (403, 429) or resp.status_code >= 500:
                last_exc = requests.HTTPError(
                    f"{resp.status_code} on {url}", response=resp,
                )
                continue
            resp.raise_for_status()
            return resp
        assert last_exc is not None
        raise last_exc

    @staticmethod
    def accession_of(hit: dict) -> str:
        src = hit.get("_source", {})
        return src.get("adsh") or hit.get("_id", "").split(":")[0]

    def search(self, query: str, start_date: str, end_date: str) -> list[dict]:
        """Full-text search 8-Ks in [start_date, end_date]; paginates fully."""
        params = {
            "q": query, "forms": "8-K", "dateRange": "custom",
            "startdt": start_date, "enddt": end_date,
        }
        out: list[dict] = []
        from_ = 0
        while True:
            params["from"] = from_
            # EDGAR returns 404 + empty-results JSON body for zero-hit queries.
            resp = self.get(EDGAR_SEARCH, params=params, allow=(404,))
            try:
                data = resp.json()
            except ValueError:
                log.warning("non-JSON search response (status %s)", resp.status_code)
                break
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break
            out.extend(hits)
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            from_ += len(hits)
            if from_ >= total or from_ >= 1000:
                break
        return out

    def fetch_filing(self, cik: str, accession: str) -> dict[str, str]:
        """Return {filename: text} for the HTML documents in this accession.

        We deliberately skip ``<accession>.txt`` — SEC's "complete submission"
        file. It's an SGML-wrapped concatenation of every other document plus
        the SEC header, so it duplicates content we already have and leaks
        unparsed filing-platform markers (Workiva UUIDs etc.) past html_to_text.
        """
        nodash = accession.replace("-", "")
        idx_url = f"{EDGAR_ARCHIVES}/{int(cik)}/{nodash}/index.json"
        idx = self.get(idx_url).json()
        # SEC auto-generates several wrapper files per filing; all leak the
        # SGML <SEC-HEADER> block as text. Skip them — the primary documents
        # and exhibits carry the actual filing content.
        skip = {
            f"{accession}.txt",
            f"{accession}-index.htm",
            f"{accession}-index.html",
            f"{accession}-index-headers.html",
        }
        docs: dict[str, str] = {}
        for item in idx.get("directory", {}).get("item", []):
            name = item.get("name", "")
            low = name.lower()
            if not low.endswith((".htm", ".html")) or name in skip:
                continue
            url = f"{EDGAR_ARCHIVES}/{int(cik)}/{nodash}/{name}"
            try:
                body = self.get(url).text
            except requests.RequestException as e:
                log.warning("failed to fetch %s: %s", url, e)
                continue
            docs[name] = html_to_text(body)
        return docs


# ─── Extraction ───────────────────────────────────────────────────────────────

@dataclass
class IOC:
    type: str
    value: str
    context: str = ""

    def key(self) -> tuple[str, str]:
        return (self.type, self.value.lower())


_RE_WS = re.compile(r"\s+")

# Keywords that mark a paragraph as incident-relevant. Aligned with the EDGAR
# full-text query in DEFAULT_QUERY plus a few common synonyms — any filing the
# search returned should match at least one of these somewhere.
_RE_CYBER = re.compile(
    r"\b(?:item\s*1\.05|cyber(?:security|attack)?|ransom(?:ware)?|"
    r"unauthorized\s+access|data\s+breach|threat\s+actor|intrusion|"
    r"malware|exfiltrat|compromis|security\s+incident|encrypt(?:ed|ion)?|"
    r"phish(?:ing)?)\b",
    re.IGNORECASE,
)


def relevant_windows(text: str, neighbors: int = 1) -> str:
    """Narrow a filing's text to paragraphs near cyber keywords.

    8-K filings are mostly forward-looking statements, risk-factor boilerplate,
    and signature blocks. The incident discussion is usually a few paragraphs.
    Restricting both regex and LLM extraction to keyword-hit paragraphs (plus
    ``neighbors`` on either side, to keep prose flow around the hit) cuts false
    positives and shrinks LLM input dramatically — a single filing can drop
    from 50k+ chars to under 5k.

    Returns the empty string if nothing matched; callers should fall back to
    the full text in that case so downstream extraction still runs.
    """
    paras = text.split("\n")
    keep: set[int] = set()
    for i, p in enumerate(paras):
        if _RE_CYBER.search(p):
            keep.update(range(max(0, i - neighbors),
                              min(len(paras), i + neighbors + 1)))
    return "\n".join(paras[i] for i in sorted(keep))


def _context(text: str, span: tuple[int, int], width: int = 120) -> str:
    a = max(0, span[0] - width)
    b = min(len(text), span[1] + width)
    return _RE_WS.sub(" ", text[a:b]).strip()


def _has_known_tld(domain: str) -> bool:
    return "." in domain and 2 <= len(domain.rsplit(".", 1)[1]) <= 24


def extract_regex(text: str, high_precision_only: bool = False) -> list[IOC]:
    """Regex-based IOC extraction.

    When ``high_precision_only`` is True, only types with low false-positive
    rates run (hashes, CVE, BTC, ATT&CK). The noisy contextual types
    (domain/ipv4/url/email) are skipped — those are best handled by the LLM
    pass, since in 8-K prose they're nearly always IR boilerplate.
    """
    text = refang(text)
    found: dict[tuple[str, str], IOC] = {}

    def add(t: str, v: str, span: tuple[int, int]) -> None:
        # Build the context window only on first sight — repeated matches of
        # the same indicator (common in 8-Ks) would otherwise re-slice and
        # re-collapse whitespace for each duplicate, then get thrown away by
        # setdefault.
        key = (t, v.lower())
        if key not in found:
            found[key] = IOC(t, v, _context(text, span))

    if not high_precision_only:
        for m in RE_URL.finditer(text):
            add("url", m.group(0).rstrip(".,);"), m.span())
        for m in RE_IPV4.finditer(text):
            ip = m.group(0)
            if ip.startswith(("0.", "127.", "255.255.255")):
                continue
            add("ipv4", ip, m.span())
        for m in RE_DOMAIN.finditer(text):
            d = m.group(0).lower().rstrip(".")
            if d in DOMAIN_BLOCKLIST or not _has_known_tld(d):
                continue
            add("domain", d, m.span())
        for m in RE_EMAIL.finditer(text):
            e = m.group(0).lower()
            if e.split("@", 1)[1] in EMAIL_DOMAIN_BLOCKLIST:
                continue
            add("email", e, m.span())

    for m in RE_SHA256.finditer(text):
        add("sha256", m.group(0).lower(), m.span())
    for m in RE_SHA1.finditer(text):
        add("sha1", m.group(0).lower(), m.span())
    for m in RE_MD5.finditer(text):
        add("md5", m.group(0).lower(), m.span())
    for m in RE_CVE.finditer(text):
        add("cve", m.group(0).upper(), m.span())
    for m in RE_BTC.finditer(text):
        add("btc", m.group(0), m.span())
    for m in RE_ATTACK.finditer(text):
        add("attack_pattern", m.group(0).upper(), m.span())

    # Drop bare domains that are already inside a captured URL or email.
    # Concatenate the URL/email values into one haystack so each domain
    # check is a single C-level substring search instead of a Python loop.
    haystack = "\n".join(
        i.value for i in found.values() if i.type in ("url", "email")
    )
    return [
        ioc for ioc in found.values()
        if not (ioc.type == "domain" and ioc.value in haystack)
    ]


# ─── LLM ──────────────────────────────────────────────────────────────────────

LLM_SYSTEM = """You extract indicators of compromise (IOCs) from SEC 8-K cybersecurity disclosures.

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
- Output JSON only — no prose, no markdown fences."""


class LLM:
    def __init__(self, base_url: str, model: str | None = None, timeout: int = 180) -> None:
        self.url = base_url.rstrip("/")
        self.timeout = timeout
        # Shared session enables HTTP keep-alive across the many per-filing
        # POSTs we make during backfill — the LLM endpoint stays hot instead
        # of forcing a new TCP+HTTP handshake on every call.
        self.session = requests.Session()
        self.model = model or self._autodetect_model()

    def _autodetect_model(self) -> str:
        """Pick the first model the server advertises via /v1/models."""
        try:
            r = self.session.get(f"{self.url}/v1/models", timeout=10)
            r.raise_for_status()
            data = r.json().get("data") or []
            if data:
                model = data[0].get("id")
                if model:
                    log.info("auto-selected LLM model: %s", model)
                    return model
        except (requests.RequestException, ValueError, KeyError) as e:
            log.warning("could not auto-detect LLM model (%s); using 'local'", e)
        return "local"

    def extract(self, text: str) -> list[IOC]:
        if not text.strip():
            return []
        payload = {
            "model": self.model,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": LLM_SYSTEM},
                {"role": "user", "content": text[:24_000]},
            ],
            "response_format": {"type": "json_object"},
        }
        try:
            r = self.session.post(
                f"{self.url}/v1/chat/completions",
                json=payload, timeout=self.timeout,
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
        except (requests.RequestException, KeyError, IndexError, ValueError) as e:
            log.warning("LLM call failed: %s", e)
            return []
        try:
            data = json.loads(_strip_code_fence(content))
        except json.JSONDecodeError:
            log.warning("LLM returned non-JSON: %s", content[:200])
            return []
        out: list[IOC] = []
        for item in data.get("iocs", []) if isinstance(data, dict) else []:
            t, v = item.get("type"), item.get("value")
            if t and v:
                out.append(IOC(str(t), str(v), str(item.get("context", ""))))
        return out


def _strip_code_fence(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()


# ─── STIX 2.1 / TAXII 2.1 ─────────────────────────────────────────────────────

_STIX_TIME = "%Y-%m-%dT%H:%M:%S.000Z"

# IOC types that map cleanly to STIX indicator patterns.
STIX_PATTERN = {
    "ipv4":         "[ipv4-addr:value = '{v}']",
    "ipv6":         "[ipv6-addr:value = '{v}']",
    "domain":       "[domain-name:value = '{v}']",
    "url":          "[url:value = '{v}']",
    "email":        "[email-addr:value = '{v}']",
    "md5":          "[file:hashes.MD5 = '{v}']",
    "sha1":         "[file:hashes.'SHA-1' = '{v}']",
    "sha256":       "[file:hashes.'SHA-256' = '{v}']",
    "filename":     "[file:name = '{v}']",
    "mutex":        "[mutex:name = '{v}']",
    "registry_key": "[windows-registry-key:key = '{v}']",
    "btc":          "[cryptocurrency-wallet:address = '{v}']",
    "monero":       "[cryptocurrency-wallet:address = '{v}']",
}


def _stix_id(t: str) -> str:
    return f"{t}--{uuid.uuid4()}"


def _stix_now() -> str:
    return datetime.now(timezone.utc).strftime(_STIX_TIME)


def _stix_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def build_stix_bundle(record: dict) -> dict:
    """Produce a STIX 2.1 bundle for one 8-K filing's IOCs.

    Indicators (and specialized SDOs like threat-actor / malware / vulnerability
    / attack-pattern / tool) are linked together by a single report SDO that
    references the originating SEC filing.
    """
    now = _stix_now()
    objects: list[dict] = []

    identity_id = _stix_id("identity")
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now,
        "name": record["filer"], "identity_class": "organization",
        "external_references": [
            {"source_name": "sec-cik", "external_id": str(record["cik"])},
        ],
    })

    obj_refs: list[str] = []
    for ioc in record["iocs"]:
        t, v = ioc["type"], ioc["value"]
        ctx = (ioc.get("context") or "")[:500]
        sdo: dict | None = None

        if t in STIX_PATTERN:
            sdo = {
                "type": "indicator", "spec_version": "2.1",
                "id": _stix_id("indicator"),
                "created": now, "modified": now,
                "name": f"{t}: {v}", "description": ctx,
                "pattern": STIX_PATTERN[t].format(v=_stix_escape(v)),
                "pattern_type": "stix", "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "created_by_ref": identity_id,
            }
        elif t in ("cve", "vulnerability"):
            sdo = {
                "type": "vulnerability", "spec_version": "2.1",
                "id": _stix_id("vulnerability"),
                "created": now, "modified": now, "name": v, "description": ctx,
                "external_references": [
                    {"source_name": "cve", "external_id": v},
                ] if t == "cve" else [],
                "created_by_ref": identity_id,
            }
        elif t == "threat_actor":
            sdo = {
                "type": "threat-actor", "spec_version": "2.1",
                "id": _stix_id("threat-actor"),
                "created": now, "modified": now, "name": v, "description": ctx,
                "threat_actor_types": ["unknown"],
                "created_by_ref": identity_id,
            }
        elif t == "malware_family":
            sdo = {
                "type": "malware", "spec_version": "2.1",
                "id": _stix_id("malware"),
                "created": now, "modified": now,
                "name": v, "description": ctx, "is_family": True,
                "malware_types": ["unknown"],
                "created_by_ref": identity_id,
            }
        elif t == "attack_pattern":
            sdo = {
                "type": "attack-pattern", "spec_version": "2.1",
                "id": _stix_id("attack-pattern"),
                "created": now, "modified": now, "name": v, "description": ctx,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": v},
                ],
                "created_by_ref": identity_id,
            }
        elif t == "tool_name":
            sdo = {
                "type": "tool", "spec_version": "2.1",
                "id": _stix_id("tool"),
                "created": now, "modified": now, "name": v, "description": ctx,
                "created_by_ref": identity_id,
            }

        if sdo is not None:
            objects.append(sdo)
            obj_refs.append(sdo["id"])

    report_refs = obj_refs or [identity_id]
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _stix_id("report"),
        "created": now, "modified": now,
        "name": f"SEC 8-K disclosure — {record['filer']} ({record['accession']})",
        "description": (
            f"IOCs extracted from SEC 8-K filing {record['accession']} "
            f"filed {record['filed']}."
        ),
        "published": now, "report_types": ["threat-report"],
        "object_refs": report_refs,
        "external_references": [
            {"source_name": "sec-edgar", "url": record["filing_index"],
             "external_id": record["accession"]},
        ],
        "created_by_ref": identity_id,
    })

    return {"type": "bundle", "id": _stix_id("bundle"), "objects": objects}


class Taxii:
    """Minimal TAXII 2.1 client that pushes STIX bundles to a collection."""

    def __init__(self, base_url: str, collection_id: str,
                 user: str | None = None, password: str | None = None,
                 token: str | None = None) -> None:
        self.url = base_url.rstrip("/")
        self.collection = collection_id
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/taxii+json;version=2.1",
            "Accept": "application/taxii+json;version=2.1",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif user is not None:
            self.session.auth = (user, password or "")

    def push(self, bundle: dict) -> bool:
        # TAXII 2.1's add-objects endpoint accepts an envelope, not a bundle.
        envelope = {"objects": bundle["objects"]}
        url = f"{self.url}/collections/{self.collection}/objects/"
        try:
            r = self.session.post(url, json=envelope, timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            log.warning("TAXII push failed: %s", e)
            return False
        return True


# ─── Plaintext report ─────────────────────────────────────────────────────────

def write_text_report(record: dict, fh: IO[str]) -> None:
    sep = "=" * 80
    fh.write(f"\n{sep}\n")
    fh.write(f"[{record['filed']}] {record['filer']}\n")
    fh.write(f"Accession: {record['accession']}\n")
    fh.write(f"Filing:    {record['filing_index']}\n")
    fh.write(f"IOCs ({record['ioc_count']}):\n")
    if not record["iocs"]:
        fh.write("  (none)\n")
    else:
        for i in record["iocs"]:
            fh.write(f"  - [{i['type']}] {i['value']}\n")
            ctx = " ".join((i.get("context") or "").split())[:200]
            if ctx:
                fh.write(f"      ctx: {ctx}\n")
    fh.write(f"{sep}\n")
    fh.flush()


# ─── State ────────────────────────────────────────────────────────────────────

@dataclass
class State:
    seen: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(seen=set(data.get("seen", [])))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("could not read state %s: %s — starting fresh", path, e)
            return cls()

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps({"seen": sorted(self.seen)}, indent=2))
        tmp.replace(path)


# ─── Run loop ─────────────────────────────────────────────────────────────────

def merge_iocs(*lists: list[IOC]) -> list[IOC]:
    seen: dict[tuple[str, str], IOC] = {}
    for lst in lists:
        for ioc in lst:
            seen.setdefault(ioc.key(), ioc)
    return list(seen.values())


def process_filing(edgar: Edgar, llm: LLM | None, hit: dict, accession: str) -> dict | None:
    src = hit.get("_source", {})
    ciks = src.get("ciks", [])
    if not ciks:
        return None
    cik = ciks[0]
    docs = edgar.fetch_filing(cik, accession)
    if not docs:
        return None
    blob = "\n\n".join(docs.values())

    # Narrow to keyword-relevant paragraphs (plus immediate neighbors) so both
    # regex and LLM operate on the incident discussion, not the risk-factor
    # boilerplate / signature blocks. Falls back to the full text only if the
    # window came back empty — every filing matched the EDGAR query somewhere,
    # so an empty window means our local keyword set drifted.
    window = relevant_windows(blob)
    if not window:
        log.debug("%s: no cyber-keyword paragraphs found, using full text",
                  accession)
        window = blob

    # Regex stays restricted to high-precision types (hashes/CVE/BTC/ATT&CK)
    # when LLM is on; the LLM handles the contextual types.
    regex_iocs = extract_regex(window, high_precision_only=llm is not None)
    llm_iocs = llm.extract(window) if llm is not None else []
    iocs = merge_iocs(regex_iocs, llm_iocs)

    return {
        "accession": accession,
        "cik": cik,
        "filer": (src.get("display_names") or [""])[0],
        "filed": src.get("file_date"),
        "form": src.get("form"),
        "url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany"
               f"&CIK={int(cik)}&type=8-K",
        "filing_index": f"{EDGAR_ARCHIVES}/{int(cik)}/"
                        f"{accession.replace('-', '')}/{accession}-index.htm",
        "iocs": [{"type": i.type, "value": i.value, "context": i.context}
                 for i in iocs],
        "ioc_count": len(iocs),
        "extracted_at": datetime.now(timezone.utc).isoformat(),
    }


@dataclass
class Sinks:
    """Bundle of output destinations a cycle writes each filing to."""
    jsonl: IO[str] | None = None
    text: IO[str] | None = None
    stix: IO[str] | None = None
    taxii: Taxii | None = None

    def emit(self, record: dict) -> None:
        if self.jsonl is not None:
            self.jsonl.write(json.dumps(record) + "\n")
            self.jsonl.flush()
        if self.text is not None:
            write_text_report(record, self.text)
        # Skip STIX/TAXII for empty filings — a bundle with no indicators is
        # just an identity + report stub, which clutters the feed without
        # adding signal. JSONL/text still record the zero-IOC filing as
        # negative-result evidence.
        if record["ioc_count"] > 0 and (
            self.stix is not None or self.taxii is not None
        ):
            bundle = build_stix_bundle(record)
            if self.stix is not None:
                self.stix.write(json.dumps(bundle) + "\n")
                self.stix.flush()
            if self.taxii is not None:
                self.taxii.push(bundle)


def cycle(edgar: Edgar, llm: LLM | None, state: State, state_path: Path,
          query: str, lookback_days: int, sinks: Sinks) -> int:
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=lookback_days)
    log.info("searching EDGAR %s → %s", start, end)
    hits = edgar.search(query, start.isoformat(), end.isoformat())
    log.info("%d candidate filings", len(hits))

    new = 0
    for hit in hits:
        accession = Edgar.accession_of(hit)
        if not accession or accession in state.seen:
            continue
        try:
            record = process_filing(edgar, llm, hit, accession)
        except requests.RequestException as e:
            log.warning("fetch failed for %s: %s", accession, e)
            continue
        state.seen.add(accession)
        if record:
            sinks.emit(record)
            new += 1
            log.info("%s %s — %d IOCs", record["filed"], accession,
                     record["ioc_count"])
    state.save(state_path)
    return new


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Monitor SEC 8-K filings for cybersecurity IOCs.",
    )
    ap.add_argument("--user-agent", required=True,
                    help='EDGAR requires this. e.g. "Acme Research foo@example.com"')
    ap.add_argument("--query", default=DEFAULT_QUERY,
                    help="EDGAR full-text search query")
    ap.add_argument("--lookback-days", type=int, default=2,
                    help="How far back to search each poll (default: 2)")
    ap.add_argument("--backfill-days", type=int, default=None,
                    help="How far back to backfill and extract IOCs. When "
                         "passed explicitly, forces a backfill at this depth "
                         "regardless of state file contents (use to widen "
                         "an existing run's window). When omitted, the "
                         "default is 365 days on first run only; subsequent "
                         "runs skip backfill. Set to 0 to skip backfill on "
                         "first run too.")
    ap.add_argument("--state-file", type=Path, default=Path("8k_state.json"))
    ap.add_argument("--output", type=Path, default=None,
                    help="Append JSONL output here (default: stdout)")
    ap.add_argument("--text-output", type=Path, default=None,
                    help="Append human-readable per-filing reports here")
    ap.add_argument("--stix-output", type=Path, default=None,
                    help="Append STIX 2.1 bundles here (one bundle per line)")
    ap.add_argument("--taxii-url", default=None,
                    help="TAXII 2.1 API root URL (e.g. https://taxii.example/api/)")
    ap.add_argument("--taxii-collection", default=None,
                    help="TAXII 2.1 collection id to push bundles into")
    ap.add_argument("--taxii-user", default=None, help="TAXII basic-auth user")
    ap.add_argument("--taxii-pass", default=None, help="TAXII basic-auth password")
    ap.add_argument("--taxii-token", default=None, help="TAXII bearer token")
    ap.add_argument("--interval", type=int, default=0,
                    help="If >0, loop forever sleeping this many seconds")
    ap.add_argument("--llm-url", default=None,
                    help="OpenAI-compatible base URL (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--llm-model", default=None,
                    help="Model id to send; if omitted, auto-detects via /v1/models")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--clean-start", action="store_true",
                    help="Delete the state file and any output files this "
                         "invocation would write to (--output, --text-output, "
                         "--stix-output), then run normally. Prompts for "
                         "confirmation. Useful for re-running a backfill "
                         "from scratch.")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="Skip the --clean-start confirmation prompt.")
    ap.add_argument("--log-file", type=Path, default=Path("run.log"),
                    help="Append run logs (banner + per-filing INFO lines + "
                         "warnings/errors) to this file. Default: run.log")
    ap.add_argument("--no-log-file", action="store_true",
                    help="Disable file logging entirely.")
    ap.add_argument("--no-banner", action="store_true",
                    help="Suppress the ASCII startup banner")
    ap.add_argument("--no-color", action="store_true",
                    help="Force-disable ANSI colour output")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if (args.taxii_url or args.taxii_collection) and not (args.taxii_url and args.taxii_collection):
        ap.error("--taxii-url and --taxii-collection must be provided together")

    global _USE_COLOR
    _USE_COLOR = (
        sys.stderr.isatty()
        and not args.no_color
        and not os.environ.get("NO_COLOR")
    )

    if not args.no_banner:
        print_banner(sys.stderr)

    handlers: list[logging.Handler] = []
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_HackerFormatter(colored=True))
    handlers.append(stderr_handler)

    if not args.no_log_file:
        try:
            file_handler = logging.FileHandler(args.log_file, mode="a")
            file_handler.setFormatter(_HackerFormatter(colored=False))
            handlers.append(file_handler)
        except OSError as e:
            print(f"warning: could not open log file {args.log_file}: {e}",
                  file=sys.stderr)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=handlers,
    )
    # urllib3/requests emit a DEBUG line per HTTP request/connection, which
    # drowns out our own log under -v. Keep them at WARNING regardless of
    # verbose level so the per-filing IOC lines stay visible.
    for noisy in ("urllib3", "requests", "urllib3.connectionpool"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if args.clean_start:
        log_path = None if args.no_log_file else args.log_file
        targets = [p for p in (args.state_file, args.output,
                               args.text_output, args.stix_output, log_path)
                   if p is not None and p.exists()]
        if not targets:
            log.info("clean-start: no files to remove")
        else:
            log.warning("clean-start will DELETE %d file(s):", len(targets))
            for p in targets:
                log.warning("  - %s", p)
            if not args.yes:
                if not sys.stdin.isatty():
                    log.error("clean-start needs a TTY for confirmation; "
                              "pass --yes to skip the prompt")
                    return 2
                reply = input("Proceed? [y/N] ").strip().lower()
                if reply not in ("y", "yes"):
                    log.info("clean-start aborted")
                    return 1
            for p in targets:
                try:
                    p.unlink()
                    log.info("removed %s", p)
                except OSError as e:
                    log.warning("could not remove %s: %s", p, e)

    edgar = Edgar(args.user_agent)
    llm = None if args.no_llm or not args.llm_url else LLM(args.llm_url, args.llm_model)
    if llm is not None:
        log.info("LLM enabled at %s (model=%s)", args.llm_url, llm.model)
    state = State.load(args.state_file)

    sinks = Sinks(
        jsonl=args.output.open("a") if args.output else sys.stdout,
        text=args.text_output.open("a") if args.text_output else None,
        stix=args.stix_output.open("a") if args.stix_output else None,
        taxii=Taxii(args.taxii_url, args.taxii_collection,
                    user=args.taxii_user, password=args.taxii_pass,
                    token=args.taxii_token) if args.taxii_url else None,
    )
    if sinks.taxii is not None:
        log.info("TAXII push enabled: %s collection=%s",
                 args.taxii_url, args.taxii_collection)

    # Backfill: pull the past N days and run them through the full extract
    # pipeline. State is checkpointed as we go so steady-state polls only
    # touch newer filings.
    #
    # - If --backfill-days was passed explicitly: honour it every run (lets
    #   the user widen an existing run's window without deleting state).
    # - Otherwise: default to 365 on first run only (empty state). Skip on
    #   subsequent runs so we don't re-scan a year on every restart.
    if args.backfill_days is not None:
        backfill_days = args.backfill_days
    elif not state.seen:
        backfill_days = 365
    else:
        backfill_days = 0

    if backfill_days > 0:
        tag = "first run" if not state.seen else "user-requested"
        log.info("%s: backfilling past %d days", tag, backfill_days)
        n = cycle(edgar, llm, state, args.state_file, args.query,
                  backfill_days, sinks)
        log.info("backfill complete: %d filings processed", n)

    try:
        while True:
            try:
                n = cycle(edgar, llm, state, args.state_file,
                          args.query, args.lookback_days, sinks)
                log.info("cycle done: %d new filings", n)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log.exception("cycle failed: %s", e)
            if args.interval <= 0:
                break
            log.info("sleeping %ds", args.interval)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        for fh in (sinks.jsonl, sinks.text, sinks.stix):
            if fh is not None and fh is not sys.stdout:
                fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
