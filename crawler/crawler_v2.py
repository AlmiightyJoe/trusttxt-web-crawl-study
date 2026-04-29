#!/usr/bin/env python3

# Main crawler used to detect trust.txt implementations across domains.
#
# Responsibilities:
# - Requests /.well-known/trust.txt and /trust.txt
# - Handles redirects and HTTP fallback
# - Applies content-based classification (gate system)
# - Stores valid files and false positives separately
# - Extracts new domains from discovered files
#
# Designed to reflect real-world server behavior rather than assuming strict compliance.

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import os
import re
import sys
import threading
import time
import termios
import tty
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, Optional, Set, Tuple, List
from urllib.parse import urlparse

import aiohttp

# Standard locations defined by the trust.txt specification
PATHS: Tuple[str, str] = ("/.well-known/trust.txt", "/trust.txt")

# Regular expressions used to extract URLs and domain references
# from retrieved trust.txt content (used for optional expansion)
URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
    re.IGNORECASE,
)

PAUSED = False
STOP_REQUESTED = False

# Defines the column structure for valid trust.txt results
# Keeping this fixed ensures consistent CSV output across runs
FOUND_FIELDS = [
    "ts_utc",
    "domain",
    "scheme",
    "requested_path",
    "final_url",
    "final_host",
    "status",
    "bytes",
    "sha256",
    "saved_to",
    "content_type",
    "gate_class",
    "gate_reason",
    "redirect_chain",
]

# Defines the column structure for domains where no valid trust.txt file was found
NOT_FOUND_FIELDS = ["ts_utc", "domain", "reason", "attempts"]

# Returns current UTC timestamp for reproducible logging
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# Creates output directories if they do not already exist
def ensure_dir(path: str) -> None:
    if path:
        os.makedirs(path, exist_ok=True)

# Generates SHA-256 hash of stored response content
# Used to identify and verify saved files
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# Normalizes domain input to ensure consistency:
# - strips scheme if present
# - enforces valid domain format
# - removes invalid or local entries (e.g. localhost)
def normalize_domain(s: str) -> Optional[str]:
    s = s.strip().lower()
    if not s:
        return None

    if "://" in s:
        try:
            p = urlparse(s)
            s = (p.hostname or "").lower()
        except Exception:
            return None

    s = s.rstrip(".")
    if len(s) > 253 or "." not in s:
        return None
    if any(ch for ch in s if not (ch.isalnum() or ch in "-.")):
        return None
    if s == "localhost":
        return None

    return s

# Extracts base domain (e.g. flpress.com)
# Used to control crawling scope and redirect validation
def etld1(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])

# Allows runtime control of the crawler:
# P = Pause, R = Resume, X = Stop
def keyboard_listener():
    global PAUSED, STOP_REQUESTED

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not STOP_REQUESTED:
            ch = sys.stdin.read(1).lower()
            if ch == "p":
                PAUSED = True
                print("\n[PAUSED] Press R to resume")
            elif ch == "r":
                PAUSED = False
                print("\n[RESUMED]")
            elif ch == "x":
                STOP_REQUESTED = True
                PAUSED = False
                print("\n[EXIT REQUESTED] Finishing current domain and stopping…")
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# Extracts domains from valid trust.txt content
# Used for optional recursive discovery of additional domains
def extract_domains_from_text(text: str) -> Set[str]:
    found: Set[str] = set()

    for m in URL_RE.findall(text):
        try:
            p = urlparse(m)
            if p.hostname:
                d = normalize_domain(p.hostname)
                if d:
                    found.add(d)
        except Exception:
            pass

    for m in DOMAIN_RE.findall(text):
        d = normalize_domain(m)
        if d:
            found.add(d)

    return found

# Writes one row to a CSV file and creates the header if the file is new
def write_csv_row(csv_path: str, row: Dict[str, object], fieldnames: Iterable[str]) -> None:
    ensure_dir(os.path.dirname(csv_path))
    exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(fieldnames))
        if not exists:
            w.writeheader()
        w.writerow(row)

# Loads a text file into a set, ignoring empty lines and comments
def load_lines_set(path: str) -> Set[str]:
    out: Set[str] = set()
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.add(line)
    return out

# Loads and normalizes seed domains from the configured seed file
def load_seeds(seeds_path: str) -> Set[str]:
    raw = load_lines_set(seeds_path)
    seeds: Set[str] = set()
    for x in raw:
        d = normalize_domain(x)
        if d:
            seeds.add(d)
    return seeds

# Appends newly discovered domains to the seed file
# Prevents duplicates by checking against known_seeds
def append_new_seeds(seeds_path: str, new_domains: Set[str], known_seeds: Set[str]) -> int:
    to_add = sorted([d for d in new_domains if d not in known_seeds])
    if not to_add:
        return 0
    with open(seeds_path, "a", encoding="utf-8") as f:
        for d in to_add:
            f.write(d + "\n")
            known_seeds.add(d)
    return len(to_add)

# Records a processed domain so it is not crawled again in later runs
def append_visited(visited_path: str, domain: str) -> None:
    ensure_dir(os.path.dirname(visited_path))
    with open(visited_path, "a", encoding="utf-8") as f:
        f.write(domain + "\n")

# Simple request limiter used to avoid sending requests too quickly
class PoliteLimiter:
    def __init__(self, min_delay_s: float):
        self.min_delay = max(min_delay_s, 0.1)
        self._next = 0.0

    async def wait(self):
        now = time.monotonic()
        if now < self._next:
            await asyncio.sleep(self._next - now)
        self._next = max(self._next, time.monotonic()) + self.min_delay

# Stores the result of one HTTP request in a structured format
@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    redirect_chain: str
    status: Optional[int]
    error: str
    body: bytes
    content_type: str

# Stores the result of the content validation step
@dataclass
class GateDecision:
    gate_class: str
    gate_reason: str
    should_save: bool


# Core classification logic (gate system):
# Determines whether a response is a valid trust.txt file or a false positive.
#
# This replaces naive validation based on HTTP status codes by inspecting content.
# It filters out:
# - HTML pages (fallback or CMS responses)
# - redirect shells
# - WAF / bot challenge pages
# - binary or malformed responses
def sniff_gate(body: bytes, content_type: str) -> GateDecision:
    ctype = (content_type or "").lower()
    if not body or len(body.strip()) == 0:
        return GateDecision("EMPTY_OR_WHITESPACE", "empty body", False)

    sample = body[:2048]
    sample_l = sample.lower()

    if b"\x00" in sample:
        return GateDecision("BINARY_OR_ENCODED", "NUL byte detected", False)

    # HTML & redirect-like shells
    if sample_l.startswith(b"<!doctype") or b"<html" in sample_l or b"<head" in sample_l:
        if b"<frameset" in sample_l:
            return GateDecision("HTML_FALSE_POSITIVE", "frameset fallback", False)
        if b"window.location" in sample_l or b"location.href" in sample_l:
            return GateDecision("HTML_FALSE_POSITIVE", "javascript redirect page", False)
        return GateDecision("HTML_FALSE_POSITIVE", "html detected", False)

    # WAF markers
    waf_markers = [
        b"_incapsula_resource",
        b"cf-chl-",
        b"cloudflare",
        b"attention required",
        b"captcha",
        b"akamai",
        b"imperva",
    ]
    if any(m in sample_l for m in waf_markers):
        return GateDecision("WAF_OR_BOT_CHALLENGE", "waf/bot marker detected", False)

    if "text/html" in ctype:
        return GateDecision("HTML_FALSE_POSITIVE", "content-type text/html", False)

    # Heuristic: too many non-printables -> reject
    nonprint = sum(1 for b in sample if b < 9 or (b > 13 and b < 32))
    ratio = nonprint / max(len(sample), 1)
    if ratio > 0.10:
        return GateDecision("NONSTANDARD_TEXT_ENCODING", f"nonprintable_ratio={ratio:.2f}", False)

    return GateDecision("VALID_TEXT", "text-like content", True)

# Performs HTTP request with redirect handling and error control
# Applies redirect policy to avoid cross-domain contamination
# (e.g. avoiding unrelated content being misclassified as trust.txt)
async def fetch(
    session: aiohttp.ClientSession,
    limiter: PoliteLimiter,
    scheme: str,
    domain: str,
    path: str,
    timeout_s: int,
    user_agent: str,
    max_redirects: int,
    allow_cross_domain_redirects: bool,
    allow_same_etld1_redirects: bool,
) -> FetchResult:
    requested_url = f"{scheme}://{domain}{path}"

    while PAUSED:
        await asyncio.sleep(0.2)
    if STOP_REQUESTED:
        return FetchResult(requested_url, requested_url, "", None, "stopped", b"", "")

    await limiter.wait()

    try:
        async with session.get(
            requested_url,
            timeout=aiohttp.ClientTimeout(total=timeout_s),
            allow_redirects=True,
            max_redirects=max_redirects,
            headers={"User-Agent": user_agent, "Accept": "text/plain,*/*;q=0.8"},
        ) as r:
            body = await r.read()
            ctype = r.headers.get("Content-Type", "")

            final_url = str(r.url)
            final_host = (urlparse(final_url).hostname or "").lower()

            chain_parts: List[str] = []
            for h in r.history:
                chain_parts.append(f"{h.status}:{str(h.url)}")
            chain = (" -> ".join(chain_parts) + f" -> {r.status}:{final_url}") if chain_parts else ""

            # Redirect policy (block cross-domain by default)
            if final_host and final_host != domain:
                allowed = False
                if allow_cross_domain_redirects:
                    allowed = True
                elif allow_same_etld1_redirects and etld1(final_host) == etld1(domain):
                    allowed = True

                if not allowed:
                    return FetchResult(
                        requested_url=requested_url,
                        final_url=final_url,
                        redirect_chain=chain,
                        status=r.status,
                        error="redirect_blocked_cross_domain",
                        body=b"",
                        content_type=ctype,
                    )

            return FetchResult(requested_url, final_url, chain, r.status, "", body, ctype)

    except asyncio.TimeoutError:
        return FetchResult(requested_url, requested_url, "", None, "timeout", b"", "")
    except aiohttp.TooManyRedirects:
        return FetchResult(requested_url, requested_url, "", None, "too_many_redirects", b"", "")
    except aiohttp.ClientConnectorError:
        return FetchResult(requested_url, requested_url, "", None, "client_error:ClientConnectorError", b"", "")
    except aiohttp.ClientSSLError:
        return FetchResult(requested_url, requested_url, "", None, "client_error:ClientSSLError", b"", "")
    except aiohttp.ClientError as e:
        return FetchResult(requested_url, requested_url, "", None, f"client_error:{type(e).__name__}", b"", "")
    except Exception as e:
        return FetchResult(requested_url, requested_url, "", None, f"error:{type(e).__name__}", b"", "")


# Saves response body to disk under the relevant output category
def save_blob(output_dir: str, domain: str, subdir: str, filename: str, body: bytes) -> str:
    ddir = os.path.join(output_dir, subdir, domain)
    ensure_dir(ddir)
    fpath = os.path.join(ddir, filename)
    with open(fpath, "wb") as f:
        f.write(body)
    return fpath

# Converts requested path into a safe filename for storage
def safe_name_from_requested(scheme: str, path: str) -> str:
    p = path.strip("/").replace("/", "_") or "root"
    return f"{scheme}_{p}.txt"

# Loads crawler settings from the selected JSON configuration file
def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Main Crawling loop:
# Iterates through domains, applies classification, and records results.
# Maintains state (visited, queue) and enforces crawl limits.
async def crawl(cfg: dict) -> int:
    # Read required configuration values
    output_dir = cfg["output_dir"]
    seeds_path = cfg["seeds_file"]

    # Use configured max_domains; defaults to 10.000 if not provided in JSON
    # A value of 0 disables the crawl limit
    raw_max = cfg.get("max_domains", 10000)
    if raw_max in (None, 0, "0"):
    	max_domains = None
    else:
    	max_domains = int(raw_max)
    	
    timeout_s = int(cfg.get("timeout_seconds", 15))
    max_file_kb = int(cfg.get("max_file_kb", 256))
    global_delay = float(cfg.get("global_delay_seconds", 0.05))
    domain_pause = float(cfg.get("domain_pause_seconds", 0.10))
    http_fallback = bool(cfg.get("http_fallback", True))
    user_agent = str(cfg.get("user_agent", "trusttxt-research-crawler/6.0"))
    same_etld1_only = bool(cfg.get("same_etld1_only", False))

    # v2 keys
    max_redirects = int(cfg.get("max_redirects", 5))
    allow_cross_domain_redirects = bool(cfg.get("allow_cross_domain_redirects", False))
    allow_same_etld1_redirects = bool(cfg.get("allow_same_etld1_redirects", True))
    save_fp_samples = bool(cfg.get("save_false_positive_samples", True))
    fp_sample_bytes = int(cfg.get("false_positive_sample_bytes", 4096))

    # Prepare output file paths
    found_csv = os.path.join(output_dir, "found", "found_v2.csv")
    not_found_csv = os.path.join(output_dir, "not_found", "not_found_v2.csv")
    visited_path = cfg.get("visited_file", os.path.join(output_dir, "state", "visited.txt"))

    # Create required output directories before crawling starts
    ensure_dir(os.path.join(output_dir, "found"))
    ensure_dir(os.path.join(output_dir, "not_found"))
    ensure_dir(os.path.join(output_dir, "state"))
    ensure_dir(os.path.join(output_dir, "false_positives"))

    # Load previously visited domains to support resumable crawling
    known_seeds = load_seeds(seeds_path)
    if not known_seeds:
        print(f"No valid seeds in {seeds_path}", file=sys.stderr)
        return 2

    visited = load_lines_set(visited_path)

    # Queue controls which domains still need to be checked
    queue: Deque[str] = deque(sorted(known_seeds))
    queued_set: Set[str] = set(queue)

    limiter = PoliteLimiter(global_delay)

    visited_count = 0
    found_count = 0

    # HTTPS is attempted first, HTTP is only used if fallback is enabled
    schemes = ["https"] + (["http"] if http_fallback else [])

    async with aiohttp.ClientSession() as session:
        # Process one domain at a time from the queue
        while queue:
            if STOP_REQUESTED:
                print("\n[STOPPED] Graceful exit requested.")
                break
            while PAUSED:
                await asyncio.sleep(0.2)

            if max_domains and (len(visited) + visited_count) >= max_domains:
                print(f"\nReached max-domains cap ({max_domains}). Stopping.")
                break

            domain = queue.popleft()
            queued_set.discard(domain)

            domain = normalize_domain(domain) or ""
            # Skip invalid or already processed domains
            if not domain or domain in visited:
                continue

            print(
                f"\rchecking={domain}  visited={len(visited)+visited_count}  queue={len(queue)}  found={found_count}     ",
                end="",
                flush=True,
            )

            # Track all request outcomes for this domain (a little scuffed)
            attempts: List[str] = []
            domain_found = False
            discovered: Set[str] = set()

            # Test each configured scheme and trust.txt path
            for scheme in schemes:
                for path in PATHS:
                    fr = await fetch(
                        session=session,
                        limiter=limiter,
                        scheme=scheme,
                        domain=domain,
                        path=path,
                        timeout_s=timeout_s,
                        user_agent=user_agent,
                        max_redirects=max_redirects,
                        allow_cross_domain_redirects=allow_cross_domain_redirects,
                        allow_same_etld1_redirects=allow_same_etld1_redirects,
                    )

                    # Store request failure and continue with the next attempt
                    if fr.status is None:
                        attempts.append(f"{scheme}{path}:{fr.error}")
                        await asyncio.sleep(domain_pause)
                        continue

                    # Cross-domain redirects are blocked unless explicitly allowed
                    if fr.error == "redirect_blocked_cross_domain":
                        attempts.append(f"{scheme}{path}:{fr.status}:redirect_blocked")
                        await asyncio.sleep(domain_pause)
                        continue

                    # Skip oversized responses to avoid processing non-relevant content
                    if fr.body and len(fr.body) > max_file_kb * 1024:
                        attempts.append(f"{scheme}{path}:{fr.status}:oversize>{max_file_kb}KB")
                        await asyncio.sleep(domain_pause)
                        continue

		    # Only evaluate successful responses with content
		    # Further validation is handled by the gate system 
                    if fr.status == 200 and fr.body:
                        gate = sniff_gate(fr.body, fr.content_type)

                        # Valid trust.txt content detected -> save file and extract additional domains
                        if gate.should_save:
                            fname = safe_name_from_requested(scheme, path)
                            saved_to = save_blob(output_dir, domain, "found", fname, fr.body)
                            sha = sha256_bytes(fr.body)
                            final_host = (urlparse(fr.final_url).hostname or "").lower()

                            write_csv_row(
                                found_csv,
                                {
                                    "ts_utc": utc_now_iso(),
                                    "domain": domain,
                                    "scheme": scheme,
                                    "requested_path": path,
                                    "final_url": fr.final_url,
                                    "final_host": final_host,
                                    "status": fr.status,
                                    "bytes": len(fr.body),
                                    "sha256": sha,
                                    "saved_to": saved_to,
                                    "content_type": fr.content_type,
                                    "gate_class": gate.gate_class,
                                    "gate_reason": gate.gate_reason,
                                    "redirect_chain": fr.redirect_chain,
                                },
                                FOUND_FIELDS,
                            )

                            try:
                                text = fr.body.decode("utf-8", errors="replace")
                                discovered |= extract_domains_from_text(text)
                            except Exception:
                                pass

                            domain_found = True
                            found_count += 1
                            break
                        
                        # False positive detected -> record classification and optionally store sample
                        # (used later for analysis of incorrect responses)
                        else:
                            attempts.append(f"{scheme}{path}:{fr.status}:{gate.gate_class}")
                            if save_fp_samples:
                                sample = fr.body[:fp_sample_bytes]
                                fpname = f"{gate.gate_class}_{safe_name_from_requested(scheme, path)}"
                                save_blob(output_dir, domain, "false_positives", fpname, sample)
                    else:
                        attempts.append(f"{scheme}{path}:{fr.status}")

                    await asyncio.sleep(domain_pause)

                if scheme == "https" and domain_found:
                    break
                if domain_found:
                    break

            # Mark domain as visited after all attempts are complete
            append_visited(visited_path, domain)
            visited.add(domain)
            visited_count += 1

            # If a valid trust.txt file was found, optionally add discovered domains from the file to the crawl queue
            if domain_found:
                if same_etld1_only:
                    base = etld1(domain)
                    discovered = {d for d in discovered if etld1(d) == base}

                append_new_seeds(seeds_path, discovered, known_seeds)
                for nd in sorted(discovered):
                    if nd not in visited and nd not in queued_set:
                        queue.append(nd)
                        queued_set.add(nd)
            # If no valid file was found, write a not_found record with the most relevant reason
            else:
                joined = ";".join(attempts)

                # Assign high-level reason for failure
                # Used for statistical analysis
                # (e.g. HTML false positives, network errors, access issues)
                reason = "NOT_FOUND"
                if "timeout" in joined:
                    reason = "NETWORK_TIMEOUT"
                elif "ClientConnectorError" in joined:
                    reason = "NETWORK_CONNECTOR"
                elif "ClientSSLError" in joined:
                    reason = "NETWORK_TLS"
                elif "too_many_redirects" in joined:
                    reason = "TOO_MANY_REDIRECTS"
                elif "redirect_blocked" in joined:
                    reason = "CROSS_DOMAIN_REDIRECT_BLOCKED"
                elif "WAF_OR_BOT_CHALLENGE" in joined:
                    reason = "WAF_OR_BOT_CHALLENGE"
                elif "HTML_FALSE_POSITIVE" in joined:
                    reason = "HTML_FALSE_POSITIVE"
                elif ":404" in joined:
                    reason = "NOT_FOUND_404"
                elif ":401" in joined or ":403" in joined:
                    reason = "ACCESS_DENIED"
                elif ":429" in joined:
                    reason = "RATE_LIMITED"
                elif "BINARY_OR_ENCODED" in joined:
                    reason = "BINARY_OR_ENCODED"

                write_csv_row(
                    not_found_csv,
                    {"ts_utc": utc_now_iso(), "domain": domain, "reason": reason, "attempts": joined},
                    NOT_FOUND_FIELDS,
                )

    print("\nDone.")
    print(f"Output dir:    {output_dir}")
    print(f"Found CSV:     {found_csv}")
    print(f"Not found CSV: {not_found_csv}")
    print(f"Visited file:  {visited_path}")
    return 0


# Parses command-line argument for selecting configuration file
def main() -> int:
    ap = argparse.ArgumentParser(description="trust.txt crawler v2 (gated)")
    ap.add_argument("--config", default="config.json", help="Path to config.json (default: ./config.json)")
    args = ap.parse_args()

    # Starts keyboard listener in the background for pause/resume/stop control
    listener = threading.Thread(target=keyboard_listener, daemon=True)
    listener.start()

    cfg = load_config(args.config)
    return asyncio.run(crawl(cfg))


if __name__ == "__main__":
    raise SystemExit(main())
