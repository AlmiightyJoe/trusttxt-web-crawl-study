#!/usr/bin/env python3
"""
crawler.py

Crawls domains for trust.txt at known locations, logs results, downloads found files,
and continues crawling by extracting domains/hosts referenced in discovered trust.txt files.

Usage:
  python3 crawler.py --config config.json
  Implemented usage of CLI to pause, resume and exit the crawler.
  P = Pause | R = Resume | X = Exit

Notes:
- Default locations: /.well-known/trust.txt and /trust.txt
- Extracts domains from URLs and domain-like tokens in the trust.txt content
- BFS crawl with deduplication
"""

from __future__ import annotations

import threading
import termios
import tty
import sys
import argparse
import asyncio
import csv
import hashlib
import json
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp


PATHS: Tuple[str, str] = ("/.well-known/trust.txt", "/trust.txt")

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
    re.IGNORECASE,
)

FOUND_FIELDS = ["ts_utc", "domain", "scheme", "found_path", "status", "bytes", "sha256", "saved_to", "content_type"]
NOT_FOUND_FIELDS = ["ts_utc", "domain", "attempts"]
PAUSED = False
STOP_REQUESTED = False



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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

def keyboard_listener():
    """
    Listens for single-key commands:
    P = Pause
    R = Resume
    X = Exit (graceful)
    """
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


def write_csv_row(csv_path: str, row: Dict[str, object], fieldnames: Iterable[str]) -> None:
    ensure_dir(os.path.dirname(csv_path))
    exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(fieldnames))
        if not exists:
            w.writeheader()
        w.writerow(row)


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


def load_seeds(seeds_path: str) -> Set[str]:
    raw = load_lines_set(seeds_path)
    seeds: Set[str] = set()
    for x in raw:
        d = normalize_domain(x)
        if d:
            seeds.add(d)
    return seeds


def append_new_seeds(seeds_path: str, new_domains: Set[str], known_seeds: Set[str]) -> int:
    to_add = sorted([d for d in new_domains if d not in known_seeds])
    if not to_add:
        return 0
    with open(seeds_path, "a", encoding="utf-8") as f:
        for d in to_add:
            f.write(d + "\n")
            known_seeds.add(d)
    return len(to_add)


def append_visited(visited_path: str, domain: str) -> None:
    ensure_dir(os.path.dirname(visited_path))
    with open(visited_path, "a", encoding="utf-8") as f:
        f.write(domain + "\n")


class PoliteLimiter:
    """Global minimum delay between ANY two HTTP requests."""
    def __init__(self, min_delay_s: float):
        self.min_delay = max(min_delay_s, 0.1)
        self._next = 0.0

    async def wait(self):
        now = time.monotonic()
        if now < self._next:
            await asyncio.sleep(self._next - now)
        self._next = max(self._next, time.monotonic()) + self.min_delay


@dataclass
class FetchOutcome:
    scheme: str
    path: str
    status: Optional[int]
    error: str
    bytes_len: int
    sha256: str
    saved_to: str
    content_type: str


async def fetch(
    session: aiohttp.ClientSession,
    limiter: PoliteLimiter,
    scheme: str,
    domain: str,
    path: str,
    timeout_s: int,
    user_agent: str,
) -> Tuple[Optional[int], str, bytes, str]:
    url = f"{scheme}://{domain}{path}"
    while PAUSED:
        await asyncio.sleep(0.2)

    if STOP_REQUESTED:
    	return None, "stopped", b"", ""

    await limiter.wait()
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout_s),
            allow_redirects=False,  # safety: no cross-domain redirects
            headers={"User-Agent": user_agent, "Accept": "text/plain,*/*;q=0.8"},
        ) as r:
            body = await r.read()
            ctype = r.headers.get("Content-Type", "")
            return r.status, "", body, ctype
    except asyncio.TimeoutError:
        return None, "timeout", b"", ""
    except aiohttp.ClientError as e:
        return None, f"client_error:{type(e).__name__}", b"", ""
    except Exception as e:
        return None, f"error:{type(e).__name__}", b"", ""


def save_found(output_dir: str, domain: str, scheme: str, path: str, body: bytes) -> str:
    ddir = os.path.join(output_dir, "found", domain)
    ensure_dir(ddir)
    fname = f"{scheme}_{path.strip('/').replace('/', '_')}.txt"
    fpath = os.path.join(ddir, fname)
    with open(fpath, "wb") as f:
        f.write(body)
    return fpath


def etld1(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


async def crawl(cfg: dict) -> int:
    output_dir = cfg["output_dir"]
    seeds_path = cfg["seeds_file"]

    max_domains = int(cfg.get("max_domains", 10000))
    timeout_s = int(cfg.get("timeout_seconds", 15))
    max_file_kb = int(cfg.get("max_file_kb", 256))
    global_delay = float(cfg.get("global_delay_seconds", 2.0))
    domain_pause = float(cfg.get("domain_pause_seconds", 1.0))
    http_fallback = bool(cfg.get("http_fallback", True))
    user_agent = str(cfg.get("user_agent", "trusttxt-research-crawler/5.0"))
    same_etld1_only = bool(cfg.get("same_etld1_only", False))

    found_csv = os.path.join(output_dir, "found", "found.csv")
    not_found_csv = os.path.join(output_dir, "not_found", "not_found.csv")
    visited_path = os.path.join(output_dir, "state", "visited.txt")

    ensure_dir(os.path.join(output_dir, "found"))
    ensure_dir(os.path.join(output_dir, "not_found"))
    ensure_dir(os.path.join(output_dir, "state"))

    known_seeds = load_seeds(seeds_path)
    if not known_seeds:
        print(f"No valid seeds in {seeds_path}", file=sys.stderr)
        return 2

    visited = load_lines_set(visited_path)

    queue: Deque[str] = deque(sorted(known_seeds))
    queued_set: Set[str] = set(queue)

    limiter = PoliteLimiter(global_delay)

    visited_count = 0
    found_count = 0

    schemes = ["https"] + (["http"] if http_fallback else [])

    async with aiohttp.ClientSession() as session:
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
            if not domain or domain in visited:
                continue

            print(
                f"\rchecking={domain}  visited={len(visited)+visited_count}  queue={len(queue)}  found={found_count}     ",
                end="",
                flush=True,
            )

            outcomes: list[FetchOutcome] = []
            domain_found = False

            for scheme in schemes:
                # 1) /.well-known/trust.txt
                s1, e1, b1, c1 = await fetch(session, limiter, scheme, domain, PATHS[0], timeout_s, user_agent)
                if b1 and len(b1) > max_file_kb * 1024:
                    outcomes.append(FetchOutcome(scheme, PATHS[0], s1, f"oversize>{max_file_kb}KB", len(b1), "", "", c1))
                else:
                    if s1 == 200 and b1:
                        p1 = save_found(output_dir, domain, scheme, PATHS[0], b1)
                        outcomes.append(FetchOutcome(scheme, PATHS[0], s1, e1, len(b1), sha256_bytes(b1), p1, c1))
                        domain_found = True
                    else:
                        outcomes.append(FetchOutcome(scheme, PATHS[0], s1, e1, len(b1) if b1 else 0, "", "", c1))

                await asyncio.sleep(domain_pause)

                # 2) /trust.txt
                s2, e2, b2, c2 = await fetch(session, limiter, scheme, domain, PATHS[1], timeout_s, user_agent)
                if b2 and len(b2) > max_file_kb * 1024:
                    outcomes.append(FetchOutcome(scheme, PATHS[1], s2, f"oversize>{max_file_kb}KB", len(b2), "", "", c2))
                else:
                    if s2 == 200 and b2:
                        p2 = save_found(output_dir, domain, scheme, PATHS[1], b2)
                        outcomes.append(FetchOutcome(scheme, PATHS[1], s2, e2, len(b2), sha256_bytes(b2), p2, c2))
                        domain_found = True
                    else:
                        outcomes.append(FetchOutcome(scheme, PATHS[1], s2, e2, len(b2) if b2 else 0, "", "", c2))

                if scheme == "https" and domain_found:
                    break

            append_visited(visited_path, domain)
            visited.add(domain)
            visited_count += 1

            if domain_found:
                found_count += 1
                first_ok = next((o for o in outcomes if o.status == 200 and o.saved_to), None)

                write_csv_row(
                    found_csv,
                    {
                        "ts_utc": utc_now_iso(),
                        "domain": domain,
                        "scheme": first_ok.scheme if first_ok else "",
                        "found_path": first_ok.path if first_ok else "",
                        "status": first_ok.status if first_ok else "",
                        "bytes": first_ok.bytes_len if first_ok else 0,
                        "sha256": first_ok.sha256 if first_ok else "",
                        "saved_to": first_ok.saved_to if first_ok else "",
                        "content_type": first_ok.content_type if first_ok else "",
                    },
                    FOUND_FIELDS,
                )

                discovered: Set[str] = set()
                for o in outcomes:
                    if o.status == 200 and o.saved_to:
                        try:
                            with open(o.saved_to, "rb") as f:
                                text = f.read().decode("utf-8", errors="replace")
                            discovered |= extract_domains_from_text(text)
                        except Exception:
                            pass

                if same_etld1_only:
                    base = etld1(domain)
                    discovered = {d for d in discovered if etld1(d) == base}

                append_new_seeds(seeds_path, discovered, known_seeds)

                for nd in sorted(discovered):
                    if nd not in visited and nd not in queued_set:
                        queue.append(nd)
                        queued_set.add(nd)

            else:
                summary = ";".join(
                    f"{o.scheme}{o.path}:{o.status if o.status is not None else (o.error or 'err')}"
                    for o in outcomes
                )
                write_csv_row(
                    not_found_csv,
                    {"ts_utc": utc_now_iso(), "domain": domain, "attempts": summary},
                    NOT_FOUND_FIELDS,
                )

    print("\nDone.")
    print(f"Output dir:    {output_dir}")
    print(f"Found CSV:     {found_csv}")
    print(f"Not found CSV: {not_found_csv}")
    print(f"Visited file:  {visited_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="trust.txt crawler (config-driven)")
    ap.add_argument("--config", default="config.json", help="Path to config.json (default: ./config.json)")
    args = ap.parse_args()
    
    listener = threading.Thread(target=keyboard_listener, daemon=True)
    listener.start()

    cfg = load_config(args.config)
    return asyncio.run(crawl(cfg))


if __name__ == "__main__":
    raise SystemExit(main())

