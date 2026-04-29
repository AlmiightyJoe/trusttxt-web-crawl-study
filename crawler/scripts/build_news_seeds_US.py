#!/usr/bin/env python3
"""
Build a US news-domain seeds list (1 domain per line) for trust.txt crawling.

Source:
- W3Newspapers USA directory (state + city pages).

Outputs:
- news_us.txt (lowercase, deduped, root-domain only; subdomains allowed)

Rules:
- Allow subdomains (keep full netloc)
- Root only (strip any /path)
- Keep per TLD (no collapsing)
"""

from __future__ import annotations

import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# W3Newspapers pages used as starting points for collecting US news domains
USA_INDEX = "https://www.w3newspapers.com/usa/"
USA_CITIES = "https://www.w3newspapers.com/usa/cities/"
NORTH_AMERICA = "https://www.w3newspapers.com/north-america/"
# User-Agent used when requesting W3Newspapers pages
UA = "Mozilla/5.0 (compatible; trusttxt-crawler/2.0; +https://example.invalid)"

# Link schemes that should not be treated as web domains
SKIP_SCHEMES = {"mailto", "javascript", "tel"}

# Fetches a webpage and returns parsed HTML using BeautifulSoup
# raise_for_status() makes HTTP errors explicit
def fetch(url: str) -> BeautifulSoup:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")

# Cleans and normalizes extracted domains
# Removes schemes, "www.", ports, and directory self-links
def norm_domain(href: str) -> str | None:
    href = (href or "").strip()
    if not href:
        return None

    if href.startswith("//"):
        href = "https:" + href
    if href.startswith("www."):
        href = "https://" + href

    p = urlparse(href)
    if p.scheme and p.scheme.lower() in SKIP_SCHEMES:
        return None

    netloc = (p.netloc or "").lower()
    if not netloc:
        return None

    # strip www
    if netloc.startswith("www."):
        netloc = netloc[4:]

    # drop ports
    netloc = re.sub(r":\d+$", "", netloc)

    # ignore self-links back to directory site
    if netloc.endswith("w3newspapers.com"):
        return None

    if "." not in netloc:
        return None

    return netloc.rstrip(".")

# Finds additional pages (states, cities) to continue crawling
def extract_internal_pages(soup: BeautifulSoup, base_url: str) -> set[str]:
    """
    Collect internal W3Newspapers pages (states, cities, specialty lists)
    that we should traverse to get outbound news domains.
    """
    pages: set[str] = set()
    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        full = urljoin(base_url, href)
        p = urlparse(full)
        if "w3newspapers.com" not in p.netloc:
            continue
        # keep only USA-related paths
        path = p.path.lower()
        if path.startswith("/usa/") or path == "/usa/":
            pages.add(full)
    return pages

# Extracts outbound news domains from W3Newspapers page
def extract_outbound_domains(soup: BeautifulSoup) -> set[str]:
    domains: set[str] = set()
    for a in soup.select("a[href]"):
        d = norm_domain(a.get("href"))
        if d:
            domains.add(d)
    return domains

# Main workflow:
# - start from USA index, city, and North America pages
# - discover additional USA-related pages
# - extract outbound new domains
# - deduplicate and write crawler seed file
def main() -> int:
    to_visit: set[str] = {USA_INDEX, USA_CITIES, NORTH_AMERICA}
    visited: set[str] = set()
    all_domains: set[str] = set()

    while to_visit:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)

        try:
            soup = fetch(url)
        except Exception as e:
            print(f"[warn] failed {url}: {e}", file=sys.stderr)
            continue

        # collect outbound news domains from this page
        all_domains |= extract_outbound_domains(soup)

        # discover more /usa/* pages to traverse (states, cities, etc.)
        to_visit |= extract_internal_pages(soup, url)

    # final cleanup: remove any remaining directory-domain artifacts
    all_domains = {d for d in all_domains if not d.endswith("w3newspapers.com")}

    out = sorted(all_domains)
    out_path = "news_us.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for d in out:
            f.write(d + "\n")

    print(f"[ok] wrote {len(out)} domains to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
