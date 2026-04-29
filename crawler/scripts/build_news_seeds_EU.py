#!/usr/bin/env python3
"""
Build a Europe news-domain seeds list (1 domain per line) for trust.txt crawling.

Inputs:
- Scrapes W3Newspapers Europe index + each country page.

Outputs:
- seeds_europe_news.txt (lowercase, deduped, root-domain only; subdomains allowed)

Notes:
- "Subdomains allowed" keeps netloc as-is (e.g., news.site.tld stays news.site.tld).
- "Root only": any /path is stripped; only the domain part is used.
- "Keep per TLD": no cross-TLD collapsing.
- "Exclude Russian state media": excludes a hardcoded list (adjust as needed).
"""

from __future__ import annotations

import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# W3Newspapers Europe index used as the starting point for collecting country pages
EUROPE_INDEX = "https://www.w3newspapers.com/europe/"
# User-Agent used when requesting W3Newspapers pages
UA = "Mozilla/5.0 (compatible; trusttxt-crawler/2.0; +https://example.invalid)"

# Exclude: Russian state media (explicit list; extend if you want)
EXCLUDE_DOMAINS = {
    "rt.com",
    "sputniknews.com",
    "tass.com",
    "ria.ru",
    "rg.ru",
    "1tv.ru",
    "vesti.ru",
    "russia.tv",
    "tvzvezda.ru",
    "smotrim.ru",
    "rtr-planeta.com",
    "interfax.ru",  # (often treated as state-adjacent; remove if you disagree)
}

# Skip junk link targets
SKIP_SCHEMES = {"mailto", "javascript", "tel"}

# Cleans and normalizes extracted domains
def norm_domain(href: str) -> str | None:
    href = href.strip()
    if not href:
        return None

    # Some directory links are protocol-relative or missing scheme
    if href.startswith("//"):
        href = "https:" + href
    if href.startswith("www."):
        href = "https://" + href

    parsed = urlparse(href)
    if parsed.scheme and parsed.scheme.lower() in SKIP_SCHEMES:
        return None

    netloc = parsed.netloc.lower()
    if not netloc:
        return None

    # Strip common prefixes
    if netloc.startswith("www."):
        netloc = netloc[4:]

    # Drop obvious tracking / directory self-links
    if netloc.endswith("w3newspapers.com"):
        return None

    # Basic sanity: must contain a dot
    if "." not in netloc:
        return None

    # Remove trailing dot
    netloc = netloc.rstrip(".")

    # Optional: drop ports
    netloc = re.sub(r":\d+$", "", netloc)

    if netloc in EXCLUDE_DOMAINS:
        return None

    return netloc

# Fetches a webpage and returns parsed HTML
# raise_for_status() makes HTTP errors explicit
def fetch(url: str) -> BeautifulSoup:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")

# Extracts country-specific pages containing news site listings
def extract_country_pages(index_soup: BeautifulSoup) -> list[str]:
    # W3Newspapers Europe page links to country pages; we collect those URLs.
    urls: set[str] = set()

    for a in index_soup.select("a[href]"):
        href = a.get("href", "").strip()
        if not href:
            continue

        # country pages are on w3newspapers.com and usually under /<country>/
        full = urljoin(EUROPE_INDEX, href)
        p = urlparse(full)

        if "w3newspapers.com" not in p.netloc:
            continue

        # heuristics: keep links likely to be country pages
        # examples: https://www.w3newspapers.com/albania/  (etc.)
        path = p.path.strip("/").lower()
        if not path:
            continue
        if path in {"europe", "newssites", "newspapers", "magazines"}:
            continue

        # avoid non-country misc pages
        if any(x in path for x in ("privacy", "contact", "about", "terms")):
            continue

        # keep single-segment paths (country/territory names)
        if "/" not in path:
            urls.add(full)

    return sorted(urls)

# Extracts domains from country pages
def extract_news_domains(country_soup: BeautifulSoup) -> set[str]:
    domains: set[str] = set()
    for a in country_soup.select("a[href]"):
        href = a.get("href", "")
        if not href:
            continue

        # W3Newspapers uses outgoing links; capture domain from href
        d = norm_domain(href)
        if d:
            domains.add(d)
    return domains

# Main workflow:
# - fetch Europe index
# - collect country pages
# - extract news domains from each country page
# - deduplicate and write crawler seed file
def main() -> int:
    index = fetch(EUROPE_INDEX)
    country_pages = extract_country_pages(index)

    all_domains: set[str] = set()

    for url in country_pages:
        try:
            soup = fetch(url)
            all_domains |= extract_news_domains(soup)
        except Exception as e:
            print(f"[warn] failed {url}: {e}", file=sys.stderr)

    out = sorted(all_domains)

    # Write deduplicated domain list used as crawler input
    out_path = "news_eu.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for d in out:
            f.write(d + "\n")

    print(f"[ok] wrote {len(out)} domains to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
