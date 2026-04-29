#!/usr/bin/env python3

# Extracts media organization domains from Wikipedia category pages

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import csv
import re
import time

# Base Wikipedia domain used to convert relative links into full URLs
BASE = "https://en.wikipedia.org"
# Wikipedia category used as the source for American Journalism organizations
CATEGORY_URL = "https://en.wikipedia.org/wiki/Category:American_journalism_organizations"

# User-Agent identifes the script during requests
HEADERS = {"User-Agent": "trusttxt-media-org-research/1.0"}

# Normalizes URLs into domain names for crawler seed input
# Removes "www." to avoid duplicate entries
def normalize_domain(url):
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

# Extracts official website URL from Wikipedia infobox
def extract_official_website(soup):
    infobox = soup.find("table", {"class": "infobox"})
    if not infobox:
        return None
    for row in infobox.find_all("tr"):
        header = row.find("th")
        if header and "website" in header.text.lower():
            link = row.find("a", href=True)
            if link:
                return link["href"]
    return None

# Crawls the Wikipedia category and collects organization page URLs
# Handles category pagination using the "next page" link
def crawl_category():
    page_url = CATEGORY_URL
    org_pages = set()

    while page_url:
        r = requests.get(page_url, headers=HEADERS)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.select("#mw-pages a"):
            href = link.get("href")
            if href and href.startswith("/wiki/") and ":" not in href:
                org_pages.add(urljoin(BASE, href))

        next_link = soup.find("a", string="next page")
        page_url = urljoin(BASE, next_link["href"]) if next_link else None
        time.sleep(1)

    return org_pages

# Main workflow:
# - collect organization pages
# - extract official websites
# - normalize domains
# - write CSV reference file and crawler seed file
def main():
    org_pages = crawl_category()
    results = []

    for page in org_pages:
        try:
            r = requests.get(page, headers=HEADERS)
            soup = BeautifulSoup(r.text, "html.parser")

            website = extract_official_website(soup)
            domain = normalize_domain(website)

            if domain:
                results.append({
                    "name": soup.find("h1").text.strip(),
                    "source_page": page,
                    "domain": domain
                })

            time.sleep(0.5)

        except Exception as e:
            print("Error:", page, e)

    # Write reference CSV containing organization name, source page, and extracted domain
    with open("media_orgs_us.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "source_page", "domain"])
        writer.writeheader()
        writer.writerows(results)

    # Write deduplicated domain list used as crawler input
    domains = sorted(set(r["domain"] for r in results))
    with open("seeds_media_orgs_us.txt", "w") as f:
        for d in domains:
            f.write(d + "\n")

    print(f"Extracted {len(domains)} domains")

if __name__ == "__main__":
    main()
