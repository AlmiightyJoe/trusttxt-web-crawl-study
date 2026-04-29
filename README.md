# trusttxt-web-crawl-study
Crawler and dataset for analyzing trust.txt adoption in EU and US media organizations.


This project implements a Python-based web crawler designed to identify and analyze the presence of trust.txt files across media-related domains. The crawler checks standard locations (/.well-known/trust.txt and /trust.txt), retrieves responses, and classifies them into valid implementations, false positives, or non-existent cases.


The project supports empirical analysis of trust.txt adoption, enabling comparison between regions (EU vs US) and providing insight into how transparency mechanisms are implemented in practice. It offers a reproducible method for measuring adoption at scale using publicly accessible web data.


How users can get started
Clone the repository
Create and activate a virtual environment

Install dependencies:

pip install -r requirements.txt

Configure datasets in:
config/eu.json
config/us.json

Run the crawler:
python3 run.py

Outputs will be written to the configured output directories.


Refer to the README and configuration files for setup and usage details. The session starter guide provides additional instructions for running long crawling sessions.

This project is maintained by Joakim Skjelbred as part of a bachelor’s study in cybersecurity. Contributions are not actively managed, but the repository is available for reference and reproducibility.