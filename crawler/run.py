#!/usr/bin/env python3
#
# Optional wrapper script for running the crawler across multiple datasets.
#
# This script loads separate configuration files for EU and US datasets,
# validates that the required paths exist, and then starts crawler_v2.py
# once per configuration.
#
# This provides a repeatable way to run multiple crawls without manually
# changing config_v2.json between runs.

import json
import os
import subprocess
import sys

# Absolute path to the directory where this script is located.
# Used to build file paths that work regardless of where the script is executed from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Path to the main crawler script that will be executed.
CRAWLER = os.path.join(BASE_DIR, "crawler_v2.py")

# Region-specific configuration files.
# Each file defines its own seed file, output directory, and visited file.
EU_CONFIG = os.path.join(BASE_DIR, "config", "eu.json")
US_CONFIG = os.path.join(BASE_DIR, "config", "us.json")


# Utility function to ensure parent directory exists
def ensure_parent(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)

# Utility function to ensure directory exists
def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

# Validates configuration file before execution:
# - checks required fields exist
# - ensures output and state directories are created
# - verifies that the seed file is available
def validate_config(cfg_path: str) -> dict:
    if not os.path.isfile(cfg_path):
        raise FileNotFoundError(f"Missing config: {cfg_path}")

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # These fields are required because the crawler needs:
    # - an output location
    # - an input seed list
    # - a visited-state file for tracking progress
    required = ["output_dir", "seeds_file", "visited_file"]
    missing = [k for k in required if k not in cfg or not str(cfg[k]).strip()]
    if missing:
        raise ValueError(f"{cfg_path} missing keys: {', '.join(missing)}")

    # Create output and state directories before the crawler starts.
    # This prevents runtime errors caused by missing folders.
    ensure_dir(cfg["output_dir"])
    ensure_parent(cfg["visited_file"])

    # The seed file must already exist because it contains the domains to crawl. (refer to README if unsure)
    if not os.path.isfile(cfg["seeds_file"]):
        raise FileNotFoundError(f"Seeds file not found: {cfg['seeds_file']} (from {cfg_path})")

    return cfg

# Executes crawler for a specific dataset using its configuration file
# Runs crawler_v2.py as a separate process
def run_region(name: str, cfg_path: str) -> None:
    cfg = validate_config(cfg_path)

    # Print selected configuration so the run can be verified in the terminal.
    print(f"\n[*] REGION: {name}")
    print(f"    config : {cfg_path}")
    print(f"    seeds  : {cfg['seeds_file']}")
    print(f"    output : {cfg['output_dir']}")
    print(f"    visited: {cfg['visited_file']}")

    # Build command using the same Python interpreter currently running this script.
    # This avoids issues where "python3" points to a different environment.
    cmd = [sys.executable, CRAWLER, "--config", cfg_path]
    
    # Execute the crawler and stop immediately if the process fails.
    subprocess.run(cmd, check=True)

    print(f"[+] Finished: {name}")


def main() -> int:
    # Confirm that crawler_v2.py exists before trying to run it.
    if not os.path.isfile(CRAWLER):
        print(f"[!] crawler not found: {CRAWLER}", file=sys.stderr)
        return 2

    # Run each configured dataset in sequence.
    # If the EU run fails, the US run will not start.
    run_region("EU", EU_CONFIG)
    run_region("US", US_CONFIG)

    print("\n[ok] all regions completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
