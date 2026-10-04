#!/usr/bin/env python3
"""
open_in_firefox.py - Open URLs from a file in Firefox in configurable chunks.

Usage:
    python3 open_in_firefox.py [FILE] [CHUNK_SIZE] [DELAY]
    python3 open_in_firefox.py -f urls.txt -s 10 -d 5
    python3 open_in_firefox.py -f urls.txt -s 15 --private
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from typing import List

# ANSI colors
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def find_firefox(custom_path: str = None) -> str:
    """Find the Firefox binary executable."""
    if custom_path:
        if shutil.which(custom_path):
            return custom_path
        sys.stderr.write(f"{RED}[ERROR] Specified browser '{custom_path}' not found.{RESET}\n")
        sys.exit(1)

    for candidate in ["firefox", "firefox-esr"]:
        found = shutil.which(candidate)
        if found:
            return found

    sys.stderr.write(
        f"{RED}[ERROR] Neither 'firefox' nor 'firefox-esr' was found in PATH.{RESET}\n"
    )
    sys.exit(1)


def sanitize_urls(filepath: str) -> List[str]:
    """Read file and return cleaned, valid URLs."""
    if not os.path.isfile(filepath):
        sys.stderr.write(f"{RED}[ERROR] File '{filepath}' does not exist.{RESET}\n")
        sys.exit(1)

    urls = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Add default https:// scheme if missing protocol
            if "://" not in line:
                line = f"https://{line}"

            urls.append(line)

    return urls


def open_chunk(browser_bin: str, urls: List[str], private: bool = False, dry_run: bool = False):
    """Launch the browser with the batch of URLs."""
    if dry_run:
        print(f"{YELLOW}⚡ [DRY RUN] Simulated opening {len(urls)} tabs in Firefox.{RESET}")
        return

    cmd = [browser_bin]
    if private:
        cmd.append("--private-window")
    cmd.extend(urls)

    # Detach process to prevent hanging the terminal
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    mode_str = " (Private)" if private else ""
    print(f"{GREEN}✓ Launched {len(urls)} tabs in Firefox{mode_str}.{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Open URLs from a file in Firefox in configurable chunks."
    )
    parser.add_argument("file", nargs="?", help="Path to URL file")
    parser.add_argument("chunk_size", nargs="?", type=int, help="URLs per batch (default: 10)")
    parser.add_argument("delay", nargs="?", type=float, help="Delay in seconds between batches")

    parser.add_argument("-f", "--file", dest="flag_file", help="Path to URL file")
    parser.add_argument("-s", "--size", dest="flag_size", type=int, default=10, help="Chunk size")
    parser.add_argument("-d", "--delay", dest="flag_delay", type=float, default=0.0, help="Delay in seconds")
    parser.add_argument("-p", "--private", action="store_true", help="Open in Private Browsing")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Simulate without opening tabs")
    parser.add_argument("-b", "--browser", help="Custom Firefox binary path")

    args = parser.parse_args()

    # Resolve arguments (positional vs options)
    file_path = args.flag_file or args.file
    if not file_path:
        try:
            file_path = input("Enter path to URL file: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

    chunk_size = args.chunk_size if args.chunk_size is not None else args.flag_size
    delay = args.delay if args.delay is not None else args.flag_delay

    if chunk_size <= 0:
        sys.stderr.write(f"{RED}[ERROR] Chunk size must be greater than 0.{RESET}\n")
        sys.exit(1)

    browser_bin = find_firefox(args.browser)
    urls = sanitize_urls(file_path)
    total_urls = len(urls)

    if total_urls == 0:
        print(f"{YELLOW}[!] No valid URLs found in '{file_path}'. Exiting.{RESET}")
        sys.exit(0)

    total_chunks = (total_urls + chunk_size - 1) // chunk_size

    print(f"\n{BOLD}{CYAN}======================================================{RESET}")
    print(f"{BOLD}{GREEN}  Firefox URL Batch Opener (Python){RESET}")
    print(f"{BOLD}{CYAN}======================================================{RESET}")
    print(f"  {BOLD}Input File:{RESET}    {file_path}")
    print(f"  {BOLD}Total URLs:{RESET}    {YELLOW}{total_urls}{RESET}")
    print(f"  {BOLD}Chunk Size:{RESET}    {YELLOW}{chunk_size}{RESET} URLs/batch")
    print(f"  {BOLD}Total Batches:{RESET} {YELLOW}{total_chunks}{RESET}")
    print(f"  {BOLD}Browser:{RESET}       {browser_bin}")
    if args.dry_run:
        print(f"  {BOLD}Mode:{RESET}          {YELLOW}[DRY RUN] Simulation only{RESET}")
    elif args.private:
        print(f"  {BOLD}Mode:{RESET}          {CYAN}Private Window{RESET}")
    if delay > 0:
        print(f"  {BOLD}Pacing:{RESET}        Auto-advance after {YELLOW}{delay}s{RESET}")
    else:
        print(f"  {BOLD}Pacing:{RESET}        {GREEN}Interactive (wait for Enter key){RESET}")
    print(f"{BOLD}{CYAN}======================================================{RESET}\n")

    current_idx = 0
    chunk_num = 1

    try:
        while current_idx < total_urls:
            end_idx = min(current_idx + chunk_size, total_urls)
            batch = urls[current_idx:end_idx]

            print(
                f"{BOLD}{BLUE}--- Batch [{chunk_num}/{total_chunks}] "
                f"({len(batch)} URLs: #{current_idx + 1} to #{end_idx} of {total_urls}) ---{RESET}"
            )
            for u in batch:
                print(f"  {DIM}→{RESET} {u}")

            open_chunk(browser_bin, batch, private=args.private, dry_run=args.dry_run)

            current_idx = end_idx
            chunk_num += 1

            if current_idx >= total_urls:
                print(f"\n{BOLD}{GREEN}✔ All {total_urls} URLs have been opened in Firefox!{RESET}\n")
                break

            if delay > 0:
                print(f"{YELLOW}Waiting {delay}s before next batch... (Ctrl+C to abort){RESET}\n")
                time.sleep(delay)
            else:
                print()
                while True:
                    prompt = (
                        f"{BOLD}{CYAN}Press [Enter] for next batch, [s] to skip, [q] to quit: {RESET}"
                    )
                    choice = input(prompt).strip().lower()
                    if choice == "q":
                        print(f"\n{YELLOW}Quitting. Remaining URLs skipped.{RESET}")
                        sys.exit(0)
                    elif choice == "s":
                        print(f"{YELLOW}Skipping batch {chunk_num}...{RESET}")
                        current_idx = min(current_idx + chunk_size, total_urls)
                        chunk_num += 1
                        break
                    else:
                        print()
                        break
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Script interrupted by user. Exiting.{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
