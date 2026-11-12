#!/usr/bin/env python3
"""
Metasploit CVE Extractor
------------------------
A Python module to extract CVE identifiers from Metasploit Framework modules.
Can be imported or run as a standalone script.
"""

import os
import re
import sys
import shutil
from typing import Set, Dict, List, Optional, Tuple

from cve.datasources.utils import clone_repository


def extract_cves_from_directory(directory: str) -> Set[str]:
    """
    Extract all unique CVEs from Metasploit module files in the given directory.

    Args:
        directory: Path to Metasploit Framework directory

    Returns:
        Set of unique CVE identifiers

    Raises:
        ValueError: If modules directory doesn't exist
    """
    modules_dir = os.path.join(directory, 'modules')

    if not os.path.exists(modules_dir):
        raise ValueError(f"Modules directory not found at {modules_dir}")

    all_cves = set()
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    for root, _, files in os.walk(modules_dir):
        for file in files:
            if file.endswith('.rb'):
                module_path = os.path.join(root, file)

                try:
                    with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        matches = cve_pattern.findall(content)
                        all_cves.update(match.upper() for match in matches)
                except Exception:
                    # Skip files with reading errors
                    continue

    return all_cves


def get_metasploit_cves(
        directory: Optional[str] = None,
        repo_url: str = "https://github.com/rapid7/metasploit-framework.git",
        cleanup: bool = True
) -> List[str]:
    """
    Get all unique CVEs from Metasploit Framework.

    Args:
        directory: Path to existing Metasploit Framework directory (if None, will clone the repo)
        repo_url: Repository URL to clone (if directory is None)
        cleanup: Whether to remove the cloned directory after extraction

    Returns:
        Sorted list of unique CVE identifiers
    """
    temp_dir = None

    try:
        if directory:
            if not os.path.exists(directory):
                raise ValueError(f"Directory {directory} does not exist")
            msf_dir = directory
        else:
            msf_dir = temp_dir = clone_repository(repo_url)

        all_cves = extract_cves_from_directory(msf_dir)
        return sorted(all_cves)

    finally:
        if cleanup and temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def filter_cves_by_year(cves: List[str], year: str) -> List[str]:
    """
    Filter CVEs by year.

    Args:
        cves: List of CVE identifiers
        year: Year to filter by (e.g., "2023")

    Returns:
        Filtered list of CVE identifiers
    """
    return [cve for cve in cves if cve.split('-')[1] == year]


# Example usage if run as script
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Extract CVEs from Metasploit Framework modules.')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-d', '--directory', help='Existing local Metasploit directory')
    parser.add_argument('-y', '--year', help='Filter CVEs by specific year (e.g., 2023)')
    args = parser.parse_args()

    try:
        cves = get_metasploit_cves(directory=args.directory)

        if args.year:
            cves = filter_cves_by_year(cves, args.year)

        if args.output:
            with open(args.output, 'w') as f:
                for cve in cves:
                    f.write(f"{cve}\n")
            print(f"Found {len(cves)} CVEs. Results written to {args.output}", file=sys.stderr)
        else:
            for cve in cves:
                print(cve)
            print(f"Found {len(cves)} CVEs.", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)