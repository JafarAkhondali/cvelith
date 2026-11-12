#!/usr/bin/env python3
"""
Nuclei CVE Extractor
--------------------
A Python module to extract CVE identifiers from Nuclei templates.
Uses the Project Discovery's cves.json file for efficient extraction.
"""

import json
import sys
import requests
from typing import List, Optional, Dict, Set, Any


def get_nuclei_cves(
        json_url: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json",
        timeout: int = 30
) -> List[str]:
    """
    Get all unique CVEs from Nuclei templates using the cves.json file.

    Args:
        json_url: URL to the Nuclei cves.json file
        timeout: Request timeout in seconds

    Returns:
        Sorted list of unique CVE identifiers

    Raises:
        requests.RequestException: If HTTP request fails
        ValueError: If JSON parsing fails
    """
    try:
        response = requests.get(json_url, timeout=timeout)
        response.raise_for_status()  # Raise exception for HTTP errors

        # Parse the data line by line as it's in JSON Lines format (each line is a separate JSON object)
        all_cves: Set[str] = set()

        # Handle both regular JSON array and JSON Lines format
        try:
            # First try parsing as a JSON array
            data = response.json()
            if isinstance(data, list):
                for template in data:
                    extract_cves_from_template(template, all_cves)
            else:
                # Handle single JSON object
                extract_cves_from_template(data, all_cves)

        except json.JSONDecodeError:
            # If that fails, try parsing as JSON Lines (newline-delimited JSON)
            for line in response.text.splitlines():
                if line.strip():
                    try:
                        template = json.loads(line)
                        extract_cves_from_template(template, all_cves)
                    except json.JSONDecodeError:
                        continue

        return sorted(all_cves)

    except requests.RequestException as e:
        raise requests.RequestException(f"Error fetching Nuclei CVEs data: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while extracting Nuclei CVEs: {e}")


def extract_cves_from_template(template: Dict[str, Any], all_cves: Set[str]) -> None:
    """
    Extract CVE IDs from a template and add them to the all_cves set.

    Args:
        template: A single template dictionary
        all_cves: Set to collect unique CVE IDs
    """
    # Check for direct CVE ID in the "ID" field
    if "ID" in template and isinstance(template["ID"], str) and template["ID"].startswith("CVE-"):
        all_cves.add(template["ID"].upper())

    # Also check lowercase "id" for compatibility
    elif "id" in template and isinstance(template["id"], str) and template["id"].startswith("CVE-"):
        all_cves.add(template["id"].upper())

    # Check for CVEs in Info.Classification structure
    if "Info" in template and "Classification" in template["Info"]:
        classification = template["Info"]["Classification"]

        # Check if classification has CVE-id field
        if "CVE-ID" in classification:
            cve_ids = classification["CVE-ID"]
            add_cve_ids(cve_ids, all_cves)

        # Also check lowercase "cve-id" for compatibility
        elif "cve-id" in classification:
            cve_ids = classification["cve-id"]
            add_cve_ids(cve_ids, all_cves)

    # Check lowercase "info" for compatibility
    elif "info" in template and "classification" in template["info"]:
        classification = template["info"]["classification"]

        # Check for CVE IDs in classification
        if "cve-id" in classification:
            cve_ids = classification["cve-id"]
            add_cve_ids(cve_ids, all_cves)


def add_cve_ids(cve_ids: Any, all_cves: Set[str]) -> None:
    """
    Add CVE IDs to the all_cves set.

    Args:
        cve_ids: String or List of CVE IDs
        all_cves: Set to collect unique CVE IDs
    """
    if isinstance(cve_ids, list):
        for cve_id in cve_ids:
            if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                all_cves.add(cve_id.upper())
    elif isinstance(cve_ids, str) and cve_ids.startswith("CVE-"):
        all_cves.add(cve_ids.upper())


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


def get_cve_statistics(cves: List[str]) -> Dict[str, Any]:
    """
    Generate statistics about CVEs by year.

    Args:
        cves: List of CVE identifiers

    Returns:
        Dictionary with statistics
    """
    years = {}
    for cve in cves:
        parts = cve.split('-')
        if len(parts) >= 2:
            year = parts[1]
            years[year] = years.get(year, 0) + 1

    return {
        "total": len(cves),
        "by_year": dict(sorted(years.items(), key=lambda x: x[0]))
    }


# Example usage if run as script
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Extract CVEs from Nuclei templates.')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-y', '--year', help='Filter CVEs by specific year (e.g., 2023)')
    parser.add_argument('-s', '--stats', action='store_true', help='Show statistics')
    parser.add_argument('-u', '--url',
                        default="https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json",
                        help='URL to Nuclei cves.json file')
    parser.add_argument('-f', '--file', help='Local JSON file to process instead of URL')
    args = parser.parse_args()

    try:
        if args.file:
            print(f"Reading from local file: {args.file}", file=sys.stderr)
            with open(args.file, 'r') as f:
                all_cves = set()
                # Handle both JSON and JSON Lines format
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for template in data:
                            extract_cves_from_template(template, all_cves)
                    else:
                        extract_cves_from_template(data, all_cves)
                except json.JSONDecodeError:
                    # Reset file pointer and try as JSON Lines
                    f.seek(0)
                    for line in f:
                        if line.strip():
                            try:
                                template = json.loads(line)
                                extract_cves_from_template(template, all_cves)
                            except json.JSONDecodeError:
                                continue
                cves = sorted(all_cves)
        else:
            print("Fetching Nuclei CVEs data...", file=sys.stderr)
            cves = get_nuclei_cves(json_url=args.url)

        if args.year:
            cves = filter_cves_by_year(cves, args.year)

        if args.stats:
            stats = get_cve_statistics(cves)
            print("\nNuclei CVEs Statistics:", file=sys.stderr)
            print(f"Total unique CVEs: {stats['total']}", file=sys.stderr)
            print("\nCVEs by year:", file=sys.stderr)
            for year, count in stats['by_year'].items():
                print(f"  {year}: {count}", file=sys.stderr)
            print("", file=sys.stderr)

        if args.output:
            with open(args.output, 'w') as f:
                for cve in cves:
                    f.write(f"{cve}\n")
            print(f"Found {len(cves)} CVEs. Results written to {args.output}", file=sys.stderr)
        else:
            for cve in cves:
                print(cve)
            print(f"\nFound {len(cves)} CVEs.", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)