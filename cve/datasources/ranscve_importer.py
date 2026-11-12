import os
import re
import tempfile
import shutil
from typing import List, Dict, Any, Optional

from cve.datasources.utils import clone_repository


def parse_cve_from_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse a file in the Vulnerabilities directory to extract CVE information.

    Args:
        file_path: Path to the file to parse

    Returns:
        List of dictionaries containing CVE information
    """
    cve_data = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract filename without extension to use as ransomware group name
        ransomware_group = os.path.splitext(os.path.basename(file_path))[0]

        # Find all CVE patterns (CVE-YYYY-NNNNN)
        cve_pattern = re.compile(r'(CVE-\d{4}-\d{1,15})')
        cves = cve_pattern.findall(content)

        # Extract lines containing CVEs to get context and sources
        lines = content.split('\n')
        for line in lines:
            for cve in cves:
                if cve in line:
                    # Extract source URLs from the line
                    url_pattern = re.compile(r'https?://[^\s\)\]]+')
                    sources = url_pattern.findall(line)

                    # Create entry for this CVE
                    cve_entry = {
                        'cve_id': cve,
                        'ransomware_group': ransomware_group, # TODO: Finding group name is buggy.
                        'sources': sources, # TODO: This might be buggy
                        'context': line.strip() # TODO: This might be buggy
                    }

                    # Check if this exact CVE entry already exists
                    if not any(entry['cve_id'] == cve and entry['ransomware_group'] == ransomware_group for entry in
                               cve_data):
                        cve_data.append(cve_entry)

    except Exception as e:
        print(f"Error parsing file {file_path}: {str(e)}")

    return cve_data


def extract_cve_info(repo_dir: str) -> List[Dict[str, Any]]:
    """
    Extract CVE information from the Vulnerabilities directory.

    Args:
        repo_dir: Path to the cloned repository

    Returns:
        List of dictionaries containing CVE information
    """
    vulnerabilities_dir = os.path.join(repo_dir, 'Vulnerabilities')

    if not os.path.exists(vulnerabilities_dir):
        raise FileNotFoundError(f"Vulnerabilities directory not found in {repo_dir}")

    all_cve_data = []

    # Process each file in the Vulnerabilities directory
    for filename in os.listdir(vulnerabilities_dir):
        if filename.endswith(('.md', '.txt')):  # Process markdown and text files
            file_path = os.path.join(vulnerabilities_dir, filename)
            cve_data = parse_cve_from_file(file_path)
            all_cve_data.extend(cve_data)

    return all_cve_data


def get_ransomware_vulnerability_data(
        repo_url: str = "https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix.git",
        cleanup: bool = True) -> List[Dict[str, Any]]:
    """
    Main function to extract CVE information from the Ransomware-Vulnerability-Matrix repository.

    Args:
        repo_url: URL of the repository
        cleanup: Whether to clean up temporary directories after execution

    Returns:
        List of dictionaries containing CVE information
    """
    temp_dir = None

    try:
        temp_dir = clone_repository(repo_url)
        cve_data = extract_cve_info(temp_dir)
        return cve_data

    finally:
        # Clean up temporary directory if specified
        if cleanup and temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)