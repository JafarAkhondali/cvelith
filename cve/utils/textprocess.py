import re

CVE_PATTERN = r"CVE-\d{4}-\d{4,11}"
# Some peple may incorrectly add
def extract_cves(text):
    if text is None: return []
    text = text.replace('_', '-').replace('--', '-').replace('–', '-')
    matches = re.finditer(CVE_PATTERN, text, re.MULTILINE | re.IGNORECASE)
    unique_matches = set()
    for match in matches:
        cve_id = match.group(0).upper()
        year = int(cve_id.split('-')[1].strip())
        # This is required as some 'people' enter invalid CVE years.
        if not(1999 <= year < 2035):
            continue
        unique_matches.add(cve_id)
    return list(unique_matches)
