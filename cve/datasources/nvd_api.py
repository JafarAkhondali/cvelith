import gc
from urllib.parse import urlparse
import datetime
import json
from io import BytesIO
import requests
from zipfile import ZipFile

from tqdm import tqdm
import tldextract
from django.db import transaction, connection, close_old_connections
from cve.datasources.db_importers import insert_cpe, insert_cve, insert_cvss, insert_cve_cwe_relationship, insert_reference
import ijson

extractor = tldextract.TLDExtract(cache_dir=False)

def db_worker_init():
    """
    Ensures each worker process starts with a clean/fresh DB connection
    instead of using the parent's connection.
    """
    close_old_connections()

def extract_description(cve):
    descriptions = cve.get('descriptions', [])
    for d in descriptions:
        if d['lang'].lower().startswith('en'):
            return d['value']
    return ''

def extract_cvsses(metrics):
    formatted_metrics = []
    for key, val in (metrics.items()):
        if not key.startswith('cvss'):
            continue
        for t_key in val:
            cvss = t_key.get('cvssData', {})
            cvss_version = cvss['version']
            vector_string = cvss['vectorString']
            base_score = cvss['baseScore']
            base_severity = cvss.get('baseSeverity', '?')
            formatted_metrics.append({
                "cvss": cvss,
                "cvss_version": cvss_version,
                "vector_string": vector_string,
                "base_score": base_score,
                "base_severity": base_severity
            })
    return list(formatted_metrics)


def extract_cpe(cve_item):
    result = []
    max_length = 400

    configurations = cve_item.get("configurations", [])
    for configuration in configurations:
        for node in configuration["nodes"]:
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable") and "criteria" in cpe:
                    cpe_uri = cpe["criteria"]
                    # Format: cpe:2.3:a:vendor:product:...
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor and product and (vendor != "n/a" or product != "n/a"):
                            result.append({
                                "vendor": vendor[:max_length],
                                "product": product[:max_length],
                                "vendor_product": f"{vendor}:{product}"
                            })
            # for cpe in node.get("children", []):
            #     for child_cpe in cpe.get("cpe_match", []):
            #         parts = child_cpe.get("cpe23Uri", "").split(":")
            #         if len(parts) >= 5:
            #             vendor = parts[3]
            #             product = parts[4]
            #             if vendor and product and (vendor != "n/a" or product != "n/a"):
            #                 result.append({
            #                     "vendor": vendor[:max_length],
            #                     "product": product[:max_length],
            #                     "vendor_product": f"{vendor}:{product}"
            #                 })

    return result


def process_cve(cursor, cve):
    try:
        # This part uses raw SQL queries for performance.
        # Process CVE
        cve = cve['cve']
        cve_id = cve['id'].upper()
        cve_status = 'U'
        published_date = cve['published']
        reserved_date = None # cve['dateReserved'] TODO: NIST currently doesn't support it? !!!
        cve_description = extract_description(cve)
        date_added = datetime.datetime.now().date()
        insert_cve(cursor, cve_id, cve_description, published_date, reserved_date, cve_status, date_added)
        cpes = extract_cpe(cve)

        metrics = extract_cvsses(cve.get('metrics', {}))
        for m in metrics:
            insert_cvss(cursor, cve_id, m['cvss_version'], m['base_score'], m['base_severity'], m['vector_string'], m['cvss'])

        cwe_ids = set()

        for pt_data in cve.get('weaknesses', {}):
            description = pt_data.get('description',[])
            for element in description:
                cwe_id = element.get("value", "").upper()
                if cwe_id.startswith("CWE-"):
                    cwe_ids.add(cwe_id)
        for cwe_id in cwe_ids:
            insert_cve_cwe_relationship(cursor, cve_id, cwe_id)

        # # Process reference
        for ref in cve['references']:
            url = ref.get('url', 'NULL')

            hostname = 'NULL'
            registered_domain = 'NULL'
            if url != 'NULL':
                hostname = urlparse(url).netloc.lstrip('www.')
                registered_domain = extractor(url).registered_domain

            ref_source = ref.get('source', 'NULL')
            description = ref.get('name', 'NULL')  # useless
            tags = '"' + '"'.join(ref.get('tags', '')) + '"' # Maybe normalize later.
            insert_reference(cursor, cve_id, description, url, hostname, ref_source, tags, registered_domain)
    finally:
        del cve

    try:
        for cpe in cpes:
            for key in cpe:
                if key == 'vendor':
                    vendor = cpe[key]
                elif key == 'product':
                    product = cpe[key]
                elif key == 'vendor_product':
                    vendor_product = cpe[key]
            insert_cpe(cursor, cve_id, vendor, product, vendor_product)
    except Exception as e:
        print(f"error in cpe: {e}")
        print(cpe)


def import_cves(from_year=2002, to_year=datetime.datetime.now().year):
    """
    Gather & import CVEs from NVD feed (JSON) for each year, in parallel.
    """
    # 1. Gather all CVE items from all years
    for year in range(from_year, to_year + 1):
        print(f"Processing year {year}")

        # ZIP name on NVD
        zip_filename = f"nvdcve-2.0-{year}.json.zip"
        # JSON file *inside* the zip
        inner_json_filename = zip_filename[:-4]  # "nvdcve-2.0-YYYY.json"

        zip_file_url = f"https://nvd.nist.gov/feeds/json/cve/2.0/{zip_filename}"

        # Download the zip (still in memory for now)
        response = requests.get(zip_file_url)
        response.raise_for_status()

        # Open the zip and the inner JSON
        with ZipFile(BytesIO(response.content)) as zf:
            with zf.open(inner_json_filename) as f:
                # Streaming JSON: one vulnerability at a time
                vulns_iter = ijson.items(f, "vulnerabilities.item", use_float=True)

                with transaction.atomic():
                    with connection.cursor() as cursor:
                        # Wrap the streaming iterator with tqdm
                        pbar = tqdm(vulns_iter, desc=f"Importing CVEs {year}")

                        for i, item in enumerate(pbar, start=1):
                            try:
                                process_cve(cursor, item)
                            except Exception as e:
                                print(f"Error processing {item['cve']['id']}: {e}")

                            if i % 1000 == 0:
                                gc.collect()

        del response, pbar, i
        del vulns_iter
        gc.collect()

    print("All CVEs processed.")