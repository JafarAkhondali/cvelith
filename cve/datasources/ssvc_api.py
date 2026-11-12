import sys
from urllib.parse import urlparse
import datetime
from django.db import transaction, close_old_connections, connection
from tqdm import tqdm
import tldextract
import subprocess
import glob
import xml.etree.ElementTree as ET
import zipfile
import io
import requests
from cve.datasources.db_importers import (insert_cpe, insert_cve, insert_kev, insert_ssvc, insert_reference,
                                          insert_cve_cwe_relationship, load_json_mmap, insert_cvss)


REPO_DIR_NAME = 'cvelistV5'

def init_repo():
    subprocess.run(['git', 'clone', '--filter=blob:none', '--depth=1', '--single-branch', 'https://github.com/CVEProject/cvelistV5.git'])
    subprocess.run(['git', 'pull'], cwd=REPO_DIR_NAME)
    print("Clone & Updating done.")


def extract_ssvc(adp):
    def format_ssvc(ssvc):
        formatted_ssvc = {}
        for item in ssvc:
            key, value = item.popitem()
            formatted_ssvc[key] = value.lower()
        return formatted_ssvc

    for e in adp:
        if 'metrics' not in e: continue
        for m in e['metrics']:
            if 'other' not in m: continue
            other_metrics = m['other']
            if other_metrics['type'] == 'ssvc':
                ssvc = other_metrics['content']['options']
                if len(ssvc) != 3:
                    sys.stderr(f" {adp} --\n {ssvc}")
                    return
                ssvc = format_ssvc(ssvc)
                return {
                    "exploitation": ssvc['Exploitation'],
                    "automatable": ssvc['Automatable'],
                    "technical_impact": ssvc['Technical Impact'],
                }
            # if ee.get('other', {}).get('type') == 'ssvc':
    return None


def extract_kev(adp):
    for e in adp:
        if 'metrics' not in e: continue
        for m in e['metrics']:
            if 'other' not in m: continue
            other_metrics = m['other']
            if other_metrics['type'] == 'kev':
                kev = other_metrics['content']
                return {
                    "date_added": kev['dateAdded'],
                    "organizer": "CVEorg"
                }
    return None

def extract_description(cve):
    descriptions = cve.get('containers', {}).get('cna', {}).get('descriptions',[])
    for d in descriptions:
        if d.get('lang').startswith('en'):
            return d.get('value')
    return None

def extract_cwes(cna):
    cwes_set = set()
    problems = cna.get('problemTypes', [])
    for d in problems:
        #TODO:CVE-2024-49416
        if d.get('descriptions')[0].get('type', '').upper() == 'CWE':
            cwe_id = d.get('descriptions')[0].get('cweId', '').upper().strip()
            if cwe_id != '': cwes_set.add(cwe_id)
    return list(cwes_set)

def extract_cvss(cna):
    formatted_metrics = []
    metrics = cna.get('metrics', [])
    for metric in metrics:
        for key in metric.keys():
            if key.startswith('cvss'):
                cvss = metric[key]
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



def import_cwes():
    CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    def download_and_extract_cwe():
        """Download and extract the CWE XML file from MITRE."""
        response = requests.get(CWE_ZIP_URL)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content), "r") as zip_ref:
            xml_file_name = [name for name in zip_ref.namelist() if name.endswith(".xml")][0]  # Get XML file
            with zip_ref.open(xml_file_name) as xml_file:
                return ET.parse(xml_file).getroot()

    def parse_cwe_data(root):
        """Extract CWE data from the XML structure."""
        cwe_list = []
        # Locate all Weakness elements under Weaknesses
        is_category = False
        for entries in root:
            for entry in entries:
                cwe_id = f'CWE-{entry.get("ID")}'
                name = entry.get("Name")
                status = entry.get("Status")
                cwe_list.append((cwe_id, name, status, is_category))
            is_category = True
        return cwe_list

    def insert_into_db(cwe_list):
        """Insert CWE data into the PostgreSQL database."""
        with connection.cursor() as cursor:
            insert_query = """
                INSERT INTO cve_cwe (id, name, status, is_category)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING;
            """

            cursor.executemany(insert_query, cwe_list)
            connection.commit()
            print(f"Inserted {cursor.rowcount} CWEs successfully.")

    xml_root = download_and_extract_cwe()
    cwe_data = parse_cwe_data(xml_root)

    if cwe_data:
        insert_into_db(cwe_data)


def import_cves(from_year=2002, to_year=datetime.datetime.now().year):
    """
    gathering CVE records by processing JSON files.
    """
    init_repo()

    # gather all files
    cve_files = []
    for year in range(from_year, to_year + 1):
        cve_files.extend(glob.glob(f"{REPO_DIR_NAME}/cves/{year}/**/CVE-*.json", recursive=True))

    for cve_file in tqdm(cve_files, desc="Importing CVEs"):
        with connection.cursor() as cursor:
            try:
                cve_json = load_json_mmap(cve_file)
                process_cve(cursor, cve_json)
            except Exception as e:
                print(f"Error processing {cve_file}: {e}")



def db_worker_init():
    """
    Ensure each worker process has its own fresh DB connection
    by closing any inherited connection from the parent.
    """
    close_old_connections()

def process_cve_worker(args):
    """
    Worker function to process a single CVE file.
    """
    cve_file, progress_queue = args
    # with db_lock:
    #connection.close()
    with connection.cursor() as cursor:
        try:
            # Load the CVE JSON data
            #cve_json = json.loads(open(cve_file).read())
            cve_json = load_json_mmap(cve_file)
            # Process the CVE
            process_cve(cursor, cve_json)
        except Exception as e:
            print(f"Error processing {cve_file}: {e}")
        finally:
            progress_queue.put(1)

def init_pool(l):
    """
    Initialize the pool with a shared lock.
    """
    # global db_lock
    # db_lock = l
    # connection.close()
    pass

def extract_cpe(adp, cna):
    result = []
    max_length=400
    for entry in cna.get("affected", []):
        vendor = entry.get("vendor")
        product = entry.get("product")
        if not vendor and not product:
            continue
        if vendor == "n/a" and product == "n/a":
            continue
        if vendor and product:
            result.append({"vendor": vendor[0:max_length], "product": product[0:max_length], "vendor_product": f"{vendor}:{product}"})
    for e in adp:
        for entry in e.get("affected", []):
            vendor = entry.get("vendor")
            product = entry.get("product")
            if vendor=="n/a" and product=="n/a":
                continue
            if vendor and product:
                result.append({"vendor": vendor[0:max_length], "product": product[0:max_length], "vendor_product": f"{vendor}:{product}"})

    return result

def process_cve(cursor, cve):
    adp = cve['containers'].get('adp', [])
    cna = cve['containers'].get('cna', [])
    ssvc = extract_ssvc(adp)
    kev = extract_kev(adp)
    cpes= extract_cpe(adp, cna)

    cve_id = cve['cveMetadata']['cveId'].upper().strip()
    description = extract_description(cve)
    cwe_ids = extract_cwes(cna)
    cvsses = extract_cvss(cna)
    date_reserved = cve['cveMetadata'].get('dateReserved', None)
    date_published = cve['cveMetadata'].get('datePublished', None)
    date_added = datetime.datetime.now().date()

    cve_staus = cve['cveMetadata']['state']
    if cve_staus == 'REJECTED':
        cve_staus = 'R'
    elif cve_staus == 'PUBLISHED':
        cve_staus = 'P'
    else:
        cve_staus = 'O'

    insert_cve(cursor, cve_id, description, date_published, date_reserved, cve_staus, date_added)
    try:
        if ssvc:
            insert_ssvc(cursor, cve_id, ssvc)
    except Exception as e:
        print(f"error in ssvc : {e}")

    try:
        if kev:
            insert_kev(cursor, cve_id, kev)
    except Exception as e:
        print(f"error in kev: {e}")

    try:
        for cwe_id in cwe_ids:
            insert_cve_cwe_relationship(cursor, cve_id, cwe_id)
    except Exception as e:
        print(f"error in cve cwe: {e}")

    try:
        for m in cvsses:
            insert_cvss(cursor, cve_id, m['cvss_version'], m['base_score'], m['base_severity'], m['vector_string'], m['cvss'])
    except Exception as e:
        print("error in cvss ", e)
    # Process references from both the main 'references' and 'adp' sections
    references = cve.get('references', {}).get('reference_data', [])

    # Extract references from 'adp'
    for adp_entry in adp:
        adp_references = adp_entry.get('references', [])
        references.extend(adp_references)

    for ref in references:
        url = ref.get('url')
        description = ref.get('name', '')
        hostname = urlparse(url).hostname if url else ''
        ref_source = ref.get('refsource', '')
        tag = ','.join(ref.get('tags', []))
        registered_domain = tldextract.extract(url).registered_domain if url else ''
        insert_reference(cursor, cve_id, description, url, hostname, ref_source, tag, registered_domain)

    #TODO: CPE extraction is not working
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
