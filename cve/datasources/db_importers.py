import json
import mmap

import psycopg2


def load_json_mmap(file_path):
    with open(file_path, "r") as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
            return json.loads(m.read().decode("utf-8"))



def insert_ssvc(cursor, cve_id, ssvc):
    cursor.execute("""
                   INSERT INTO cve_ssvc (cve_id, exploitation, automatable, technical_impact)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (cve_id) DO UPDATE
                    SET 
                        cve_id = %s,
                        exploitation = %s,
                        automatable = %s,
                        technical_impact = %s;
               """, [cve_id, ssvc['exploitation'], ssvc['automatable'], ssvc['technical_impact']] * 2)

def insert_kev(cursor, cve_id, kev):
    cursor.execute("""
                       INSERT INTO cve_kev (cve_id, date, organizer)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (cve_id, date, organizer) DO UPDATE
                        SET 
                            cve_id = %s,
                            date = %s,
                            organizer = %s;
                   """, [cve_id, kev['date_added'], kev['organizer']] * 2)

def insert_msf(cursor, cve_id, date_added=None):
    cursor.execute("""
                       INSERT INTO cve_msf (cve_id, date)
                       VALUES (%s, %s)
                       ON CONFLICT (cve_id) DO NOTHING ;
                   """, [cve_id, date_added])

def insert_nuclei(cursor, cve_id, date_added=None):
    cursor.execute("""
                       INSERT INTO cve_nuclei (cve_id, date)
                       VALUES (%s, %s)
                       ON CONFLICT (cve_id) DO NOTHING ;
                   """, [cve_id, date_added])

def insert_ranscve(cursor, cve_id, date_added=None, source=None, groups=None):
    cursor.execute("""
                       INSERT INTO cve_ransomware (cve_id, date, source, groups)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (cve_id) DO NOTHING ;
                   """, [cve_id, date_added, source, groups])

def insert_cve(cursor, cve_id, description, date_published, date_reserved, cve_status, date_added):
    """
    Inserts or updates a CVE entry in the database.
    If a conflict on 'id' occurs, only updates fields that are non-null in the new data.
    Prevents overwriting existing values with nulls.
    """
    query = """
        INSERT INTO cve_cve (
            id, description, date_published, date_reserved, date_added, status
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE
        SET 
            description     = COALESCE(EXCLUDED.description, cve_cve.description),
            date_published  = COALESCE(EXCLUDED.date_published, cve_cve.date_published),
            date_reserved   = COALESCE(EXCLUDED.date_reserved, cve_cve.date_reserved),
            status          = COALESCE(EXCLUDED.status, cve_cve.status)
    """
    cursor.execute(query, [
        cve_id, description, date_published, date_reserved, date_added, cve_status
    ])



def insert_cwe(cursor, cwe_id, name, description, url, is_category):
    cursor.execute("""
        INSERT INTO cve_cwe (id, name, is_category)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE
        SET 
            name = EXCLUDED.name,
            is_category = EXCLUDED.is_category;
    """, [cwe_id, name, description, url, is_category])


def insert_cve_cwe_relationship(cursor, cve_id, cwe_id):
    cursor.execute("""
        INSERT INTO cve_cve_cwes (cve_id, cwe_id)
        VALUES (%s, %s)
        ON CONFLICT (cve_id, cwe_id) DO NOTHING;
    """, [cve_id, cwe_id])


def insert_reference(cursor, cve_id, description, url, hostname, ref_source, tag, registered_domain):
    cursor.execute("""
        INSERT INTO cve_reference (cve_id, description, url, hostname, ref_source, tag, registered_domain)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id, tag, url) DO NOTHING;
    """, [cve_id, description, url, hostname, ref_source, tag, registered_domain])


def insert_cpe(cursor, cve_id, vendor, product, vendor_product):
    cursor.execute("""
        INSERT INTO cve_cpe (cve_id, vendor, product, vendor_product)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id, vendor_product) DO NOTHING;
    """, [cve_id, vendor, product, vendor_product])


def insert_cvss(cursor, cve_id, version, base_score, base_severity, vector_string, metrics):
    cursor.execute("""
        INSERT INTO cve_cvss (cve_id, version, base_score, base_severity, vector_string, metrics)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id, version) DO UPDATE
        SET 
            base_score = EXCLUDED.base_score,
            base_severity = EXCLUDED.base_severity,
            vector_string = EXCLUDED.vector_string,
            metrics = EXCLUDED.metrics;
    """, [cve_id, version, base_score, base_severity, vector_string, psycopg2.extras.Json(metrics)])

def insert_cve_iot(cursor, cve_id, label, component, reason):
    cursor.execute("""
        INSERT INTO cve_iot_classification (cve_id, is_iot, affected_component, reason)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id, is_iot) DO UPDATE
        SET 
            is_iot = EXCLUDED.is_iot,
            affected_component = EXCLUDED.affected_component,
            reason = EXCLUDED.reason;
    """, [cve_id, label, component, reason])