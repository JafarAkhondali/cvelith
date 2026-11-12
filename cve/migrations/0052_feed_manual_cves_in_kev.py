from datetime import datetime

from django.db import migrations, models

def insert_kevs(apps, schema_editor):
    KEV = apps.get_model('cve', 'KEV')
    default_date = '2030-1-1'
    organizer = 'manual'

    cve_list = [
        "CVE-2021-28312",
        "CVE-2021-1636",
        "CVE-2017-1000251",
        "CVE-2025-24071",
        "CVE-2021-24084",
        "CVE-2023-42820",
        "CVE-2023-1829",
        "CVE-2021-24085",
        "CVE-2021-31728",
        "CVE-2022-0778",
        "CVE-2022-27666",
        "CVE-2015-3636",
        "CVE-2022-27255",
        "CVE-2022-23222"
    ]

    for cve_id in cve_list:
        KEV.objects.get_or_create(
            cve_id=cve_id,
            date=default_date,
            organizer=organizer
        )
class Migration(migrations.Migration):

    dependencies = [
        ('cve', '0051_alter_cpe_product_alter_cpe_vendor_and_more'),
    ]



    operations = [
        migrations.RunPython(insert_kevs),
    ]