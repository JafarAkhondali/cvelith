from django.db import models
from typing import Optional

from model_utils.fields import AutoCreatedField, AutoLastModifiedField
from django.utils.translation import gettext_lazy as _
from postgres_copy import CopyManager
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created`` and ``modified`` fields.

    """
    created = AutoCreatedField('created_at')
    modified = AutoLastModifiedField('modified_at')

    class Meta:
        abstract = True


class CVE(models.Model):
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.
    """
    id = models.CharField(max_length=50, primary_key=True, help_text="Unique CVE identifier.")
    description = models.TextField(help_text="Description of the CVE.", null=True, blank=True)

    date_published = models.DateTimeField(help_text="Date when the CVE was published publicly.", null=True, default=None)
    date_reserved = models.DateTimeField(help_text="Date when the CVE was reserved.", null=True, default=None)
    date_added = models.DateTimeField(help_text="Date when the CVE was added to this dataset.", null=True, blank=True)


    class CVEStatus(models.TextChoices):
        other = "O", _("Other")
        available = "P", _("Published")
        rejected = "R", _("Rejected")
        unknown = "U", _("Unknown")

    status = models.CharField(
        max_length=2,
        choices=CVEStatus.choices,
        default=CVEStatus.available,
    )

    cwes = models.ManyToManyField('CWE', related_name='cwes')

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['id'], name='unique_cve_id'),
        ]
        indexes = [
            models.Index(fields=['status'], name='cve_status'),
        ]

    def __str__(self) -> str:
        return str(self.id)

class CWE(models.Model):
    id = models.CharField(max_length=50, primary_key=True, help_text="Unique CWE identifier.")
    name = models.CharField(max_length=150, help_text="CWE name.", null=True, blank=True, default=None)
    status = models.CharField(max_length=150, help_text="CWE status.", null=True, blank=True, default=None)
    is_category = models.BooleanField(null=True, default=False)


    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['id'], name='unique_cwe_id'),
            models.UniqueConstraint(fields=['name'], name='unique_cwe_name')
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.id})"

class Reference(models.Model):
    """
    Represents a reference for a specific CVE entry.
    """
    cve_id = models.CharField(max_length=200)
    tag = models.CharField(max_length=2**10, help_text="Tag references(e.g. exploit)", null=True, blank=True)
    description = models.TextField(help_text="Description of the reference.", null=True, blank=True)
    url = models.URLField(max_length=2**10,help_text="URL to the reference.", null=True, blank=True)
    hostname = models.CharField(max_length=128, help_text="Parsed hostname of the URL.", null=True, blank=True)
    registered_domain = models.CharField(max_length=128, help_text="Parsed registered domain path of the URL.", null=True, blank=True)
    ref_source = models.CharField(max_length=2**7, help_text="RefSource (What is this?)", null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cve_id', 'tag', 'url'], name='unique_ref_url_tag_cve'),
        ]

    def __str__(self) -> str:
        return f"Reference for {self.cve}"

class SSVC(models.Model):
    cve_id = models.CharField(max_length=200)
    exploitation = models.CharField(max_length=2**6, help_text="Exploitation", null=True, blank=True)
    automatable = models.CharField(max_length=2**6, help_text="Automatable", null=True, blank=True)
    technical_impact = models.CharField(max_length=2**6, help_text="Technical Impact", null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cve_id'], name='unique_ssvc_cve_id'),
        ]

    def __str__(self) -> str:
        return f"SSVC for {self.cve}"


class CPE(models.Model):
    """
    Common Platform Enumeration (CPE) for a specific CVE entry.
    """
    cve_id = models.CharField(max_length=200)
    vendor=models.CharField(max_length=800, help_text="Vendor name", null=True)
    product=models.CharField(max_length=800, help_text="Product name",null=True)
    vendor_product=models.CharField(max_length=1600, help_text="Vendor and product name",null=True)
    # cpe = models.CharField(help_text="CPE text")
    # description = models.TextField(help_text="Description of the CPE.")
    # link = models.URLField(help_text="URL to the CPE details.")

    def __str__(self) -> str:
        return f"CPE for {self.vendor}"

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cve_id', 'vendor_product'], name='unique_cve_id_cpe'),
        ]


class IoT_classification(models.Model):
    cve_id = models.CharField(max_length=200)
    is_iot = models.BooleanField(default=False, help_text="Whether the CVE is IoT related or not.")
    affected_component = models.CharField(max_length=200, help_text="Affected component of the IoT device (e.g. device, communication, application, cloud backend, unsure).", null=True, blank=True)
    reason = models.TextField(help_text="Reasoning for the IoT classification.", null=True, blank=True)

    def __str__(self) -> str:
        return f"IoT classification for {self.cve_id}"

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cve_id', 'is_iot'], name='unique_cve_iot_label'),
        ]
        indexes = [
            models.Index(fields=['is_iot'], name='cve_iot_index'),
        ]


class POC(TimeStampedModel):
    """
    Proof of Concept (PoC) demonstrating an exploit for the CVE, which is GitHub repository.
    """
    name = models.CharField(max_length=200, help_text="Name or description of the PoC.")
    github_id = models.IntegerField(help_text="ID field in GitHub repositories.", null=True)
    link = models.URLField(help_text="URL to the PoC resource.")
    last_checked = models.DateTimeField(null=True, blank=True, help_text="Last checked time for updating star count")
    repo_first_commit = models.DateTimeField(auto_now=True, help_text="Last checked time for updating star count")
    stars_count = models.IntegerField(help_text="Current star count of the repository", default=0)
    forks_count = models.IntegerField(help_text="Current fork count of the repository", default=0)
    watch_count = models.IntegerField(help_text="Current watch count of the repository", default=0)
    repo_size = models.IntegerField(help_text="Current size of the repository in KB", null=True)
    repo_language = models.CharField(help_text="Language of the repository", max_length=50, null=True)
    repo_created_at = models.DateTimeField(help_text="Time the repository was created", null=True, blank=True)
    about = models.TextField(help_text="About section of the PoC.", null=True, blank=True)
    readme = models.TextField(help_text="Readme section of the repo.", null=True, blank=True)
    cve_count = models.IntegerField(default=0, help_text="How many CVEs does this repo contain")
    has_issues = models.BooleanField(default=None, null=True, help_text="Issues status.")

    class POCStatus(models.TextChoices):
        new = "N", _("New")
        removed = "R", _("Removed")
        unknown = "U", _("Unknown")

    status = models.CharField(
        max_length=2,
        choices=POCStatus.choices,
        default=POCStatus.new,
    )

    def __str__(self) -> str:
        return self.link

    class Meta:
        indexes = [
            models.Index(fields=['github_id'], name='poc_github_id'),
            models.Index(fields=['cve_count'], name='poc_cve_count'),
            models.Index(fields=['repo_created_at'], name='poc_created_at'),
        ]


class Star(TimeStampedModel):
    """
    Represents a "star" or endorsement of a specific CVE or PoC.
    """
    # No user identifiers are stored (anonymized dataset); each row is one star event.
    poc = models.ForeignKey(POC, on_delete=models.CASCADE, related_name="stars", null=True, blank=True)
    starred_at = models.DateTimeField(help_text="Timestamp of when the user starred the repository")

    class Meta:
        indexes = [
            models.Index(fields=['poc_id', 'starred_at'], name='poc_starred_at_index'),
        ]
    def __str__(self) -> str:
        return f"Star at {self.starred_at} for {self.poc}"

class Fork(models.Model):
    """
    Represents a "fork" event for a specific PoC repository.
    """
    # No user identifiers or fork URLs are stored (anonymized dataset); each row is one fork event.
    poc = models.ForeignKey(POC, on_delete=models.CASCADE, related_name="forks", null=True, blank=True)
    forked_at = models.DateTimeField(help_text="Timestamp of when the user forked the repository")

    indexes = [
        models.Index(fields=['poc_id', 'forked_at'], name='poc_forked_at_index'),
    ]


class Watch(models.Model):
    """
    Represents a "watch" event for a specific PoC repository.
    """
    # No user identifiers are stored (anonymized dataset); each row is one watch event.
    poc = models.ForeignKey(POC, on_delete=models.CASCADE, related_name="watches", null=True, blank=True)
    watched_at = models.DateTimeField(help_text="Timestamp of when the user started watching the repository")

class CVEPOCMapping(models.Model):
    cve_id = models.CharField(max_length=200)
    poc_id = models.IntegerField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['cve_id', 'poc_id'], name='unique_cve_poc_mapping')
        ]
        indexes = [
            models.Index(fields=['cve_id', 'poc_id'], name='cve_id_poc_id_index'),
            models.Index(fields=['poc_id', 'cve_id'], name='poc_id_cve_id_index'),
        ]



class EPSS(models.Model):
    cve = models.CharField(max_length=20, primary_key=True)
    epss = models.DecimalField(max_digits=10, decimal_places=8, help_text="EPSS score")
    date = models.DateField()
    objects = CopyManager()

    class Meta:
        managed = False  # Prevent Django from managing the table, as we want to partitioning
        constraints = [
            models.UniqueConstraint(fields=("cve", "date"), name="epss_unique_cve_date"),
        ]

        indexes = [
            models.Index(fields=['cve'], name='cve'),
        ]

class KEV(models.Model):
    cve_id = models.CharField(max_length=20)
    date = models.DateField(null=True)
    organizer = models.CharField(max_length=50, help_text="Organization of the KEV")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("cve_id", "date", "organizer"), name="kev_unique_cve_type"),
        ]
        indexes = [
            models.Index(fields=['cve_id', 'organizer'], name='cve_id_kev_organizer'),
        ]

class CVSS(models.Model):
    """
    {
                    "cvssV4_0": {
                        "version": "4.0",
                        "baseScore": 6.3,
                        "vectorString": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                        "baseSeverity": "MEDIUM"
                    }
                },
                {
                    "cvssV3_1": {
                        "version": "3.1",
                        "baseScore": 5.6,
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        "baseSeverity": "MEDIUM"
                    }
                },
    """
    cve_id = models.CharField(max_length=20)
    version = models.DecimalField(max_digits=30, decimal_places=15, help_text="CVSS version(e.g. 3.1, 4.0)")
    base_score = models.DecimalField(max_digits=30, decimal_places=15)
    base_severity = models.CharField(max_length=20, help_text="CVSS base severity")
    vector_string = models.TextField(help_text="CVSS vector string")
    metrics = models.JSONField(default=dict, help_text="CVSS metrics for different CVSS versions")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("version", "cve_id"), name="cvss_version_cveid_unique"),
        ]
        indexes = [
            models.Index(fields=['cve_id'], name='cve_id'),
            models.Index(fields=['cve_id', 'version'], name='cve_id_version'),
        ]

class MSF(models.Model):
    cve_id = models.CharField(max_length=20)
    date = models.DateField(null=True, default=None)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["cve_id"], name="cve_id_unique_msf")
        ]

        indexes = [
            models.Index(fields=['cve_id'], name='cve_id_msf'),
        ]

class Nuclei(models.Model):
    cve_id = models.CharField(max_length=20)
    date = models.DateField(null=True, default=None)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["cve_id"], name="cve_id_unique_nuclei")
        ]

        indexes = [
            models.Index(fields=['cve_id'], name='cve_id_nuclei'),
        ]

class Ransomware(models.Model):
    cve_id = models.CharField(max_length=20)
    source = models.CharField(max_length=1000, default=None, null=True)
    date = models.DateField(null=True, default=None)
    groups = models.CharField(max_length=1000, default=None, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["cve_id"], name="cve_id_unique_ransomware")
        ]

        indexes = [
            models.Index(fields=['cve_id'], name='cve_id_ransomware'),
        ]


class GpmDashboardCache(models.Model):
    snapshot_date = models.DateField(primary_key=True)  # one row per day
    badges = models.JSONField()                         # all KPIs in one JSON
    created_at = models.DateTimeField(auto_now_add=True)
    version = models.PositiveSmallIntegerField(default=1)

    class Meta:
        db_table = "gpm_dashboard_cache"
