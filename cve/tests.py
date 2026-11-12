from django.test import TestCase
from .models import CVE, Reference, CPE, POC, Star
from .utils.textprocess import extract_cves
#
#
# class CVEModelTest(TestCase):
#
#     def setUp(self) -> None:
#         self.cve = CVE.objects.create(id="CVE-2021-12345", description="A test CVE entry")
#
#     def test_create_cve(self):
#         self.assertEqual(self.cve.id, "CVE-2021-12345")
#         self.assertEqual(self.cve.description, "A test CVE entry")
#
#
# class ReferenceModelTest(TestCase):
#
#     def setUp(self) -> None:
#         self.cve = CVE.objects.create(id="CVE-2021-12345", description="A test CVE entry")
#         self.reference = Reference.objects.create(cve=self.cve, description="A test reference",
#                                                   url="http://example.com")
#
#     def test_reference_creation(self):
#         self.assertEqual(self.reference.cve, self.cve)
#         self.assertEqual(self.reference.url, "http://example.com")
#
#
# class CPEModelTest(TestCase):
#
#     def setUp(self) -> None:
#         self.cve = CVE.objects.create(id="CVE-2021-12345", description="A test CVE entry")
#         self.cpe = CPE.objects.create(cve=self.cve, description="A test CPE", link="http://example.com/cpe")
#
#     def test_cpe_creation(self):
#         self.assertEqual(self.cpe.cve, self.cve)
#         self.assertEqual(self.cpe.link, "http://example.com/cpe")
#
#
# class POCModelTest(TestCase):
#
#     def setUp(self) -> None:
#         self.cve = CVE.objects.create(id="CVE-2021-12345", description="A test CVE entry")
#         self.poc = POC.objects.create(cve=self.cve, name="Test POC", link="http://example.com/poc")
#
#     def test_poc_creation(self):
#         self.assertEqual(self.poc.cve, self.cve)
#         self.assertEqual(self.poc.link, "http://example.com/poc")

#
# class StarModelTest(TestCase):
#
#     def setUp(self) -> None:
#         self.cve = CVE.objects.create(id="CVE-2021-12345", description="A test CVE entry")
#         self.poc = POC.objects.create(cve=self.cve, name="Test POC", link="http://example.com/poc")
#         self.star = Star.objects.create(cve=self.cve, name="Test User")
#
#     def test_star_creation(self):
#         self.assertEqual(self.star.cve, self.cve)
#         self.assertEqual(self.star.name, "Test User")

class CVERegexTest(TestCase):
    def test_single_cve(self):
        to_find = "CVE-2024-1131"
        text = """HelloCVE-2024-1131AndHere"""
        matches = extract_cves(text)
        self.assertListEqual(matches, [to_find])

    def test_multi_cves(self):
        to_find = ["CVE-2024-1131", "CVE-2024-1132"]
        text = """HelloCVE-2024-1131AndHereCVE-2024-1132"""
        matches = extract_cves(text)
        self.assertListEqual(matches, to_find)

    def test_multi_cves_multiline(self):
        to_find = ["CVE-2024-1131", "CVE-2024-1132"]
        text = """HelloCVE-2024-1131And
        HereCVE-2024-1132"""
        matches = extract_cves(text)
        self.assertListEqual(matches, to_find)

    def test_multi_cves_multiline_case_sensitive(self):
        to_find = ["CVE-2024-1131", "CVE-2024-1132"]
        text = """HelloCvE-2024-1131And
        HerecVe-2024-1132"""
        matches = extract_cves(text)
        self.assertListEqual(matches, to_find)

    def test_multi_cves_multiline_case_sensitive_no_duplicate(self):
        to_find = ["CVE-2024-1131", "CVE-2024-1132"]
        text = """HelloCvE-2024-1131And
        HerecVe-2024-1132 CVE-2024-1131 cVe-2024-1132 """
        matches = extract_cves(text)
        self.assertListEqual(matches, to_find)

