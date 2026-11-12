from rest_framework import serializers
from cve.models import CVE, CWE, Reference, CVSS, KEV

class CWESerializer(serializers.ModelSerializer):
    class Meta:
        model = CWE
        fields = "__all__"

class CVSSSerializer(serializers.ModelSerializer):
    class Meta:
        model = CVSS
        fields = "__all__"

class ReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reference
        fields = ["tag", "url"]

class KEVSerializer(serializers.ModelSerializer):
    class Meta:
        model = KEV
        fields = ["date", "organizer"]

class CveSerializer(serializers.ModelSerializer):
    # show full CWE objects, not just IDs
    cwes = CWESerializer(many=True, read_only=True)

    # Reference doesn’t have a FK to CVE, so we fetch by cve_id
    references = serializers.SerializerMethodField(read_only=True)

    cvss = serializers.SerializerMethodField(read_only=True)

    kev  = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CVE
        fields = [
            "id",
            "description",
            "status",
            "date_published",
            "date_reserved",
            "date_added",
            "cwes",
            "cvss",
            "references",
            "kev",
        ]

    def get_references(self, obj):
        qs = Reference.objects.filter(cve_id=obj.id)
        return ReferenceSerializer(qs, many=True).data

    def get_cvss(self, obj):
        qs = CVSS.objects.filter(cve_id=obj.id)
        return CVSSSerializer(qs, many=True).data

    def get_kev(self, obj):
        qs = KEV.objects.filter(cve_id=obj.id, organizer='CISA')
        return KEVSerializer(qs, many=True).data
