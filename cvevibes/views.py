import json

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection
from django.views.decorators.cache import cache_page
from rest_framework import serializers
from cve.models import CVE
from rest_framework import viewsets
from django.views.decorators.vary import vary_on_headers
from rest_framework.pagination import PageNumberPagination
from django.utils.decorators import method_decorator
from django.core.validators import RegexValidator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_200_OK
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK
from django.http import JsonResponse

# Create your views here.
from rest_framework import viewsets
from cve.models import CVE
from cve.services.gpm_cache import get_or_compute_today_badges
from .serializers import CveSerializer
from django.views.decorators.cache import cache_control


def cached_after_auth(timeout, methods=('get',)):
    """
    Cache view methods *after* DRF authentication/permission checks.

    Decorating `dispatch` with cache_page would serve cached responses before
    DRF authenticates the request (anyone could read cached data). Decorating
    the handler methods (get/list/retrieve) runs inside dispatch after
    `initial()`, so only authenticated requests reach the cache. The data is the
    same for every user, so the cache is shared and responses are marked private
    so Cloudflare/shared proxies never store them.
    """
    def wrap(cls):
        for m in methods:
            cls = method_decorator(cache_page(timeout, key_prefix='api'), name=m)(cls)
            cls = method_decorator(cache_control(private=True), name=m)(cls)
        return cls
    return wrap


#
# @method_decorator(vary_on_headers('Authorization'), name='dispatch')
# @method_decorator(cache_page(3600 * 5, key_prefix='authenticated_only'), name='dispatch')
# class GPMListView(APIView):
#     """
#     List all repositories from the database view.
#     Supports optional ordering by whitelisted columns.
#     Optional filter: ?not_kev_only=true => only CVEs that are NOT in KEV.
#     """
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         try:
#             # trend duration
#             days = int(request.query_params.get('days', 365 * 30))
#
#             def as_bool(val):
#                 return str(val).lower() in ("1", "true", "yes")
#
#             # query params
#             kev_only = as_bool(request.query_params.get("kev_only"))
#             not_kev_only = as_bool(request.query_params.get("not_kev_only"))
#
#             # build WHERE clause
#             if kev_only:
#                 kev_where_clause = "WHERE g.is_kev = TRUE"
#             elif not_kev_only:
#                 kev_where_clause = "WHERE g.is_kev = FALSE"
#             else:
#                 kev_where_clause = ""
#
#             query = f"""
#             WITH GPM AS MATERIALIZED (
#     SELECT COUNT(*) AS gpm, cve_id
#     FROM ghp_with_time
#     WHERE interacted_time >= (
#         SELECT interacted_time
#         FROM ghp_with_time
#         ORDER BY interacted_time DESC
#         LIMIT 1
#     ) - INTERVAL '%s days'
#     GROUP BY cve_id
# ),
# GPM_WITH_KEV AS MATERIALIZED (
#     SELECT
#         g.*,
#         (kev.cve_id IS NOT NULL) AS is_kev
#     FROM GPM g
#     LEFT JOIN cve_kev kev
#       ON kev.cve_id = g.cve_id
#      AND kev.organizer = 'CISA'
# )
# SELECT
#   g.cve_id,
#   g.gpm,
#   g.is_kev,
#   cv.base_score,
#   cv.base_severity,
#   cv.vector_string,
#   c.description,
#   c.date_reserved,
#   c.date_published,
#   kev.date AS kev_date,
#   STRING_AGG(DISTINCT cw.name, '|SEP_CWE_SEP|' ORDER BY cw.name) AS cwe_names
# FROM GPM_WITH_KEV g
# LEFT JOIN cve_cve c ON c.id = g.cve_id
# LEFT JOIN cve_cvss_max cv ON cv.cve_id = g.cve_id
# LEFT JOIN cve_cve_cwes cc ON cc.cve_id = g.cve_id
# LEFT JOIN cve_cwe cw ON cw.id = cc.cwe_id
# LEFT JOIN cve_kev kev ON kev.cve_id = g.cve_id AND kev.organizer = 'CISA'
# {kev_where_clause}
# GROUP BY
#   g.cve_id, g.gpm, g.is_kev,
#   cv.version, cv.base_score, cv.base_severity, cv.vector_string,
#   c.id, kev.date, c.date_reserved, c.date_published
# ORDER BY g.gpm DESC
# LIMIT 100;
#             """
#
#             with connection.cursor() as cursor:
#                 cursor.execute(query, [days])
#                 columns = [col[0] for col in cursor.description]
#                 results = [dict(zip(columns, row)) for row in cursor.fetchall()]
#
#             return Response({
#                 'count': len(results),
#                 'results': results
#             })
#
#         except Exception as e:
#             print(str(e))
#             return Response(
#                 {'error': 'Error! ' + str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

# @method_decorator(vary_on_headers('Authorization'), name='dispatch')
# @method_decorator(cache_page(60 * 5, key_prefix='authenticated_only'), name='dispatch')
# class GPMListView(APIView):
#     """
#     List all repositories from the database view.
#     Supports optional ordering by whitelisted columns.
#     """
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         try:
#             # trend duration
#             days = int(request.query_params.get('days', 365*30))
#
#             query = """
#             with GPM as (SELECT COUNT(*) as gpm, cve_id FROM ghp_with_time
#              WHERE (interacted_time >= (SELECT MAX(interacted_time) FROM ghp_with_time) - INTERVAL '%s days')
#              GROUP BY cve_id
# --              having COUNT(*) > 5
#              ),
#      cve_cvss_max AS (
#          SELECT t.*
#          FROM cvevibes_db.public.cve_cvss t
#                   JOIN (
#              SELECT
#                  cve_id,
#                  MAX(CAST(version AS DECIMAL(3,1))) AS latest_version
#              FROM cvevibes_db.public.cve_cvss
#              GROUP BY cve_id
#          ) v
#                        ON t.cve_id = v.cve_id
#                            AND CAST(t.version AS DECIMAL(3,1)) = v.latest_version
#      )
#      --filtered_cve_epss as (select * from cve_epss where cve in (select cve_id from gpm) and date =(select max(date) from cve_epss where cve='CVE-2025-1000'))
# SELECT
#   g.cve_id, g.gpm, cv.base_score, cv.base_severity, cv.vector_string, c.description, c.date_reserved, c.date_published, kev.date kev,
#   --, e.epss
#   STRING_AGG(DISTINCT cw.name, '|SEP_CWE_SEP|' ORDER BY cw.name) AS cwe_names
# FROM GPM g
# LEFT JOIN cve_cve c  ON c.id = g.cve_id
# LEFT JOIN cve_cvss_max   cv ON cv.cve_id = g.cve_id
# -- JOIN filtered_cve_epss e ON e.cve = g.cve_id
# LEFT JOIN cve_cve_cwes cc ON cc.cve_id = g.cve_id
# LEFT JOIN cve_cwe      cw ON cw.id = cc.cwe_id
# LEFT JOIN cve_kev      kev  ON kev.cve_id = g.cve_id AND kev.organizer='CISA'
# GROUP BY g.cve_id, g.gpm, cv.version, cv.base_score, cv.base_severity, cv.vector_string, c.id, kev.date, c.date_reserved, c.date_published
# --, e.epss
# ORDER BY g.gpm DESC
# LIMIT 100
# """
#
#             with connection.cursor() as cursor:
#                 cursor.execute(query, [days])
#                 columns = [col[0] for col in cursor.description]
#                 results = [dict(zip(columns, row)) for row in cursor.fetchall()]
#
#             return Response({
#                 'count': len(results),
#                 'results': results
#             })
#
#         except Exception as e:
#             print(str(e))
#             return Response(
#                 {'error': 'Error!' + str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
#
# @method_decorator(vary_on_headers('Authorization'), name='dispatch')
# @method_decorator(cache_page(3600 * 5, key_prefix='authenticated_only'), name='dispatch')
# class GPMOnlyCVEsView(APIView):
#     """
#     List all repositories from the database view.
#     Supports optional ordering by whitelisted columns.
#     """
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         try:
#             # trend duration
#             days = int(request.query_params.get('days', 365*30))
#
#             query = """
# WITH uit AS MATERIALIZED (
#   -- Build the interactions once (ghp_with_time is a view)
#   SELECT t.cve_id, t.interacted_time
#   FROM ghp_with_time t
# ),
# max_t AS (
#   SELECT MAX(interacted_time) AS max_it FROM uit
# ),
# gpm AS (\
#   SELECT u.cve_id, COUNT(*)::bigint AS gpm
#   FROM uit u
#   JOIN max_t m
#     ON u.interacted_time >= m.max_it - INTERVAL '%s days'
#   GROUP BY u.cve_id
# )
# SELECT
#   g.cve_id,
#   g.gpm,
#   c.status,
#   c.description,
#   c.date_published
# FROM gpm g
# LEFT JOIN cve_cve c
#   ON c.id = g.cve_id
# WHERE
#   c.id IS NULL              -- keep CVEs not present in cve_cve
#   OR c.status IN ('R','U')  -- or present with allowed status
# ORDER BY g.gpm DESC NULLS LAST, g.cve_id;
# """
#             with connection.cursor() as cursor:
#                 cursor.execute(query, [days])
#                 columns = [col[0] for col in cursor.description]
#                 results = [dict(zip(columns, row)) for row in cursor.fetchall()]
#
#             return Response({
#                 'count': len(results),
#                 'results': results
#             })
#
#         except Exception as e:
#             print(str(e))
#             return Response(
#                 {'error': 'Error!' + str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )



@cached_after_auth(3600 * 5)
class GPMListView(APIView):
    """
    List GPM CVEs with optional filters:
    - ?gpm_only=true       -> only CVEs where (c.id IS NULL OR c.status IN ('R','U'))
    - ?kev_only=true       -> only CVEs that are in KEV
    - ?not_kev_only=true   -> only CVEs that are NOT in KEV
    You can combine gpm_only with either kev_only or not_kev_only.

    Pagination:
    - ?page=N (default: 1)
    - ?page_size=M (default: 50, max: 200)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # trend duration
            days = int(request.query_params.get('days', 365 * 30))

            def as_bool(val):
                return str(val).lower() in ("1", "true", "yes")

            # pagination params
            try:
                page = int(request.query_params.get("page", 1))
            except ValueError:
                page = 1
            try:
                page_size = int(request.query_params.get("page_size", 50))
            except ValueError:
                page_size = 50

            page = max(page, 1)
            page_size = max(1, min(page_size, 200))  # cap page_size

            offset = (page - 1) * page_size
            limit = page_size + 1  # fetch one extra row to detect "has_next"

            # filters
            gpm_only     = as_bool(request.query_params.get("gpm_only"))
            kev_only     = as_bool(request.query_params.get("kev_only"))
            not_kev_only = as_bool(request.query_params.get("not_kev_only"))

            # Build WHERE conditions
            conditions = []

            # GPM-only semantics (from your first view)
            if gpm_only:
                conditions.append("(c.id IS NULL OR c.status IN ('R','U') or c.date_published IS NULL)")

            # KEV filters (mutually exclusive: kev_only wins if both are set)
            if kev_only:
                conditions.append("g.is_kev = TRUE")
            elif not_kev_only:
                conditions.append("g.is_kev = FALSE")

            where_clause = ""
            if conditions:
                where_clause = "WHERE " + " AND ".join(conditions)

            # NOTE: only {where_clause} is interpolated; all values use SQL params
            query = f"""
WITH GPM  AS (
    SELECT 
        COUNT(*) AS gpm,
        cve_id
    FROM ghp_with_time
    WHERE interacted_time >= (
        SELECT interacted_time
        FROM ghp_with_time
        ORDER BY interacted_time DESC
        LIMIT 1
    ) - INTERVAL '%s days'
    GROUP BY cve_id
),
GPM_WITH_KEV AS (
    SELECT
        g.*,
        (kev.cve_id IS NOT NULL) AS is_kev
    FROM GPM g
    LEFT JOIN cve_kev kev
      ON kev.cve_id = g.cve_id
     AND kev.organizer = 'CISA'
)
SELECT
  g.cve_id,
  g.gpm relative_gpm,
  g.is_kev,
  cv.base_score,
  cv.base_severity,
  cv.vector_string,
  c.description,
  c.date_reserved,
  c.date_published,
  kev.date AS kev_date,
  gpmtotal.total_interactions as total_gpm,
  STRING_AGG(DISTINCT cw.name, '|SEP_CWE_SEP|' ORDER BY cw.name) AS cwe_names
FROM GPM_WITH_KEV g
LEFT JOIN cve_cve c          ON c.id = g.cve_id
LEFT JOIN cve_cvss_max cv    ON cv.cve_id = g.cve_id
LEFT JOIN cve_cve_cwes cc    ON cc.cve_id = g.cve_id
LEFT JOIN cve_cwe cw         ON cw.id = cc.cwe_id
LEFT JOIN cve_kev kev        ON kev.cve_id = g.cve_id AND kev.organizer = 'CISA'
LEFT JOIN interaction_counts gpmtotal ON gpmtotal.cve_id = g.cve_id
{where_clause}
GROUP BY
  g.cve_id, g.gpm, g.is_kev,
  cv.version, cv.base_score, cv.base_severity, cv.vector_string,
  c.id, kev.date, c.date_reserved, c.date_published, gpmtotal.total_interactions
ORDER BY g.gpm DESC
LIMIT %s OFFSET %s;
"""

            params = [days, limit, offset]

            with connection.cursor() as cursor:
                cursor.execute(query, params)
                columns = [col[0] for col in cursor.description]
                rows = cursor.fetchall()

            # detect has_next using the extra row
            has_next = len(rows) > page_size
            if has_next:
                rows = rows[:page_size]

            results = [dict(zip(columns, row)) for row in rows]

            return Response({
                'page': page,
                'page_size': page_size,
                'count': len(results),
                'has_next': has_next,
                'results': results,
            })

        except Exception as e:
            print(str(e))
            return Response(
                {'error': 'Error! ' + str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




# @method_decorator(vary_on_headers('Authorization'), name='dispatch')
@cached_after_auth(3600 * 24)
class GPMDailyView(APIView):
    """
    Used as main chart
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Daily interactions in GPM
            days = int(request.query_params.get('days', 7))

            query = """select
  interacted_time::date              as day,
  count(*)              as samples
from ghp_with_time
where interacted_time >= now() - (%s || ' days')::interval
group by 1
order by 1;
"""

            with connection.cursor() as cursor:
                cursor.execute(query, [days])
                columns = [col[0] for col in cursor.description]
                results = [dict(zip(columns, row)) for row in cursor.fetchall()]

            return Response({
                'count': len(results),
                'results': results
            })

        except Exception as e:
            print(str(e))
            return Response(
                {'error': 'Error!' + str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# Cache per URL (querystring included) for 5 minutes
@cached_after_auth(3600 * 5)
class GPMDailyDetailView(APIView):
    """
    Daily interactions in GPM for a specific CVE.
    Query params:
      - days (int, default=7)
    Path params:
      - cveid (e.g., CVE-2024-12345)
    """
    permission_classes = [IsAuthenticated]

    # simple CVE format check
    cve_validator = RegexValidator(
        regex=r"^CVE-\d{4}-\d{4,12}$",
        message="cveid must look like CVE-YYYY-NNNN."
    )

    def get(self, request, cveid: str):
        try:
            # validate path param
            self.cve_validator(cveid)

            # sanitize/parse days
            try:
                days = int(request.query_params.get('days', 365*30))
                if days <= 0:
                    raise ValueError
            except ValueError:
                return Response(
                    {"error": "days must be a positive integer"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            query = """
                select
                  interacted_time::date as day,
                  count(*)              as samples
                from ghp_with_time
                where interacted_time >= now() - (%s || ' days')::interval
                  and cve_id = %s
                group by 1
                order by 1;
            """

            with connection.cursor() as cursor:
                cursor.execute(query, [days, cveid])
                columns = [col[0] for col in cursor.description]
                results = [dict(zip(columns, row)) for row in cursor.fetchall()]


                cursor.execute("SELECT date from cve_kev where organizer='CISA' and cve_id=%s", [cveid])
                kev = cursor.fetchone()
                kev_date = None
                if kev:
                    kev_date = [0]


            return Response({
                "cveid": cveid,
                "days": days,
                "count": len(results),
                "results": results,
                "kev": kev_date
            })

        except Exception as e:
            # log as needed
            print(str(e))
            return Response(
                {"error": "Error! " + str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

import time

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def GPMBadges(request):
    badges = json.loads(get_or_compute_today_badges())
    return JsonResponse({'badges':badges}, status=HTTP_200_OK)



class CustomPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100




@cached_after_auth(3600 * 5, methods=('list', 'retrieve'))
class CVEViewSet(viewsets.ReadOnlyModelViewSet):  # <- only list + retrieve
    permission_classes = [IsAuthenticated]
    queryset = CVE.objects.all().prefetch_related("cwes")
    serializer_class = CveSerializer
    pagination_class = CustomPagination
    # If you want to be extra strict, you could also set:
    # http_method_names = ["get", "head", "options"]


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user:
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=HTTP_200_OK)
    return Response({'error': 'Invalid credentials'}, status=HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    request.user.auth_token.delete()
    return Response({'message': 'Logged out successfully'}, status=HTTP_200_OK)