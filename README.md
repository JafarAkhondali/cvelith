# CVElith — GPM (GitHub Popularity Metric)

CVElith collects public vulnerability data into one PostgreSQL database and serves it through a Django REST API and a React dashboard.

It ingests CVE records, links them to GitHub proof-of-concept (PoC) exploit repositories, and scores each CVE by how much attention those PoCs get on GitHub: the **GPM score**.

## Contents

- [GPM score](#gpm-score)
- [Dataset](#dataset)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Deployment (behind Cloudflare)](#deployment-behind-cloudflare)
- [Local development](#local-development)
- [API guide](#api-guide)
- [Maintenance](#maintenance)

## GPM score

The GPM score of a CVE measures how much attention its GitHub PoC repositories receive. Its exact definition is given in the accompanying paper.

- `ghp_with_time` holds every counted interaction with its timestamp.
- `interaction_counts.total_interactions` is the all-time GPM per CVE.
- The API's "relative GPM" is the same count, limited to the last `days` days.

The dataset contains **no GitHub user identifiers**: star, fork and watch rows hold only the PoC and a timestamp.

## Dataset

The dataset isn't stored in this repository. **Download it from: <!-- TODO: add dataset URL --> _link coming soon_.**

To set up the site from the download, put `gpm_dataset.dump` and `SHA256SUMS` in `data/` and follow [Path A](#path-a--from-the-dataset-dump-recommended-takes-minutes).

| File | Contents |
|---|---|
| `gpm_dataset.dump` | `pg_dump` custom-format archive of the full database, PostgreSQL 17. |
| `csv/<table>.csv.gz` | One gzipped CSV with a header row per table and materialized view. |
| `SHA256SUMS` | Checksums of the dump and every CSV. Verify with `sha256sum -c SHA256SUMS`. |

What the export leaves out:

- **Accounts and sessions:** rows of `auth_user`, `authtoken_token`, `django_session`, `django_admin_log` and `gpm_dashboard_cache`. Their table structure is kept so the Django app runs on a restored copy.
- **EPSS history:** `cve_epss` and its 16 `epss_hash_*` partitions are empty, about 271M rows left out for size. Re-fetch with `python3 manage.py fetch_epss`.

### Tables

| Name | Contents |
|---|---|
| `cve_cve` | CVE records: description, dates, status |
| `cve_cvss` / `cve_cvss_max` *(mat. view)* | CVSS scores; highest-version score per CVE |
| `cve_cwe`, `cve_cve_cwes` | CWE categories and the CVE↔CWE mapping |
| `cve_cpe`, `cve_reference`, `cve_ssvc` | Affected products, references, CISA SSVC decisions |
| `cve_kev` | Known Exploited Vulnerabilities (CISA and others) |
| `cve_msf` / `cve_nuclei` | Metasploit module and Nuclei template mappings |
| `cve_ransomware` | Ransomware-associated CVEs |
| `cve_poc` | GitHub PoC repositories. `github_id` is the **repository** ID; `link` is the repo URL. |
| `cve_cvepocmapping` | CVE↔PoC mapping |
| `cve_star` / `cve_fork` / `cve_watch` | One row per star, fork or watch event: `poc_id` plus timestamp. No user data. |
| `ghp_with_time` *(mat. view)* | Every counted GPM interaction: `cve_id`, `poc_id`, `interaction_type` (`star`/`fork`/`watch`/`poc`), `interacted_time` |
| `interaction_counts` *(mat. view)* | All-time GPM per CVE (`total_interactions`) |
| `gpm_score_snapshot` | Frozen per-CVE scores computed before user identifiers were removed |
| `cve_epss` | EPSS history; empty in the export |

### Restoring the dump

```bash
createdb -h HOST -p PORT -U USER gpm
pg_restore -h HOST -p PORT -U USER -d gpm --no-owner --no-acl gpm_dataset.dump
```

Restore into an **empty** database (no `migrate` beforehand). To restore into this project's Compose stack, follow [Path A](#path-a--from-the-dataset-dump-recommended-takes-minutes).

## Architecture

```
Browser ──HTTPS──▶ Cloudflare ──HTTPS (Origin cert)──▶ Caddy :443
                                                         ├─ /api/*  ──▶ backend (gunicorn + Django) :8000 ──▶ Postgres 17
                                                         └─ /*      ──▶ React SPA (static files from dist_volume)
```

| Compose service | Role |
|---|---|
| `db2026ccs` | PostgreSQL 17. Data is stored in volume `db_data2026ccs`. Host port `${POSTGRES_PORT}` is bound to **127.0.0.1 only**. |
| `backend` | Django REST API (`cvevibes/` project, `cve/` app) under gunicorn: 3 workers, 120 s timeout. Reaches the database at `db2026ccs:5432`. |
| `frontend` | One-shot build: compiles the Vite/React app and copies it into `dist_volume`, then exits. |
| `caddy` | Terminates TLS for `${SITE_DOMAIN}` and serves the SPA, with unknown paths falling back to `index.html`. Proxies `/api/*` to the backend **with the prefix kept**. Redirects HTTP to HTTPS. |

The frontend calls the API on the same origin (`/api/v1/...`). To develop the frontend against a separate backend, set `VITE_API_BASE_URL`.

## Configuration

Copy `env.example` to `.env` and fill it in. Compose and Django both read it.

| Variable | Description |
|---|---|
| `SECRET_KEY` | Django secret key. Generate one with `python3 -c "from django.core.management.utils import get_random_secret_key as g; print(g())"`. |
| `DEBUG` | `False` in production |
| `SITE_DOMAIN` | Public hostname Caddy serves, e.g. `gpm.example.org` |
| `ALLOWED_HOSTS` | Must include `SITE_DOMAIN` |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Database credentials. They are applied only when the volume is **first** created. To change the password later, also run `ALTER USER ... PASSWORD '...'`. |
| `POSTGRES_HOST` / `POSTGRES_PORT` | Used by host-side tools such as `manage.py` and `psql`: `127.0.0.1` and the published port. Inside Compose the backend overrides these to `db2026ccs:5432`. |
| `GITHUB_TOKEN` | GitHub API token, used by `fetch_pocs` |
| `VULNCHECK_TOKEN` | VulnCheck API token |
| `MAX_CVES_PER_REPO` | Cap on CVEs linked per PoC repository |
| `COMPOSE_PROJECT_NAME` | Optional. Gives this stack's containers and volumes unique names, so they don't clash with other Compose projects on the same host. |
| `HTTPS_PORT` / `HTTP_PORT` | Host ports Caddy publishes; default `443` and `80`. You can include a bind address, e.g. `HTTPS_PORT=0.0.0.0:8448` and `HTTP_PORT=127.0.0.1:8088`. |

## Deployment (behind Cloudflare)

### 1. Cloudflare

1. **DNS:** add an `A` record (and `AAAA` if the server has IPv6) for your hostname, pointing to the server, with **Proxied** (orange cloud) turned on.
2. **SSL/TLS → Overview:** set the encryption mode to **Full (strict)**.
3. **SSL/TLS → Origin Server → Create Certificate:**
   - Use an RSA or ECC key.
   - Hostnames: your `SITE_DOMAIN`. Add a wildcard such as `*.example.org` if you want the certificate to cover other subdomains.
   - Save the files on the server as:
     ```
     certs/origin.pem   # the Origin Certificate
     certs/origin.key   # the private key
     ```
   - `certs/` is mounted read-only into Caddy at `/etc/caddy/certs` and must never be committed.
4. Turn on **Always Use HTTPS** (SSL/TLS → Edge Certificates).
5. **If ports 80/443 are already used on the server**, publish Caddy on another port and add an Origin Rule. Visitors still use the normal `https://` URL.
   - Rules → Origin Rules → Create rule.
   - Condition: *Hostname equals your `SITE_DOMAIN`*. Action: *Destination Port → `8448`*.
   - In `.env`: `HTTPS_PORT=0.0.0.0:8448` and `HTTP_PORT=127.0.0.1:8088`.
   - Origin Rules with a port override are available on the Free plan.

Caddy only accepts connections from Cloudflare's IP ranges and private addresses; everything else is dropped. Nobody can skip Cloudflare by connecting to the server's IP directly.
- Publish the HTTPS port on **IPv4 only** (`0.0.0.0:PORT`). Docker's IPv6 proxy would make outside clients look like private addresses and get through.
- Cloudflare occasionally changes its ranges. Compare the `Caddyfile` lists with https://www.cloudflare.com/ips/ now and then.

The Origin certificate is trusted only by Cloudflare. Visiting the server's IP directly gives a browser warning, which is expected. Caddy never requests Let's Encrypt certificates (`auto_https disable_certs`).

### 2. Configure

```bash
cp env.example .env               # then set SECRET_KEY, DEBUG=False, POSTGRES_PASSWORD, ...
mkdir -p certs                    # put origin.pem / origin.key here
chmod 600 .env
```

Ports **80 and 443** must be free on the host, or set `HTTPS_PORT`/`HTTP_PORT` as in Cloudflare step 5.

### 3. Load the data (first time only)

Pick **one** of the two paths. Both were tested end to end on PostgreSQL 17.

#### Path A — from the dataset dump (recommended, takes minutes)

**One command:** put `gpm_dataset.dump` (and its `SHA256SUMS`) in `data/`, then run:

```bash
./scripts/setup_from_dump.sh            # or: ./scripts/setup_from_dump.sh /path/to/gpm_dataset.dump
docker compose exec -it backend python manage.py apiuser create YOUR_USER
```

The script verifies the checksum, restores only if the database is empty, builds and starts all services, migrates and refreshes the views. It's safe to re-run after updating the code. The manual steps below do the same thing.

The dump must go into an **empty** database. Restore it **before** running `migrate`.

```bash
# 1. Start only the database (creates an empty DB from .env on first run)
docker compose up -d db2026ccs

# 2. Restore the dump (about 1 minute). Run from the folder that holds gpm_dataset.dump.
docker compose exec -T db2026ccs sh -c \
  'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error' \
  < gpm_dataset.dump

# 3. Start everything
docker compose up -d --build

# 4. Check the schema and rebuild the GPM views.
#    `migrate` should say "No migrations to apply".
docker compose exec backend python manage.py migrate
docker compose exec backend python manage.py refresh_cache

# 5. Create an account (see "Authentication")
docker compose exec -it backend python manage.py apiuser create YOUR_USER
```

The dump contains no user accounts, so step 5 is required. EPSS history isn't included; run `fetch_epss` (Path B, step 4) if you need it.

If `pg_restore` complains about existing objects, the database isn't empty: `migrate` was probably run first. Reset it with `docker compose down -v`, which **deletes all Compose volumes**, and start again from step 1.

#### Path B — from scratch, without a dump (takes hours)

Build an empty schema with migrations, then fill it from the upstream sources. This needs internet access and a `GITHUB_TOKEN` in `.env`.

```bash
# 1. Start the stack; the database starts empty
docker compose up -d --build

# 2. Create all tables and the GPM materialized views
docker compose exec backend python manage.py migrate

# 3. CVE records first: everything else links to them.
#    Downloads CWE, NVD feeds and a shallow clone of CVEProject/cvelistV5.
docker compose exec backend python manage.py fetch_cves 1999 2026     # start_year end_year

# 4. Other sources (any order, after fetch_cves)
docker compose exec backend python manage.py fetch_pocs --start-year 1999 --end-year 2026   # GitHub PoCs + stars/forks; slowest step (API rate limits)
docker compose exec backend python manage.py fetch_kevs
docker compose exec backend python manage.py fetch_msf
docker compose exec backend python manage.py fetch_nuclei
docker compose exec backend python manage.py fetch_ranscve
docker compose exec backend python manage.py fetch_epss               # optional: very large (~270M rows)

# 5. Build the GPM views from the fetched data
docker compose exec backend python manage.py refresh_cache

# 6. Create an account
docker compose exec -it backend python manage.py apiuser create YOUR_USER
```

Notes:
- Files the fetchers download go into the backend container's filesystem and are lost when the container is recreated. Only the data in Postgres persists.
- A from-scratch build won't match the published dataset exactly: GitHub only reports current stars and forks, so stars that were later removed are missing. It also has no `gpm_score_snapshot`; that table exists only in the dump.
- You can run the same commands from the host instead (see [Local development](#local-development)). `fetch_epss` then needs `sudo apt install parallel`.

### 4. Check it

```bash
curl -I https://$SITE_DOMAIN/                                   # 200, SPA
curl https://$SITE_DOMAIN/api/v1/gpm-badges/                    # 401 without a token
curl -X POST https://$SITE_DOMAIN/api/v1/login/ \
     -H 'Content-Type: application/json' \
     -d '{"username":"USER","password":"PASS"}'               # {"token": "..."}
curl -H "Authorization: Token TOKEN" https://$SITE_DOMAIN/api/v1/gpm-badges/
```

## Local development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
docker compose up -d db2026ccs         # Postgres on 127.0.0.1:${POSTGRES_PORT}
python manage.py migrate
python manage.py runserver             # API on http://127.0.0.1:8000/api/v1/

cd frontend && npm ci
VITE_API_BASE_URL=http://127.0.0.1:8000 npm run dev   # SPA on http://localhost:8080
```

Connect to the database directly:

```bash
psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

## API guide

Base URL: **`https://<SITE_DOMAIN>/api/v1/`**. With `runserver` it's `http://127.0.0.1:8000/api/v1/`. Caddy forwards `/api/...` unchanged, so the paths are identical in both setups.

### Authentication

Everything except `login` requires a DRF **token**, sent as `Authorization: Token <token>`. There is no sign-up endpoint and the Django admin is disabled. Accounts are managed on the server with the `apiuser` command.

Prefix each command with `docker compose exec -it backend` in Compose, or run it directly with `python manage.py ...` in a local venv.

```bash
python manage.py apiuser create alice              # prompts for a password, prints alice's token
python manage.py apiuser create bot --token-only   # no password: API token only, no web login
python manage.py apiuser list                      # users, token yes/no, password yes/no, last login
python manage.py apiuser token alice               # show alice's token
python manage.py apiuser token alice --rotate      # issue a new token; the old one stops working
python manage.py apiuser revoke alice              # delete the token; alice must log in again
python manage.py apiuser password alice            # set a new password
python manage.py apiuser delete alice              # delete the account and its token
```

Details:
- Passwords go through Django's validators: at least 8 characters, not common, not all digits.
- For scripts, pass `--password-stdin` to `create` or `password`: `echo "$PW" | python manage.py apiuser create alice --password-stdin`.
- The token is printed alone on the last line, so `... | tail -1` captures it.
- Use `--token-only` for scripts and integrations: they get a token without a password that could be guessed at the login endpoint.

Ways to get a token:
- **Web UI and password users:** `POST /api/v1/login/` returns the user's token, creating it if needed.
- **Server side:** `apiuser create` or `apiuser token`.

Tokens don't expire. To cut off access, use `POST /api/v1/logout/` (deletes the caller's own token), `apiuser revoke`, or `apiuser token --rotate`.

```bash
TOKEN=$(curl -s -X POST https://$SITE_DOMAIN/api/v1/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"USER","password":"PASS"}' | jq -r .token)

curl -H "Authorization: Token $TOKEN" "https://$SITE_DOMAIN/api/v1/gpm/?days=30&page_size=10"
```

Responses:

| Case | Response |
|---|---|
| Missing or invalid token | `401 {"detail": ...}` |
| Wrong credentials at login | `400 {"error": "Invalid credentials"}` |

### Endpoints

| Endpoint | Method | Description | Cache |
|---|---|---|---|
| `/api/v1/login/` | POST | `{"username","password"}` → `{"token"}` | — |
| `/api/v1/logout/` | POST | Deletes the current token | — |
| `/api/v1/cve/` | GET | CVE list, paginated: `page`, `page_size` (default 20, max 100) | 5 h |
| `/api/v1/cve/{id}/` | GET | One CVE, e.g. `/api/v1/cve/CVE-2021-44228/` | 5 h |
| `/api/v1/gpm/` | GET | CVEs ranked by GPM in a time window (see below) | 5 h |
| `/api/v1/gpm/{cveid}/` | GET | Daily interaction counts for one CVE. `days` defaults to all time. | 5 h |
| `/api/v1/gpm-daily/` | GET | Daily interaction counts across all CVEs (main chart). `days` defaults to 7. | 24 h |
| `/api/v1/gpm-badges/` | GET | Summary stats: GPM CVE count, median and average GPM, repo count, latest sync. Recomputed once per day. | daily (DB) |

`/api/v1/gpm/` query parameters:

| Parameter | Effect |
|---|---|
| `days` | Window for `relative_gpm`. Default: all time. |
| `gpm_only=true` | Only CVEs with no published CVE record (missing, reserved or rejected) |
| `kev_only=true` / `not_kev_only=true` | Only CVEs in CISA KEV, or only CVEs not in it |
| `page`, `page_size` | Paging. Default page size 50, max 200. The response has `has_next`. |

Each result includes:

- `cve_id`
- `relative_gpm` (interactions in the window) and `total_gpm` (all time, from `interaction_counts`)
- `is_kev`, `kev_date`
- CVSS fields: `base_score`, `base_severity`, `vector_string`
- `description`, `date_reserved`, `date_published`
- `cwe_names`, separated by `|SEP_CWE_SEP|`

### Caching

Responses are cached in memory for each gunicorn worker. Caching happens **after** authentication, so cached data is never served to unauthenticated requests or revoked tokens. Responses are marked `Cache-Control: private`, so Cloudflare does not store them.

After a data update, restart the backend to clear the cache: `docker compose restart backend`.

## Maintenance

Refresh the materialized views after any data change:

```bash
python manage.py refresh_cache     # ghp_with_time, cve_cvss_max, interaction_counts
```

Data fetchers (`fetch_epss` needs `parallel`: `sudo apt install parallel`):

```bash
python manage.py fetch_cves      # CVE records
python manage.py fetch_pocs      # GitHub PoC repos + star/fork history (needs GITHUB_TOKEN)
python manage.py fetch_epss      # EPSS history
python manage.py fetch_kevs      # KEV catalogs
python manage.py fetch_msf       # Metasploit mappings
python manage.py fetch_nuclei    # Nuclei mappings
python manage.py fetch_ranscve   # Ransomware CVEs
```

`fetch_pocs` stores no user identifiers. On re-runs it adds only stars and forks newer than the latest one already stored for each PoC.
