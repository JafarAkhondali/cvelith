#!/usr/bin/env bash
# Set up (or update) the stack from a dataset dump. Safe to re-run.
#
#   ./scripts/setup_from_dump.sh [path/to/gpm_dataset.dump]     (default: data/gpm_dataset.dump)
#
# 1. starts the database, 2. restores the dump ONLY if the database is empty,
# 3. builds and starts everything, 4. migrates + refreshes the GPM views.
# Only touches this compose project (COMPOSE_PROJECT_NAME in .env).
set -euo pipefail
cd "$(dirname "$0")/.."

DUMP=${1:-data/gpm_dataset.dump}
[ -f .env ] || { echo "Missing .env (copy env.example and fill it in)"; exit 1; }
[ -f certs/origin.pem ] && [ -f certs/origin.key ] || { echo "Missing certs/origin.pem / certs/origin.key"; exit 1; }

dc() { docker compose "$@"; }
echo "Compose project: $(dc config 2>/dev/null | sed -n 's/^name: //p')"

echo "==> Starting database"
dc up -d --wait db2026ccs

tables=$(dc exec -T db2026ccs sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "select count(*) from information_schema.tables where table_schema='"'"'public'"'"'"')
if [ "$tables" = "0" ]; then
    [ -f "$DUMP" ] || { echo "Database is empty and dump '$DUMP' not found"; exit 1; }
    if [ -f "$(dirname "$DUMP")/SHA256SUMS" ]; then
        echo "==> Verifying dump checksum"
        (cd "$(dirname "$DUMP")" && grep " $(basename "$DUMP")\$" SHA256SUMS | sha256sum -c -)
    fi
    echo "==> Restoring $DUMP (about a minute)"
    dc exec -T db2026ccs sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error' < "$DUMP"
else
    echo "==> Database already has $tables tables; skipping restore"
fi

echo "==> Building and starting all services"
dc up -d --build

echo "==> Migrating and refreshing GPM views"
dc exec -T backend python manage.py migrate --noinput
dc exec -T backend python manage.py refresh_cache

echo "==> Status"
dc ps
echo
echo "Done. Create a login with:  docker compose exec -it backend python manage.py apiuser create <username>"
