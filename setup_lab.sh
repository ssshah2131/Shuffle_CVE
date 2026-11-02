#!/usr/bin/env bash
# One-shot lab for reproducing the Shuffle on-prem OpenID id_token authentication bypass.
#
# What it does:
#   1. Downloads the official Shuffle v2.3.0 docker-compose.yml + .env from GitHub
#   2. Pins the backend image to ghcr.io/shuffle/shuffle-backend:2.3.0
#   3. Starts only what's needed: OpenSearch + backend (API on :5001)
#   4. Registers the first (admin) user, exactly as a new installation does
#   5. Configures OpenID Connect SSO for the org, exactly as an admin does
#      (the IdP URLs are placeholders - no real IdP is needed or contacted)
#
# Requirements: Linux, docker + docker compose plugin, curl, python3, ~4 GB free RAM.
# Usage:        bash setup_lab.sh            (normal mode: no client_secret)
#               SECRET=mysecret bash setup_lab.sh   (also set an OpenID client_secret)
set -euo pipefail

LAB_DIR="${LAB_DIR:-$PWD/shuffle-lab}"
B="http://localhost:5001"
ADMIN_EMAIL="admin@victim.local"
ADMIN_PASS="VictimAdminPass123!"
CLIENT_ID="shuffle-sso-client"
SECRET="${SECRET:-}"

mkdir -p "$LAB_DIR" && cd "$LAB_DIR"
echo "[*] Fetching official Shuffle v2.3.0 deployment files"
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/docker-compose.yml
curl -fsSLo .env               https://raw.githubusercontent.com/Shuffle/Shuffle/v2.3.0/.env
sed -i 's#shuffle-backend:latest#shuffle-backend:2.3.0#; s/-Xms3072m -Xmx3072m/-Xms1024m -Xmx1024m/' docker-compose.yml
mkdir -p shuffle-database shuffle-files && chmod 777 shuffle-database
sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true   # OpenSearch requirement

echo "[*] Starting OpenSearch + Shuffle backend 2.3.0"
docker compose up -d opensearch backend

echo -n "[*] Waiting for backend API"
for _ in $(seq 1 60); do
  curl -s -m3 "$B/api/v1/checkusers" | grep -q success && break
  echo -n "."; sleep 5
done; echo

echo "[*] Registering first admin user: $ADMIN_EMAIL"
APIKEY=$(curl -s -X POST "$B/api/v1/register" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" |
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("apikey",""))')
[ -n "$APIKEY" ] || { echo "[-] register failed (lab already initialised? run: docker compose down -v && rm -rf $LAB_DIR)"; exit 1; }

ORG=$(curl -s "$B/api/v1/getinfo" -H "Authorization: Bearer $APIKEY" |
  python3 -c 'import sys,json;print(json.load(sys.stdin)["active_org"]["id"])')
echo "[+] Org id: $ORG"

echo "[*] Enabling OpenID Connect SSO on the org (admin action)"
curl -s -X POST "$B/api/v1/orgs/$ORG" -H "Authorization: Bearer $APIKEY" -H 'Content-Type: application/json' \
  -d "{\"org_id\":\"$ORG\",\"editing\":\"sso_config\",\"sso_config\":{\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$SECRET\",\"openid_authorization\":\"https://idp.example.com/oauth2/authorize\",\"openid_token\":\"https://idp.example.com/oauth2/token\"}}"
echo

cat <<EOF

[+] Lab ready.
    Backend API      : $B
    Victim admin     : $ADMIN_EMAIL / $ADMIN_PASS   (attacker does NOT know this password)
    OpenID client_id : $CLIENT_ID

Now run the exploit (unauthenticated):
    python3 shuffle_openid_takeover.py --url $B --email $ADMIN_EMAIL          # take over existing admin
    python3 shuffle_openid_takeover.py --url $B --email attacker@evil.example # create a NEW rogue admin

Tear down:  cd $LAB_DIR && docker compose down -v && cd .. && sudo rm -rf $LAB_DIR
EOF
