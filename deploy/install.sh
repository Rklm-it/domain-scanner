#!/usr/bin/env bash
# Bare-metal install on a fresh Debian/Ubuntu VPS (no Docker).
#   curl -fsSL <raw-url>/deploy/install.sh | sudo bash
# or, from a clone:  sudo ./deploy/install.sh
set -euo pipefail

APP_DIR=/opt/domain-scanner
REPO="${REPO:-}"

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo $0)" >&2
  exit 1
fi

echo "==> installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git nginx curl

echo "==> creating service user"
id -u scanner &>/dev/null || useradd --system --create-home --home-dir /var/lib/scanner scanner

echo "==> placing the application in $APP_DIR"
if [[ -n "$REPO" && ! -d "$APP_DIR/.git" ]]; then
  git clone "$REPO" "$APP_DIR"
elif [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" pull --ff-only
else
  # Running from a clone: copy this checkout into place.
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  mkdir -p "$APP_DIR"
  cp -r "$SRC"/. "$APP_DIR"/
fi

echo "==> python environment"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements-web.txt"
"$APP_DIR/.venv/bin/pip" install --quiet --no-deps -e "$APP_DIR"

echo "==> configuration"
mkdir -p "$APP_DIR/data"
if [[ ! -f "$APP_DIR/.env" ]]; then
  TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  # A generated token beats a blank one nobody remembers to fill in.
  sed -i "s|^SCANNER_TOKEN=.*|SCANNER_TOKEN=$TOKEN|" "$APP_DIR/.env"
  sed -i "s|^SCANNER_TRUST_PROXY=.*|SCANNER_TRUST_PROXY=1|" "$APP_DIR/.env"
  echo
  echo "    ACCESS TOKEN: $TOKEN"
  echo "    (also stored in $APP_DIR/.env)"
  echo
fi
chown -R scanner:scanner "$APP_DIR"
chmod 600 "$APP_DIR/.env"

echo "==> systemd service"
cp "$APP_DIR/deploy/domain-scanner.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now domain-scanner

sleep 2
if curl -fsS http://127.0.0.1:8000/api/health >/dev/null; then
  echo "==> service is up on 127.0.0.1:8000"
else
  echo "!! service did not answer; check: journalctl -u domain-scanner -n 50" >&2
  exit 1
fi

cat <<'NEXT'

Next, to put it on a domain with TLS:

  1. Point an A record at this server.
  2. sudo cp /opt/domain-scanner/deploy/nginx.conf \
       /etc/nginx/sites-available/domain-scanner
     sudo sed -i 's/scanner.example.com/YOUR.DOMAIN/g' \
       /etc/nginx/sites-available/domain-scanner
     sudo ln -sf /etc/nginx/sites-available/domain-scanner \
       /etc/nginx/sites-enabled/
  3. sudo apt install -y certbot python3-certbot-nginx
     sudo certbot --nginx -d YOUR.DOMAIN
  4. sudo nginx -t && sudo systemctl reload nginx

Do not open port 8000 in the firewall: nginx reaches it over loopback.
NEXT
