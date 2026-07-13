#!/bin/bash
# BundledWS — Renew SSL Certificate
# Decrypts Cloudflare API token just-in-time, renews Let's Encrypt cert,
# and reloads nginx. The token is never written to disk in plaintext.
#
# Usage: ./renew-cert.sh
# Runs as a cron job (acme.sh auto-renewal hook).
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENCRYPTED_FILE="${APP_DIR}/.cf-encrypted"
ENV_FILE="${APP_DIR}/.env"

if [ ! -f "$ENCRYPTED_FILE" ] || [ ! -f "$ENV_FILE" ]; then
  echo "SSL not configured. Skipping renewal."
  exit 0
fi

# Read domain from .env
DOMAIN=$(grep BWS_DOMAIN "$ENV_FILE" | cut -d= -f2)
if [ -z "$DOMAIN" ]; then
  echo "BWS_DOMAIN not set in .env. Skipping."
  exit 0
fi

MACHINE_ID=$(cat /etc/machine-id)
if [ -z "$MACHINE_ID" ]; then
  echo "Error: Cannot read /etc/machine-id"
  exit 1
fi

# Decrypt token in-memory — never touches a file
export CF_Token=$(node -e "
  const { readAndDecrypt } = require('${APP_DIR}/dist/crypto.js');
  console.log(readAndDecrypt('${ENCRYPTED_FILE}', '${MACHINE_ID}'));
")

if [ -z "$CF_Token" ]; then
  echo "Error: Failed to decrypt API token."
  exit 1
fi

# Run acme.sh renewal (no --reloadcmd — handle nginx separately)
echo "Renewing certificate for $DOMAIN..."
~/.acme.sh/acme.sh --renew -d "$DOMAIN" --dns dns_cf --server letsencrypt 2>&1 || true
RENEW_EXIT=$?

# Wipe token from environment
unset CF_Token

# Check cert files still exist after renewal
CERT_DIR_ECC="$HOME/.acme.sh/${DOMAIN}_ecc"
CERT_DIR_RSA="$HOME/.acme.sh/${DOMAIN}"
if [ -d "$CERT_DIR_ECC" ] && [ -f "$CERT_DIR_ECC/fullchain.cer" ]; then
  echo "Certificate renewed successfully."
elif [ -d "$CERT_DIR_RSA" ] && [ -f "$CERT_DIR_RSA/fullchain.cer" ]; then
  echo "Certificate renewed successfully."
else
  echo "ERROR: Certificate renewal failed."
  echo "Check: ~/.acme.sh/acme.sh --renew -d $DOMAIN --dns dns_cf --server letsencrypt"
  exit 1
fi

# Reload or start nginx with the new certificate
if systemctl is-active nginx &>/dev/null; then
  echo "Reloading nginx..."
  systemctl reload nginx || {
    echo "Reload failed, attempting restart..."
    systemctl restart nginx
  }
else
  echo "Nginx is not running. Starting nginx..."
  systemctl start nginx 2>/dev/null || nginx 2>/dev/null || true
fi

echo "Certificate renewal complete."
