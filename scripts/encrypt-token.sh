#!/bin/bash
# BundledWS — Encrypt Cloudflare API Token
# Encrypts a token using AES-256-GCM, tied to the VPS machine ID.
# Usage: ./encrypt-token.sh <token> [output-path]
#   token:       Cloudflare API token with DNS:Edit permission
#   output-path: Where to write encrypted blob (default: /opt/bundledws/.cf-encrypted)
set -euo pipefail

TOKEN="${1:?Usage: encrypt-token.sh <token> [output-path]}"
OUTPUT="${2:-/opt/bundledws/.cf-encrypted}"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -f /etc/machine-id ]; then
  echo "Error: /etc/machine-id not found. Cannot derive encryption key."
  exit 1
fi

MACHINE_ID=$(cat /etc/machine-id)

# Use the compiled crypto module
node -e "
  const { encryptAndStore } = require('${APP_DIR}/dist/crypto.js');
  encryptAndStore(process.env.TOKEN, '${OUTPUT}', '${MACHINE_ID}');
"

chmod 600 "$OUTPUT"
echo "Token encrypted and stored at: $OUTPUT"
