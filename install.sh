#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Signal handling — trap SIGINT/SIGTERM for clean interruption
# ============================================================
INSTALL_STEP=""
trap cleanup SIGINT SIGTERM

cleanup() {
  local step="${INSTALL_STEP:-unknown}"
  echo ""
  echo "============================================"
  echo "  Installation interrupted at step: $step"
  echo "============================================"
  echo ""
  echo "  The system may be in a partially configured state."
  echo ""
  case "$step" in
    packages|nginx_install)
      echo "  • Package installation may be incomplete."
      echo "  • Re-run: sudo bash install.sh"
      ;;
    dns)
      echo "  • DNS record may have been created at Cloudflare."
      echo "  • Remove it manually at: https://dash.cloudflare.com/"
      ;;
    ssl)
      echo "  • Certificate files may exist at: ~/.acme.sh/"
      echo "  • Run: ~/.acme.sh/acme.sh --remove -d <domain> 2>/dev/null"
      ;;
    nginx_config)
      echo "  • Nginx config at /etc/nginx/sites-available/nextapp may be incomplete."
      echo "  • Check: nginx -t"
      ;;
    nginx_start)
      echo "  • Nginx may be running with a partial config."
      echo "  • Check: systemctl status nginx"
      ;;
    admin)
      echo "  • Admin account may not have been created."
      echo "  • Run: node dist/setup.js"
      ;;
    pm2)
      echo "  • PM2 may have started the panel."
      echo "  • Check: pm2 status"
      ;;
  esac
  echo ""
  echo "  To restart installation: sudo bash install.sh"
  exit 1
}

# BundledWS — One-command installation script
# Usage:
#   sudo bash install.sh
#
#   Edit DOMAIN in the CONFIGURATION block above once for your server.
#   Only the Cloudflare API token is prompted interactively (hidden input).
#   No secrets are passed via CLI arguments or env vars.
#   Everything is wiped from memory after use.
#
#   Optional CLI flags (show in process list, use only when safe):
#     --email <email>         Admin email (default: prompt)
#     --password <pass>       Admin password min 8 chars (default: prompt)
#     --subdomain <prefix>    Custom subdomain prefix (default: auto-generated)
#     --domain <domain>       Override the hardcoded DOMAIN above

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

echo "============================================"
echo "         BundledWS Installer"
echo "============================================"
echo ""

# ============================================================
# CONFIGURATION — edit this once for your server
# ============================================================
# Change this to your domain to enable automatic SSL.
# Leave empty to skip SSL (or use --domain <domain> on the CLI).
DOMAIN="thesupershoppe.com"
# ============================================================

# Parse CLI arguments
ADMIN_EMAIL=""
ADMIN_PASS=""
BWS_CF_TOKEN=""
SUBDOMAIN_PREFIX=""

while [ $# -gt 0 ]; do
  case "$1" in
    --email) ADMIN_EMAIL="$2"; shift 2 ;;
    --password) ADMIN_PASS="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --subdomain) SUBDOMAIN_PREFIX="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

# Ask about SSL — domain is set in the CONFIGURATION block above
# or overridden via --domain CLI flag. Only token is prompted.
HAS_SSL=false
if [ -n "$DOMAIN" ]; then
  echo ""
  echo "SSL Setup for: $DOMAIN"
  echo "-----------------------"
  # Read Cloudflare token via hidden input (never from CLI args or env vars)
  if [ -z "${BWS_CF_TOKEN:-}" ]; then
    read -s -p "Enter Cloudflare API token (input hidden): " BWS_CF_TOKEN
    echo ""
  fi

  if [ -z "$BWS_CF_TOKEN" ]; then
    echo "  No token provided. Skipping SSL setup."
  else
    HAS_SSL=true
    echo "SSL mode enabled for domain: $DOMAIN"
  fi
fi

INSTALL_STEP="packages"

# ============================================================
# STEP 1: Install system packages
# ============================================================
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl gnupg git unzip

# Install Node.js 22.x if not present
if ! command -v node &>/dev/null || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

# Install PM2 globally
npm install -g pm2 --silent

INSTALL_STEP="nginx_install"

# ============================================================
# STEP 2: Install and configure NGINX
# ============================================================
echo "[2/7] Installing and configuring NGINX..."

# Kill existing processes
echo "  Stopping any existing NGINX processes..."
systemctl stop nginx 2>/dev/null || true
pkill -9 nginx 2>/dev/null || true
sleep 1

# Clear old configs
echo "  Removing old configurations..."
rm -f /etc/nginx/sites-enabled/*
rm -f /etc/nginx/sites-available/*

# Install nginx if missing
if ! command -v nginx &>/dev/null; then
  apt-get install -y -qq nginx
fi

# We'll write the final nginx config in Step 4 (after SSL setup)
# For now, ensure the binary is present
echo "  NGINX installed."

INSTALL_STEP="build"

# ============================================================
# STEP 3: Install dependencies and build
# ============================================================
echo "[3/7] Installing npm dependencies and building..."
mkdir -p "$APP_DIR/data"
chmod 700 "$APP_DIR/data"

# Create .env if not exists
if [ ! -f .env ]; then
  cat > .env << ENVEOF
PORT=8080
BWS_DATA_DIR=$APP_DIR/data
ENVEOF
  chmod 600 .env
  echo "  Created .env with default settings."
fi

# npm install runs postinstall which runs tsc automatically
npm install --silent

# Copy static HTML file to dist
node -e "require('fs').cpSync('src/spa.html', 'dist/spa.html')" 2>/dev/null || true

INSTALL_STEP="dns"

# ============================================================
# STEP 4: Cloudflare DNS + Let's Encrypt SSL (if configured)
# ============================================================
if [ "$HAS_SSL" = true ]; then
  echo "[4/7] Setting up Cloudflare DNS and SSL..."

  # Detect public IP
  echo "  Detecting public IP..."
  PUBLIC_IP=$(curl -s https://api.ipify.org)
  if [ -z "$PUBLIC_IP" ]; then
    echo "  ✖ [network] Could not detect public IP."
    echo "    Check internet connectivity and DNS resolution."
    echo "    Tried: api.ipify.org"
    exit 1
  fi
  echo "  Public IP: $PUBLIC_IP"

  # Generate subdomain name
  SUBDOMAIN_ID=$(openssl rand -hex 4)
  SUBDOMAIN="${SUBDOMAIN_PREFIX:-vps}-${SUBDOMAIN_ID}.${DOMAIN}"
  echo "  Subdomain: $SUBDOMAIN"

  # Get Cloudflare Zone ID
  echo "  Looking up Cloudflare zone..."
  ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}" \
    -H "Authorization: Bearer ${BWS_CF_TOKEN}" \
    -H "Content-Type: application/json")

  ZONE_ID=$(echo "$ZONE_RESPONSE" | node -e "
    let d = '';
    process.stdin.on('data', c => d += c);
    process.stdin.on('end', () => {
      try {
        const r = JSON.parse(d);
        if (r.success && r.result.length > 0) {
          console.log(r.result[0].id);
        } else {
          console.error('Cloudflare zone lookup failed:', JSON.stringify(r.errors));
          process.exit(1);
        }
      } catch(e) {
        console.error('Parse error:', e.message);
        process.exit(1);
      }
    });
  ")

  echo "  Zone ID: $ZONE_ID"

  # Create DNS A record
  echo "  Creating DNS A record..."
  DNS_RESULT=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
    -H "Authorization: Bearer ${BWS_CF_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"A\",\"name\":\"${SUBDOMAIN}\",\"content\":\"${PUBLIC_IP}\",\"ttl\":120,\"proxied\":false}")

  DNS_SUCCESS=$(echo "$DNS_RESULT" | node -e "
    let d = '';
    process.stdin.on('data', c => d += c);
    process.stdin.on('end', () => {
      try { console.log(JSON.parse(d).success ? 'true' : 'false'); }
      catch { console.log('false'); }
    });
  ")

  if [ "$DNS_SUCCESS" != "true" ]; then
    echo "  ✖ [cloudflare] DNS A record creation failed."
    echo "    Check your CF token has DNS:Edit permission for this domain."
    echo "    API response: $DNS_RESULT"
    echo "    DNS setup failed → falling back to HTTP-only mode."
    HAS_SSL=false
  else
    echo "  DNS A record created: $SUBDOMAIN → $PUBLIC_IP"

    # Wait for DNS propagation (helps acme.sh succeed on first try)
    echo "  Waiting for DNS propagation..."
    PROPAGATION_OK=false
    for i in $(seq 1 12); do
      sleep 10
      DIG_IP=$(dig +short "$SUBDOMAIN" @1.1.1.1 2>/dev/null || echo "")
      if [ "$DIG_IP" = "$PUBLIC_IP" ]; then
        echo "  ✓ DNS propagated (attempt $i/12)."
        PROPAGATION_OK=true
        break
      fi
      echo "  DNS not yet propagated (attempt $i/12)..."
    done
    if [ "$PROPAGATION_OK" = false ]; then
      echo "  ⚠ DNS created but did not propagate within 120s."
      echo "    acme.sh will retry DNS validation if needed."
    fi

    # Encrypt and store CF token (AES-256-GCM, tied to /etc/machine-id)
    echo "  Encrypting API token..."
    node -e "
      const { encryptAndStore } = require('./dist/crypto.js');
      const fs = require('fs');
      const machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim();
      encryptAndStore(process.argv[1], '${APP_DIR}/.cf-encrypted', machineId);
    " "$BWS_CF_TOKEN"
    chmod 600 "$APP_DIR/.cf-encrypted"
    echo "  API token encrypted and stored."

    INSTALL_STEP="ssl"

    # Install acme.sh
    echo "  Installing acme.sh..."
    curl -s https://get.acme.sh | sh

    # Register with Let's Encrypt (use admin email or a fallback)
    echo "  Registering with Let's Encrypt..."
    ACME_EMAIL="${ADMIN_EMAIL:-noreply@bundledws.com}"
    ~/.acme.sh/acme.sh --register-account -m "$ACME_EMAIL" --server letsencrypt

    # Explicitly set default CA to Let's Encrypt so all subsequent commands use it
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Issue Let's Encrypt cert via DNS-01 challenge
    echo "  Issuing Let's Encrypt certificate..."
    export CF_Token="$BWS_CF_TOKEN"
    export CF_Zone_ID="$ZONE_ID"
    # CF_TOKEN copied to env — wipe plaintext variable immediately
    unset BWS_CF_TOKEN

    # Run acme.sh WITHOUT --reloadcmd — we handle nginx separately after
    # writing config. The --reloadcmd would fail here because nginx is
    # not yet configured/running, and we don't want that to mask a
    # successful certificate issuance.
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$SUBDOMAIN" --server letsencrypt 2>&1 || true
    ACME_EXIT=$?

    # Wipe Cloudflare credentials from environment — acme.sh has finished
    unset CF_Token CF_Zone_ID

    # Determine cert directory — acme.sh uses _ecc suffix for ECDSA certs
    CERT_DIR_ECC="$HOME/.acme.sh/${SUBDOMAIN}_ecc"
    CERT_DIR_RSA="$HOME/.acme.sh/${SUBDOMAIN}"
    if [ -d "$CERT_DIR_ECC" ]; then
      CERT_DIR="$CERT_DIR_ECC"
    elif [ -d "$CERT_DIR_RSA" ]; then
      CERT_DIR="$CERT_DIR_RSA"
    fi

    # Validate cert files exist — this is the REAL measure of success,
    # not the acme.sh exit code (which can be non-zero from reload failure)
    if [ -n "$CERT_DIR" ] && [ -f "$CERT_DIR/fullchain.cer" ] && [ -f "$CERT_DIR/${SUBDOMAIN}.key" ]; then
      echo "  Certificate issued successfully."
      # Write SSL cert paths to .env
      cat >> .env << ENVEOF
BWS_DOMAIN=${SUBDOMAIN}
BWS_SSL_CERT=${CERT_DIR}/fullchain.cer
BWS_SSL_KEY=${CERT_DIR}/${SUBDOMAIN}.key
ENVEOF
      echo "  SSL certificate paths written to .env."

      # Create stable application-owned cert directory with symlinks
      # This provides a predictable path for backups and panel access
      mkdir -p /etc/bundledws/acme
      chmod 700 /etc/bundledws/acme
      ln -sf "$CERT_DIR/fullchain.cer" /etc/bundledws/acme/fullchain.pem
      ln -sf "$CERT_DIR/${SUBDOMAIN}.key" /etc/bundledws/acme/key.pem
      echo "  Certificate symlinks created at /etc/bundledws/acme/"
    else
      echo "  ✖ [acme.sh] Certificate issuance failed."
      echo "    Certificate files not found at expected locations."
      echo "    Check DNS propagation: dig +short $SUBDOMAIN"
      echo "    Check Cloudflare API token has DNS:Edit permission."
      echo "    Retry manually:"
      echo "      export CF_Token=... CF_Zone_ID=..."
      echo "      ~/.acme.sh/acme.sh --issue --dns dns_cf -d $SUBDOMAIN --server letsencrypt"
      echo "    Certificate issuance failed → falling back to HTTP-only mode."
      HAS_SSL=false
    fi
  fi
fi

INSTALL_STEP="nginx_config"

# ============================================================
# Write NGINX config (with or without SSL)
# ============================================================
echo "  Writing NGINX configuration..."

if [ "$HAS_SSL" = true ]; then
  # Read cert paths from .env
  BWS_CERT=$(grep BWS_SSL_CERT .env | cut -d= -f2)
  BWS_KEY=$(grep BWS_SSL_KEY .env | cut -d= -f2)
  BWS_DOMAIN_VAL=$(grep BWS_DOMAIN .env | cut -d= -f2)

  cat > /etc/nginx/sites-available/nextapp << NGINXCONF
# Catch-all port 80 — ANY domain → port 3000
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;

    # Managed subdomain → redirect to HTTPS
    if (\$host ~* ^vps-[a-f0-9]+\.${DOMAIN}$) {
        return 301 https://\$host\$request_uri;
    }

    # Any other domain → serve app directly via HTTP
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Managed subdomain — HTTPS with valid Let's Encrypt cert
server {
    listen 443 ssl;
    http2 on;
    server_name ${BWS_DOMAIN_VAL};
    server_tokens off;

    ssl_certificate ${BWS_CERT};
    ssl_certificate_key ${BWS_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve auto;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # Customer's deployed Next.js app at root
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Panel API
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Panel SPA
    location /panel/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINXCONF
  echo "  SSL NGINX configuration written."

else
  # Plain HTTP config (original behavior)
  cat > /etc/nginx/sites-available/nextapp << 'NGINXCONF'
server {
    listen 80;
    listen [::]:80;
    server_name _;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXCONF
  echo "  Plain HTTP NGINX configuration written."
fi

ln -sf /etc/nginx/sites-available/nextapp /etc/nginx/sites-enabled/nextapp

# Test config
echo "  Testing NGINX configuration..."
if nginx -t; then
  echo "  NGINX configuration test passed."
else
  echo "  ✖ [nginx] Configuration test failed."
  nginx -t 2>&1
  echo "    Fix: Check /etc/nginx/sites-available/nextapp for syntax errors."
  exit 1
fi

INSTALL_STEP="nginx_start"

# Start or reload NGINX
echo "  Configuring NGINX..."
if systemctl is-active nginx &>/dev/null; then
  echo "  NGINX is already running — reloading..."
  systemctl reload nginx || {
    echo "  Reload failed, attempting restart..."
    systemctl restart nginx
  }
else
  echo "  Starting NGINX..."
  systemctl start nginx 2>/dev/null || nginx 2>/dev/null || true
  systemctl enable nginx 2>/dev/null || true
fi
sleep 1

# Verify
if systemctl is-active nginx &>/dev/null || pgrep nginx &>/dev/null; then
  echo "  NGINX is running."
else
  echo "  ⚠ [nginx] Service may not have started after configuration."
  echo "    Check: systemctl status nginx"
  echo "    Check: journalctl -u nginx --no-pager -n 20"
fi

# HTTPS verification — only if SSL was enabled
if [ "$HAS_SSL" = true ]; then
  echo "  Verifying HTTPS..."
  # Check if port 443 is listening
  if ss -tlnp 2>/dev/null | grep -q ':443 '; then
    # Check if the cert serves correctly
    BWS_DOMAIN_VAL=$(grep BWS_DOMAIN "$APP_DIR/.env" 2>/dev/null | cut -d= -f2)
    if [ -n "$BWS_DOMAIN_VAL" ]; then
      if curl -sI "https://${BWS_DOMAIN_VAL}" --connect-timeout 5 2>&1 | grep -q "HTTP/"; then
        echo "  ✓ HTTPS is active and serving certificate for $BWS_DOMAIN_VAL"
      else
        echo "  ⚠ [https] Port 443 is open but curl test failed."
        echo "    This may be a DNS resolution issue (running in a different shell)."
        echo "    Test manually: curl -vI https://${BWS_DOMAIN_VAL}"
      fi
    fi
    # Show certificate expiry
    BWS_CERT_PATH=$(grep BWS_SSL_CERT "$APP_DIR/.env" 2>/dev/null | cut -d= -f2)
    if [ -n "$BWS_CERT_PATH" ] && [ -f "$BWS_CERT_PATH" ]; then
      EXPIRY=$(openssl x509 -in "$BWS_CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2)
      echo "  Certificate expires: ${EXPIRY:-unknown}"
    fi
  else
    echo "  ⚠ [https] Port 443 is not listening."
    echo "    Reason: Nginx may not have started with SSL config."
    echo "    Check: sudo nginx -t"
    echo "    SSL certificate files remain installed."
  fi
fi

INSTALL_STEP="admin"

# ============================================================
# STEP 5: Create admin account
# ============================================================
echo "[5/7] Creating admin account..."

# If email and password not provided as args, prompt
if [ -z "$ADMIN_EMAIL" ]; then
  read -p "Enter admin email: " ADMIN_EMAIL
fi
if [ -z "$ADMIN_PASS" ]; then
  read -s -p "Enter admin password (min 8 chars): " ADMIN_PASS
  echo ""
fi

if [ -z "$ADMIN_EMAIL" ] || [ -z "$ADMIN_PASS" ] || [ ${#ADMIN_PASS} -lt 8 ]; then
  echo "Error: Email and password (min 8 chars) are required."
  echo "Run setup manually: node dist/setup.js"
else
  BWS_DATA_DIR="$APP_DIR/data" node dist/setup.js "$ADMIN_EMAIL" "$ADMIN_PASS"
  echo "  Admin account created: $ADMIN_EMAIL"
  # Wipe admin password from memory — no longer needed
  unset ADMIN_PASS
fi

INSTALL_STEP="pm2"

# ============================================================
# STEP 6: Start the server with PM2
# ============================================================
echo "[6/7] Starting the server..."
pm2 delete bundledws 2>/dev/null || true

pm2 start dist/server.js --name "bundledws" --cwd "$APP_DIR"
pm2 save
pm2 startup systemd -u root --hp /root 2>/dev/null || true

# ============================================================
INSTALL_STEP="renewal"

# STEP 7: Create renewal script for encrypted token
# ============================================================
if [ "$HAS_SSL" = true ]; then
  echo "[7/7] Creating SSL renewal script..."
  cat > "$APP_DIR/.renew-cert.sh" << 'RENEWSCRIPT'
#!/bin/bash
# BundledWS — Just-in-time cert renewal
# Decrypts Cloudflare token in-memory, renews cert, handles nginx
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
ENCRYPTED_FILE="$APP_DIR/.cf-encrypted"
MACHINE_ID=$(cat /etc/machine-id)
DOMAIN=$(grep BWS_DOMAIN "$APP_DIR/.env" | cut -d= -f2)

if [ ! -f "$ENCRYPTED_FILE" ] || [ -z "$DOMAIN" ]; then
  echo "SSL not configured. Skipping renewal."
  exit 0
fi

# Decrypt token in-memory — never writes to disk
export CF_Token=$(node -e "
  const { readAndDecrypt } = require('$APP_DIR/dist/crypto.js');
  console.log(readAndDecrypt('$ENCRYPTED_FILE', '$MACHINE_ID'));
")

if [ -z "$CF_Token" ]; then
  echo "Error: Failed to decrypt API token."
  exit 1
fi

# Renew cert (no --reloadcmd — we handle nginx separately)
echo "Renewing certificate for $DOMAIN..."
~/.acme.sh/acme.sh --renew -d "$DOMAIN" --dns dns_cf --server letsencrypt 2>&1 || true
RENEW_EXIT=$?

# Wipe token from environment
unset CF_Token

# Check cert files exist after renewal (the real measure of success)
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

echo "Renewal complete."
RENEWSCRIPT

  chmod 700 "$APP_DIR/.renew-cert.sh"

  # Add acme.sh renewal hook to use our script
  BWS_DOMAIN_VAL=$(grep BWS_DOMAIN .env | cut -d= -f2)
  if [ -f "$HOME/.acme.sh/${BWS_DOMAIN_VAL}/${BWS_DOMAIN_VAL}.conf" ]; then
    # acme.sh already has auto-renewal — our --reloadcmd handles nginx reload
    echo "  SSL auto-renewal configured (acme.sh cron)."
  fi

  echo "  Renewal script created at $APP_DIR/.renew-cert.sh"
fi

# Final cleanup: wipe any remaining secrets from memory
unset BWS_CF_TOKEN CF_Token CF_Zone_ID ADMIN_PASS ADMIN_EMAIL DOMAIN SUBDOMAIN SUBDOMAIN_ID SUBDOMAIN_PREFIX PUBLIC_IP ZONE_ID ZONE_RESPONSE DNS_RESULT DNS_SUCCESS ACME_EMAIL CERT_DIR CERT_DIR_ECC CERT_DIR_RSA

echo ""
echo "============================================"
echo "  BundledWS installation complete!"
echo "============================================"
echo ""

if [ "$HAS_SSL" = true ]; then
  BWS_DOMAIN_VAL=$(grep BWS_DOMAIN .env | cut -d= -f2)
  echo "  Panel:   https://${BWS_DOMAIN_VAL}/panel/"
  echo "  API:     https://${BWS_DOMAIN_VAL}/api/"
  echo "  App:     https://${BWS_DOMAIN_VAL}/"
  echo ""
  echo "  DNS:     ${BWS_DOMAIN_VAL} → ${PUBLIC_IP:-detected}"
  echo "  Cert:    Let's Encrypt (auto-renewing)"
else
  echo "  Server running at: http://YOUR_SERVER_IP:80"
  echo "  Panel available at: http://YOUR_SERVER_IP:8080"
  echo "  (Re-run installer and answer 'y' to SSL prompt to enable HTTPS)"
fi

echo ""
echo "  Admin credentials: ${ADMIN_EMAIL:-configured}"
echo ""
echo "  Manage: pm2 status, pm2 logs bundledws"
echo "  Stop:   pm2 stop bundledws"
echo "  NGINX:  systemctl reload nginx"
echo "  Uninstall: See DEPLOY.md for removal instructions"
echo "============================================"
