# Deploying BundledWS on a Linux VPS

## Prerequisites

- Ubuntu 22.04+ VPS (or any Linux with systemd)
- Root/sudo access
- A Supabase PostgreSQL database (or any PostgreSQL)

## Quick Install (One Command)

```bash
# On your VPS as root:
curl -fsSL https://your-server/install.sh | sudo bash
```

Or if you have the files:

```bash
sudo bash install.sh
```

The installer will:
1. Install Node.js 22, npm, git, nginx, unzip
2. Install PM2 globally
3. Copy all files to `/opt/bundledws`
4. Install npm dependencies
5. Generate Prisma client and push schema to Supabase
6. Prompt for admin email and password
7. Create a systemd service for auto-start
8. Configure nginx on port 80 as a reverse proxy
9. Start the server

After installation, visit `http://YOUR_SERVER_IP` and sign in.

## Manual Setup

### 1. Prepare the VPS

```bash
# Install dependencies
sudo apt update
sudo apt install -y curl gnupg git nginx unzip

# Install Node.js 22
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
sudo apt install -y nodejs

# Install PM2
sudo npm install -g pm2
```

### 2. Configure Environment

```bash
# Navigate to the application directory
cd /opt/bundledws

# Edit .env with your Supabase credentials
# The default .env already has your Supabase connection configured
# Change the DATABASE_URL if using a different database
```

Your `.env` file:
```env
# PostgreSQL Database URL (Supabase)
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.xcbghbmmtirybccfrypv.supabase.co:5432/postgres

# Server port
PORT=8080
```

### 3. Build and Initialize

```bash
# Install dependencies
npm install

# Generate Prisma client
npx prisma generate

# Push schema to database (creates tables)
npx prisma db push

# Build TypeScript
npx tsc

# Create admin account (interactive)
node dist/setup.js
```

### 4. Start the Server

```bash
# Direct start
node dist/server.js

# Or with PM2 (recommended for production)
pm2 start dist/server.js --name bundledws

# Save PM2 process list for auto-restart
pm2 save
pm2 startup
```

### 5. Configure Nginx (Optional)

The server runs on port 8080. To serve on port 80 with nginx:

```bash
sudo cat > /etc/nginx/sites-available/bundledws << 'EOF'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:8080;
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
EOF

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/bundledws /etc/nginx/sites-enabled/bundledws
sudo nginx -t && sudo systemctl reload nginx
```

### 6. Set Up systemd (Alternative to PM2)

```bash
sudo cat > /etc/systemd/system/bundledws.service << 'EOF'
[Unit]
Description=BundledWS Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/bundledws
ExecStart=/usr/bin/node /opt/bundledws/dist/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable bundledws
sudo systemctl start bundledws
```

## Verification

```bash
# Check server is running
curl http://127.0.0.1:8080/api/check-setup

# Expected response: {"setup":false} (if admin created) or {"setup":true} (if fresh install)

# View logs
journalctl -u bundledws -f   # If using systemd
pm2 logs bundledws            # If using PM2
```

## Security Checklist

- [ ] `.env` file has correct permissions: `chmod 600 .env`
- [ ] Database password is changed from default
- [ ] HTTPS is configured (use Let's Encrypt with `certbot`)
- [ ] Firewall allows only ports 22, 80, 443 (and 8080 if needed)
- [ ] Admin password is strong (min 8 chars, mixed case + numbers)
- [ ] Regular backups of the database are configured

## Updating

```bash
cd /opt/bundledws
git pull                  # Or copy new files
npm install               # Update dependencies
npx prisma generate       # Update Prisma client
npx tsc                   # Rebuild TypeScript
pm2 restart bundledws     # Restart the server
```

## Architecture

```
Internet → Port 80 (nginx) → Port 8080 (BundledWS server)
                ↓                    ↓
         Static files,         API routes,
         reverse proxy         SPA GUI,
                               Git/Zip deploy,
                               PM2 management,
                               Nginx config

Database → Supabase PostgreSQL
```

The server is a single Node.js process that handles:
- HTTP API (all `/api/*` routes)
- Web GUI (vanilla JS single-page application)
- Deploy engine (git clone, zip extract, npm install, build)
- Process management (PM2 start/stop/restart)
- Nginx configuration (domain setup, reverse proxy)

No separate frontend build step. No database other than Supabase PostgreSQL.