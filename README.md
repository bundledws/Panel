# BundledWS

Single-instance Node.js hosting platform. Deploy apps via Git or zip upload with one command.

## Quick Install

```bash
# On a fresh Ubuntu 22.04+ VPS as root:
sudo bash install.sh
```

The installer will:
1. Install Node.js 22, npm, git, nginx, pm2, unzip
2. Set up the application in `/opt/bundledws`
3. Connect to Supabase PostgreSQL
4. Prompt for admin email and password
5. Create a systemd service that auto-starts on boot
6. Configure nginx as a reverse proxy on port 80

After installation, visit `http://YOUR_SERVER_IP` and sign in.

## Manual Start

```bash
cd /opt/bundledws
node dist/setup.js   # Create admin account (first time only)
node dist/server.js  # Start on port 8080
```

## Features

- **Dashboard**: Real-time app status, deployment history
- **Deploy via Git**: Paste a repo URL, select branch, optional build command
- **Deploy via Zip**: Upload a zip file, extract, install, build
- **Services**: Start/stop/restart your app, view logs
- **Environment Variables**: Set and manage env vars
- **Domain**: Configure custom domains with nginx reverse proxy
- **Security**: Rate limiting, scrypt password hashing, HTTP-only cookies

## Architecture

BundledWS is a single Node.js process that serves both the API and the web GUI on port 8080. It uses:
- **Supabase PostgreSQL** for data storage
- **PM2** for process management of deployed apps
- **Nginx** for reverse proxy and domain handling
- **Prisma** for database access

## File Structure

```
/opt/bundledws/
├── src/
│   ├── server.ts      # HTTP server with all API routes
│   ├── spa.ts         # Single-page web GUI (vanilla JS)
│   ├── control-plane.ts # Database operations
│   ├── auth.ts        # Password hashing, session management
│   ├── deploy.ts      # Git clone, zip extract, PM2 lifecycle
│   ├── nginx.ts       # Nginx config generation and management
│   ├── upload.ts      # Multipart form-data parser
│   ├── env.ts         # Environment variable helpers
│   └── setup.ts       # Interactive admin setup script
├── prisma/
│   └── schema.prisma  # Database schema
├── dist/              # Compiled JavaScript
└── install.sh         # One-command installer