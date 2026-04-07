#!/usr/bin/env bash
# SignalTrace setup script
# Supports both Docker and manual installs.
# Run from the root of the SignalTrace repository.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}SignalTrace Setup${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "This script will configure SignalTrace for your environment."
echo "Press Enter to accept defaults where shown."
echo ""

# ── Install type ──────────────────────────────────────────────────────────────
echo -e "${CYAN}Install type${RESET}"
echo "  1) Docker (recommended)"
echo "  2) Manual (Ubuntu + Apache)"
echo ""
read -r -p "  Choice [1]: " INSTALL_TYPE_INPUT
INSTALL_TYPE="${INSTALL_TYPE_INPUT:-1}"
echo ""

if [ "$INSTALL_TYPE" != "1" ] && [ "$INSTALL_TYPE" != "2" ]; then
    echo -e "${RED}Invalid choice. Please enter 1 or 2.${RESET}"
    exit 1
fi

if [ "$INSTALL_TYPE" = "1" ]; then
    OUTPUT_FILE="$SCRIPT_DIR/.env"
else
    OUTPUT_FILE="$SCRIPT_DIR/includes/config.local.php"
fi

# ── Guard: existing config file ───────────────────────────────────────────────
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}Warning: $(basename $OUTPUT_FILE) already exists.${RESET}"
    read -r -p "Overwrite it? [y/N] " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "Aborted. Your existing file was not changed."
        exit 0
    fi
    echo ""
fi

# ── Helper functions ──────────────────────────────────────────────────────────
prompt() {
    local label="$1"
    local var="$2"
    local default="$3"
    local hint="$4"
    local secret="$5"

    echo -e "${CYAN}${label}${RESET}"
    [ -n "$hint" ] && echo -e "  ${hint}"
    if [ -n "$default" ]; then
        if [ "$secret" = "secret" ]; then
            read -r -s -p "  Value [${default}]: " input
            echo ""
        else
            read -r -p "  Value [${default}]: " input
        fi
        eval "$var=\"${input:-$default}\""
    else
        if [ "$secret" = "secret" ]; then
            read -r -s -p "  Value (leave blank to skip): " input
            echo ""
        else
            read -r -p "  Value (leave blank to skip): " input
        fi
        eval "$var=\"${input}\""
    fi
    echo ""
}

generate_hash_php() {
    local password="$1"
    php -r "echo password_hash('${password}', PASSWORD_DEFAULT) . PHP_EOL;"
}

generate_salt() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 64
    else
        php -r "echo bin2hex(random_bytes(64)) . PHP_EOL;"
    fi
}

find_free_port() {
    local port=8080
    while ss -tlnp 2>/dev/null | grep -q ":${port} "; do
        port=$((port + 1))
    done
    echo $port
}

# ── Shared: admin username ────────────────────────────────────────────────────
echo -e "${BOLD}── Admin Credentials ────────────────────────────────────────${RESET}"
echo ""
prompt "Admin username" ADMIN_USERNAME "admin"

# ── Admin password ────────────────────────────────────────────────────────────
echo -e "${CYAN}Admin password${RESET}"
echo "  Enter a password and the script will hash it for you."
read -r -s -p "  Password: " ADMIN_PASSWORD
echo ""

if [ -z "$ADMIN_PASSWORD" ]; then
    echo -e "${RED}Error: password cannot be blank.${RESET}"
    exit 1
fi

DEFER_HASH=false

if [ "$INSTALL_TYPE" = "2" ]; then
    # Manual install always has PHP available
    echo "  Generating bcrypt hash..."
    ADMIN_PASSWORD_HASH=$(generate_hash_php "$ADMIN_PASSWORD")
    echo -e "  ${GREEN}Hash generated.${RESET}"
else
    # Docker — try PHP or Python locally, otherwise defer to container
    if command -v php &>/dev/null; then
        echo "  Generating bcrypt hash..."
        ADMIN_PASSWORD_HASH=$(generate_hash_php "$ADMIN_PASSWORD")
        echo -e "  ${GREEN}Hash generated.${RESET}"
    elif python3 -c "import bcrypt" 2>/dev/null; then
        echo "  Generating bcrypt hash..."
        ADMIN_PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('${ADMIN_PASSWORD}'.encode(), bcrypt.gensalt()).decode())")
        echo -e "  ${GREEN}Hash generated.${RESET}"
    else
        echo -e "  ${YELLOW}PHP not found — hash will be generated from the container after build.${RESET}"
        ADMIN_PASSWORD_HASH="__DEFER__"
        DEFER_HASH=true
    fi
fi
echo ""

# ── Visitor hash salt ─────────────────────────────────────────────────────────
echo -e "${CYAN}Visitor hash salt${RESET}"
echo "  Used to anonymise visitor fingerprints. Leave blank to auto-generate."
read -r -p "  Value (leave blank to auto-generate): " VISITOR_HASH_SALT

if [ -z "$VISITOR_HASH_SALT" ]; then
    echo "  Generating salt..."
    VISITOR_HASH_SALT=$(generate_salt)
    echo -e "  ${GREEN}Salt generated.${RESET}"
fi
echo ""

# ── Docker only: port ─────────────────────────────────────────────────────────
if [ "$INSTALL_TYPE" = "1" ]; then
    echo -e "${BOLD}── Docker Configuration ─────────────────────────────────────${RESET}"
    echo ""

    # If container is running, stop it first so its port is freed for detection
    CONTAINER_WAS_RUNNING=false
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^signaltrace$"; then
        CONTAINER_WAS_RUNNING=true
        echo "  Stopping existing container to free port..."
        docker compose stop 2>/dev/null
        echo ""
    fi

    # Use existing port from .env if present, otherwise find a free one
    EXISTING_PORT=$(grep "^SIGNALTRACE_PORT=" "$OUTPUT_FILE" 2>/dev/null | cut -d= -f2)
    if [ -n "$EXISTING_PORT" ]; then
        SUGGESTED_PORT="$EXISTING_PORT"
    else
        SUGGESTED_PORT=$(find_free_port)
    fi

    echo -e "${CYAN}Host port${RESET}"
    echo "  Which port should SignalTrace listen on?"
    read -r -p "  Port [${SUGGESTED_PORT}]: " PORT_INPUT
    SIGNALTRACE_PORT="${PORT_INPUT:-$SUGGESTED_PORT}"
    echo ""
fi

# ── Shared: GeoIP ─────────────────────────────────────────────────────────────
echo -e "${BOLD}── GeoIP Enrichment (optional but recommended) ──────────────${RESET}"
echo "  Sign up free at https://www.maxmind.com to get these."
echo ""
prompt "MaxMind Account ID" MAXMIND_ACCOUNT_ID "" ""
prompt "MaxMind License Key" MAXMIND_LICENSE_KEY "" "" "secret"

# ── Shared: export API token ──────────────────────────────────────────────────
echo -e "${BOLD}── Export API Token (optional) ──────────────────────────────${RESET}"
echo "  Used for Splunk scripted inputs and other automation."
echo ""
echo -e "${CYAN}Export API token${RESET}"
echo "  Leave blank to skip, or press Enter to auto-generate one."
read -r -p "  Value (Enter to auto-generate, or type your own): " EXPORT_TOKEN_INPUT

if [ "$EXPORT_TOKEN_INPUT" = "" ]; then
    read -r -p "  Auto-generate a token? [Y/n] " autogen
    if [[ ! "$autogen" =~ ^[Nn]$ ]]; then
        if command -v openssl &>/dev/null; then
            SIGNALTRACE_EXPORT_API_TOKEN=$(openssl rand -hex 32)
            echo -e "  ${GREEN}Token generated.${RESET}"
        else
            SIGNALTRACE_EXPORT_API_TOKEN=""
            echo -e "  ${YELLOW}openssl not found, leaving blank.${RESET}"
        fi
    else
        SIGNALTRACE_EXPORT_API_TOKEN=""
    fi
else
    SIGNALTRACE_EXPORT_API_TOKEN="$EXPORT_TOKEN_INPUT"
fi
echo ""

# ── Shared: trusted proxy IP ──────────────────────────────────────────────────
echo -e "${BOLD}── Reverse Proxy (optional) ─────────────────────────────────${RESET}"
echo "  Set this if SignalTrace runs behind nginx, Caddy, or Traefik."
echo "  Use the proxy container IP or subnet, e.g. 172.16.0.0/12"
echo ""
prompt "Trusted proxy IP" SIGNALTRACE_TRUSTED_PROXY_IP "" ""

# ── Write output file ─────────────────────────────────────────────────────────
if [ "$INSTALL_TYPE" = "1" ]; then
    cat > "$OUTPUT_FILE" << EOF
# SignalTrace Docker Environment Configuration
# Generated by setup.sh — do not commit this file to version control.

# ============================================================
# Required
# ============================================================

SIGNALTRACE_ADMIN_USERNAME=${ADMIN_USERNAME}
SIGNALTRACE_PORT=${SIGNALTRACE_PORT}
SIGNALTRACE_ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
SIGNALTRACE_VISITOR_HASH_SALT=${VISITOR_HASH_SALT}

# ============================================================
# GeoIP enrichment (optional but recommended)
# Sign up free at https://www.maxmind.com
# ============================================================

MAXMIND_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID}
MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}

# ============================================================
# Export API token (optional)
# Used for Splunk scripted inputs and other automation.
# ============================================================

SIGNALTRACE_EXPORT_API_TOKEN=${SIGNALTRACE_EXPORT_API_TOKEN}

# ============================================================
# Reverse proxy trust (optional)
# Set to the IP of your reverse proxy if running behind one.
# ============================================================

SIGNALTRACE_TRUSTED_PROXY_IP=${SIGNALTRACE_TRUSTED_PROXY_IP}
EOF

else
    cat > "$OUTPUT_FILE" << EOF
<?php
// SignalTrace Local Configuration
// Generated by setup.sh — do not commit this file to version control.

// ============================================================
// Required
// ============================================================

define('ADMIN_USERNAME',      '${ADMIN_USERNAME}');
define('ADMIN_PASSWORD_HASH', '${ADMIN_PASSWORD_HASH}');
define('VISITOR_HASH_SALT',   '${VISITOR_HASH_SALT}');

// ============================================================
// GeoIP enrichment (optional but recommended)
// ============================================================

define('MAXMIND_ACCOUNT_ID',  '${MAXMIND_ACCOUNT_ID}');
define('MAXMIND_LICENSE_KEY', '${MAXMIND_LICENSE_KEY}');

// ============================================================
// Export API token (optional)
// Used for Splunk scripted inputs and other automation.
// ============================================================

define('EXPORT_API_TOKEN', '${SIGNALTRACE_EXPORT_API_TOKEN}');

// ============================================================
// Reverse proxy trust (optional)
// Set to the IP of your reverse proxy if running behind one.
// ============================================================

define('TRUSTED_PROXY_IP', '${SIGNALTRACE_TRUSTED_PROXY_IP}');

// ============================================================
// Optional tuning — uncomment and adjust as needed
// ============================================================

// define('AUTH_MAX_FAILURES', 5);
// define('AUTH_LOCKOUT_SECS', 900);
// define('SELF_REFERER_DOMAIN', '');
EOF
fi

# ── Deferred hash generation (Docker, no local PHP) ───────────────────────────
if [ "$DEFER_HASH" = true ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Generating password hash..."
    echo ""

    # Build if needed
    if ! docker image inspect signaltrace-signaltrace &>/dev/null; then
        echo "  Building container image first..."
        if ! docker compose build; then
            echo -e "${RED}Error: docker compose build failed. Fix the build error and re-run setup.sh.${RESET}"
            exit 1
        fi
    fi

    # Start the container temporarily to exec into it
    echo "  Starting container to generate hash..."
    docker compose up -d 2>/dev/null
    sleep 2

    ADMIN_PASSWORD_HASH=$(docker exec signaltrace php -r "echo password_hash('${ADMIN_PASSWORD}', PASSWORD_DEFAULT) . PHP_EOL;" 2>/dev/null)

    if [ -z "$ADMIN_PASSWORD_HASH" ]; then
        echo -e "${RED}Error: could not generate hash. Run this manually then restart the container:${RESET}"
        echo ""
        echo "  HASH=\$(docker exec signaltrace php -r \"echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;\")"
        echo "  sed -i \"s|SIGNALTRACE_ADMIN_PASSWORD_HASH=__DEFER__|SIGNALTRACE_ADMIN_PASSWORD_HASH=\${HASH}|\" .env"
        echo "  docker compose restart"
        exit 1
    fi

    sed -i "s|SIGNALTRACE_ADMIN_PASSWORD_HASH=__DEFER__|SIGNALTRACE_ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}|" "$OUTPUT_FILE"

    if grep -q "__DEFER__" "$OUTPUT_FILE"; then
        echo -e "${RED}Error: hash replacement failed. Run this manually:${RESET}"
        echo ""
        echo "  HASH=\$(docker exec signaltrace php -r \"echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;\")"
        echo "  sed -i \"s|SIGNALTRACE_ADMIN_PASSWORD_HASH=__DEFER__|SIGNALTRACE_ADMIN_PASSWORD_HASH=\${HASH}|\" .env"
        echo "  docker compose restart"
        exit 1
    fi

    echo -e "  ${GREEN}Hash generated and written to .env.${RESET}"
    echo ""
    CONTAINER_WAS_RUNNING=true
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}${BOLD}$(basename $OUTPUT_FILE) written successfully.${RESET}"
echo ""

if [ "$INSTALL_TYPE" = "1" ]; then
    if [ "$CONTAINER_WAS_RUNNING" = true ]; then
        echo "Restarting container with new configuration..."
        docker compose up -d
        echo -e "  ${GREEN}Container restarted.${RESET}"
    else
        echo "Next step:"
        echo "  docker compose up -d"
    fi
    echo ""
    echo -e "${CYAN}SignalTrace will be available at: http://localhost:${SIGNALTRACE_PORT}/admin${RESET}"
else
    echo "Next steps:"
    echo "  1. Run geoipupdate to download GeoIP databases (if MaxMind credentials are set)"
    echo "  2. Initialise the database:"
    echo "       sqlite3 /var/www/signaltrace/data/database.db < db/schema.sql"
    echo "  3. Configure your Apache vhost — see README.md for the full config"
    echo "  4. Restart Apache: sudo systemctl restart apache2"
fi
echo ""

if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
    echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
    echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
    echo ""
fi
