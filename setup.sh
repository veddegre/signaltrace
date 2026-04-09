#!/usr/bin/env bash
# SignalTrace setup script
# Supports Docker and manual installs.
# Can be run from inside the cloned repo, or downloaded standalone:
#   curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/setup.sh | sudo bash

set -e

REPO_URL="https://github.com/veddegre/signaltrace.git"
INSTALL_DIR="/var/www/signaltrace"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -- Colours ------------------------------------------------------------------
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

# -- Install type --------------------------------------------------------------
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

# -- For manual installs: install packages and clone repo first ---------------
if [ "$INSTALL_TYPE" = "2" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing system packages..."
    echo ""
    sudo apt-get update -qq
    sudo apt-get install -y \
        apache2 \
        php \
        php-sqlite3 \
        php-mbstring \
        php-xml \
        php-curl \
        sqlite3 \
        composer \
        unzip \
        git \
        software-properties-common
    if ! command -v geoipupdate &>/dev/null; then
        sudo add-apt-repository -y ppa:maxmind/ppa
        sudo apt-get update -qq
        sudo apt-get install -y geoipupdate
    fi
    sudo a2enmod rewrite
    echo -e "  ${GREEN}System packages installed.${RESET}"
    echo ""

    # Clone repo if not already running from inside it
    if [ ! -f "$SCRIPT_DIR/db/schema.sql" ]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Cloning SignalTrace repository..."
        echo ""
        if [ -d "$INSTALL_DIR" ]; then
            echo -e "${YELLOW}${INSTALL_DIR} already exists.${RESET}"
            read -r -p "  Remove and re-clone? [y/N] " reclone
            if [[ "$reclone" =~ ^[Yy]$ ]]; then
                sudo rm -rf "$INSTALL_DIR"
            else
                echo "  Using existing directory."
            fi
        fi
        if [ ! -d "$INSTALL_DIR" ]; then
            sudo git clone "$REPO_URL" "$INSTALL_DIR"
        fi
        sudo chown -R www-data:www-data "$INSTALL_DIR"
        SCRIPT_DIR="$INSTALL_DIR"
        echo -e "  ${GREEN}Repository cloned to ${INSTALL_DIR}.${RESET}"
        echo ""
    fi

    OUTPUT_FILE="$SCRIPT_DIR/includes/config.local.php"
else
    OUTPUT_FILE="$SCRIPT_DIR/.env"
fi

# -- Guard: existing config file -----------------------------------------------
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}Warning: $(basename "$OUTPUT_FILE") already exists.${RESET}"
    read -r -p "Overwrite it? [y/N] " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "Aborted. Your existing file was not changed."
        exit 0
    fi
    echo ""
fi

# -- Helper functions ----------------------------------------------------------
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

# -- Shared: admin username ----------------------------------------------------
echo -e "${BOLD}── Admin Credentials ────────────────────────────────────────${RESET}"
echo ""
prompt "Admin username" ADMIN_USERNAME "admin"

# -- Admin password ------------------------------------------------------------
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
    echo "  Generating bcrypt hash..."
    ADMIN_PASSWORD_HASH=$(generate_hash_php "$ADMIN_PASSWORD")
    echo -e "  ${GREEN}Hash generated.${RESET}"
else
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

# -- Visitor hash salt ---------------------------------------------------------
echo -e "${CYAN}Visitor hash salt${RESET}"
echo "  Used to anonymise visitor fingerprints. Leave blank to auto-generate."
read -r -p "  Value (leave blank to auto-generate): " VISITOR_HASH_SALT

if [ -z "$VISITOR_HASH_SALT" ]; then
    echo "  Generating salt..."
    VISITOR_HASH_SALT=$(generate_salt)
    echo -e "  ${GREEN}Salt generated.${RESET}"
fi
echo ""

# -- Docker only: port ---------------------------------------------------------
CONTAINER_WAS_RUNNING=false
if [ "$INSTALL_TYPE" = "1" ]; then
    echo -e "${BOLD}── Docker Configuration ─────────────────────────────────────${RESET}"
    echo ""

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^signaltrace$"; then
        CONTAINER_WAS_RUNNING=true
        echo "  Stopping existing container to free port..."
        docker compose stop 2>/dev/null
        echo ""
    fi

    EXISTING_PORT=$(grep "^SIGNALTRACE_PORT=" "$OUTPUT_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"')
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

# -- Shared: GeoIP -------------------------------------------------------------
echo -e "${BOLD}── GeoIP Enrichment (optional but recommended) ──────────────${RESET}"
echo "  Sign up free at https://www.maxmind.com to get these."
echo ""
prompt "MaxMind Account ID" MAXMIND_ACCOUNT_ID "" ""
prompt "MaxMind License Key" MAXMIND_LICENSE_KEY "" "" "secret"

# -- Shared: export API token --------------------------------------------------
echo -e "${BOLD}── Export API Token (optional) ──────────────────────────────${RESET}"
echo "  Used for Splunk scripted inputs and other automation."
echo ""
echo "  Press Enter to auto-generate  |  Type a value to use your own  |  Type 'none' to skip"
echo ""
read -r -p "  Value: " EXPORT_TOKEN_INPUT

if [ "${EXPORT_TOKEN_INPUT,,}" = "none" ]; then
    SIGNALTRACE_EXPORT_API_TOKEN=""
    echo -e "  ${YELLOW}Export API token disabled.${RESET}"
elif [ -z "$EXPORT_TOKEN_INPUT" ]; then
    if command -v openssl &>/dev/null; then
        SIGNALTRACE_EXPORT_API_TOKEN=$(openssl rand -hex 32)
        echo -e "  ${GREEN}Token auto-generated.${RESET}"
    else
        SIGNALTRACE_EXPORT_API_TOKEN=""
        echo -e "  ${YELLOW}openssl not found — token skipped. Install openssl and re-run to generate one.${RESET}"
    fi
else
    SIGNALTRACE_EXPORT_API_TOKEN="$EXPORT_TOKEN_INPUT"
    echo -e "  ${GREEN}Token set.${RESET}"
fi
echo ""

# -- Shared: trusted proxy IP --------------------------------------------------
echo -e "${BOLD}── Reverse Proxy (optional) ─────────────────────────────────${RESET}"
echo "  Set this if SignalTrace runs behind nginx, Caddy, or Traefik."
echo ""
prompt "Trusted proxy IP" SIGNALTRACE_TRUSTED_PROXY_IP "" ""

# -- Optional tuning -----------------------------------------------------------
echo -e "${BOLD}── Optional Tuning ──────────────────────────────────────────${RESET}"
echo "  Press Enter to accept defaults for all of these."
echo ""

echo -e "${CYAN}Auth lockout threshold${RESET}"
echo "  Failed login attempts before an IP is locked out."
read -r -p "  Value [5]: " AUTH_MAX_FAILURES_INPUT
AUTH_MAX_FAILURES="${AUTH_MAX_FAILURES_INPUT:-5}"
echo ""

echo -e "${CYAN}Auth lockout duration${RESET}"
echo "  How long a lockout lasts in seconds."
read -r -p "  Value [900]: " AUTH_LOCKOUT_SECS_INPUT
AUTH_LOCKOUT_SECS="${AUTH_LOCKOUT_SECS_INPUT:-900}"
echo ""

echo -e "${CYAN}Self-referrer domain${RESET}"
echo "  Your site's own domain (e.g. example.com). When set, requests"
echo "  arriving at / with your domain in the Referer header receive a"
echo "  score penalty — helps catch crawler traffic. Leave blank to disable."
read -r -p "  Value (leave blank to skip): " SELF_REFERER_DOMAIN
echo ""

# -- Write output file ---------------------------------------------------------
if [ "$INSTALL_TYPE" = "1" ]; then
    cat > "$OUTPUT_FILE" << EOF
SIGNALTRACE_ADMIN_USERNAME="${ADMIN_USERNAME}"
SIGNALTRACE_PORT="${SIGNALTRACE_PORT}"
SIGNALTRACE_ADMIN_PASSWORD_HASH='${ADMIN_PASSWORD_HASH}'
SIGNALTRACE_VISITOR_HASH_SALT="${VISITOR_HASH_SALT}"
MAXMIND_ACCOUNT_ID="${MAXMIND_ACCOUNT_ID}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY}"
SIGNALTRACE_EXPORT_API_TOKEN="${SIGNALTRACE_EXPORT_API_TOKEN}"
SIGNALTRACE_TRUSTED_PROXY_IP="${SIGNALTRACE_TRUSTED_PROXY_IP}"
AUTH_MAX_FAILURES="${AUTH_MAX_FAILURES}"
AUTH_LOCKOUT_SECS="${AUTH_LOCKOUT_SECS}"
SELF_REFERER_DOMAIN="${SELF_REFERER_DOMAIN}"
EOF
else
    cat > "$OUTPUT_FILE" << EOF
<?php
define('ADMIN_USERNAME',      '${ADMIN_USERNAME}');
define('ADMIN_PASSWORD_HASH', '${ADMIN_PASSWORD_HASH}');
define('VISITOR_HASH_SALT',   '${VISITOR_HASH_SALT}');
define('MAXMIND_ACCOUNT_ID',  '${MAXMIND_ACCOUNT_ID}');
define('MAXMIND_LICENSE_KEY', '${MAXMIND_LICENSE_KEY}');
define('EXPORT_API_TOKEN',    '${SIGNALTRACE_EXPORT_API_TOKEN}');
define('TRUSTED_PROXY_IP',    '${SIGNALTRACE_TRUSTED_PROXY_IP}');
define('AUTH_MAX_FAILURES',   ${AUTH_MAX_FAILURES});
define('AUTH_LOCKOUT_SECS',   ${AUTH_LOCKOUT_SECS});
EOF
    if [ -n "$SELF_REFERER_DOMAIN" ]; then
        echo "define('SELF_REFERER_DOMAIN', '${SELF_REFERER_DOMAIN}');" >> "$OUTPUT_FILE"
    fi
fi

# -- Deferred hash generation (Docker, no local PHP) --------------------------
if [ "$DEFER_HASH" = true ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Generating password hash via Docker..."
    echo ""

    if ! docker image inspect signaltrace-signaltrace &>/dev/null; then
        echo "  Building container image first..."
        docker compose build
    fi

    echo "  Starting container to generate hash..."
    docker compose up -d 2>/dev/null
    sleep 3

    ADMIN_PASSWORD_HASH=$(docker exec signaltrace php -r "echo password_hash('${ADMIN_PASSWORD}', PASSWORD_DEFAULT);" 2>/dev/null)

    if [ -z "$ADMIN_PASSWORD_HASH" ]; then
        echo -e "${RED}Error: could not generate hash via Docker. Run manually:${RESET}"
        echo ""
        echo "  HASH=\$(docker exec signaltrace php -r \"echo password_hash('yourpassword', PASSWORD_DEFAULT);\")"
        echo "  sed -i \"s|SIGNALTRACE_ADMIN_PASSWORD_HASH='__DEFER__'|SIGNALTRACE_ADMIN_PASSWORD_HASH='\${HASH}'|\" .env"
        echo "  docker compose restart"
        exit 1
    fi

    ESC_HASH=$(echo "$ADMIN_PASSWORD_HASH" | sed 's/\$/\\$/g')
    sed -i "s|SIGNALTRACE_ADMIN_PASSWORD_HASH='__DEFER__'|SIGNALTRACE_ADMIN_PASSWORD_HASH='${ESC_HASH}'|" "$OUTPUT_FILE"

    echo -e "  ${GREEN}Hash generated and written to .env.${RESET}"
    CONTAINER_WAS_RUNNING=true
fi

# -- Done ----------------------------------------------------------------------
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}${BOLD}$(basename "$OUTPUT_FILE") written successfully.${RESET}"
echo ""

if [ "$INSTALL_TYPE" = "1" ]; then
    if [ "$CONTAINER_WAS_RUNNING" = true ]; then
        docker compose up -d
        echo -e "  ${GREEN}Container restarted.${RESET}"
    else
        echo "Next step: docker compose up -d"
    fi
    echo ""
    echo -e "${CYAN}Available at: http://localhost:${SIGNALTRACE_PORT}/admin${RESET}"
else
    # ── Composer dependencies -------------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing PHP dependencies..."
    echo ""
    cd "$SCRIPT_DIR" && sudo -u www-data composer install --no-dev --no-interaction
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: composer install failed.${RESET}"
        exit 1
    fi
    echo -e "  ${GREEN}PHP dependencies installed.${RESET}"
    echo ""

    # ── GeoIP configuration --------------------------------------------------
    if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Configuring GeoIP..."
        echo ""
        sudo mkdir -p /var/lib/GeoIP
        sudo tee /etc/GeoIP.conf > /dev/null << GEOIPCONF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-ASN GeoLite2-Country
DatabaseDirectory /var/lib/GeoIP
GEOIPCONF
        echo "  /etc/GeoIP.conf written."
        echo "  Downloading GeoIP databases..."
        if sudo geoipupdate; then
            echo -e "  ${GREEN}GeoIP databases downloaded to /var/lib/GeoIP/.${RESET}"
        else
            echo -e "  ${YELLOW}Warning: geoipupdate failed. Run 'sudo geoipupdate' manually once credentials are correct.${RESET}"
        fi
        echo ""
    else
        echo -e "${YELLOW}Note: MaxMind credentials not provided — GeoIP enrichment will be unavailable.${RESET}"
        echo "  To enable it later, add your credentials to /etc/GeoIP.conf and run: sudo geoipupdate"
        echo ""
    fi

    # ── Database initialisation -----------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    DB_FILE="/var/www/signaltrace/data/database.db"
    DB_DIR="/var/www/signaltrace/data"

    if [ -f "$DB_FILE" ]; then
        echo -e "${YELLOW}Database already exists at ${DB_FILE}.${RESET}"
        read -r -p "  Re-initialise it? This will wipe all data. [y/N] " reinit
        if [[ ! "$reinit" =~ ^[Yy]$ ]]; then
            echo "  Skipping database initialisation."
            SKIP_DB=true
        fi
    fi

    if [ "${SKIP_DB:-false}" = false ]; then
        echo "Initialising database..."
        sudo mkdir -p "$DB_DIR"
        sudo chown www-data:www-data "$DB_DIR"
        sudo chmod 775 "$DB_DIR"
        [ -f "$DB_FILE" ] && sudo rm -f "$DB_FILE"
        sudo -u www-data sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/schema.sql"
        sudo chown www-data:www-data "$DB_FILE"
        sudo chmod 664 "$DB_FILE"
        echo -e "  ${GREEN}Database initialised.${RESET}"
        echo ""

        read -r -p "  Load sample data so the dashboard has something to show? [y/N] " doseed
        if [[ "$doseed" =~ ^[Yy]$ ]]; then
            sudo -u www-data sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/seed.sql"
            echo -e "  ${GREEN}Sample data loaded.${RESET}"
        fi
    fi
    echo ""

    # ── Fix ownership ---------------------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Setting file ownership..."
    sudo chown -R www-data:www-data /var/www/signaltrace
    sudo chmod -R 775 /var/www/signaltrace/data
    echo -e "  ${GREEN}Ownership set to www-data.${RESET}"
    echo ""

    # ── Apache vhost ----------------------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Configuring Apache..."
    echo ""
    read -r -p "  ServerName (your domain or IP, e.g. signaltrace.example.com): " APACHE_SERVER_NAME
    APACHE_SERVER_NAME="${APACHE_SERVER_NAME:-localhost}"

    sudo tee /etc/apache2/sites-available/signaltrace.conf > /dev/null << APACHECONF
<VirtualHost *:80>
    ServerName ${APACHE_SERVER_NAME}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_access.log combined
</VirtualHost>
APACHECONF

    sudo a2ensite signaltrace.conf
    sudo a2dissite 000-default.conf 2>/dev/null || true
    sudo systemctl restart apache2
    echo -e "  ${GREEN}Apache configured and restarted.${RESET}"
    echo ""

    echo -e "${CYAN}SignalTrace is available at: http://${APACHE_SERVER_NAME}/admin${RESET}"
fi
echo ""

if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
    echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
    echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
    echo ""
fi
