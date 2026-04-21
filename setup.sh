#!/usr/bin/env bash
# SignalTrace setup script
# Supports Docker and manual installs.
# Can be run from inside the cloned repo, or downloaded standalone:
#   curl -fsSL https://raw.githubusercontent.com/veddegre/signaltrace/main/setup.sh | bash
#
# Notes:
# - Run with: bash setup.sh
# - The script will prompt for sudo when needed.
# - For manual installs, the app is staged into /var/www/signaltrace.
# - If Cloudflare Access + admin subdomain are enabled, Apache handles:
#     https://admin.example.com/  ->  https://admin.example.com/admin
# - If you provide a Cloudflare DNS API token, the script will use the
#   certbot Cloudflare DNS plugin so certificates can renew while proxied.

set -e

REPO_URL="https://github.com/veddegre/signaltrace.git"
INSTALL_DIR="/var/www/signaltrace"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

require_sudo() {
    if [ -n "$SUDO" ]; then
        $SUDO -v
    fi
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

RUN_SYSTEM_TASKS=true

echo ""
echo -e "${BOLD}SignalTrace Setup${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "This script will configure SignalTrace for your environment."
echo "Press Enter to accept defaults where shown."
echo ""

# -- Install type --------------------------------------------------------------
echo -e "${CYAN}Install type${RESET}"
echo "  1) Docker — pre-built image (fastest, no build step)"
echo "  2) Docker — build from source"
echo "  3) Manual (Ubuntu + Apache)"
echo ""
read -r -p "  Choice [1]: " INSTALL_TYPE_INPUT
INSTALL_TYPE="${INSTALL_TYPE_INPUT:-1}"
echo ""

if [ "$INSTALL_TYPE" != "1" ] && [ "$INSTALL_TYPE" != "2" ] && [ "$INSTALL_TYPE" != "3" ]; then
    echo -e "${RED}Invalid choice. Please enter 1, 2, or 3.${RESET}"
    exit 1
fi

# -- Manual install warning ----------------------------------------------------
if [ "$INSTALL_TYPE" = "3" ]; then
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║                        WARNING                           ║${RESET}"
    echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}║  The manual install is designed for a FRESH Ubuntu       ║${RESET}"
    echo -e "${RED}${BOLD}║  server with no existing web services.                   ║${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}║  It will:                                                ║${RESET}"
    echo -e "${RED}${BOLD}║  * Install and configure Apache                          ║${RESET}"
    echo -e "${RED}${BOLD}║  * Disable the default Apache site                       ║${RESET}"
    echo -e "${RED}${BOLD}║  * Overwrite /etc/GeoIP.conf if it exists                ║${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}║  Do NOT run this on a server already hosting other       ║${RESET}"
    echo -e "${RED}${BOLD}║  websites or services.                                   ║${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    read -r -p "  I understand. Continue? [y/N] " confirm_manual
    if [[ ! "$confirm_manual" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# -- Manual install prep -------------------------------------------------------
if [ "$INSTALL_TYPE" = "3" ]; then
    require_sudo

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing system packages..."
    echo ""
    $SUDO apt-get update -qq
    $SUDO apt-get install -y \
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
        software-properties-common \
        certbot \
        python3-certbot-apache \
        python3-certbot-dns-cloudflare

    if ! command -v geoipupdate >/dev/null 2>&1; then
        $SUDO add-apt-repository -y ppa:maxmind/ppa
        $SUDO apt-get update -qq
        $SUDO apt-get install -y geoipupdate
    fi

    $SUDO a2enmod rewrite >/dev/null
    echo -e "  ${GREEN}System packages installed.${RESET}"
    echo ""

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Staging SignalTrace into ${INSTALL_DIR}..."
    echo ""

    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        if [ -d "$INSTALL_DIR" ]; then
            echo -e "${YELLOW}${INSTALL_DIR} already exists.${RESET}"
            read -r -p "  Remove and replace it with the current source? [y/N] " replace_install
            if [[ "$replace_install" =~ ^[Yy]$ ]]; then
                $SUDO rm -rf "$INSTALL_DIR"
            else
                echo -e "${RED}Manual install requires files to live in ${INSTALL_DIR}.${RESET}"
                echo "Aborted to avoid mixing files from two locations."
                exit 1
            fi
        fi

        if [ -f "$SCRIPT_DIR/db/schema.sql" ]; then
            $SUDO mkdir -p "$INSTALL_DIR"
            $SUDO cp -a "$SCRIPT_DIR"/. "$INSTALL_DIR"/
            echo -e "  ${GREEN}Copied repository into ${INSTALL_DIR}.${RESET}"
        else
            $SUDO git clone "$REPO_URL" "$INSTALL_DIR"
            echo -e "  ${GREEN}Repository cloned to ${INSTALL_DIR}.${RESET}"
        fi
    else
        echo -e "  ${GREEN}Already running from ${INSTALL_DIR}.${RESET}"
    fi
    echo ""

    SCRIPT_DIR="$INSTALL_DIR"
    OUTPUT_FILE="$SCRIPT_DIR/includes/config.local.php"
else
    OUTPUT_FILE="$SCRIPT_DIR/.env"
fi

# -- Existing config -----------------------------------------------------------
MODIFY_EXISTING=false
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}$(basename "$OUTPUT_FILE") already exists.${RESET}"
    echo ""
    echo "  1) Update it — keep existing values as defaults, change only sections you choose"
    echo "  2) Overwrite it — start fresh, all values will be re-prompted"
    echo "  3) Abort — exit without changing anything"
    echo ""
    read -r -p "  Choice [1]: " existing_choice
    case "${existing_choice:-1}" in
        2)
            echo -e "  ${YELLOW}Will overwrite existing file.${RESET}"
            ;;
        3)
            echo "Aborted. Your existing file was not changed."
            exit 0
            ;;
        *)
            MODIFY_EXISTING=true
            echo -e "  ${GREEN}Will update existing values section by section.${RESET}"
            ;;
    esac
    echo ""
fi

if [ "$MODIFY_EXISTING" = true ] && [ "$INSTALL_TYPE" = "3" ]; then
    echo "  System/infrastructure tasks are things like:"
    echo "  • composer update"
    echo "  • GeoIP config/write"
    echo "  • database initialisation"
    echo "  • file permissions"
    echo "  • Apache vhost rewrite"
    echo "  • Let's Encrypt / certbot"
    echo ""
    read -r -p "  Re-run system/infrastructure tasks too? [y/N] " rerun_system_tasks
    if [[ "$rerun_system_tasks" =~ ^[Yy]$ ]]; then
        RUN_SYSTEM_TASKS=true
    else
        RUN_SYSTEM_TASKS=false
    fi
    echo ""
fi

if [ "$MODIFY_EXISTING" = true ] && [ "$INSTALL_TYPE" != "3" ]; then
    RUN_SYSTEM_TASKS=false
fi

# -- Helpers -------------------------------------------------------------------
read_existing_php() {
    local key="$1"
    if [ -f "$OUTPUT_FILE" ]; then
        grep -oP "define\('${key}',\s*'?\K[^';)]*" "$OUTPUT_FILE" 2>/dev/null | head -1
    fi
}

read_existing_php_literal() {
    local key="$1"
    if [ -f "$OUTPUT_FILE" ]; then
        grep -oP "define\('${key}',\s*\K[^;)]+" "$OUTPUT_FILE" 2>/dev/null | head -1 | tr -d ' '
    fi
}

prompt() {
    local label="$1"
    local var="$2"
    local default="$3"
    local hint="$4"
    local secret="$5"

    echo -e "${CYAN}${label}${RESET}"
    [ -n "$hint" ] && echo "  $hint"
    if [ -n "$default" ]; then
        if [ "$secret" = "secret" ]; then
            read -r -s -p "  Value [${default}]: " input
            echo ""
        else
            read -r -p "  Value [${default}]: " input
        fi
        eval "$var=\"\${input:-$default}\""
    else
        if [ "$secret" = "secret" ]; then
            read -r -s -p "  Value (leave blank to skip): " input
            echo ""
        else
            read -r -p "  Value (leave blank to skip): " input
        fi
        eval "$var=\"\${input}\""
    fi
    echo ""
}

section_choice_existing() {
    local label="$1"
    echo -e "${BOLD}${label}${RESET}"
    echo "  1) Keep existing"
    echo "  2) Reconfigure"
    echo "  3) Remove/disable"
    echo ""
    read -r -p "  Choice [1]: " SECTION_CHOICE
    SECTION_CHOICE="${SECTION_CHOICE:-1}"
    echo ""
}

generate_hash_php() {
    local password="$1"
    php -r "echo password_hash('${password}', PASSWORD_DEFAULT) . PHP_EOL;"
}

generate_salt() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 64
    else
        php -r "echo bin2hex(random_bytes(64)) . PHP_EOL;"
    fi
}

find_free_port() {
    local port=8080
    while ss -tln 2>/dev/null | grep -q ":${port} "; do
        port=$((port + 1))
    done
    echo "$port"
}

# -- Admin credentials ---------------------------------------------------------
echo -e "${BOLD}── Admin Credentials ────────────────────────────────────────${RESET}"
echo ""
_existing_username=$(read_existing_php "ADMIN_USERNAME")
prompt "Admin username" ADMIN_USERNAME "${_existing_username:-admin}"

echo -e "${CYAN}Admin password${RESET}"
if [ "$MODIFY_EXISTING" = true ]; then
    echo "  Leave blank to keep your existing password hash unchanged."
    read -r -s -p "  New password (blank to keep existing): " ADMIN_PASSWORD
    echo ""
    if [ -z "$ADMIN_PASSWORD" ]; then
        ADMIN_PASSWORD_HASH=$(read_existing_php "ADMIN_PASSWORD_HASH")
        DEFER_HASH=false
        echo -e "  ${GREEN}Keeping existing password hash.${RESET}"
        echo ""
    else
        read -r -s -p "  Confirm new password: " ADMIN_PASSWORD_CONFIRM
        echo ""
        if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
            echo -e "  ${RED}Passwords do not match. Keeping existing hash.${RESET}"
            ADMIN_PASSWORD_HASH=$(read_existing_php "ADMIN_PASSWORD_HASH")
            ADMIN_PASSWORD=""
            DEFER_HASH=false
            echo ""
        fi
    fi
else
    echo "  Enter a password and the script will hash it for you."
    while true; do
        read -r -s -p "  Password: " ADMIN_PASSWORD
        echo ""
        if [ -z "$ADMIN_PASSWORD" ]; then
            echo -e "${RED}Error: password cannot be blank.${RESET}"
            continue
        fi
        read -r -s -p "  Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo ""
        if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
            echo -e "${RED}Passwords do not match. Try again.${RESET}"
            echo ""
        else
            break
        fi
    done
fi

DEFER_HASH=false
if [ -n "$ADMIN_PASSWORD" ]; then
    if command -v php >/dev/null 2>&1; then
        echo "  Generating bcrypt hash..."
        ADMIN_PASSWORD_HASH=$(generate_hash_php "$ADMIN_PASSWORD")
        echo -e "${GREEN}Hash generated.${RESET}"
    elif python3 -c "import bcrypt" 2>/dev/null; then
        echo "  Generating bcrypt hash..."
        ADMIN_PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('${ADMIN_PASSWORD}'.encode(), bcrypt.gensalt()).decode())")
        echo -e "${GREEN}Hash generated.${RESET}"
    else
        echo -e "${YELLOW}PHP not found — hash will be generated later.${RESET}"
        ADMIN_PASSWORD_HASH="__DEFER__"
        DEFER_HASH=true
    fi
    echo ""
fi

# -- Visitor hash salt ---------------------------------------------------------
echo -e "${CYAN}Visitor hash salt${RESET}"
_existing_salt=$(read_existing_php "VISITOR_HASH_SALT")
if [ -n "$_existing_salt" ]; then
    echo "  Used to anonymise visitor fingerprints. Leave blank to keep existing."
    read -r -p "  Value (blank to keep existing): " VISITOR_HASH_SALT
    VISITOR_HASH_SALT="${VISITOR_HASH_SALT:-$_existing_salt}"
else
    echo "  Used to anonymise visitor fingerprints. Leave blank to auto-generate."
    read -r -p "  Value (leave blank to auto-generate): " VISITOR_HASH_SALT
fi

if [ -z "$VISITOR_HASH_SALT" ]; then
    echo "  Generating salt..."
    VISITOR_HASH_SALT=$(generate_salt)
    echo -e "${GREEN}Salt generated.${RESET}"
fi
echo ""

# -- Docker settings -----------------------------------------------------------
CONTAINER_WAS_RUNNING=false
if [ "$INSTALL_TYPE" = "1" ] || [ "$INSTALL_TYPE" = "2" ]; then
    echo -e "${BOLD}── Docker Configuration ─────────────────────────────────────${RESET}"
    echo ""

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^signaltrace$"; then
        CONTAINER_WAS_RUNNING=true
        echo "  Stopping existing container to free port..."
        docker compose stop >/dev/null 2>&1 || true
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

# -- GeoIP ---------------------------------------------------------------------
MAXMIND_ACCOUNT_ID=""
MAXMIND_LICENSE_KEY=""
_existing_mm_account=$(read_existing_php "MAXMIND_ACCOUNT_ID")
_existing_mm_license=$(read_existing_php "MAXMIND_LICENSE_KEY")

echo -e "${BOLD}── GeoIP Enrichment (optional but recommended) ──────────────${RESET}"
echo "  Sign up free at https://www.maxmind.com to get these."
echo ""

if [ "$MODIFY_EXISTING" = true ] && { [ -n "$_existing_mm_account" ] || [ -n "$_existing_mm_license" ]; }; then
    section_choice_existing "GeoIP"
    case "$SECTION_CHOICE" in
        2)
            prompt "MaxMind Account ID" MAXMIND_ACCOUNT_ID "$_existing_mm_account" ""
            prompt "MaxMind License Key" MAXMIND_LICENSE_KEY "$_existing_mm_license" "" "secret"
            ;;
        3)
            MAXMIND_ACCOUNT_ID=""
            MAXMIND_LICENSE_KEY=""
            ;;
        *)
            MAXMIND_ACCOUNT_ID="$_existing_mm_account"
            MAXMIND_LICENSE_KEY="$_existing_mm_license"
            ;;
    esac
else
    prompt "MaxMind Account ID" MAXMIND_ACCOUNT_ID "${_existing_mm_account:-}" ""
    prompt "MaxMind License Key" MAXMIND_LICENSE_KEY "${_existing_mm_license:-}" "" "secret"
fi

# -- Export API token ----------------------------------------------------------
_existing_export_token=$(read_existing_php "EXPORT_API_TOKEN")

echo -e "${BOLD}── Export API Token (optional) ──────────────────────────────${RESET}"
echo "  Used for Splunk scripted inputs and other automation."
echo ""

if [ "$MODIFY_EXISTING" = true ] && [ -n "$_existing_export_token" ]; then
    section_choice_existing "Export API Token"
    case "$SECTION_CHOICE" in
        2)
            echo "  Press Enter to auto-generate  |  Type a value to use your own  |  Type 'none' to disable"
            echo ""
            read -r -p "  Value: " EXPORT_TOKEN_INPUT
            if [ "${EXPORT_TOKEN_INPUT,,}" = "none" ]; then
                SIGNALTRACE_EXPORT_API_TOKEN=""
                echo -e "${YELLOW}  Export API token disabled.${RESET}"
            elif [ -z "$EXPORT_TOKEN_INPUT" ]; then
                if command -v openssl >/dev/null 2>&1; then
                    SIGNALTRACE_EXPORT_API_TOKEN=$(openssl rand -hex 32)
                    echo -e "${GREEN}  Token auto-generated.${RESET}"
                else
                    SIGNALTRACE_EXPORT_API_TOKEN="$_existing_export_token"
                    echo -e "${YELLOW}  openssl not found — keeping existing token.${RESET}"
                fi
            else
                SIGNALTRACE_EXPORT_API_TOKEN="$EXPORT_TOKEN_INPUT"
                echo -e "${GREEN}  Token set.${RESET}"
            fi
            ;;
        3)
            SIGNALTRACE_EXPORT_API_TOKEN=""
            echo -e "${YELLOW}  Export API token disabled.${RESET}"
            ;;
        *)
            SIGNALTRACE_EXPORT_API_TOKEN="$_existing_export_token"
            echo -e "${GREEN}  Keeping existing export API token.${RESET}"
            ;;
    esac
else
    echo "  Press Enter to auto-generate  |  Type a value to use your own  |  Type 'none' to skip"
    echo ""
    read -r -p "  Value: " EXPORT_TOKEN_INPUT

    if [ "${EXPORT_TOKEN_INPUT,,}" = "none" ]; then
        SIGNALTRACE_EXPORT_API_TOKEN=""
        echo -e "${YELLOW}  Export API token disabled.${RESET}"
    elif [ -z "$EXPORT_TOKEN_INPUT" ]; then
        if command -v openssl >/dev/null 2>&1; then
            SIGNALTRACE_EXPORT_API_TOKEN=$(openssl rand -hex 32)
            echo -e "${GREEN}  Token auto-generated.${RESET}"
        else
            SIGNALTRACE_EXPORT_API_TOKEN=""
            echo -e "${YELLOW}  openssl not found — token skipped.${RESET}"
        fi
    else
        SIGNALTRACE_EXPORT_API_TOKEN="$EXPORT_TOKEN_INPUT"
        echo -e "${GREEN}  Token set.${RESET}"
    fi
fi
echo ""

# -- Reverse proxy -------------------------------------------------------------
echo -e "${BOLD}── Reverse Proxy (optional) ─────────────────────────────────${RESET}"
echo "  Set this if SignalTrace runs behind nginx, Caddy, or Traefik."
echo ""
_existing_proxy_ip=$(read_existing_php "TRUSTED_PROXY_IP")
if [ "$MODIFY_EXISTING" = true ] && [ -n "$_existing_proxy_ip" ]; then
    echo -e "${CYAN}Trusted proxy IP${RESET}"
    echo "  Leave blank to keep existing."
    read -r -p "  Value [${_existing_proxy_ip}]: " proxy_ip_input
    SIGNALTRACE_TRUSTED_PROXY_IP="${proxy_ip_input:-$_existing_proxy_ip}"
    echo ""
else
    prompt "Trusted proxy IP" SIGNALTRACE_TRUSTED_PROXY_IP "${_existing_proxy_ip:-}" ""
fi

# -- Cloudflare Access + DNS plugin -------------------------------------------
CF_ACCESS_ENABLED_VAL="false"
CF_ACCESS_AUD_VAL=""
CF_ACCESS_TEAM_DOMAIN_VAL=""
CF_ADMIN_SUBDOMAIN=""
CF_DNS_PLUGIN_ENABLED="false"
CF_DNS_API_TOKEN=""

_existing_cf_enabled=$(read_existing_php_literal "CF_ACCESS_ENABLED")
_existing_cf_aud=$(read_existing_php "CF_ACCESS_AUD")
_existing_cf_team=$(read_existing_php "CF_ACCESS_TEAM_DOMAIN")

if [ "$INSTALL_TYPE" = "3" ]; then
    echo -e "${BOLD}── Cloudflare Access / DNS (optional) ───────────────────────${RESET}"
    echo "  Adds Cloudflare Zero Trust in front of the admin panel."
    echo ""
    echo "  For the Access AUD token:"
    echo "    Zero Trust Dashboard → Access → Applications → your app → Configure → Additional settings → AUD"
    echo ""
    echo "  For the team domain:"
    echo "    Zero Trust Dashboard → Settings → General / Team domain"
    echo ""
    echo "  For the DNS API token used by certbot renewals:"
    echo "    Cloudflare Dashboard → My Profile → API Tokens → Create Token"
    echo "    Recommended permissions:"
    echo "      Zone → DNS → Edit"
    echo "      Zone → Zone → Read"
    echo "    Scope it to this zone only."
    echo ""

    if [ "$MODIFY_EXISTING" = true ] && { [ "$_existing_cf_enabled" = "true" ] || [ -n "$_existing_cf_aud" ]; }; then
        section_choice_existing "Cloudflare Access / DNS"
        case "$SECTION_CHOICE" in
            2)
                prompt "Cloudflare Access AUD token" CF_ACCESS_AUD_VAL "$_existing_cf_aud" ""
                prompt "Cloudflare team domain" CF_ACCESS_TEAM_DOMAIN_VAL "$_existing_cf_team" "e.g. yourteam.cloudflareaccess.com"
                prompt "Admin subdomain" CF_ADMIN_SUBDOMAIN "" "e.g. admin.example.com"
                echo -e "${CYAN}Cloudflare DNS API token${RESET}"
                read -r -s -p "  Value (leave blank to skip DNS plugin setup): " CF_DNS_API_TOKEN
                echo ""
                echo ""
                if [ -n "$CF_DNS_API_TOKEN" ]; then
                    CF_DNS_PLUGIN_ENABLED="true"
                fi
                if [ -n "$CF_ACCESS_AUD_VAL" ] && [ -n "$CF_ACCESS_TEAM_DOMAIN_VAL" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                    CF_ACCESS_ENABLED_VAL="true"
                fi
                ;;
            3)
                CF_ACCESS_ENABLED_VAL="false"
                CF_ACCESS_AUD_VAL=""
                CF_ACCESS_TEAM_DOMAIN_VAL=""
                CF_ADMIN_SUBDOMAIN=""
                CF_DNS_PLUGIN_ENABLED="false"
                CF_DNS_API_TOKEN=""
                ;;
            *)
                CF_ACCESS_ENABLED_VAL="true"
                CF_ACCESS_AUD_VAL="$_existing_cf_aud"
                CF_ACCESS_TEAM_DOMAIN_VAL="$_existing_cf_team"
                ;;
        esac
    else
        read -r -p "  Enable Cloudflare Access? [y/N] " do_cf_access
        if [[ "$do_cf_access" =~ ^[Yy]$ ]]; then
            echo ""
            prompt "Cloudflare Access AUD token" CF_ACCESS_AUD_VAL "" ""
            prompt "Cloudflare team domain" CF_ACCESS_TEAM_DOMAIN_VAL "" "e.g. yourteam.cloudflareaccess.com"
            prompt "Admin subdomain" CF_ADMIN_SUBDOMAIN "" "e.g. admin.example.com"
            echo -e "${CYAN}Cloudflare DNS API token${RESET}"
            read -r -s -p "  Value (leave blank to skip DNS plugin setup): " CF_DNS_API_TOKEN
            echo ""
            echo ""
            if [ -n "$CF_DNS_API_TOKEN" ]; then
                CF_DNS_PLUGIN_ENABLED="true"
            fi
            if [ -n "$CF_ACCESS_AUD_VAL" ] && [ -n "$CF_ACCESS_TEAM_DOMAIN_VAL" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                CF_ACCESS_ENABLED_VAL="true"
            fi
        fi
    fi
    echo ""
fi

# -- Demo mode -----------------------------------------------------------------
DEMO_MODE_ENABLED=false
DEMO_APP_NAME="SignalTrace"
DEMO_BASE_URL=""
DEMO_DEFAULT_REDIRECT_URL="https://example.com/"
DEMO_ADMIN_USERNAME_DISPLAY="demo"
DEMO_ADMIN_PASSWORD_DISPLAY=""

_existing_demo_mode=$(read_existing_php_literal "DEMO_MODE")
_existing_demo_user=$(read_existing_php "DEMO_ADMIN_USERNAME")
_existing_demo_pass=$(read_existing_php "DEMO_ADMIN_PASSWORD")

if [ "$INSTALL_TYPE" = "3" ]; then
    echo -e "${BOLD}── Demo Mode (optional) ─────────────────────────────────────${RESET}"
    echo ""

    if [ "$MODIFY_EXISTING" = true ] && [ "$_existing_demo_mode" = "true" ]; then
        section_choice_existing "Demo Mode"
        case "$SECTION_CHOICE" in
            2)
                DEMO_MODE_ENABLED=true
                read -r -p "  App Name [SignalTrace]: " demo_app_name_input
                DEMO_APP_NAME="${demo_app_name_input:-SignalTrace}"
                echo ""
                read -r -p "  Base URL: " DEMO_BASE_URL
                echo ""
                read -r -p "  Default Redirect URL [https://example.com/]: " demo_redirect_input
                DEMO_DEFAULT_REDIRECT_URL="${demo_redirect_input:-https://example.com/}"
                echo ""
                read -r -p "  Demo username to display [${_existing_demo_user:-demo}]: " demo_user_input
                DEMO_ADMIN_USERNAME_DISPLAY="${demo_user_input:-${_existing_demo_user:-demo}}"
                echo ""
                read -r -p "  Demo password to display [${_existing_demo_pass:-}]: " demo_pass_input
                DEMO_ADMIN_PASSWORD_DISPLAY="${demo_pass_input:-$_existing_demo_pass}"
                echo ""
                ;;
            3)
                DEMO_MODE_ENABLED=false
                ;;
            *)
                DEMO_MODE_ENABLED=true
                DEMO_ADMIN_USERNAME_DISPLAY="${_existing_demo_user:-demo}"
                DEMO_ADMIN_PASSWORD_DISPLAY="${_existing_demo_pass:-}"
                ;;
        esac
    else
        read -r -p "  Enable demo mode? [y/N] " do_demo
        if [[ "$do_demo" =~ ^[Yy]$ ]]; then
            DEMO_MODE_ENABLED=true
            echo ""
            read -r -p "  App Name [SignalTrace]: " demo_app_name_input
            DEMO_APP_NAME="${demo_app_name_input:-SignalTrace}"
            echo ""
            read -r -p "  Base URL: " DEMO_BASE_URL
            echo ""
            read -r -p "  Default Redirect URL [https://example.com/]: " demo_redirect_input
            DEMO_DEFAULT_REDIRECT_URL="${demo_redirect_input:-https://example.com/}"
            echo ""
            read -r -p "  Demo username to display [demo]: " demo_user_input
            DEMO_ADMIN_USERNAME_DISPLAY="${demo_user_input:-demo}"
            echo ""
            read -r -p "  Demo password to display: " DEMO_ADMIN_PASSWORD_DISPLAY
            echo ""
        fi
    fi
    echo ""
fi

# -- Optional tuning -----------------------------------------------------------
echo -e "${BOLD}── Optional Tuning ──────────────────────────────────────────${RESET}"
echo "  Press Enter to accept defaults for all of these."
echo ""

_existing_auth_failures=$(read_existing_php "AUTH_MAX_FAILURES")
read -r -p "  Auth lockout threshold [${_existing_auth_failures:-5}]: " AUTH_MAX_FAILURES_INPUT
AUTH_MAX_FAILURES="${AUTH_MAX_FAILURES_INPUT:-${_existing_auth_failures:-5}}"
echo ""

_existing_lockout_secs=$(read_existing_php "AUTH_LOCKOUT_SECS")
read -r -p "  Auth lockout duration [${_existing_lockout_secs:-900}]: " AUTH_LOCKOUT_SECS_INPUT
AUTH_LOCKOUT_SECS="${AUTH_LOCKOUT_SECS_INPUT:-${_existing_lockout_secs:-900}}"
echo ""

_existing_self_referer=$(read_existing_php "SELF_REFERER_DOMAIN")
read -r -p "  Self-referrer domain [${_existing_self_referer:-none}]: " SELF_REFERER_DOMAIN_INPUT
SELF_REFERER_DOMAIN="${SELF_REFERER_DOMAIN_INPUT:-$_existing_self_referer}"
echo ""

# -- Email alerting ------------------------------------------------------------
EMAIL_SMTP_HOST=""
EMAIL_SMTP_PORT="587"
EMAIL_SMTP_USER=""
EMAIL_SMTP_PASS=""
EMAIL_SMTP_FROM=""
EMAIL_SMTP_ENCRYPTION="tls"

if [ "$INSTALL_TYPE" = "3" ]; then
    _existing_smtp_host=$(read_existing_php "EMAIL_SMTP_HOST")
    _existing_smtp_port=$(read_existing_php "EMAIL_SMTP_PORT")
    _existing_smtp_enc=$(read_existing_php "EMAIL_SMTP_ENCRYPTION")
    _existing_smtp_user=$(read_existing_php "EMAIL_SMTP_USER")
    _existing_smtp_pass=$(read_existing_php "EMAIL_SMTP_PASS")
    _existing_smtp_from=$(read_existing_php "EMAIL_SMTP_FROM")

    echo -e "${BOLD}── Email Alerting (optional) ────────────────────────────────${RESET}"
    echo ""

    if [ "$MODIFY_EXISTING" = true ] && [ -n "$_existing_smtp_host" ]; then
        section_choice_existing "Email Alerting"
        case "$SECTION_CHOICE" in
            2)
                read -r -p "  SMTP host [${_existing_smtp_host:-smtp.example.com}]: " EMAIL_SMTP_HOST_INPUT
                EMAIL_SMTP_HOST="${EMAIL_SMTP_HOST_INPUT:-$_existing_smtp_host}"
                echo ""
                read -r -p "  SMTP port [${_existing_smtp_port:-587}]: " EMAIL_SMTP_PORT_INPUT
                EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT_INPUT:-${_existing_smtp_port:-587}}"
                echo ""
                echo "  1) TLS / STARTTLS"
                echo "  2) SSL"
                echo "  3) None"
                read -r -p "  Choice [1]: " EMAIL_ENC_INPUT
                case "${EMAIL_ENC_INPUT:-1}" in
                    2) EMAIL_SMTP_ENCRYPTION="ssl" ;;
                    3) EMAIL_SMTP_ENCRYPTION="none" ;;
                    *) EMAIL_SMTP_ENCRYPTION="tls" ;;
                esac
                echo ""
                read -r -p "  SMTP username [${_existing_smtp_user:-}]: " EMAIL_SMTP_USER_INPUT
                EMAIL_SMTP_USER="${EMAIL_SMTP_USER_INPUT:-$_existing_smtp_user}"
                echo ""
                echo "  Leave blank to keep existing password."
                read -r -s -p "  SMTP password: " EMAIL_SMTP_PASS
                echo ""
                if [ -z "$EMAIL_SMTP_PASS" ]; then
                    EMAIL_SMTP_PASS="$_existing_smtp_pass"
                fi
                echo ""
                read -r -p "  From address [${_existing_smtp_from:-$EMAIL_SMTP_USER}]: " EMAIL_SMTP_FROM_INPUT
                EMAIL_SMTP_FROM="${EMAIL_SMTP_FROM_INPUT:-${_existing_smtp_from:-$EMAIL_SMTP_USER}}"
                echo ""
                ;;
            3)
                EMAIL_SMTP_HOST=""
                EMAIL_SMTP_PORT="587"
                EMAIL_SMTP_USER=""
                EMAIL_SMTP_PASS=""
                EMAIL_SMTP_FROM=""
                EMAIL_SMTP_ENCRYPTION="tls"
                ;;
            *)
                EMAIL_SMTP_HOST="$_existing_smtp_host"
                EMAIL_SMTP_PORT="${_existing_smtp_port:-587}"
                EMAIL_SMTP_USER="$_existing_smtp_user"
                EMAIL_SMTP_PASS="$_existing_smtp_pass"
                EMAIL_SMTP_FROM="$_existing_smtp_from"
                EMAIL_SMTP_ENCRYPTION="${_existing_smtp_enc:-tls}"
                ;;
        esac
    else
        read -r -p "  Configure email alerting? [y/N] " do_email
        echo ""
        if [[ "$do_email" =~ ^[Yy]$ ]]; then
            read -r -p "  SMTP host [smtp.example.com]: " EMAIL_SMTP_HOST_INPUT
            EMAIL_SMTP_HOST="${EMAIL_SMTP_HOST_INPUT:-smtp.example.com}"
            echo ""
            read -r -p "  SMTP port [587]: " EMAIL_SMTP_PORT_INPUT
            EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT_INPUT:-587}"
            echo ""
            echo "  1) TLS / STARTTLS"
            echo "  2) SSL"
            echo "  3) None"
            read -r -p "  Choice [1]: " EMAIL_ENC_INPUT
            case "${EMAIL_ENC_INPUT:-1}" in
                2) EMAIL_SMTP_ENCRYPTION="ssl" ;;
                3) EMAIL_SMTP_ENCRYPTION="none" ;;
                *) EMAIL_SMTP_ENCRYPTION="tls" ;;
            esac
            echo ""
            read -r -p "  SMTP username: " EMAIL_SMTP_USER
            echo ""
            read -r -s -p "  SMTP password: " EMAIL_SMTP_PASS
            echo ""
            echo ""
            read -r -p "  From address [${EMAIL_SMTP_USER}]: " EMAIL_SMTP_FROM_INPUT
            EMAIL_SMTP_FROM="${EMAIL_SMTP_FROM_INPUT:-$EMAIL_SMTP_USER}"
            echo ""
        fi
    fi
fi

# -- Write config --------------------------------------------------------------
if [ "$INSTALL_TYPE" = "1" ] || [ "$INSTALL_TYPE" = "2" ]; then
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
    $SUDO mkdir -p "$SCRIPT_DIR/includes"

    $SUDO tee "$OUTPUT_FILE" > /dev/null << EOF
<?php
define('ADMIN_USERNAME',      '${ADMIN_USERNAME}');
define('ADMIN_PASSWORD_HASH', '${ADMIN_PASSWORD_HASH}');
define('VISITOR_HASH_SALT',   '${VISITOR_HASH_SALT}');
define('EXPORT_API_TOKEN',    '${SIGNALTRACE_EXPORT_API_TOKEN}');
define('TRUSTED_PROXY_IP',    '${SIGNALTRACE_TRUSTED_PROXY_IP}');
define('AUTH_MAX_FAILURES',   ${AUTH_MAX_FAILURES});
define('AUTH_LOCKOUT_SECS',   ${AUTH_LOCKOUT_SECS});
EOF

    if [ -n "$MAXMIND_ACCOUNT_ID" ]; then
        echo "define('MAXMIND_ACCOUNT_ID',  '${MAXMIND_ACCOUNT_ID}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then
        echo "define('MAXMIND_LICENSE_KEY', '${MAXMIND_LICENSE_KEY}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi
    if [ -n "$SELF_REFERER_DOMAIN" ]; then
        echo "define('SELF_REFERER_DOMAIN', '${SELF_REFERER_DOMAIN}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi
    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ]; then
        echo "" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "// Cloudflare Access" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('CF_ACCESS_ENABLED',     true);" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('CF_ACCESS_AUD',         '${CF_ACCESS_AUD_VAL}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('CF_ACCESS_TEAM_DOMAIN', '${CF_ACCESS_TEAM_DOMAIN_VAL}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi
    if [ -n "$EMAIL_SMTP_HOST" ]; then
        echo "" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "// Email alerting" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_HOST',       '${EMAIL_SMTP_HOST}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_PORT',       ${EMAIL_SMTP_PORT});" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_ENCRYPTION', '${EMAIL_SMTP_ENCRYPTION}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_USER',       '${EMAIL_SMTP_USER}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_PASS',       '${EMAIL_SMTP_PASS}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('EMAIL_SMTP_FROM',       '${EMAIL_SMTP_FROM}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi
    if [ "$DEMO_MODE_ENABLED" = true ]; then
        echo "" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "// Demo mode" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('DEMO_MODE',             true);" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('DEMO_ADMIN_USERNAME',   '${DEMO_ADMIN_USERNAME_DISPLAY}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
        echo "define('DEMO_ADMIN_PASSWORD',   '${DEMO_ADMIN_PASSWORD_DISPLAY}');" | $SUDO tee -a "$OUTPUT_FILE" > /dev/null
    fi

    $SUDO chown root:www-data "$OUTPUT_FILE"
    $SUDO chmod 640 "$OUTPUT_FILE"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}${BOLD}$(basename "$OUTPUT_FILE") written successfully.${RESET}"
echo ""

# -- Docker path ---------------------------------------------------------------
if [ "$INSTALL_TYPE" = "1" ] || [ "$INSTALL_TYPE" = "2" ]; then
    if [ "$INSTALL_TYPE" = "1" ] && [ "$CONTAINER_WAS_RUNNING" = false ] && [ "$DEFER_HASH" = false ]; then
        echo "  Pulling pre-built image..."
        docker pull ghcr.io/veddegre/signaltrace:latest
        echo ""
    elif [ "$INSTALL_TYPE" = "2" ] && [ "$CONTAINER_WAS_RUNNING" = false ] && [ "$DEFER_HASH" = false ]; then
        echo "  Building image..."
        docker compose build
        echo ""
    fi

    if [ "$INSTALL_TYPE" = "1" ]; then
        COMPOSE_CMD="docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml"
    else
        COMPOSE_CMD="docker compose"
    fi

    $COMPOSE_CMD up -d
    if [ "$CONTAINER_WAS_RUNNING" = true ]; then
        echo -e "${GREEN}  Container restarted.${RESET}"
    else
        echo -e "${GREEN}  Container started.${RESET}"
    fi
    echo ""
    echo -e "${CYAN}Available at: http://localhost:${SIGNALTRACE_PORT}/admin${RESET}"
    exit 0
fi

# -- Config-only update exit ---------------------------------------------------
if [ "$MODIFY_EXISTING" = true ] && [ "$RUN_SYSTEM_TASKS" != "true" ]; then
    echo -e "${GREEN}Config updated without re-running system/infrastructure tasks.${RESET}"
    echo ""
    if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
        echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
        echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
        echo ""
    fi
    exit 0
fi

# -- Manual install continue ---------------------------------------------------
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installing PHP dependencies..."
echo ""
cd "$SCRIPT_DIR" && COMPOSER_ALLOW_SUPERUSER=1 $SUDO composer update --no-dev --no-interaction
echo -e "${GREEN}  PHP dependencies installed.${RESET}"
echo ""

if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Configuring GeoIP..."
    echo ""
    $SUDO mkdir -p /var/lib/GeoIP
    $SUDO tee /etc/GeoIP.conf > /dev/null << EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-ASN GeoLite2-Country
DatabaseDirectory /var/lib/GeoIP
EOF
    echo "  /etc/GeoIP.conf written."
    echo "  Downloading GeoIP databases..."
    if $SUDO geoipupdate; then
        echo -e "${GREEN}  GeoIP databases downloaded to /var/lib/GeoIP/.${RESET}"
    else
        echo -e "${YELLOW}  Warning: geoipupdate failed.${RESET}"
    fi
    echo ""
else
    echo -e "${YELLOW}Note: MaxMind credentials not provided — GeoIP enrichment will be unavailable.${RESET}"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
DB_FILE="${INSTALL_DIR}/data/database.db"
DB_DIR="${INSTALL_DIR}/data"

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
    $SUDO mkdir -p "$DB_DIR"
    [ -f "$DB_FILE" ] && $SUDO rm -f "$DB_FILE"
    $SUDO sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/schema.sql"
    echo -e "${GREEN}  Database initialised.${RESET}"
    echo ""

    read -r -p "  Load sample data so the dashboard has something to show? [y/N] " doseed
    if [[ "$doseed" =~ ^[Yy]$ ]]; then
        $SUDO sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/seed.sql"
        echo -e "${GREEN}  Sample data loaded.${RESET}"
    fi

    if [ "$DEMO_MODE_ENABLED" = true ]; then
        $SUDO sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('app_name', '${DEMO_APP_NAME}');"
        $SUDO sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('base_url', '${DEMO_BASE_URL}');"
        $SUDO sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('default_redirect_url', '${DEMO_DEFAULT_REDIRECT_URL}');"
        echo -e "${GREEN}  Demo settings seeded into database.${RESET}"
    fi
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Setting file ownership and permissions..."

$SUDO chown root:root "$INSTALL_DIR"
$SUDO chmod 755 "$INSTALL_DIR"

if [ -d "${INSTALL_DIR}/includes" ]; then
    $SUDO chown -R root:www-data "${INSTALL_DIR}/includes"
    $SUDO find "${INSTALL_DIR}/includes" -type d -exec chmod 750 {} \;
    $SUDO find "${INSTALL_DIR}/includes" -type f -exec chmod 640 {} \;
    echo -e "${GREEN}  includes/ — root:www-data, dirs 750 files 640${RESET}"
fi

if [ -d "${INSTALL_DIR}/public" ]; then
    $SUDO chown -R root:www-data "${INSTALL_DIR}/public"
    $SUDO find "${INSTALL_DIR}/public" -type d -exec chmod 755 {} \;
    $SUDO find "${INSTALL_DIR}/public" -type f -exec chmod 644 {} \;
    echo -e "${GREEN}  public/ — root:www-data, dirs 755 files 644${RESET}"
fi

if [ -d "${INSTALL_DIR}/db" ]; then
    $SUDO chown -R root:www-data "${INSTALL_DIR}/db"
    $SUDO find "${INSTALL_DIR}/db" -type d -exec chmod 750 {} \;
    $SUDO find "${INSTALL_DIR}/db" -type f -exec chmod 640 {} \;
    echo -e "${GREEN}  db/ — root:www-data, dirs 750 files 640${RESET}"
fi

if [ -d "${INSTALL_DIR}/vendor" ]; then
    $SUDO chown -R root:www-data "${INSTALL_DIR}/vendor"
    $SUDO find "${INSTALL_DIR}/vendor" -type d -exec chmod 755 {} \;
    $SUDO find "${INSTALL_DIR}/vendor" -type f -exec chmod 644 {} \;
    echo -e "${GREEN}  vendor/ — root:www-data, dirs 755 files 644${RESET}"
fi

$SUDO mkdir -p "$DB_DIR"
$SUDO chown -R www-data:www-data "$DB_DIR"
$SUDO find "$DB_DIR" -type d -exec chmod 770 {} \;
$SUDO find "$DB_DIR" -type f -exec chmod 660 {} \;
if [ -f "$DB_FILE" ]; then
    echo -e "${GREEN}  data/database.db — www-data:www-data, 660${RESET}"
fi
echo ""

if [ "$CF_DNS_PLUGIN_ENABLED" = "true" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Configuring Cloudflare DNS plugin credentials..."
    echo ""
    $SUDO mkdir -p /root/.secrets/certbot
    $SUDO tee /root/.secrets/certbot/cloudflare.ini > /dev/null << EOF
dns_cloudflare_api_token = ${CF_DNS_API_TOKEN}
EOF
    $SUDO chmod 600 /root/.secrets/certbot/cloudflare.ini
    echo -e "${GREEN}  Cloudflare certbot credentials written.${RESET}"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Configuring Apache..."
echo ""
read -r -p "  ServerName (your domain or IP, e.g. signaltrace.example.com): " APACHE_SERVER_NAME
APACHE_SERVER_NAME="${APACHE_SERVER_NAME:-localhost}"

$SUDO tee /etc/apache2/sites-available/signaltrace.conf > /dev/null << EOF
<VirtualHost *:80>
    ServerName ${APACHE_SERVER_NAME}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_access.log combined
</VirtualHost>
EOF

if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
    $SUDO tee /etc/apache2/sites-available/signaltrace-admin.conf > /dev/null << EOF
<VirtualHost *:80>
    ServerName ${CF_ADMIN_SUBDOMAIN}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/signaltrace_admin_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_admin_access.log combined
</VirtualHost>
EOF
    $SUDO a2ensite signaltrace-admin.conf > /dev/null
    echo -e "${GREEN}  Admin subdomain HTTP vhost created for ${CF_ADMIN_SUBDOMAIN}.${RESET}"
fi

$SUDO a2enmod rewrite ssl > /dev/null
$SUDO a2ensite signaltrace.conf > /dev/null
$SUDO a2dissite 000-default.conf > /dev/null 2>&1 || true
$SUDO systemctl restart apache2
echo -e "${GREEN}  Apache configured and restarted.${RESET}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}HTTPS with Let's Encrypt (optional)${RESET}"
echo ""
read -r -p "  Set up HTTPS now? [y/N] " do_letsencrypt
if [[ "$do_letsencrypt" =~ ^[Yy]$ ]]; then
    echo ""
    read -r -p "  Email address for Let's Encrypt notifications: " LE_EMAIL
    if [ -z "$LE_EMAIL" ]; then
        echo -e "${YELLOW}No email provided — skipping HTTPS setup.${RESET}"
    else
        if [ "$CF_DNS_PLUGIN_ENABLED" = "true" ]; then
            echo "  Requesting certificate using Cloudflare DNS validation..."
            if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                $SUDO certbot certonly \
                    --dns-cloudflare \
                    --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
                    --non-interactive \
                    --agree-tos \
                    --email "$LE_EMAIL" \
                    -d "$APACHE_SERVER_NAME" \
                    -d "$CF_ADMIN_SUBDOMAIN"
            else
                $SUDO certbot certonly \
                    --dns-cloudflare \
                    --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
                    --non-interactive \
                    --agree-tos \
                    --email "$LE_EMAIL" \
                    -d "$APACHE_SERVER_NAME"
            fi
            HTTPS_ENABLED=true
        else
            echo "  Requesting certificate using Apache validation..."
            if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                $SUDO certbot --apache \
                    --non-interactive \
                    --agree-tos \
                    --email "$LE_EMAIL" \
                    -d "$APACHE_SERVER_NAME" \
                    -d "$CF_ADMIN_SUBDOMAIN" \
                    --redirect
            else
                $SUDO certbot --apache \
                    --non-interactive \
                    --agree-tos \
                    --email "$LE_EMAIL" \
                    -d "$APACHE_SERVER_NAME" \
                    --redirect
            fi
            HTTPS_ENABLED=true
        fi

        if [ "${HTTPS_ENABLED:-false}" = true ] && [ "$CF_DNS_PLUGIN_ENABLED" = "true" ]; then
            $SUDO tee /etc/apache2/sites-available/signaltrace-le-ssl.conf > /dev/null << EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName ${APACHE_SERVER_NAME}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_access.log combined

    Include /etc/letsencrypt/options-ssl-apache.conf
    SSLCertificateFile /etc/letsencrypt/live/${APACHE_SERVER_NAME}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${APACHE_SERVER_NAME}/privkey.pem
</VirtualHost>
</IfModule>
EOF
            $SUDO a2ensite signaltrace-le-ssl.conf > /dev/null

            if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                $SUDO tee /etc/apache2/sites-available/signaltrace-admin-le-ssl.conf > /dev/null << EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName ${CF_ADMIN_SUBDOMAIN}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    RewriteEngine On
    RewriteRule ^/?$ /admin [R=302,L]

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/signaltrace_admin_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_admin_ssl_access.log combined

    Include /etc/letsencrypt/options-ssl-apache.conf
    SSLCertificateFile /etc/letsencrypt/live/${APACHE_SERVER_NAME}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${APACHE_SERVER_NAME}/privkey.pem
</VirtualHost>
</IfModule>
EOF
                $SUDO a2ensite signaltrace-admin-le-ssl.conf > /dev/null
            fi

            $SUDO systemctl reload apache2
        fi
    fi
fi
echo ""

if [ "${HTTPS_ENABLED:-false}" = true ]; then
    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
        echo -e "${CYAN}SignalTrace URLs:${RESET}"
        echo "  Public honeypot: https://${APACHE_SERVER_NAME}"
        echo "  Admin panel:     https://${CF_ADMIN_SUBDOMAIN}"
        echo ""
        echo -e "${YELLOW}Cloudflare Access reminder:${RESET}"
        echo "  Make sure your Zero Trust Access application covers:"
        echo "    ${CF_ADMIN_SUBDOMAIN}/*"
    else
        echo -e "${CYAN}SignalTrace is available at: https://${APACHE_SERVER_NAME}/admin${RESET}"
    fi
else
    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
        echo -e "${CYAN}SignalTrace URLs:${RESET}"
        echo "  Public honeypot: http://${APACHE_SERVER_NAME}"
        echo "  Admin panel:     http://${CF_ADMIN_SUBDOMAIN}"
    else
        echo -e "${CYAN}SignalTrace is available at: http://${APACHE_SERVER_NAME}/admin${RESET}"
    fi
fi

if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
    echo ""
    echo -e "${YELLOW}Cloudflare setup checklist:${RESET}"
    echo "  1. Create/proxy DNS records for ${APACHE_SERVER_NAME} and ${CF_ADMIN_SUBDOMAIN}"
    echo "  2. Create a Zero Trust Access application for ${CF_ADMIN_SUBDOMAIN}/*"
    echo "  3. Add your policy/users/groups"
    if [ "$CF_DNS_PLUGIN_ENABLED" = "true" ]; then
        echo "  4. Certbot renewals can use the Cloudflare DNS plugin even while proxied"
    else
        echo "  4. Consider rerunning setup later with a Cloudflare DNS API token for renewals"
    fi
fi

echo ""
if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
    echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
    echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
    echo ""
fi
