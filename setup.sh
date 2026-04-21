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

# -- For manual installs: install packages and clone repo first ---------------
if [ "$INSTALL_TYPE" = "3" ]; then
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
        SCRIPT_DIR="$INSTALL_DIR"
        echo -e "  ${GREEN}Repository cloned to ${INSTALL_DIR}.${RESET}"
        echo ""
    fi

    OUTPUT_FILE="$SCRIPT_DIR/includes/config.local.php"
else
    OUTPUT_FILE="$SCRIPT_DIR/.env"
fi

# -- Guard: existing config file -----------------------------------------------
MODIFY_EXISTING=false
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "${YELLOW}$(basename "$OUTPUT_FILE") already exists.${RESET}"
    echo ""
    echo "  1) Update it — keep existing values as defaults, change only what you re-enter"
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
            echo -e "  ${GREEN}Will update existing values — press Enter to keep current value.${RESET}"
            ;;
    esac
    echo ""
fi

# -- Helper: read existing value from config.local.php -------------------------
read_existing_php() {
    local key="$1"
    if [ "$MODIFY_EXISTING" = true ] && [ -f "$OUTPUT_FILE" ]; then
        # Extract the value from define('KEY', 'value'); or define('KEY', value);
        grep -oP "define\('${key}',\s*'?\K[^';)]*" "$OUTPUT_FILE" 2>/dev/null | head -1
    fi
}

# -- Helper: read existing value from .env ------------------------------------
read_existing_env() {
    local key="$1"
    if [ "$MODIFY_EXISTING" = true ] && [ -f "$OUTPUT_FILE" ]; then
        grep -oP "^${key}=\"?\K[^\"]*" "$OUTPUT_FILE" 2>/dev/null | head -1
    fi
}

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
_existing_username=$(read_existing_php "ADMIN_USERNAME")
prompt "Admin username" ADMIN_USERNAME "${_existing_username:-admin}"

# -- Admin password ------------------------------------------------------------
echo -e "${CYAN}Admin password${RESET}"
if [ "$MODIFY_EXISTING" = true ]; then
    echo "  Leave blank to keep your existing password hash unchanged."
    read -r -s -p "  New password (blank to keep existing): " ADMIN_PASSWORD
    echo ""
    if [ -z "$ADMIN_PASSWORD" ]; then
        # Keep existing hash — read it from the file
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
        fi
    fi
else
    echo "  Enter a password and the script will hash it for you."
    while true; do
        read -r -s -p "  Password: " ADMIN_PASSWORD
        echo ""
        if [ -z "$ADMIN_PASSWORD" ]; then
            echo -e "  ${RED}Error: password cannot be blank.${RESET}"
            continue
        fi
        read -r -s -p "  Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo ""
        if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
            echo -e "  ${RED}Passwords do not match. Try again.${RESET}"
            echo ""
        else
            break
        fi
    done
fi

DEFER_HASH=false

if [ -n "$ADMIN_PASSWORD" ]; then
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
    echo -e "  ${GREEN}Salt generated.${RESET}"
fi
echo ""

# -- Docker only: port ---------------------------------------------------------
CONTAINER_WAS_RUNNING=false
if [ "$INSTALL_TYPE" = "1" ] || [ "$INSTALL_TYPE" = "2" ]; then
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

# -- Cloudflare Access (manual installs only) ----------------------------------
CF_ACCESS_ENABLED_VAL="false"
CF_ACCESS_AUD_VAL=""
CF_ACCESS_TEAM_DOMAIN_VAL=""
CF_ADMIN_SUBDOMAIN=""

if [ "$INSTALL_TYPE" = "3" ]; then
    echo -e "${BOLD}── Cloudflare Access (optional) ─────────────────────────────${RESET}"
    echo "  Adds per-user identity and MFA in front of /admin using"
    echo "  Cloudflare Zero Trust. Requires your domain to be on Cloudflare."
    echo "  See the wiki for setup instructions before enabling this."
    echo ""
    read -r -p "  Enable Cloudflare Access? [y/N] " do_cf_access
    if [[ "$do_cf_access" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${CYAN}Cloudflare Access AUD token${RESET}"
        echo "  Found in Zero Trust → Access controls → Applications → Edit → Additional settings → Token"
        read -r -p "  Value: " CF_ACCESS_AUD_VAL
        echo ""
        echo -e "${CYAN}Cloudflare team domain${RESET}"
        echo "  Found in Zero Trust → Settings → Teams tab (e.g. yourteam.cloudflareaccess.com)"
        read -r -p "  Value: " CF_ACCESS_TEAM_DOMAIN_VAL
        echo ""
        echo -e "${CYAN}Admin subdomain${RESET}"
        echo "  The subdomain Cloudflare Access will protect (e.g. admin.example.com)."
        echo "  A dedicated Apache vhost will be created for this subdomain that"
        echo "  routes all traffic to /admin. Leave blank to skip the vhost."
        read -r -p "  Value (e.g. admin.yourdomain.com): " CF_ADMIN_SUBDOMAIN
        echo ""
        if [ -n "$CF_ACCESS_AUD_VAL" ] && [ -n "$CF_ACCESS_TEAM_DOMAIN_VAL" ]; then
            CF_ACCESS_ENABLED_VAL="true"
            echo -e "  ${GREEN}Cloudflare Access enabled.${RESET}"
        else
            echo -e "  ${YELLOW}AUD or team domain missing — Cloudflare Access will not be enabled.${RESET}"
        fi
    fi
    echo ""
fi

# -- Demo mode (manual installs only) -----------------------------------------
DEMO_MODE_ENABLED=false
DEMO_APP_NAME="SignalTrace"
DEMO_BASE_URL=""
DEMO_DEFAULT_REDIRECT_URL="https://example.com/"
DEMO_ADMIN_USERNAME_DISPLAY="demo"
DEMO_ADMIN_PASSWORD_DISPLAY=""

if [ "$INSTALL_TYPE" = "3" ]; then
    echo -e "${BOLD}── Demo Mode (optional) ──────────────────────────────────────${RESET}"
    echo "  Demo mode shows a banner with a reset countdown and locks"
    echo "  certain settings so visitors cannot change them."
    echo ""
    read -r -p "  Enable demo mode? [y/N] " do_demo
    if [[ "$do_demo" =~ ^[Yy]$ ]]; then
        DEMO_MODE_ENABLED=true
        echo ""

        echo -e "${CYAN}App Name${RESET}"
        echo "  Displayed in the admin header."
        read -r -p "  Value [SignalTrace]: " demo_app_name_input
        DEMO_APP_NAME="${demo_app_name_input:-SignalTrace}"
        echo ""

        echo -e "${CYAN}Base URL${RESET}"
        echo "  The public URL of this install (e.g. https://trysignaltrace.com)."
        echo "  Used to build threat feed and export endpoint URLs in Settings."
        read -r -p "  Value: " DEMO_BASE_URL
        echo ""

        echo -e "${CYAN}Default Redirect URL${RESET}"
        echo "  Where unknown honeypot paths redirect to."
        read -r -p "  Value [https://example.com/]: " demo_redirect_input
        DEMO_DEFAULT_REDIRECT_URL="${demo_redirect_input:-https://example.com/}"
        echo ""

        echo -e "${CYAN}Demo username to display in banner${RESET}"
        read -r -p "  Value [demo]: " demo_user_input
        DEMO_ADMIN_USERNAME_DISPLAY="${demo_user_input:-demo}"
        echo ""

        echo -e "${CYAN}Demo password to display in banner${RESET}"
        echo "  This is display-only — it does not set the actual password."
        read -r -p "  Value: " DEMO_ADMIN_PASSWORD_DISPLAY
        echo ""

        echo -e "  ${GREEN}Demo mode enabled.${RESET}"
    fi
    echo ""
fi


echo -e "${BOLD}── Optional Tuning ──────────────────────────────────────────${RESET}"
echo "  Press Enter to accept defaults for all of these."
echo ""

_existing_auth_failures=$(read_existing_php "AUTH_MAX_FAILURES")
echo -e "${CYAN}Auth lockout threshold${RESET}"
echo "  Failed login attempts before an IP is locked out."
read -r -p "  Value [${_existing_auth_failures:-5}]: " AUTH_MAX_FAILURES_INPUT
AUTH_MAX_FAILURES="${AUTH_MAX_FAILURES_INPUT:-${_existing_auth_failures:-5}}"
echo ""

_existing_lockout_secs=$(read_existing_php "AUTH_LOCKOUT_SECS")
echo -e "${CYAN}Auth lockout duration${RESET}"
echo "  How long a lockout lasts in seconds."
read -r -p "  Value [${_existing_lockout_secs:-900}]: " AUTH_LOCKOUT_SECS_INPUT
AUTH_LOCKOUT_SECS="${AUTH_LOCKOUT_SECS_INPUT:-${_existing_lockout_secs:-900}}"
echo ""

_existing_self_referer=$(read_existing_php "SELF_REFERER_DOMAIN")
echo -e "${CYAN}Self-referrer domain${RESET}"
echo "  Your site's own domain (e.g. example.com). When set, requests"
echo "  arriving at / with your domain in the Referer header receive a"
echo "  score penalty — helps catch crawler traffic. Leave blank to disable."
read -r -p "  Value [${_existing_self_referer:-none}]: " SELF_REFERER_DOMAIN_INPUT
SELF_REFERER_DOMAIN="${SELF_REFERER_DOMAIN_INPUT:-$_existing_self_referer}"
echo ""

# -- Email alerting (manual installs only) ------------------------------------
EMAIL_SMTP_HOST=""
EMAIL_SMTP_PORT="587"
EMAIL_SMTP_USER=""
EMAIL_SMTP_PASS=""
EMAIL_SMTP_FROM=""
EMAIL_SMTP_ENCRYPTION="tls"

if [ "$INSTALL_TYPE" = "3" ]; then
    _existing_smtp_host=$(read_existing_php "EMAIL_SMTP_HOST")

    echo -e "${BOLD}── Email Alerting (optional) ────────────────────────────────${RESET}"
    echo ""
    echo -e "${YELLOW}${BOLD}Security notice:${RESET}"
    echo "  SMTP credentials give anyone who has them the ability to send email"
    echo "  on your behalf. They will be written to config.local.php and stored"
    echo "  on disk in plain text — do not use credentials shared with other"
    echo "  services, and restrict file access to root:www-data (640)."
    echo "  SignalTrace never stores these credentials in the database or exposes"
    echo "  them through the admin UI."
    echo ""

    if [ -n "$_existing_smtp_host" ]; then
        echo -e "  ${CYAN}Existing SMTP host: ${_existing_smtp_host}${RESET}"
        echo ""
        echo "  1) Keep existing email configuration"
        echo "  2) Reconfigure email alerting"
        echo "  3) Remove email alerting"
        echo ""
        read -r -p "  Choice [1]: " email_choice
        case "${email_choice:-1}" in
            2) do_email="y" ;;
            3)
                echo -e "  ${YELLOW}Email alerting will be removed from config.local.php.${RESET}"
                echo ""
                # Leave EMAIL_SMTP_HOST blank so nothing gets written
                ;;
            *)
                EMAIL_SMTP_HOST=$(read_existing_php "EMAIL_SMTP_HOST")
                EMAIL_SMTP_PORT=$(read_existing_php "EMAIL_SMTP_PORT")
                EMAIL_SMTP_ENCRYPTION=$(read_existing_php "EMAIL_SMTP_ENCRYPTION")
                EMAIL_SMTP_USER=$(read_existing_php "EMAIL_SMTP_USER")
                EMAIL_SMTP_PASS=$(read_existing_php "EMAIL_SMTP_PASS")
                EMAIL_SMTP_FROM=$(read_existing_php "EMAIL_SMTP_FROM")
                echo -e "  ${GREEN}Keeping existing email configuration.${RESET}"
                echo ""
                do_email="n"
                ;;
        esac
    else
        echo "  SignalTrace can send email alerts when threats are detected or"
        echo "  canary tokens are hit. Alerting is disabled by default."
        echo ""
        read -r -p "  Configure email alerting? [y/N] " do_email
        echo ""
    fi

    if [[ "$do_email" =~ ^[Yy]$ ]]; then
        echo -e "${BOLD}── SMTP Configuration ───────────────────────────────────────${RESET}"
        echo ""

        _existing_smtp_host=$(read_existing_php "EMAIL_SMTP_HOST")
        echo -e "${CYAN}SMTP host${RESET}"
        echo "  The hostname of your outbound mail server."
        read -r -p "  Value [${_existing_smtp_host:-smtp.example.com}]: " EMAIL_SMTP_HOST_INPUT
        EMAIL_SMTP_HOST="${EMAIL_SMTP_HOST_INPUT:-$_existing_smtp_host}"
        echo ""

        _existing_smtp_port=$(read_existing_php "EMAIL_SMTP_PORT")
        echo -e "${CYAN}SMTP port${RESET}"
        read -r -p "  Value [${_existing_smtp_port:-587}]: " EMAIL_SMTP_PORT_INPUT
        EMAIL_SMTP_PORT="${EMAIL_SMTP_PORT_INPUT:-${_existing_smtp_port:-587}}"
        echo ""

        echo -e "${CYAN}SMTP encryption${RESET}"
        echo "  1) TLS / STARTTLS (port 587, recommended)"
        echo "  2) SSL (port 465)"
        echo "  3) None (port 25, not recommended)"
        read -r -p "  Choice [1]: " EMAIL_ENC_INPUT
        case "${EMAIL_ENC_INPUT:-1}" in
            2) EMAIL_SMTP_ENCRYPTION="ssl" ;;
            3) EMAIL_SMTP_ENCRYPTION="none" ;;
            *) EMAIL_SMTP_ENCRYPTION="tls" ;;
        esac
        echo ""

        _existing_smtp_user=$(read_existing_php "EMAIL_SMTP_USER")
        echo -e "${CYAN}SMTP username${RESET}"
        read -r -p "  Value [${_existing_smtp_user:-}]: " EMAIL_SMTP_USER_INPUT
        EMAIL_SMTP_USER="${EMAIL_SMTP_USER_INPUT:-$_existing_smtp_user}"
        echo ""

        echo -e "${CYAN}SMTP password${RESET}"
        if [ -n "$(read_existing_php "EMAIL_SMTP_PASS")" ]; then
            echo "  Leave blank to keep existing password."
            read -r -s -p "  New password (blank to keep): " EMAIL_SMTP_PASS
            echo ""
            if [ -z "$EMAIL_SMTP_PASS" ]; then
                EMAIL_SMTP_PASS=$(read_existing_php "EMAIL_SMTP_PASS")
                echo -e "  ${GREEN}Keeping existing password.${RESET}"
            fi
        else
            read -r -s -p "  Value: " EMAIL_SMTP_PASS
            echo ""
        fi
        echo ""

        _existing_smtp_from=$(read_existing_php "EMAIL_SMTP_FROM")
        echo -e "${CYAN}From address${RESET}"
        echo "  The address that appears in the From field of alert emails."
        read -r -p "  Value [${_existing_smtp_from:-$EMAIL_SMTP_USER}]: " EMAIL_SMTP_FROM_INPUT
        EMAIL_SMTP_FROM="${EMAIL_SMTP_FROM_INPUT:-${_existing_smtp_from:-$EMAIL_SMTP_USER}}"
        echo ""

        echo -e "${GREEN}SMTP credentials will be written to config.local.php.${RESET}"
        echo "  After install, go to Settings → Email Alerting to:"
        echo "  • Enable alerting and set the recipient address"
        echo "  • Configure the classification threshold (bot, suspicious, etc.)"
        echo "  • Opt individual canary tokens in to per-hit email alerts"
        echo ""
    fi
fi

# -- Write output file ---------------------------------------------------------
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
    # Manual install — write config.local.php
    cat > "$OUTPUT_FILE" << EOF
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
        echo "define('MAXMIND_ACCOUNT_ID',  '${MAXMIND_ACCOUNT_ID}');" >> "$OUTPUT_FILE"
    fi
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then
        echo "define('MAXMIND_LICENSE_KEY', '${MAXMIND_LICENSE_KEY}');" >> "$OUTPUT_FILE"
    fi
    if [ -n "$SELF_REFERER_DOMAIN" ]; then
        echo "define('SELF_REFERER_DOMAIN', '${SELF_REFERER_DOMAIN}');" >> "$OUTPUT_FILE"
    fi
    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "// Cloudflare Access" >> "$OUTPUT_FILE"
        echo "define('CF_ACCESS_ENABLED',     true);" >> "$OUTPUT_FILE"
        echo "define('CF_ACCESS_AUD',         '${CF_ACCESS_AUD_VAL}');" >> "$OUTPUT_FILE"
        echo "define('CF_ACCESS_TEAM_DOMAIN', '${CF_ACCESS_TEAM_DOMAIN_VAL}');" >> "$OUTPUT_FILE"
    fi
    if [ -n "$EMAIL_SMTP_HOST" ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "// Email alerting — SMTP credentials (configure thresholds and recipients in Settings)" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_HOST',       '${EMAIL_SMTP_HOST}');" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_PORT',       ${EMAIL_SMTP_PORT});" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_ENCRYPTION', '${EMAIL_SMTP_ENCRYPTION}');" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_USER',       '${EMAIL_SMTP_USER}');" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_PASS',       '${EMAIL_SMTP_PASS}');" >> "$OUTPUT_FILE"
        echo "define('EMAIL_SMTP_FROM',       '${EMAIL_SMTP_FROM}');" >> "$OUTPUT_FILE"
    fi
    if [ "$DEMO_MODE_ENABLED" = true ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "// Demo mode" >> "$OUTPUT_FILE"
        echo "define('DEMO_MODE',             true);" >> "$OUTPUT_FILE"
        echo "define('DEMO_ADMIN_USERNAME',   '${DEMO_ADMIN_USERNAME_DISPLAY}');" >> "$OUTPUT_FILE"
        echo "define('DEMO_ADMIN_PASSWORD',   '${DEMO_ADMIN_PASSWORD_DISPLAY}');" >> "$OUTPUT_FILE"
    fi
fi

# -- Deferred hash generation (Docker, no local PHP) --------------------------
if [ "$DEFER_HASH" = true ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Generating password hash via Docker..."
    echo ""

    if [ "$INSTALL_TYPE" = "1" ]; then
        echo "  Pulling pre-built image to generate hash..."
        docker pull ghcr.io/veddegre/signaltrace:latest
    else
        if ! docker image inspect signaltrace-signaltrace &>/dev/null; then
            echo "  Building container image first..."
            docker compose build
        fi
    fi

    echo "  Starting container to generate hash..."
    if [ "$INSTALL_TYPE" = "1" ]; then
        docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml up -d 2>/dev/null
    else
        docker compose up -d 2>/dev/null
    fi
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
    if [ "$CONTAINER_WAS_RUNNING" = true ]; then
        $COMPOSE_CMD up -d
        echo -e "  ${GREEN}Container restarted.${RESET}"
    else
        $COMPOSE_CMD up -d
        echo -e "  ${GREEN}Container started.${RESET}"
    fi
    echo ""
    echo -e "${CYAN}Available at: http://localhost:${SIGNALTRACE_PORT}/admin${RESET}"
else
    # ── Composer dependencies -------------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Installing PHP dependencies..."
    echo ""
    cd "$SCRIPT_DIR" && composer update --no-dev --no-interaction
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: composer update failed.${RESET}"
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
        sudo mkdir -p "$DB_DIR"
        [ -f "$DB_FILE" ] && sudo rm -f "$DB_FILE"
        sudo sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/schema.sql"
        echo -e "  ${GREEN}Database initialised.${RESET}"
        echo ""

        read -r -p "  Load sample data so the dashboard has something to show? [y/N] " doseed
        if [[ "$doseed" =~ ^[Yy]$ ]]; then
            sudo sqlite3 "$DB_FILE" < "$SCRIPT_DIR/db/seed.sql"
            echo -e "  ${GREEN}Sample data loaded.${RESET}"
        fi

        # Seed demo settings into the database so they are correct from first boot.
        # These fields are locked in the UI when DEMO_MODE is true so they cannot
        # be changed through the Settings form.
        if [ "$DEMO_MODE_ENABLED" = true ]; then
            sudo sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('app_name', '${DEMO_APP_NAME}');"
            sudo sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('base_url', '${DEMO_BASE_URL}');"
            sudo sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO settings (key, value) VALUES ('default_redirect_url', '${DEMO_DEFAULT_REDIRECT_URL}');"
            echo -e "  ${GREEN}Demo settings seeded into database.${RESET}"
        fi
    fi
    echo ""

    # ── Fix ownership and permissions -----------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Setting file ownership and permissions..."

    # includes/, public/, db/, vendor/ — root-owned, web server read-only
    sudo chown -R root:www-data "${INSTALL_DIR}/includes/"
    sudo chmod 750 "${INSTALL_DIR}/includes/"
    sudo find "${INSTALL_DIR}/includes/" -type f -exec chmod 640 {} \;
    echo -e "  ${GREEN}includes/ — root:www-data (640)${RESET}"

    sudo chown -R root:www-data "${INSTALL_DIR}/public/"
    sudo chmod 750 "${INSTALL_DIR}/public/"
    sudo find "${INSTALL_DIR}/public/" -type f -exec chmod 640 {} \;
    echo -e "  ${GREEN}public/ — root:www-data (640)${RESET}"

    sudo chown -R root:www-data "${INSTALL_DIR}/db/"
    sudo chmod 750 "${INSTALL_DIR}/db/"
    sudo find "${INSTALL_DIR}/db/" -type f -exec chmod 640 {} \;
    echo -e "  ${GREEN}db/ — root:www-data (640)${RESET}"

    sudo chown -R root:www-data "${INSTALL_DIR}/vendor/"
    sudo find "${INSTALL_DIR}/vendor/" -type d -exec chmod 750 {} \;
    sudo find "${INSTALL_DIR}/vendor/" -type f -exec chmod 640 {} \;
    echo -e "  ${GREEN}vendor/ — root:www-data (640)${RESET}"

    # data/ — web server needs write on database and directory only
    sudo chown root:www-data "$DB_DIR"
    sudo chmod 770 "$DB_DIR"
    if [ -f "$DB_FILE" ]; then
        sudo chown root:www-data "$DB_FILE"
        sudo chmod 660 "$DB_FILE"
        echo -e "  ${GREEN}data/database.db — root:www-data (660)${RESET}"
    fi
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

    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_access.log combined
</VirtualHost>
APACHECONF

    # ── Admin subdomain vhost (Cloudflare Access) -----------------------------
    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
        sudo tee /etc/apache2/sites-available/signaltrace-admin.conf > /dev/null << ADMINCONF
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

    ErrorLog  \${APACHE_LOG_DIR}/signaltrace_admin_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_admin_access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName ${CF_ADMIN_SUBDOMAIN}
    DocumentRoot /var/www/signaltrace/public

    SetEnvIf Authorization "^(.*)$" HTTP_AUTHORIZATION=\$1

    # Route all traffic on this subdomain to /admin so that
    # https://admin.yourdomain.com routes cleanly to the admin panel.
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/admin
    RewriteCond %{REQUEST_URI} !^/admin\.css
    RewriteCond %{REQUEST_URI} !^/signaltrace_transparent\.png
    RewriteCond %{REQUEST_URI} !^/favicon
    RewriteCond %{REQUEST_URI} !^/health
    RewriteRule ^(.*)$ /admin [L]

    SSLEngine on
    # Paths filled in by certbot — run: sudo certbot --apache
    # SSLCertificateFile    /etc/letsencrypt/live/${CF_ADMIN_SUBDOMAIN}/fullchain.pem
    # SSLCertificateKeyFile /etc/letsencrypt/live/${CF_ADMIN_SUBDOMAIN}/privkey.pem

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/signaltrace_admin_error.log
    CustomLog \${APACHE_LOG_DIR}/signaltrace_admin_access.log combined
</VirtualHost>
ADMINCONF

        sudo a2ensite signaltrace-admin.conf > /dev/null
        echo -e "  ${GREEN}Admin subdomain vhost created for ${CF_ADMIN_SUBDOMAIN}.${RESET}"
    fi

    sudo a2enmod rewrite ssl
    sudo a2ensite signaltrace.conf
    sudo a2dissite 000-default.conf 2>/dev/null || true
    sudo systemctl restart apache2
    echo -e "  ${GREEN}Apache configured and restarted.${RESET}"
    echo ""

    # ── Let's Encrypt ---------------------------------------------------------
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CYAN}HTTPS with Let's Encrypt (optional)${RESET}"
    echo "  Requires a real domain name pointed at this server."
    echo "  Will not work with an IP address or localhost."
    echo ""
    read -r -p "  Set up HTTPS now? [y/N] " do_letsencrypt
    if [[ "$do_letsencrypt" =~ ^[Yy]$ ]]; then
        echo ""
        read -r -p "  Email address for Let's Encrypt notifications: " LE_EMAIL
        if [ -z "$LE_EMAIL" ]; then
            echo -e "  ${YELLOW}No email provided — skipping HTTPS setup.${RESET}"
        else
            echo "  Installing certbot..."
            sudo apt-get install -y certbot python3-certbot-apache -qq
            echo "  Requesting certificate for ${APACHE_SERVER_NAME}..."

            # Include admin subdomain in certificate if configured
            LE_DOMAINS="$APACHE_SERVER_NAME"
            if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
                LE_DOMAINS="${LE_DOMAINS},${CF_ADMIN_SUBDOMAIN}"
            fi

            if sudo certbot --apache \
                --non-interactive \
                --agree-tos \
                --email "$LE_EMAIL" \
                --domains "$LE_DOMAINS" \
                --redirect; then
                echo -e "  ${GREEN}HTTPS configured. Certificate will auto-renew.${RESET}"
                HTTPS_ENABLED=true
            else
                echo -e "  ${YELLOW}Certbot failed. Make sure your domain is pointed at this server and try:${RESET}"
                echo "  sudo certbot --apache"
            fi
        fi
    fi
    echo ""

    if [ "${HTTPS_ENABLED:-false}" = true ]; then
        if [ "$CF_ACCESS_ENABLED_VAL" = "true" ] && [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
            echo -e "${CYAN}SignalTrace URLs:${RESET}"
            echo "  Public honeypot: https://${APACHE_SERVER_NAME}"
            echo "  Admin panel:     https://${CF_ADMIN_SUBDOMAIN}"
        else
            echo -e "${CYAN}SignalTrace is available at: https://${APACHE_SERVER_NAME}/admin${RESET}"
        fi
    else
        echo -e "${CYAN}SignalTrace is available at: http://${APACHE_SERVER_NAME}/admin${RESET}"
    fi

    if [ "$CF_ACCESS_ENABLED_VAL" = "true" ]; then
        echo ""
        echo -e "${YELLOW}Cloudflare Access is enabled. Remember to:${RESET}"
        echo "  1. Create an A record for ${APACHE_SERVER_NAME} in Cloudflare with proxy enabled (orange cloud)"
        if [ -n "$CF_ADMIN_SUBDOMAIN" ]; then
        echo "  2. Create an A/CNAME for ${CF_ADMIN_SUBDOMAIN} pointing at this server with proxy enabled"
        echo "  3. Configure the Access application for ${CF_ADMIN_SUBDOMAIN} in Zero Trust"
        fi
        echo "  4. See the wiki for the full setup guide"
    fi
fi
echo ""

if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
    echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
    echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
    echo ""
fi
