#!/usr/bin/env bash
# SignalTrace setup script
# Walks through the .env configuration and generates the file.
# Run this before docker compose up -d.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

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
echo "This script will generate your .env file."
echo "Press Enter to accept defaults where shown."
echo ""

# ── Guard: existing .env ─────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}Warning: .env already exists.${RESET}"
    read -r -p "Overwrite it? [y/N] " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "Aborted. Your existing .env was not changed."
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

generate_hash() {
    local password="$1"
    if command -v php &>/dev/null; then
        php -r "echo password_hash('${password}', PASSWORD_DEFAULT) . PHP_EOL;"
    elif python3 -c "import bcrypt" 2>/dev/null; then
        python3 -c "import bcrypt; print(bcrypt.hashpw('${password}'.encode(), bcrypt.gensalt()).decode())"
    else
        # Fall back to the built image — hash generated after build
        echo "__DEFER__"
    fi
}

generate_salt() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 64
    elif command -v php &>/dev/null; then
        php -r "echo bin2hex(random_bytes(64)) . PHP_EOL;"
    else
        echo ""
    fi
}

# ── Required: admin username ──────────────────────────────────────────────────
echo -e "${BOLD}── Required ─────────────────────────────────────────────────${RESET}"
echo ""
prompt "Admin username" ADMIN_USERNAME "admin"

# ── Required: port ────────────────────────────────────────────────────────────
echo -e "${CYAN}Host port${RESET}"
echo "  Which port should SignalTrace listen on?"

# Find first unused port starting from 8080
find_free_port() {
    local port=8080
    while ss -tlnp 2>/dev/null | grep -q ":${port} " || \
          grep -q ":${port}->" /proc/net/tcp 2>/dev/null; do
        port=$((port + 1))
    done
    echo $port
}

SUGGESTED_PORT=$(find_free_port)
read -r -p "  Port [${SUGGESTED_PORT}]: " PORT_INPUT
SIGNALTRACE_PORT="${PORT_INPUT:-$SUGGESTED_PORT}"
echo ""

# ── Required: admin password ──────────────────────────────────────────────────
echo -e "${CYAN}Admin password${RESET}"
echo "  Enter a password and the script will hash it for you."
read -r -s -p "  Password: " ADMIN_PASSWORD
echo ""

if [ -z "$ADMIN_PASSWORD" ]; then
    echo -e "${RED}Error: password cannot be blank.${RESET}"
    exit 1
fi

echo "  Generating bcrypt hash..."
ADMIN_PASSWORD_HASH=$(generate_hash "$ADMIN_PASSWORD")

if [ "$ADMIN_PASSWORD_HASH" = "__DEFER__" ]; then
    echo -e "  ${YELLOW}PHP not found locally — hash will be generated from the container after build.${RESET}"
    DEFER_HASH=true
else
    if [ -z "$ADMIN_PASSWORD_HASH" ]; then
        echo -e "${RED}Error: could not generate password hash.${RESET}"
        exit 1
    fi
    echo -e "  ${GREEN}Hash generated.${RESET}"
    DEFER_HASH=false
fi
echo ""

# ── Required: visitor hash salt ───────────────────────────────────────────────
echo -e "${CYAN}Visitor hash salt${RESET}"
echo "  Used to anonymise visitor fingerprints. Leave blank to auto-generate."
read -r -p "  Value (leave blank to auto-generate): " VISITOR_HASH_SALT

if [ -z "$VISITOR_HASH_SALT" ]; then
    echo "  Generating salt..."
    VISITOR_HASH_SALT=$(generate_salt)
    if [ -z "$VISITOR_HASH_SALT" ]; then
        echo -e "${RED}Error: could not generate salt. Please install openssl or PHP and try again.${RESET}"
        exit 1
    fi
    echo -e "  ${GREEN}Salt generated.${RESET}"
fi
echo ""

# ── Optional: MaxMind GeoIP ───────────────────────────────────────────────────
echo -e "${BOLD}── GeoIP Enrichment (optional but recommended) ──────────────${RESET}"
echo "  Sign up free at https://www.maxmind.com to get these."
echo ""
prompt "MaxMind Account ID" MAXMIND_ACCOUNT_ID "" ""
prompt "MaxMind License Key" MAXMIND_LICENSE_KEY "" "" "secret"

# ── Optional: export API token ────────────────────────────────────────────────
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

# ── Optional: trusted proxy IP ────────────────────────────────────────────────
echo -e "${BOLD}── Reverse Proxy (optional) ─────────────────────────────────${RESET}"
echo "  Set this if SignalTrace runs behind nginx, Caddy, or Traefik."
echo "  Use the proxy container IP or subnet, e.g. 172.16.0.0/12"
echo ""
prompt "Trusted proxy IP" SIGNALTRACE_TRUSTED_PROXY_IP "" ""

# ── Write .env ────────────────────────────────────────────────────────────────
cat > "$ENV_FILE" << EOF
# SignalTrace Docker Environment Configuration
# Generated by setup.sh — do not commit this file to version control.

# ============================================================
# Required
# ============================================================

SIGNALTRACE_ADMIN_USERNAME=${ADMIN_USERNAME}
SIGNALTRACE_PORT=${SIGNALTRACE_PORT}
SIGNALTRACE_ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH:-__PENDING__}
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

# ── Deferred hash generation ──────────────────────────────────────────────────
if [ "$DEFER_HASH" = true ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Building container to generate password hash..."
    echo ""
    if ! docker compose build --quiet 2>&1; then
        echo -e "${RED}Error: docker compose build failed. Fix the build error and re-run setup.sh.${RESET}"
        exit 1
    fi
    echo "  Generating hash from container..."
    ADMIN_PASSWORD_HASH=$(docker run --rm signaltrace-signaltrace php -r "echo password_hash('${ADMIN_PASSWORD}', PASSWORD_DEFAULT) . PHP_EOL;" 2>/dev/null)
    if [ -z "$ADMIN_PASSWORD_HASH" ]; then
        echo -e "${RED}Error: could not generate hash from container.${RESET}"
        exit 1
    fi
    # Update the placeholder in .env
    sed -i "s|SIGNALTRACE_ADMIN_PASSWORD_HASH=__PENDING__|SIGNALTRACE_ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}|" "$ENV_FILE"
    echo -e "  ${GREEN}Hash generated and written to .env.${RESET}"
    echo ""
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}${BOLD}.env file written successfully.${RESET}"
echo ""
echo "Next step:"
echo "  docker compose up -d"
echo ""
echo -e "${CYAN}SignalTrace will be available at: http://localhost:${SIGNALTRACE_PORT}${RESET}"
echo ""

if [ -n "$SIGNALTRACE_EXPORT_API_TOKEN" ]; then
    echo -e "${YELLOW}Note: save your export API token — it will not be shown again:${RESET}"
    echo "  $SIGNALTRACE_EXPORT_API_TOKEN"
    echo ""
fi
