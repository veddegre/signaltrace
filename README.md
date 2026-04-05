# SignalTrace

![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

SignalTrace is a self-hosted honeypot and link tracker. It logs every interaction with your custom paths, scores each request for bot/human likelihood, and feeds the results into your security tooling.

No external services required. One PHP app, one SQLite database, one Apache vhost.

---

## Why SignalTrace

Most honeypot tools tell you *that* something hit an endpoint. SignalTrace tells you *what kind of thing* hit it, how confident the assessment is, and why — with enough detail to act on immediately or pipe into a SIEM.

Every hit gets a 0–100 human-likelihood score with named signal reasons. The built-in threat feed at `/feed/ips.txt` is ready to consume from a firewall or block list. The JSON and CSV export endpoints support token-based authentication for scheduled Splunk ingestion.

Good for: phishing simulations, honeypot deployments, recon detection, link tracking, threat feed generation.

---

## Screenshot

[![SignalTrace Dashboard](docs/images/dashboard.png?raw=1&v=3)](docs/images/dashboard.png?raw=1&v=3)

---

## Requirements

SignalTrace is designed to run on minimal hardware. A 1 vCPU VM with 1 GB RAM and swap enabled is sufficient. Plan for 5–10 GB of disk depending on how much traffic you log.

Software requirements: PHP 8.1+, SQLite3, Apache with mod_rewrite, Composer.

---

## Quick Start with Docker

The fastest way to get SignalTrace running is with Docker Compose.

### 1. Clone and configure

```bash
git clone https://github.com/yourusername/signaltrace.git
cd signaltrace
cp .env.example .env
```

Edit `.env` and fill in the three required values. Generate them with:

```bash
# Password hash
php -r "echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;"

# Visitor salt
openssl rand -hex 64
```

If PHP isn't installed locally, Docker can generate them for you:

```bash
docker run --rm php:8.2-cli php -r "echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;"
```

### 2. Start the container

```bash
docker compose up -d
```

SignalTrace will be available at `http://localhost/admin`. On first start the database is initialised automatically. If MaxMind credentials are set in `.env`, GeoIP databases are downloaded as well.

### 3. Updating

```bash
git pull
docker compose build
docker compose up -d
```

The SQLite database and GeoIP databases are stored in named Docker volumes and persist across rebuilds.

---

## Manual Installation (Ubuntu + Apache)

### 1. Clone the repository

```bash
cd /var/www
sudo git clone https://github.com/yourusername/signaltrace.git
sudo chown -R www-data:www-data signaltrace
```

### 2. Install dependencies

```bash
sudo apt update
sudo apt install -y apache2 php php-sqlite3 php-mbstring php-xml php-curl sqlite3 composer unzip geoipupdate
```

### 3. Install PHP dependencies

```bash
cd /var/www/signaltrace
sudo -u www-data composer install --no-dev
```

### 4. Create the data directory

```bash
sudo mkdir -p /var/www/signaltrace/data
sudo chown -R www-data:www-data /var/www/signaltrace/data
sudo chmod -R 775 /var/www/signaltrace/data
```

### 5. Set up GeoIP

Create a free account at [maxmind.com](https://www.maxmind.com) to get a license key, then configure `/etc/GeoIP.conf`:

```
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-ASN GeoLite2-Country
```

```bash
sudo geoipupdate
```

The databases land at `/var/lib/GeoIP/` which is where SignalTrace looks by default. You can override the paths with the `MAXMIND_ASN_DB` and `MAXMIND_COUNTRY_DB` environment variables if needed.

### 6. Initialize the database

```bash
sqlite3 /var/www/signaltrace/data/database.db < db/schema.sql
```

Optionally load sample data to see the dashboard with something in it:

```bash
sqlite3 /var/www/signaltrace/data/database.db < db/seed.sql
```

---

## Configuration

Copy the example config and edit it:

```bash
cp includes/config.local.php.example includes/config.local.php
vi includes/config.local.php
```

The required values are the admin username, a bcrypt password hash, and a random salt for visitor fingerprinting:

```php
define('ADMIN_USERNAME',      'admin');
define('ADMIN_PASSWORD_HASH', 'replace-with-hash');
define('VISITOR_HASH_SALT',   'replace-with-secret');
```

Generate a password hash:

```bash
php -r "echo password_hash('your-password', PASSWORD_DEFAULT) . PHP_EOL;"
```

Generate a visitor salt:

```bash
openssl rand -hex 64
```

Optional settings are documented in `config.local.php.example`. The most important ones:

```php
// How many failed login attempts are allowed before an IP is locked out.
// Defaults to 5.
define('AUTH_MAX_FAILURES', 5);

// How long a lockout lasts in seconds. Defaults to 900 (15 minutes).
define('AUTH_LOCKOUT_SECS', 900);

// Set this to your reverse proxy's IP address if SignalTrace is behind
// nginx, a load balancer, or similar. When set, X-Forwarded-For is trusted
// only from that IP, and the rightmost entry in the header is used as the
// real client IP. Leave blank if SignalTrace connects directly to the internet.
define('TRUSTED_PROXY_IP', '');

// Your site's own domain (e.g. 'example.com'). When set, requests that
// arrive at the root path with your domain in the Referer header receive
// a small score penalty. Helps catch internal scanner traffic.
// Leave blank to disable.
define('SELF_REFERER_DOMAIN', '');

// A static token for authenticating export requests from Splunk or other
// automation tools. When set, requests can authenticate with an
// Authorization: Bearer header instead of HTTP Basic Auth.
// Generate with: openssl rand -hex 32
// Leave blank to require admin credentials for all export access.
define('EXPORT_API_TOKEN', '');
```

---

## Apache Configuration

```bash
sudo vi /etc/apache2/sites-available/signaltrace.conf
```

```apache
<VirtualHost *:80>
    ServerName yourdomain.example
    DocumentRoot /var/www/signaltrace/public

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  ${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog ${APACHE_LOG_DIR}/signaltrace_access.log combined
</VirtualHost>
```

```bash
sudo a2enmod rewrite
sudo a2ensite signaltrace.conf
sudo a2dissite 000-default.conf
sudo systemctl restart apache2
```

Place this in `public/.htaccess`:

```apache
RewriteEngine On
RewriteRule ^\.well-known/acme-challenge/ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.php [QSA,L]
```

---

## HTTPS

```bash
sudo apt install -y certbot python3-certbot-apache
sudo certbot --apache
sudo certbot renew --dry-run
```

---

## Admin

```
https://yourdomain.example/admin
```

---

## Threat Feed

The threat feed is available at `/feed/ips.txt` and requires admin authentication. It outputs a deduplicated list of IPs classified at or above your configured confidence threshold, suitable for consumption by firewalls, block lists, SIEM enrichment pipelines, or temporary deny lists.

Behaviour is configured in the Settings tab: time window, minimum confidence threshold. Individual tokens and ASN rules can each be flagged to suppress their hits from feed output, so you never accidentally block infrastructure you own.

---

## SIEM and Splunk Integration

Set an export API token in `config.local.php`:

```php
define('EXPORT_API_TOKEN', 'your-generated-token');
```

Generate one with `openssl rand -hex 32`.

Then poll either export endpoint on a schedule:

```
https://yourdomain.example/export/json
https://yourdomain.example/export/csv
```

Authenticate with a header (recommended, not logged by Apache):

```
Authorization: Bearer your-generated-token
```

Or with a query parameter if your tooling doesn't support custom headers (note this appears in access logs):

```
https://yourdomain.example/export/csv?api_key=your-generated-token
```

When polled with no filters, the export applies the configured confidence threshold, minimum score, and time window from Settings. Pass `?ip=`, `?path=`, `?date_from=`, or other filter parameters to override the configured settings and get exactly the filtered view instead.

---

## Detection and Scoring

Each request is scored on arrival. The score runs from 0 (definitely a bot) to 100 (definitely human) and resolves to one of four labels: **bot**, **suspicious**, **likely-human**, or **human**.

Signals that reduce the score include missing Accept-Language, Accept-Encoding, and Sec-Fetch headers; a browser UA with no supporting browser headers (spoofed UA detection); `Accept: */*` which is what HTTP libraries send by default; known automation UA signatures; raw IP in the Host header; exploit-like query strings; and hosting/datacenter IP ranges detected via ASN org name.

The Sec-Fetch and Sec-CH-UA checks are browser-aware. Safari is not penalised for headers it never sends. The Sec-CH-UA (Client Hints) penalty only applies when the UA claims to be Chromium-based.

Behavioral signals layer on top: rapid repeat requests, burst activity, and multi-token scanning all reduce the score in proportion to how aggressively the behavior is occurring.

Paths associated with common probes carry their own penalties. High-risk paths like `.env`, `_environment`, `.aws/credentials`, `.git`, and webshell patterns knock 40 points off. Medium-risk paths like `wp-admin`, `phpinfo`, `phpmyadmin`, Laravel debug tools, and Spring Boot actuator endpoints knock off 25.

ASN rules let you add manual score penalties for specific networks via the UI.

---

## Features at a Glance

**Tracking:** custom tokens with redirect, full request logging, visitor fingerprinting, tracking pixel, GeoIP enrichment.

**Admin dashboard:** paginated activity feed, expandable request details, per-IP summary panel, date range filtering, classification badges with scores, dark mode, mobile layout.

**Token management:** create/edit/activate/deactivate/delete, per-token feed exclusion, pixel URL generation.

**ASN rules:** scoring penalties, feed exclusion, edit in place.

**Skip patterns:** exact, contains, and prefix matching to suppress known noise. Add directly from the activity feed.

**Cleanup tools:** delete by token, by IP, or selectively remove unknown-token hits.

**Data retention:** configurable retention window with manual trigger and automatic probabilistic cleanup.

**Webhook alerts:** fires on bot classification, deduplicates per IP per 5 minutes, auto-detects Slack/Discord format.

---

## Project Structure

```
signaltrace/
├── LICENSE
├── README.md
├── Dockerfile
├── docker-compose.yml
├── docker-compose.override.yml.example
├── .env.example
├── composer.json
├── composer.lock
├── data/
│   └── database.db
├── db/
│   ├── schema.sql
│   └── seed.sql
├── docker/
│   └── entrypoint.sh
├── docs/
│   └── images/
│       └── dashboard.png
├── includes/
│   ├── admin_actions.php
│   ├── admin_view.php
│   ├── auth.php
│   ├── config.local.php.example
│   ├── config.php
│   ├── db.php
│   ├── helpers.php
│   └── router.php
├── public/
│   ├── admin.css
│   └── index.php
└── vendor/
```

The `public/` directory is the only thing Apache needs to serve. Everything else — includes, data, db, vendor — lives outside the document root.

---

## Security

`config.local.php` is never committed and contains all secrets. Passwords are stored as bcrypt hashes. All SQL uses parameterised queries. URL destinations are validated against an http/https allowlist at both write time and redirect time.

Admin login has rate limiting with a configurable lockout threshold and window. CSRF tokens protect all admin POST forms. Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are sent on every HTML response. The webhook fires only to validated URLs and blocks private and loopback IP ranges to prevent SSRF. The export API token is compared in constant time.

---

## Production Checklist

- [ ] Enable HTTPS
- [ ] Set strong admin credentials and a unique visitor hash salt
- [ ] Configure `AUTH_MAX_FAILURES` and `AUTH_LOCKOUT_SECS` for your environment
- [ ] Set `TRUSTED_PROXY_IP` if running behind a reverse proxy
- [ ] Download GeoIP databases with `geoipupdate`
- [ ] Verify only `public/` is web-accessible
- [ ] Configure skip patterns to suppress known noise
- [ ] Add ASN rules for infrastructure you own or trust
- [ ] Set feed exclusions on tokens and ASNs that should never appear in your blocklist
- [ ] Tune the threat feed confidence threshold and time window
- [ ] Set `EXPORT_API_TOKEN` and configure your SIEM integration if applicable
- [ ] Add a weekly `geoipupdate` cron job

---

## Tech Stack

PHP 8.1+, SQLite via PDO, Apache with mod_rewrite, MaxMind GeoLite2. Docker and Docker Compose are supported for containerised deployments.

---

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

Found a bug? Use the bug report issue template. Have a feature idea? Open an issue to discuss it before building. Found a security vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure — please don't open a public issue.

If SignalTrace is useful to you, a ⭐ on GitHub helps others find it.

---

## Disclaimer

SignalTrace is designed for security visibility and authorised testing. It will attract scanners, bots, and automated systems by design. Use it with awareness of your environment and risk tolerance.

---

## License

MIT

---

Most tools try to hide the noise. SignalTrace makes it visible.
