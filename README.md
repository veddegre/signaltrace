# SignalTrace

![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

SignalTrace is a lightweight, self-hosted tracking and analysis platform for observing interactions with custom paths and generating actionable telemetry.

It captures interactions in real time and can expose that data as a simple, practical threat feed for use in other security tools.

---

## What SignalTrace Does

SignalTrace lets you create custom tokens (paths) that:

1. Capture detailed request data
2. Score and classify the interaction
3. Redirect to a destination

It provides visibility into who is actually interacting with endpoints, not just whether they were accessed.

Common use cases:

- Phishing simulations
- Honeypots
- Reconnaissance detection
- Link tracking
- Threat feed generation

---

## Features

### Core Tracking

- Custom tokens with redirect support
- Full request logging (IP, headers, user agent, and more)
- Visitor fingerprinting
- Tracking pixel support

### Scoring and Detection

- Confidence scoring system:
  - human
  - likely-human
  - suspicious
  - bot
- Path-based detection for suspicious requests such as `.env`, `.git`, and similar probes
- Timing-based detection:
  - rapid repeat requests
  - burst activity
- Multi-token scan detection
- Bot signal detection based on user agent and behavior

### Filtering and Analysis

- Filter by:
  - token
  - IP
  - visitor
  - date range
- Display filtering to hide low-confidence noise without deleting data
- Show all override for full visibility when needed

### Token Management

- Create tokens
- Edit existing tokens
- Activate or deactivate tokens
- Delete tokens, with optional related click cleanup
- Copy token URLs directly from the UI
- Copy pixel URLs directly from the UI

### Noise Handling

- Skip patterns:
  - Exact
  - Contains
  - Prefix
- Add skip patterns directly from activity

### Threat Feed

- Built-in IP threat feed at `/feed/ips.txt`
- Configurable:
  - time window
  - confidence threshold
- Only includes scored events
- Deduplicated output

### Platform

- SQLite backend with no external database required
- GeoIP enrichment with MaxMind
- Minimal, fast, framework-free design

---

## Screenshot

[![SignalTrace Dashboard](docs/images/dashboard.png)](docs/images/dashboard.png)

---

## Minimum Requirements

SignalTrace is designed to run on very small systems.

Recommended minimum:

- 1 vCPU
- 1 GB RAM
- 1 GB swap
- 5 to 10 GB disk

Tested on a small VM with 1 GB RAM and swap enabled.

If you enable GeoIP or retain larger datasets, additional memory may help.

---

## Installation (Ubuntu + Apache)

### 1. Install dependencies

```bash
sudo apt update
sudo apt install -y apache2 php php-sqlite3 php-mbstring php-xml php-curl sqlite3 composer unzip
```

### 2. Install PHP dependencies

```bash
composer install
```

### 3. Create the data directory

```bash
sudo mkdir -p /var/www/signaltrace/data
sudo chown -R www-data:www-data /var/www/signaltrace/data
sudo chmod -R 775 /var/www/signaltrace/data
```

### 4. Initialize the database

```bash
sqlite3 /var/www/signaltrace/data/database.db
.read db/schema.sql
```

### 5. Optional: load sample data

```bash
sqlite3 /var/www/signaltrace/data/database.db
.read db/seed.sql
```

---

## Configuration

SignalTrace uses a local configuration file for secrets.

### Create the local config

```bash
cp includes/config.local.php.example includes/config.local.php
```

### Edit the config

```bash
vi includes/config.local.php
```

Example:

```php
<?php
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD_HASH', 'replace-me');
define('VISITOR_HASH_SALT', 'replace-me');
```

### Generate a password hash

```bash
php -r "echo password_hash('your-password', PASSWORD_DEFAULT) . PHP_EOL;"
```

### Generate a visitor hash salt

```bash
openssl rand -hex 64
```

---

## Apache Configuration

Create the site config:

```bash
sudo vi /etc/apache2/sites-available/signaltrace.conf
```

Use:

```apache
<VirtualHost *:80>
    ServerName yourdomain.example
    DocumentRoot /var/www/signaltrace/public

    <Directory /var/www/signaltrace/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/signaltrace_error.log
    CustomLog ${APACHE_LOG_DIR}/signaltrace_access.log combined
</VirtualHost>
```

Enable the site:

```bash
sudo a2enmod rewrite
sudo a2ensite signaltrace.conf
sudo a2dissite 000-default.conf
sudo systemctl restart apache2
```

---

## .htaccess

Place this in `public/.htaccess`:

```apache
RewriteEngine On

RewriteRule ^\.well-known/acme-challenge/ - [L]

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ index.php [QSA,L]
```

This allows Let's Encrypt validation and routes application traffic correctly.

---

## HTTPS (Let's Encrypt)

```bash
sudo apt install -y certbot python3-certbot-apache
sudo certbot --apache
sudo certbot renew --dry-run
```

---

## Admin Access

Open:

```text
https://yourdomain.example/admin
```

---

## Threat Feed

SignalTrace includes a built-in threat feed:

```text
/feed/ips.txt
```

### What it includes

- IPs classified as suspicious or bot
- Only events with scoring data
- Deduplicated output

### What it is for

This feed is designed to be consumed by other tools, such as:

- Firewalls and block lists
- SIEM enrichment
- Detection pipelines
- Temporary deny lists

### Configuration

Threat feed behavior is controlled in the Settings tab:

- time window
- confidence threshold

---

## Interface Overview

### Dashboard

- Live activity feed
- Expandable request details
- Confidence scoring with reasons
- Filtering by token, IP, visitor, and date
- Display filtering to reduce noise without deleting data

### Tokens

- Create tokens
- Edit tokens
- Copy token URLs
- Copy pixel URLs
- Enable or disable tokens
- Delete tokens, with optional related click cleanup

### Settings

- App configuration
- Display filtering threshold
- Pixel toggle
- Noise filtering
- Threat feed settings

### Skip Patterns

- Suppress known noise
- Pattern types:
  - Exact
  - Contains
  - Prefix

---

## Project Structure

```text
signaltrace/
├── LICENSE
├── README.md
├── composer.json
├── composer.lock
├── data/
│   └── database.db
├── db/
│   ├── schema.sql
│   └── seed.sql
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
│   └── index.php
└── vendor/
```

### What these directories are for

- `public/` — Web root and only exposed directory
- `includes/` — Application logic and routing
- `db/` — Schema and seed files
- `data/` — Runtime SQLite database storage
- `docs/images/` — Documentation assets
- `vendor/` — Composer dependencies

---

## Security Notes

- `config.local.php` is not committed
- Passwords are stored as hashes
- Only `/public` should be web accessible
- Internal directories should not be web accessible
- Admin uses HTTP Basic Auth

---

## Production Checklist

- Enable HTTPS
- Set strong admin credentials
- Generate a unique visitor hash salt
- Verify only `/public` is exposed
- Configure threat feed settings
- Configure display filtering
- Review skip patterns for your environment

---

## Use Cases

- Phishing simulation tracking
- Honeypot telemetry
- Reconnaissance detection
- Link tracking
- Security research
- Threat feed generation from observed activity

---

## Tech Stack

- PHP
- SQLite
- Apache
- MaxMind GeoIP2

---

## Disclaimer

SignalTrace is designed for security visibility and testing.

It intentionally exposes endpoints and records interactions. As a result, it will attract automated traffic, scanners, and potentially malicious activity.

Use it with an understanding of your environment and risk tolerance. Ensure it aligns with your policies before deploying in production.

---

## License

MIT License

---

## Contributing

Pull requests are welcome.

---

## Final Note

Most tools try to hide noise.

SignalTrace makes it visible and lets you decide what matters.
