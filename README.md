# SignalTrace

![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

SignalTrace is a lightweight, self-hosted tracking and analysis platform for monitoring interactions with custom tokens or paths.

It is designed for security visibility, helping you understand who is interacting with your links, endpoints, or honeypot routes, and whether those interactions are human, automated, or malicious.

---

## What SignalTrace Does

SignalTrace allows you to create custom tokens (paths) that:

1. Capture detailed request data
2. Score the interaction (human, suspicious, or bot)
3. Redirect to a destination

It provides a simple telemetry layer for:

- Phishing simulations
- Honeypots
- Reconnaissance detection
- Link tracking

---

## Features

- Custom tokens or paths with redirect support
- Detailed request logging (IP, headers, user agent, and more)
- Bot detection and confidence scoring
- Visitor fingerprinting
- Filtering by token, IP, and visitor
- Skip patterns to remove scanner noise
- Tracking pixel support
- GeoIP enrichment with MaxMind
- SQLite backend with no external database required
- Minimal, fast, and framework-free

---

## Screenshot

[![SignalTrace Dashboard](docs/images/dashboard.png)](docs/images/dashboard.png)

---

## Installation (Ubuntu + Apache)

### 1. Install system dependencies

    sudo apt update
    sudo apt install -y apache2 php php-sqlite3 php-mbstring php-xml php-curl sqlite3 composer unzip

### 2. Install PHP dependencies

From the project root:

    composer install

### 3. Create the data directory

    sudo mkdir -p /var/www/signaltrace/data
    sudo chown -R www-data:www-data /var/www/signaltrace/data
    sudo chmod -R 775 /var/www/signaltrace/data

### 4. Initialize the database

    sqlite3 /var/www/signaltrace/data/database.db

Then run inside SQLite:

    .read db/schema.sql

### 5. Optional: load sample data

    sqlite3 /var/www/signaltrace/data/database.db

Then run inside SQLite:

    .read db/seed.sql

Seed data uses reserved documentation IP ranges and does not represent real traffic.

---

## Application Configuration

SignalTrace uses a local configuration file that is not committed to Git.

### 1. Create the local config file

    cp includes/config.local.php.example includes/config.local.php

### 2. Edit the configuration

    vi includes/config.local.php

Example:

    <?php
    declare(strict_types=1);

    define('ADMIN_USERNAME', 'admin');
    define('ADMIN_PASSWORD_HASH', 'replace-with-password-hash');
    define('VISITOR_HASH_SALT', 'replace-with-random-secret');

### 3. Generate the password hash

Run:

    php -r "echo password_hash('your-strong-password', PASSWORD_DEFAULT) . PHP_EOL;"

Paste the output into `ADMIN_PASSWORD_HASH`.

### 4. Generate the visitor hash salt

Run:

    openssl rand -hex 64

Paste the output into `VISITOR_HASH_SALT`.

---

## Apache Configuration

Create:

    sudo vi /etc/apache2/sites-available/signaltrace.conf

Contents:

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

Enable the site:

    sudo a2enmod rewrite
    sudo a2ensite signaltrace.conf
    sudo a2dissite 000-default.conf
    sudo systemctl restart apache2

---

## Optional .htaccess

Place this in `public/.htaccess`:

    RewriteEngine On

    RewriteCond %{REQUEST_FILENAME} -f [OR]
    RewriteCond %{REQUEST_FILENAME} -d
    RewriteRule ^ - [L]

    RewriteRule ^ index.php [L,QSA]

---

## HTTPS Setup (Let's Encrypt)

Install Certbot:

    sudo apt install -y certbot python3-certbot-apache

Run setup:

    sudo certbot --apache

Test renewal:

    sudo certbot renew --dry-run

---

## Admin Access

Open:

    https://yourdomain.example/admin

Log in using the credentials defined in `includes/config.local.php`.

---

## Project Structure

    signaltrace/
    ├── public/
    │   ├── index.php
    │   └── .htaccess
    ├── includes/
    │   ├── config.php
    │   ├── config.local.php.example
    │   ├── auth.php
    │   ├── db.php
    │   ├── helpers.php
    │   ├── router.php
    │   ├── admin_view.php
    │   └── admin_actions.php
    ├── db/
    │   ├── schema.sql
    │   └── seed.sql
    ├── data/
    ├── composer.json
    ├── composer.lock
    ├── README.md
    ├── LICENSE
    └── .gitignore

---

## Interface Overview

### Dashboard

- Activity table with expandable request details
- Top tokens view with hit counts
- Filtering by token, IP, and visitor
- Cleanup tools for removing unwanted data

### Tokens

- Create and manage tokens
- Configure redirect destinations
- Enable or disable tokens
- Delete tokens and associated clicks
- Automatic pixel URL generation

### Settings

- Application name
- Base URL
- Default redirect URL
- Unknown path behavior (redirect or 404)
- Toggle pixel tracking and noise filtering

### Skip Patterns

- Ignore scanner traffic and noise
- Pattern types:
  - Exact
  - Contains
  - Prefix
- Activate, deactivate, and delete patterns

---

## Security Notes

- `includes/config.local.php` is not committed to Git
- Secrets are stored outside version control
- Passwords are stored as hashes, not plaintext
- Only `/public` should be web accessible
- `includes/`, `db/`, and `data/` should remain outside the document root

---

## Production Checklist

- Enable HTTPS
- Set a strong admin password
- Generate a unique visitor hash salt
- Ensure `/public` is the only web root
- Verify `/includes`, `/db`, and `/data` are not web accessible
- Configure skip patterns
- Run `composer install`

---

## Use Cases

- Phishing simulation tracking
- Honeypot telemetry
- Reconnaissance detection
- Link tracking
- Security research

---

## Tech Stack

- PHP
- SQLite
- Apache
- MaxMind GeoIP2

---

## License

MIT License recommended.

---

## Contributing

Pull requests are welcome.

---

## Final Note

SignalTrace is designed to be simple, fast, and transparent, providing immediate visibility into interactions with your tokens.
