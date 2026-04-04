# SignalTrace

![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

SignalTrace is a lightweight, self-hosted tracking and analysis tool for observing interactions with custom paths and generating actionable telemetry.

It captures interactions in real time and can optionally expose that data as a simple threat feed for use in other security tools.

---

## What SignalTrace Does

SignalTrace lets you create custom tokens (paths) that:

1. Capture detailed request data  
2. Classify the interaction (human, suspicious, or bot)  
3. Redirect to a destination  

It is useful anywhere you want visibility into who is actually interacting with something.

Common use cases:

- Phishing simulations  
- Honeypots  
- Reconnaissance detection  
- Link tracking  

---

## Features

- Custom tokens with redirect support  
- Detailed request logging (IP, headers, user agent, and more)  
- Classification system (human, likely-human, suspicious, bot)  
- Visitor fingerprinting  
- Filtering by token, IP, and visitor  
- Skip patterns to suppress noise  
- Add tokens to skip patterns directly from the UI  
- Tracking pixel support  
- Threat feed generation (`/feed/ips.txt`) for integration with other tools  
- GeoIP enrichment with MaxMind  
- SQLite backend with no external database required  
- Minimal and fast, with no framework dependency  

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

Tested on a small VM with 1 GB RAM and 1 GB swap enabled.

If you enable GeoIP or keep longer retention, additional memory may help.

---

## Installation (Ubuntu + Apache)

### 1. Install dependencies

Installs Apache, PHP, SQLite, Composer, and required packages.

    sudo apt update
    sudo apt install -y apache2 php php-sqlite3 php-mbstring php-xml php-curl sqlite3 composer unzip

### 2. Install PHP dependencies

    composer install

### 3. Create the data directory

    sudo mkdir -p /var/www/signaltrace/data
    sudo chown -R www-data:www-data /var/www/signaltrace/data
    sudo chmod -R 775 /var/www/signaltrace/data

### 4. Initialize the database

    sqlite3 /var/www/signaltrace/data/database.db

Then run:

    .read db/schema.sql

### 5. Optional: load sample data

    sqlite3 /var/www/signaltrace/data/database.db

Then run:

    .read db/seed.sql

---

## Configuration

SignalTrace uses a local configuration file for secrets and credentials.

### Create local config

    cp includes/config.local.php.example includes/config.local.php

### Edit the config

    vi includes/config.local.php

Example:

    <?php
    define('ADMIN_USERNAME', 'admin');
    define('ADMIN_PASSWORD_HASH', 'replace-me');
    define('VISITOR_HASH_SALT', 'replace-me');

### Generate password hash

    php -r "echo password_hash('your-password', PASSWORD_DEFAULT) . PHP_EOL;"

### Generate visitor hash salt

    openssl rand -hex 64

---

## Apache Configuration

    sudo vi /etc/apache2/sites-available/signaltrace.conf

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

Enable:

    sudo a2enmod rewrite
    sudo a2ensite signaltrace.conf
    sudo a2dissite 000-default.conf
    sudo systemctl restart apache2

---

## .htaccess

Place this in `public/.htaccess`.

This configuration allows Let's Encrypt validation and routes application traffic correctly.

    RewriteEngine On

    RewriteRule ^\.well-known/acme-challenge/ - [L]

    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^ index.php [QSA,L]

---

## HTTPS (Let's Encrypt)

    sudo apt install -y certbot python3-certbot-apache
    sudo certbot --apache
    sudo certbot renew --dry-run

---

## Admin Access

    https://yourdomain.example/admin

---

## Threat Feed

SignalTrace can generate a lightweight IP-based threat feed derived from observed interactions.

Endpoint:

    /feed/ips.txt

### What it includes

- IPs classified as suspicious or bot activity  
- Only events with scoring data (older unclassified data is excluded)  
- Deduplicated output (one IP per line)  

### What it is for

This feed is designed to be consumed by other tools, such as:

- Firewalls (block lists)  
- SIEM enrichment  
- Detection pipelines  
- Temporary deny lists  

### Configuration

Feed behavior can be tuned in the UI:

- How long an IP remains in the feed  
- Minimum classification threshold  
- Inclusion and filtering behavior  

### Notes

This is intentionally simple. It is not a full threat intelligence platform.

The goal is to take what SignalTrace observes and make it immediately usable elsewhere.

---

## Project Structure

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

### What these directories are for

- `public/` — Web root (only exposed directory)  
- `includes/` — Application logic and routing  
- `db/` — Schema and seed files  
- `data/` — Runtime database storage  
- `docs/images/` — Documentation assets  
- `vendor/` — Composer dependencies  

---

## Interface Overview

### Dashboard

- Live activity view  
- Expandable request details  
- Filtering by token, IP, and visitor  
- Classification badges  
- Cleanup tools  

### Tokens

- Create and manage tokens  
- Configure redirect destinations  
- Enable or disable tokens  
- Pixel tracking URLs  

### Settings

- App name  
- Base URL  
- Default redirect  
- Unknown path behavior  
- Pixel toggle  
- Noise filter toggle  
- Threat feed configuration  

### Skip Patterns

- Ignore scanner noise  
- Pattern types:
  - Exact  
  - Contains  
  - Prefix  

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
- Verify directory exposure  
- Configure skip patterns  
- Configure threat feed settings  

---

## Use Cases

- Phishing simulation tracking  
- Honeypot telemetry  
- Reconnaissance detection  
- Link tracking  
- Security research  
- Generating lightweight threat feeds from observed activity  

---

## Tech Stack

- PHP  
- SQLite  
- Apache  
- MaxMind GeoIP2  

---

## Disclaimer

SignalTrace is intended for security testing and visibility.

It works by exposing endpoints and recording interactions. That means it will attract automated traffic, scanners, and other systems. This is expected.

Use it with an understanding of what you are exposing and where you are deploying it. If you plan to run this in production, make sure it aligns with your environment, policies, and risk tolerance.

---

## License

MIT License

---

## Contributing

Pull requests are welcome.

---

## Final Note

Most tools try to hide noise.

SignalTrace makes it visible.
