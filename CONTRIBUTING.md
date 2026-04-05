# Contributing to SignalTrace

Thanks for your interest in contributing. SignalTrace is a focused tool and contributions that keep it lightweight, self-contained, and easy to deploy are most welcome.

---

## Ways to Contribute

Bug reports, feature requests, pull requests, and documentation improvements are all welcome. If you're not sure whether something is a good fit, open an issue first and ask.

---

## Before Opening a Pull Request

Check existing issues and open PRs to avoid duplicate work. For anything beyond a small bug fix, it's worth opening an issue to discuss the approach before investing time building it. A PR that does one thing well is much easier to review than one that does five things at once.

---

## Development Setup

Requirements: PHP 8.1+, SQLite3, Apache with mod_rewrite, Composer. MaxMind GeoLite2 databases are optional but recommended for realistic local testing.

```bash
git clone https://github.com/yourusername/signaltrace.git
cd signaltrace
composer install

sqlite3 data/database.db < db/schema.sql
sqlite3 data/database.db < db/seed.sql   # optional sample data

cp includes/config.local.php.example includes/config.local.php
# edit includes/config.local.php with your credentials
```

Point Apache's document root at `public/` with `AllowOverride All` set for that directory.

---

## Code Style

Match the existing style throughout. Every file has `declare(strict_types=1)`. All database queries use parameterised statements. No new external dependencies without discussion — keeping `composer.json` minimal is a goal, not an accident. No `var_dump`, `print_r`, or debug output left in.

## Security

SignalTrace handles hostile traffic by design, so any PR touching request handling, authentication, database queries, or output rendering gets extra scrutiny. Call out security-relevant changes explicitly in your PR description.

## What Fits

Improvements to detection accuracy and scoring, performance improvements on SQLite queries, UI and UX work that stays within the existing stack (plain PHP, no JS frameworks), additional export formats or feed integrations, and bug fixes are all good candidates.

Swapping SQLite for a heavier database, adding a JS build pipeline, or introducing features that require cloud dependencies beyond MaxMind are probably not the right direction for this project.

---

## Reporting Security Vulnerabilities

Please do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## License

By contributing you agree that your contributions will be licensed under the MIT License.
