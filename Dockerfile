FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache, PHP, and system dependencies
RUN apt-get update && apt-get install -y \
        apache2 \
        php \
        php-cli \
        php-pdo \
        php-sqlite3 \
        php-mbstring \
        php-xml \
        php-curl \
        libapache2-mod-php \
        unzip \
        curl \
        sqlite3 \
        software-properties-common \
    && add-apt-repository ppa:maxmind/ppa \
    && apt-get update && apt-get install -y geoipupdate \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Install the SignalTrace vhost config.
# This sets the document root, enables AllowOverride, and passes the
# Authorization header through to PHP (required for Bearer token auth).
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/signaltrace

# Copy application files
COPY . .

# Install PHP dependencies
RUN composer install --no-dev --no-interaction --prefer-dist

# Create data directory and set permissions
RUN mkdir -p /var/www/signaltrace/data \
    && chown -R www-data:www-data /var/www/signaltrace \
    && chmod -R 755 /var/www/signaltrace \
    && chmod -R 775 /var/www/signaltrace/data

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2ctl", "-D", "FOREGROUND"]
