FROM php:8.2-apache

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
        libsqlite3-dev \
        libcurl4-openssl-dev \
        libxml2-dev \
        unzip \
        curl \
        geoipupdate \
    && docker-php-ext-install \
        pdo_sqlite \
        mbstring \
        xml \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Configure Apache — document root points at public/, rewrite rules enabled
RUN sed -i \
    's|DocumentRoot /var/www/html|DocumentRoot /var/www/signaltrace/public|g' \
    /etc/apache2/sites-available/000-default.conf \
    && sed -i \
    '/<\/VirtualHost>/i \\t<Directory /var/www/signaltrace/public>\n\t\tAllowOverride All\n\t\tRequire all granted\n\t</Directory>' \
    /etc/apache2/sites-available/000-default.conf

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
CMD ["apache2-foreground"]
