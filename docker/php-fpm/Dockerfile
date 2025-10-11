FROM php:8.3-fpm

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libcurl4-openssl-dev \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    libzip-dev \
    zip \
    unzip \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpq-dev \
    libicu-dev \
    libbz2-dev \
    imagemagick \
    libmagickwand-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем PHP расширения (убираем curl, xml, mbstring - они уже встроены в PHP 8.3)
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        curl \
        pdo_mysql \
        pdo_pgsql \
        exif \
        pcntl \
        bcmath \
        gd \
        zip \
        intl \
        bz2 \
        opcache

# Устанавливаем PECL расширения
RUN pecl install redis imagick \
    && docker-php-ext-enable redis imagick zip

# Устанавливаем Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Создаем необходимые директории для данных
#RUN mkdir -p /var/www/www-root/data/php_uploads

# Создаем пользователя www-data (если его нет)
RUN groupadd -f -g 33 www-data && \
    useradd -u 33 -g www-data -s /bin/bash -M www-data 2>/dev/null || true

# Устанавливаем права доступа
RUN chown -R www-data:www-data /var/www

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Устанавливаем рабочую директорию
WORKDIR /var/www/html

EXPOSE 9000

#ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["php-fpm"]
