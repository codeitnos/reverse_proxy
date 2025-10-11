#!/bin/bash
set -e

echo "Starting PHP-FPM with custom entrypoint..."

# Переходим в рабочую директорию
cd /var/www/html

# Проверяем, есть ли composer.json
if [ -f "composer.json" ]; then
    echo "Found composer.json, running composer install..."
    composer install --no-dev --optimize-autoloader --no-interaction
    echo "Composer install completed."
else
    echo "No composer.json found, skipping composer install."
fi

# Устанавливаем права
echo "Setting permissions..."
chown -R www-data:www-data /var/www/html 2>/dev/null || true

echo "Starting PHP-FPM..."
# Запускаем оригинальную команду
exec "$@"
