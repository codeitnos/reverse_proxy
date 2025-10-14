#!/bin/bash

# ============================================
# Скрипт обновления reverse_proxy
# ============================================

INSTALL_DIR="/var/reverse_proxy"
BACKUP_DIR="/var/reverse_proxy_backup_$(date +%Y%m%d_%H%M%S)"
DOWNLOAD_URL="https://github.com/codeitnos/reverse_proxy/archive/refs/tags/latest.zip"

echo "============================================"
echo "Обновление reverse_proxy"
echo "============================================"

# Проверка наличия директории
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Ошибка: Директория $INSTALL_DIR не найдена!"
    exit 1
fi

cd "$INSTALL_DIR" || exit 1

# Остановка контейнеров
echo "Остановка Docker контейнеров..."
docker compose down
if [ $? -ne 0 ]; then
    echo "Ошибка при остановке контейнеров!"
    exit 1
fi

# Создание резервной копии
echo "Создание резервной копии..."
cp -r "$INSTALL_DIR" "$BACKUP_DIR"
echo "Резервная копия создана: $BACKUP_DIR"

# Скачивание новой версии
echo "Скачивание обновления..."
cd /tmp || exit 1
rm -f reverse_proxy.zip
wget "$DOWNLOAD_URL" -O reverse_proxy.zip

if [ $? -ne 0 ]; then
    echo "Ошибка загрузки!"
    echo "Восстановление из резервной копии..."
    rm -rf "$INSTALL_DIR"
    cp -r "$BACKUP_DIR" "$INSTALL_DIR"
    cd "$INSTALL_DIR" || exit 1
    docker compose up -d
    exit 1
fi

# Распаковка
echo "Распаковка обновления..."
rm -rf /tmp/reverse_proxy_update
unzip -q reverse_proxy.zip -d /tmp/reverse_proxy_update

if [ $? -ne 0 ]; then
    echo "Ошибка распаковки!"
    echo "Восстановление из резервной копии..."
    rm -rf "$INSTALL_DIR"
    cp -r "$BACKUP_DIR" "$INSTALL_DIR"
    cd "$INSTALL_DIR" || exit 1
    docker compose up -d
    exit 1
fi

# Обновление файлов (сохраняем конфигурацию)
echo "Обновление файлов..."
cd /tmp/reverse_proxy_update/* || exit 1

# Копируем новые файлы, кроме конфигов
rsync -av --exclude='*.env' --exclude='config/' --exclude='data/' ./ "$INSTALL_DIR/"

if [ $? -ne 0 ]; then
    echo "Ошибка обновления файлов!"
    echo "Восстановление из резервной копии..."
    rm -rf "$INSTALL_DIR"
    cp -r "$BACKUP_DIR" "$INSTALL_DIR"
    cd "$INSTALL_DIR" || exit 1
    docker compose up -d
    exit 1
fi

# Очистка временных файлов
echo "Очистка..."
rm -f /tmp/reverse_proxy.zip
rm -rf /tmp/reverse_proxy_update

# Запуск контейнеров
echo "Запуск Docker контейнеров..."
cd "$INSTALL_DIR" || exit 1
docker compose up -d

if [ $? -ne 0 ]; then
    echo "Ошибка запуска контейнеров!"
    echo "NEW Восстановление из резервной копии..."
    rm -rf "$INSTALL_DIR"
    cp -r "$BACKUP_DIR" "$INSTALL_DIR"
    cd "$INSTALL_DIR" || exit 1
    docker compose up -d
    exit 1
fi

echo ""
echo "============================================"
echo "✓ Обновление завершено успешно!"
echo "============================================"
echo "Резервная копия: $BACKUP_DIR"
echo "Статус контейнеров:"
docker compose ps
echo "============================================"
