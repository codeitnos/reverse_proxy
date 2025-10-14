/**
 * Модуль автоматической синхронизации DNS записей с CloudFlare
 * Проверяет соответствие внешнего IP сервера с IP в DNS записях
 * и автоматически обновляет их при несоответствии
 */

const https = require('https');

class SyncScheduler {
    constructor() {
        this.intervalId = null;
        this.isRunning = false;
        this.lastSyncTime = null;
        this.syncHistory = [];
        this.maxHistorySize = 100;
    }

    /**
     * Запуск планировщика
     * @param {number} intervalMinutes - интервал проверки в минутах (30, 60, 720, 1440 или null)
     * @param {Function} syncCallback - функция для выполнения синхронизации
     * @param {Object} config - конфигурация с токеном и функциями
     */
    start(intervalMinutes, syncCallback, config) {
        // Останавливаем предыдущий таймер, если был запущен
        this.stop();

        if (!intervalMinutes || intervalMinutes <= 0) {
            console.log('⏸️  Планировщик синхронизации отключен');
            return;
        }

        const intervalMs = intervalMinutes * 60 * 1000;

        console.log(`🔄 Запуск планировщика синхронизации DNS`);
        console.log(`⏰ Интервал проверки: ${intervalMinutes} минут (${intervalMs}ms)`);

        this.isRunning = true;
        this.config = config;
        this.syncCallback = syncCallback;

        // Запускаем периодическую проверку
        this.intervalId = setInterval(async () => {
            await this.performSync();
        }, intervalMs);

        console.log('✅ Планировщик синхронизации успешно запущен');
    }

    /**
     * Остановка планировщика
     */
    stop() {
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
            this.isRunning = false;
            console.log('⏹️  Планировщик синхронизации остановлен');
        }
    }

    /**
     * Выполнение синхронизации
     */
    async performSync() {
        if (!this.config || !this.syncCallback) {
            console.error('❌ Конфигурация не установлена');
            return;
        }

        const startTime = new Date();
        console.log(`\n🔄 [${startTime.toISOString()}] Начало автоматической синхронизации DNS...`);

        try {
            const result = await this.syncCallback();

            const endTime = new Date();
            const duration = endTime - startTime;

            const syncRecord = {
                timestamp: startTime.toISOString(),
                duration: duration,
                success: true,
                updated: result.updated || 0,
                errors: result.errors || 0,
                details: result.details || []
            };

            this.lastSyncTime = startTime;
            this.addToHistory(syncRecord);

            console.log(`✅ Синхронизация завершена за ${duration}ms`);
            console.log(`   Обновлено записей: ${result.updated || 0}`);
            console.log(`   Ошибок: ${result.errors || 0}`);

            if (result.details && result.details.length > 0) {
                console.log('   Детали:');
                result.details.forEach(detail => {
                    const status = detail.updated ? '✅' : (detail.error ? '❌' : 'ℹ️');
                    console.log(`   ${status} ${detail.domain}: ${detail.message}`);
                });
            }

        } catch (error) {
            const endTime = new Date();
            const duration = endTime - startTime;

            console.error('❌ Ошибка при автоматической синхронизации:', error);

            const syncRecord = {
                timestamp: startTime.toISOString(),
                duration: duration,
                success: false,
                error: error.message
            };

            this.addToHistory(syncRecord);
        }
    }

    /**
     * Добавление записи в историю синхронизаций
     */
    addToHistory(record) {
        this.syncHistory.unshift(record);

        // Ограничиваем размер истории
        if (this.syncHistory.length > this.maxHistorySize) {
            this.syncHistory = this.syncHistory.slice(0, this.maxHistorySize);
        }
    }

    /**
     * Получение статуса планировщика
     */
    getStatus() {
        return {
            isRunning: this.isRunning,
            lastSyncTime: this.lastSyncTime ? this.lastSyncTime.toISOString() : null,
            historyCount: this.syncHistory.length,
            recentHistory: this.syncHistory.slice(0, 10) // последние 10 записей
        };
    }

    /**
     * Получение истории синхронизаций
     */
    getHistory(limit = 50) {
        return this.syncHistory.slice(0, limit);
    }
}

module.exports = SyncScheduler;
