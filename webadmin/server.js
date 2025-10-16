const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const util = require('util');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const multer = require('multer');
const https = require('https');
const execPromise = util.promisify(exec);
const SyncScheduler = require('./sync-scheduler');

const app = express();
const PORT = 8881;

// Создаем экземпляр планировщика синхронизации
const syncScheduler = new SyncScheduler();

// Настройка multer для загрузки файлов
const upload = multer({
    dest: '/tmp/',
    limits: { fileSize: 500 * 1024 * 1024 } // 500MB лимит
});

// Путь к папке с данными
const DATA_DIR = "/data";

// Пути к файлам данных
const USER_DATA_FILE = path.join(DATA_DIR, 'user.json');
const ITEMS_DATA_FILE = path.join(DATA_DIR, 'items.json');

// Пути для nginx конфигов
const NGINX_CONFIG_DIR = '/nginx_config';
const NGINX_TEMPLATE_PATH = '/app/nginx/template.conf';
const NGINX_SSL_TEMPLATE_PATH = '/app/nginx/template_ssl.conf';

// Путь к папке acme.sh
const ACME_DIR = '/acme.sh';

// Функция для извлечения корневого домена из поддомена
function getRootDomain(fullDomain) {
    const parts = fullDomain.split('.');
    if (parts.length >= 2) {
        return parts.slice(-2).join('.');
    }
    return fullDomain;
}

// Функция для выполнения HTTPS запросов к CloudFlare API
function cloudflareRequest(method, path, token, data = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.cloudflare.com',
            port: 443,
            path: path,
            method: method,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };

        if (data && (method === 'POST' || method === 'PUT')) {
            const postData = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(postData);
        }

        const req = https.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                try {
                    const parsedData = JSON.parse(responseData);
                    resolve(parsedData);
                } catch (error) {
                    reject(new Error('Failed to parse response: ' + responseData));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        if (data && (method === 'POST' || method === 'PUT')) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

// Функция для получения внешнего IP сервера
async function getServerExternalIp() {
    return new Promise((resolve, reject) => {
        https.get('https://ifconfig.me/ip', (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                resolve(data.trim());
            });
        }).on('error', (error) => {
            console.error('❌ Ошибка получения внешнего IP:', error);
            reject(error);
        });
    });
}

// Функция для получения Zone ID из CloudFlare
async function getCloudFlareZoneId(domain, token) {
    try {
        const response = await cloudflareRequest('GET', `/client/v4/zones?name=${domain}`, token);

        if (response.success && response.result && response.result.length > 0) {
            return response.result[0].id;
        }
        return null;
    } catch (error) {
        console.error('❌ Ошибка получения Zone ID:', error);
        return null;
    }
}

// Функция для получения A-записи из CloudFlare
async function getCloudFlareARecord(zoneId, recordName, token) {
    try {
        const response = await cloudflareRequest('GET', `/client/v4/zones/${zoneId}/dns_records?type=A&name=${recordName}`, token);

        if (response.success && response.result && response.result.length > 0) {
            return response.result[0];
        }
        return null;
    } catch (error) {
        console.error('❌ Ошибка получения A-записи:', error);
        return null;
    }
}

// Функция для создания A-записи в CloudFlare
async function createCloudFlareARecord(zoneId, subdomain, ip, token) {
    try {
        const data = {
            type: 'A',
            name: subdomain,
            content: ip,
            proxied: false
        };

        const response = await cloudflareRequest('POST', `/client/v4/zones/${zoneId}/dns_records`, token, data);
        return response;
    } catch (error) {
        console.error('❌ Ошибка создания A-записи:', error);
        return { success: false, error: error.message };
    }
}

// Функция для обновления A-записи в CloudFlare
async function updateCloudFlareARecord(zoneId, recordId, subdomain, ip, token) {
    try {
        const data = {
            type: 'A',
            name: subdomain,
            content: ip,
            proxied: false
        };

        const response = await cloudflareRequest('PUT', `/client/v4/zones/${zoneId}/dns_records/${recordId}`, token, data);
        return response;
    } catch (error) {
        console.error('❌ Ошибка обновления A-записи:', error);
        return { success: false, error: error.message };
    }
}

// Функция для удаления A-записи из CloudFlare
async function deleteCloudFlareARecord(zoneId, recordId, token) {
    try {
        const response = await cloudflareRequest('DELETE', `/client/v4/zones/${zoneId}/dns_records/${recordId}`, token);
        return response;
    } catch (error) {
        console.error('❌ Ошибка удаления A-записи:', error);
        return { success: false, error: error.message };
    }
}

// Функция для загрузки данных пользователя
function loadUserData() {
    try {
        if (fs.existsSync(USER_DATA_FILE)) {
            const data = fs.readFileSync(USER_DATA_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Ошибка при загрузке данных пользователя:', error);
    }
    // Данные по умолчанию
    return {
        username: 'admin',
        passwordHash: bcrypt.hashSync('password123', 10),
        cf_token: '',
        sync_interval: null // null = отключено, или число минут: 30, 60, 720, 1440
    };
}

// Функция для сохранения данных пользователя
function saveUserData(userData) {
    try {
        fs.writeFileSync(USER_DATA_FILE, JSON.stringify(userData, null, 2), 'utf8');
        console.log('✅ Данные пользователя сохранены');
    } catch (error) {
        console.error('❌ Ошибка при сохранении данных пользователя:', error);
    }
}

// Функция для загрузки записей
function loadItems() {
    try {
        if (fs.existsSync(ITEMS_DATA_FILE)) {
            const data = fs.readFileSync(ITEMS_DATA_FILE, 'utf8');
            const loadedData = JSON.parse(data);
            return {
                items: loadedData.items || [],
                counter: loadedData.counter || 1
            };
        }
    } catch (error) {
        console.error('Ошибка при загрузке записей:', error);
    }
    return { items: [], counter: 1 };
}

// Функция для сохранения записей
function saveItems() {
    try {
        const data = {
            items: items,
            counter: itemIdCounter
        };
        fs.writeFileSync(ITEMS_DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
        console.log('✅ Записи сохранены');
    } catch (error) {
        console.error('❌ Ошибка при сохранении записей:', error);
    }
}

// Функция для проверки наличия SSL сертификата
function checkSslCertificate(domain) {
    try {
        const rootDomain = getRootDomain(domain);
        const certPaths = [
            path.join(ACME_DIR, `*.${rootDomain}_ecc`),
            path.join(ACME_DIR, `*.${rootDomain}`)
        ];

        for (const certPath of certPaths) {
            if (fs.existsSync(certPath)) {
                // Проверяем наличие необходимых файлов сертификата
                const files = fs.readdirSync(certPath);
                const hasCert = files.some(f => f.endsWith('.cer') && !f.includes('ca.cer'));
                const hasKey = files.some(f => f.endsWith('.key'));
                const hasFullchain = files.some(f => f === 'fullchain.cer');

                if (hasCert && hasKey && hasFullchain) {
                    return {
                        exists: true,
                        path: certPath,
                        rootDomain: rootDomain
                    };
                }
            }
        }

        return {
            exists: false,
            rootDomain: rootDomain,
            message: `SSL сертификат для домена *.${rootDomain} не найден. Получите сертификат через меню "🔐 Получить сертификат"`
        };
    } catch (error) {
        console.error('❌ Ошибка проверки SSL сертификата:', error);
        return {
            exists: false,
            error: error.message
        };
    }
}

// Функция для создания nginx конфига из шаблона
function createNginxConfig(domain, dest, ssl = false) {
    try {
        // Проверяем существование папки nginx_config
        if (!fs.existsSync(NGINX_CONFIG_DIR)) {
            fs.mkdirSync(NGINX_CONFIG_DIR, { recursive: true });
            console.log('📁 Создана папка для nginx конфигов');
        }

        // Выбираем шаблон в зависимости от SSL
        const templatePath = ssl ? NGINX_SSL_TEMPLATE_PATH : NGINX_TEMPLATE_PATH;

        // Читаем шаблон
        if (!fs.existsSync(templatePath)) {
            console.error('❌ Шаблон nginx не найден:', templatePath);
            return { success: false, error: 'Шаблон nginx не найден' };
        }

        let template = fs.readFileSync(templatePath, 'utf8');

        // Извлекаем хост из destination
        let newHost = dest;
        try {
            const url = new URL(dest);
            newHost = url.host; // host включает hostname и port (например: 192.168.1.22:8123)
        } catch (e) {
            // Если не удалось распарсить как URL, убираем протокол вручную
            newHost = dest.replace(/^https?:\/\//, '');
        }

        // Заменяем параметры
        template = template.replace(/{host}/g, domain);
        template = template.replace(/{destination}/g, dest);
        template = template.replace(/{new_host}/g, newHost);

        // Для SSL-шаблона также заменяем {domain} на корневой домен
        if (ssl) {
            const rootDomain = getRootDomain(domain);
            template = template.replace(/{domain}/g, rootDomain);
            console.log(`🔐 Используется SSL-шаблон. Корневой домен: ${rootDomain}`);
        }

        // Сохраняем конфиг
        const configPath = path.join(NGINX_CONFIG_DIR, domain+'.conf');
        fs.writeFileSync(configPath, template, 'utf8');
        console.log(`✅ Создан nginx конфиг: ${configPath}`);

        return {
            success: true,
            config: template,
            path: configPath
        };
    } catch (error) {
        console.error('❌ Ошибка при создании nginx конфига:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Функция для удаления nginx конфига
function deleteNginxConfig(domain) {
    try {
        const configPath = path.join(NGINX_CONFIG_DIR, domain+'.conf');
        if (fs.existsSync(configPath)) {
            fs.unlinkSync(configPath);
            console.log(`🗑️  Удален nginx конфиг: ${configPath}`);
            return true;
        }
        return false;
    } catch (error) {
        console.error('❌ Ошибка при удалении nginx конфига:', error);
        return false;
    }
}

// Функция для проверки конфигурации nginx
async function testNginxConfig() {
    try {
        const { stdout, stderr } = await execPromise('docker exec nginx_webserver nginx -t 2>&1');
        console.log('✅ Nginx конфигурация валидна');
        return { success: true, output: stdout + stderr };
    } catch (error) {
        console.error('❌ Ошибка в конфигурации nginx:', error.stdout + error.stderr);
        return {
            success: false,
            error: error.stdout + error.stderr,
            message: 'Ошибка в конфигурации nginx'
        };
    }
}

// Функция для перезагрузки nginx
async function reloadNginx() {
    try {
        const { stdout, stderr } = await execPromise('docker exec nginx_webserver nginx -s reload 2>&1');
        console.log('🔄 Nginx перезагружен успешно');
        return { success: true, output: stdout + stderr };
    } catch (error) {
        console.error('❌ Ошибка при перезагрузке nginx:', error.stdout + error.stderr);
        return {
            success: false,
            error: error.stdout + error.stderr,
            message: 'Ошибка при перезагрузке nginx'
        };
    }
}

// Функция для применения изменений nginx (проверка + перезагрузка)
async function applyNginxChanges() {
    // Сначала проверяем конфигурацию
    const testResult = await testNginxConfig();
    if (!testResult.success) {
        return testResult;
    }

    // Если проверка прошла успешно, перезагружаем
    return await reloadNginx();
}

// Функция для рекурсивного копирования папки
function copyFolderRecursiveSync(source, target) {
    if (!fs.existsSync(target)) {
        fs.mkdirSync(target, { recursive: true });
    }

    if (fs.lstatSync(source).isDirectory()) {
        const files = fs.readdirSync(source);
        files.forEach(file => {
            const curSource = path.join(source, file);
            const curTarget = path.join(target, file);

            if (fs.lstatSync(curSource).isDirectory()) {
                copyFolderRecursiveSync(curSource, curTarget);
            } else {
                fs.copyFileSync(curSource, curTarget);
            }
        });
    }
}

// Загрузка данных при старте
let userData = loadUserData();
const itemsData = loadItems();
let items = itemsData.items;
let itemIdCounter = itemsData.counter;

// Сохраняем начальные данные, если файлов не было
saveUserData(userData);
saveItems();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'your-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Middleware для проверки авторизации
function requireAuth(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Главная страница
app.get('/', requireAuth, (req, res) => {
    const indexPath = path.join(__dirname, 'views', 'index.html');
    res.sendFile(indexPath);
});

// Страница входа
app.get('/login', (req, res) => {
    if (req.session.authenticated) {
        return res.redirect('/');
    }
    const loginPath = path.join(__dirname, 'views', 'login.html');
    res.sendFile(loginPath);
});

// Обработка входа
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === userData.username && await bcrypt.compare(password, userData.passwordHash)) {
        req.session.authenticated = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Неверные учетные данные' });
    }
});

// Выход
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// API для работы с записями
app.get('/api/items', requireAuth, (req, res) => {
    res.json(items);
});

app.post('/api/items', requireAuth, async (req, res) => {
    const { domain, dest, item3, ssl, active, notes } = req.body;

    // Проверяем наличие SSL сертификата, если SSL включен
    if (ssl) {
        const certCheck = checkSslCertificate(domain);
        if (!certCheck.exists) {
            return res.status(400).json({
                error: 'SSL сертификат не найден',
                details: certCheck.message || certCheck.error
            });
        }
    }

    const newItem = {
        id: itemIdCounter++,
        domain,
        dest,
        item3,
        ssl: ssl !== undefined ? ssl : false,
        active: active !== undefined ? active : true,
        notes: notes || ''
    };
    items.push(newItem);
    saveItems();

    // Создаем nginx конфиг, если запись активна
    if (newItem.active) {
        const configResult = createNginxConfig(domain, dest, newItem.ssl);

        if (!configResult.success) {
            items.pop();
            itemIdCounter--;
            saveItems();
            return res.status(500).json({
                error: 'Ошибка создания конфигурации',
                details: configResult.error
            });
        }

        // Проверяем и перезагружаем nginx
        const nginxResult = await applyNginxChanges();
        if (!nginxResult.success) {
            items.pop();
            itemIdCounter--;
            saveItems();
            deleteNginxConfig(domain);

            return res.status(500).json({
                error: 'Ошибка конфигурации Nginx',
                details: nginxResult.error,
                config: configResult.config
            });
        }
    }

    res.json(newItem);
});

app.put('/api/items/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const { domain, dest, item3, ssl, active, notes } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        // Проверяем наличие SSL сертификата, если SSL включен
        if (ssl) {
            const certCheck = checkSslCertificate(domain);
            if (!certCheck.exists) {
                return res.status(400).json({
                    error: 'SSL сертификат не найден',
                    details: certCheck.message || certCheck.error
                });
            }
        }

        const oldItem = { ...items[itemIndex] };
        const oldDomain = items[itemIndex].domain;
        const oldActive = items[itemIndex].active;

        items[itemIndex] = {
            id,
            domain,
            dest,
            item3,
            ssl: ssl !== undefined ? ssl : items[itemIndex].ssl,
            active: active !== undefined ? active : items[itemIndex].active,
            notes: notes !== undefined ? notes : (items[itemIndex].notes || '')
        };
        saveItems();

        // Удаляем старый конфиг, если домен изменился
        if (oldDomain !== domain) {
            deleteNginxConfig(oldDomain);
        }

        let configResult = { success: true, config: '' };

        // Управляем конфигом в зависимости от статуса active
        if (items[itemIndex].active) {
            configResult = createNginxConfig(domain, dest, items[itemIndex].ssl);
            if (!configResult.success) {
                items[itemIndex] = oldItem;
                saveItems();
                if (oldDomain !== domain && oldActive) {
                    createNginxConfig(oldDomain, oldItem.dest, oldItem.ssl);
                }
                return res.status(500).json({
                    error: 'Ошибка создания конфигурации',
                    details: configResult.error
                });
            }
        } else {
            deleteNginxConfig(domain);
        }

        // Проверяем и перезагружаем nginx
        const nginxResult = await applyNginxChanges();
        if (!nginxResult.success) {
            // Откатываем изменения при ошибке
            items[itemIndex] = oldItem;
            saveItems();

            // Восстанавливаем конфиги
            if (oldDomain !== domain && oldActive) {
                createNginxConfig(oldDomain, oldItem.dest, oldItem.ssl);
            }
            if (oldActive) {
                createNginxConfig(oldDomain, oldItem.dest, oldItem.ssl);
            } else {
                deleteNginxConfig(domain);
            }

            return res.status(500).json({
                error: 'Ошибка конфигурации Nginx',
                details: nginxResult.error,
                config: configResult.config
            });
        }

        res.json(items[itemIndex]);
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

// Endpoint для переключения SSL
app.patch('/api/items/:id/toggle-ssl', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const { ssl } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        const domain = items[itemIndex].domain;

        // Проверяем наличие SSL сертификата при включении SSL
        if (ssl) {
            const certCheck = checkSslCertificate(domain);
            if (!certCheck.exists) {
                return res.status(400).json({
                    error: 'SSL сертификат не найден',
                    details: certCheck.message || certCheck.error,
                    certInfo: certCheck
                });
            }
        }

        const oldSsl = items[itemIndex].ssl;
        items[itemIndex].ssl = ssl;
        saveItems();

        let configResult = { success: true, config: '' };

        // Пересоздаем конфиг с новыми параметрами, если запись активна
        if (items[itemIndex].active) {
            configResult = createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, items[itemIndex].ssl);

            if (!configResult.success) {
                items[itemIndex].ssl = oldSsl;
                saveItems();
                return res.status(500).json({
                    error: 'Ошибка создания конфигурации',
                    details: configResult.error
                });
            }

            // Проверяем и перезагружаем nginx
            const nginxResult = await applyNginxChanges();
            if (!nginxResult.success) {
                // Откатываем изменения при ошибке
                items[itemIndex].ssl = oldSsl;
                saveItems();
                createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, oldSsl);

                return res.status(500).json({
                    error: 'Ошибка конфигурации Nginx',
                    details: nginxResult.error,
                    config: configResult.config
                });
            }
        }

        res.json({
            success: true,
            ssl: items[itemIndex].ssl,
            config: configResult.config
        });
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

// Endpoint для переключения активности записи
app.patch('/api/items/:id/toggle-active', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const { active } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        // Проверяем наличие SSL сертификата при активации записи с SSL
        if (active && items[itemIndex].ssl) {
            const certCheck = checkSslCertificate(items[itemIndex].domain);
            if (!certCheck.exists) {
                return res.status(400).json({
                    error: 'SSL сертификат не найден',
                    details: certCheck.message || certCheck.error,
                    certInfo: certCheck
                });
            }
        }

        const oldActive = items[itemIndex].active;
        items[itemIndex].active = active;
        saveItems();

        let configResult = { success: true, config: '' };

        // Управляем конфигом в зависимости от нового статуса
        if (active) {
            configResult = createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, items[itemIndex].ssl);

            if (!configResult.success) {
                items[itemIndex].active = oldActive;
                saveItems();
                return res.status(500).json({
                    error: 'Ошибка создания конфигурации',
                    details: configResult.error
                });
            }
        } else {
            deleteNginxConfig(items[itemIndex].domain);
        }

        // Проверяем и перезагружаем nginx
        const nginxResult = await applyNginxChanges();
        if (!nginxResult.success) {
            // Откатываем изменения при ошибке
            items[itemIndex].active = oldActive;
            saveItems();

            // Восстанавливаем конфиг
            if (oldActive) {
                createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, items[itemIndex].ssl);
            } else {
                deleteNginxConfig(items[itemIndex].domain);
            }

            return res.status(500).json({
                error: 'Ошибка конфигурации Nginx',
                details: nginxResult.error,
                config: configResult.config
            });
        }

        res.json({
            success: true,
            active: items[itemIndex].active,
            config: configResult.config
        });
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

app.delete('/api/items/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        const deletedItem = { ...items[itemIndex] };
        const domain = items[itemIndex].domain;
        items.splice(itemIndex, 1);
        saveItems();

        // Удаляем nginx конфиг
        deleteNginxConfig(domain);

        // Проверяем и перезагружаем nginx
        const nginxResult = await applyNginxChanges();
        if (!nginxResult.success) {
            // Откатываем изменения при ошибке
            items.splice(itemIndex, 0, deletedItem);
            saveItems();

            // Восстанавливаем конфиг если он был активен
            if (deletedItem.active) {
                createNginxConfig(domain, deletedItem.dest, deletedItem.ssl);
            }

            return res.status(500).json({
                error: 'Ошибка конфигурации Nginx',
                details: nginxResult.error
            });
        }

        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

// Смена пароля
app.post('/api/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (await bcrypt.compare(currentPassword, userData.passwordHash)) {
        userData.passwordHash = await bcrypt.hash(newPassword, 10);
        saveUserData(userData);
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Неверный текущий пароль' });
    }
});

// Сохранение CloudFlare токена
app.post('/api/save-cf-token', requireAuth, async (req, res) => {
    const { cf_token } = req.body;

    if (!cf_token) {
        return res.status(400).json({ error: 'Токен CloudFlare обязателен' });
    }

    try {
        userData.cf_token = cf_token;
        saveUserData(userData);
        res.json({ success: true, message: 'Токен CloudFlare успешно сохранен' });
    } catch (error) {
        console.error('❌ Ошибка при сохранении токена:', error);
        res.status(500).json({ error: 'Ошибка при сохранении токена' });
    }
});

// Получение статуса токена (есть или нет)
app.get('/api/cf-token-status', requireAuth, (req, res) => {
    res.json({
        hasToken: !!userData.cf_token,
        tokenPreview: userData.cf_token ? '***' + userData.cf_token.slice(-4) : null
    });
});

// Экспорт настроек в ZIP
app.get('/api/export-settings', requireAuth, async (req, res) => {
    try {
        console.log('📦 Начало создания архива с настройками...');

        // Устанавливаем заголовки для скачивания файла
        const date = new Date().toISOString().split('T')[0];
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=settings-backup-${date}.zip`);

        // Создаем архиватор
        const archive = archiver('zip', {
            zlib: { level: 9 }
        });

        // Обработка ошибок
        archive.on('error', (err) => {
            console.error('❌ Ошибка при создании архива:', err);
            res.status(500).json({ error: 'Ошибка при создании архива' });
        });

        // Передаем поток в response
        archive.pipe(res);

        // Добавляем файлы JSON
        if (fs.existsSync(ITEMS_DATA_FILE)) {
            archive.file(ITEMS_DATA_FILE, { name: 'items.json' });
            console.log('✅ Добавлен items.json');
        }

        if (fs.existsSync(USER_DATA_FILE)) {
            archive.file(USER_DATA_FILE, { name: 'user.json' });
            console.log('✅ Добавлен user.json');
        }

        // Добавляем папку acme.sh, если она существует
        if (fs.existsSync(ACME_DIR)) {
            archive.directory(ACME_DIR, 'acme.sh');
            console.log('✅ Добавлена папка acme.sh');
        } else {
            console.log('⚠️  Папка acme.sh не найдена');
        }

        // Завершаем архив
        await archive.finalize();
        console.log('✅ Архив успешно создан');

    } catch (error) {
        console.error('❌ Ошибка при экспорте настроек:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Ошибка при экспорте настроек' });
        }
    }
});

function clearDir(dirPath) {
    if (!fs.existsSync(dirPath)) return;
    for (const entry of fs.readdirSync(dirPath)) {
        const entryPath = path.join(dirPath, entry);
        const stat = fs.lstatSync(entryPath);
        if (stat.isDirectory()) {
            fs.rmSync(entryPath, { recursive: true, force: true });
        } else {
            fs.unlinkSync(entryPath);
        }
    }
}

// Улучшенная функция clearDir с обработкой ошибок и логированием
function clearDirImproved(dirPath) {
    console.log(`🧹 Начало очистки директории: ${dirPath}`);

    if (!fs.existsSync(dirPath)) {
        console.log('   ⚠️  Директория не существует');
        return { success: true, cleared: 0, errors: [] };
    }

    let clearedCount = 0;
    const errors = [];

    try {
        const entries = fs.readdirSync(dirPath);
        console.log(`   📋 Найдено элементов для удаления: ${entries.length}`);

        for (const entry of entries) {
            const entryPath = path.join(dirPath, entry);

            try {
                const stat = fs.lstatSync(entryPath);

                if (stat.isDirectory()) {
                    console.log(`   🗑️  Удаление папки: ${entry}`);
                    fs.rmSync(entryPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
                    clearedCount++;
                } else {
                    console.log(`   🗑️  Удаление файла: ${entry}`);
                    fs.unlinkSync(entryPath);
                    clearedCount++;
                }
                console.log(`      ✓ Успешно удалено: ${entry}`);
            } catch (err) {
                console.error(`      ✗ Ошибка удаления ${entry}:`, err.message);
                errors.push({ file: entry, error: err.message });

                // Пытаемся удалить с sudo/повышенными правами через chmod
                try {
                    if (stat.isDirectory()) {
                        // Рекурсивно меняем права
                        execSync(`chmod -R 777 "${entryPath}" 2>/dev/null || true`);
                        fs.rmSync(entryPath, { recursive: true, force: true });
                    } else {
                        execSync(`chmod 777 "${entryPath}" 2>/dev/null || true`);
                        fs.unlinkSync(entryPath);
                    }
                    console.log(`      ✓ Удалено после изменения прав: ${entry}`);
                    clearedCount++;
                } catch (err2) {
                    console.error(`      ✗ Не удалось удалить даже после chmod:`, err2.message);
                }
            }
        }

        console.log(`   ✅ Очистка завершена: удалено ${clearedCount} из ${entries.length}`);
        return { success: errors.length === 0, cleared: clearedCount, errors };

    } catch (err) {
        console.error('   ❌ Критическая ошибка при очистке:', err.message);
        return { success: false, cleared: clearedCount, errors: [{ file: 'directory', error: err.message }] };
    }
}

// Улучшенная функция copyFolderRecursiveSync с обработкой ошибок
function copyFolderRecursiveSyncImproved(source, target) {
    console.log(`📋 Копирование: ${source} -> ${target}`);

    if (!fs.existsSync(source)) {
        console.error('   ❌ Источник не существует');
        return { success: false, copied: 0, errors: [{ file: source, error: 'Source does not exist' }] };
    }

    let copiedCount = 0;
    const errors = [];

    try {
        // Создаем целевую директорию
        if (!fs.existsSync(target)) {
            fs.mkdirSync(target, { recursive: true, mode: 0o777 });
            console.log(`   📁 Создана целевая директория: ${target}`);
        }

        const stat = fs.lstatSync(source);

        if (stat.isDirectory()) {
            const files = fs.readdirSync(source);
            console.log(`   📄 Найдено элементов для копирования: ${files.length}`);

            for (const file of files) {
                const curSource = path.join(source, file);
                const curTarget = path.join(target, file);

                try {
                    const curStat = fs.lstatSync(curSource);

                    if (curStat.isDirectory()) {
                        console.log(`   📁 Копирование папки: ${file}`);
                        const result = copyFolderRecursiveSyncImproved(curSource, curTarget);
                        copiedCount += result.copied;
                        errors.push(...result.errors);
                    } else if (curStat.isSymbolicLink()) {
                        console.log(`   🔗 Копирование символической ссылки: ${file}`);
                        const linkTarget = fs.readlinkSync(curSource);
                        fs.symlinkSync(linkTarget, curTarget);
                        copiedCount++;
                    } else {
                        console.log(`   📄 Копирование файла: ${file}`);
                        fs.copyFileSync(curSource, curTarget);
                        // Копируем права доступа
                        fs.chmodSync(curTarget, curStat.mode);
                        copiedCount++;
                    }
                    console.log(`      ✓ Успешно: ${file}`);

                } catch (err) {
                    console.error(`      ✗ Ошибка копирования ${file}:`, err.message);
                    errors.push({ file: file, error: err.message });
                }
            }
        }

        console.log(`   ✅ Копирование завершено: ${copiedCount} элементов`);
        return { success: errors.length === 0, copied: copiedCount, errors };

    } catch (err) {
        console.error('   ❌ Критическая ошибка при копировании:', err.message);
        return { success: false, copied: copiedCount, errors: [{ file: 'directory', error: err.message }] };
    }
}

// Импорт настроек из ZIP
app.post('/api/import-settings', requireAuth, upload.single('settings'), async (req, res) => {
    let tempDir = null;

    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }

        console.log('📥 Начало импорта настроек из:', req.file.path);

        // Создаем временную директорию для распаковки
        tempDir = path.join('/tmp', 'import_' + Date.now());
        fs.mkdirSync(tempDir, { recursive: true, mode: 0o777 });
        console.log('📁 Создана временная директория:', tempDir);

        // Распаковываем ZIP
        const zip = new AdmZip(req.file.path);

        // Устанавливаем права доступа для распакованных файлов
        const zipEntries = zip.getEntries();
        console.log(`📦 ZIP содержит ${zipEntries.length} элементов`);

        // Распаковываем с установкой прав
        zipEntries.forEach(entry => {
            try {
                if (entry.isDirectory) {
                    const dirPath = path.join(tempDir, entry.entryName);
                    if (!fs.existsSync(dirPath)) {
                        fs.mkdirSync(dirPath, { recursive: true, mode: 0o777 });
                    }
                } else {
                    const filePath = path.join(tempDir, entry.entryName);
                    const fileDir = path.dirname(filePath);
                    if (!fs.existsSync(fileDir)) {
                        fs.mkdirSync(fileDir, { recursive: true, mode: 0o777 });
                    }
                    fs.writeFileSync(filePath, entry.getData(), { mode: 0o666 });
                }
            } catch (err) {
                console.error(`⚠️  Ошибка распаковки ${entry.entryName}:`, err.message);
            }
        });

        console.log('✅ Архив распакован в:', tempDir);

        // Проверяем структуру распакованного архива
        console.log('\n📦 === АНАЛИЗ СТРУКТУРЫ АРХИВА ===');
        const tempContents = fs.readdirSync(tempDir);
        console.log(`📋 Элементов в корне временной папки: ${tempContents.length}`);
        tempContents.forEach(item => {
            const itemPath = path.join(tempDir, item);
            const stat = fs.statSync(itemPath);
            const type = stat.isDirectory() ? '📁 DIR ' : '📄 FILE';
            console.log(`   ${type}: ${item}`);

            // Если это директория, показываем её содержимое
            if (stat.isDirectory()) {
                try {
                    const subItems = fs.readdirSync(itemPath);
                    console.log(`      └─ Содержит ${subItems.length} элементов`);
                    if (subItems.length > 0 && subItems.length <= 10) {
                        subItems.forEach(sub => console.log(`         - ${sub}`));
                    }
                } catch (e) {
                    console.log(`      └─ Ошибка чтения: ${e.message}`);
                }
            }
        });
        console.log('📦 === КОНЕЦ АНАЛИЗА ===\n');

        // Восстанавливаем items.json
        const itemsPath = path.join(tempDir, 'items.json');
        if (fs.existsSync(itemsPath)) {
            fs.copyFileSync(itemsPath, ITEMS_DATA_FILE);
            console.log('✅ Восстановлен items.json');

            // Перезагружаем данные в память
            const newItemsData = loadItems();
            items = newItemsData.items;
            itemIdCounter = newItemsData.counter;

            // Отключаем ssl и active для всех записей
            items = items.map(item => ({
                ...item,
                ssl: false,
                active: false
            }));

            // Сохраняем изменения
            saveItems();
            console.log('🔒 SSL и Active отключены для всех импортированных записей');
        }

        // Восстанавливаем user.json
        const userPath = path.join(tempDir, 'user.json');
        if (fs.existsSync(userPath)) {
            fs.copyFileSync(userPath, USER_DATA_FILE);
            console.log('✅ Восстановлен user.json');

            // Перезагружаем данные пользователя
            userData = loadUserData();
        }

        // Очищаем старые nginx конфиги (кроме default.conf)
        console.log('🧹 Очистка старых nginx конфигов...');
        if (fs.existsSync(NGINX_CONFIG_DIR)) {
            const configFiles = fs.readdirSync(NGINX_CONFIG_DIR);
            let deletedCount = 0;
            for (const file of configFiles) {
                if (file !== 'default.conf' && file.endsWith('.conf')) {
                    try {
                        const filePath = path.join(NGINX_CONFIG_DIR, file);
                        fs.unlinkSync(filePath);
                        console.log(`   ✓ Удален: ${file}`);
                        deletedCount++;
                    } catch (err) {
                        console.error(`   ✗ Ошибка удаления ${file}:`, err.message);
                    }
                }
            }
            console.log(`   Удалено конфигов: ${deletedCount}`);
        }

        // Восстанавливаем папку acme.sh
        // Ищем папку acme.sh (может быть в корне или в подпапке)
        let acmeTempPath = null;

        console.log('\n🔍 === ПОИСК ПАПКИ ACME.SH ===');

        // Проверяем напрямую в корне
        const directPath = path.join(tempDir, 'acme.sh');
        console.log(`🔍 Проверка: ${directPath}`);
        if (fs.existsSync(directPath) && fs.statSync(directPath).isDirectory()) {
            acmeTempPath = directPath;
            console.log('✅ Найдена в корне временной папки');
        } else {
            console.log('❌ Не найдена в корне, ищем в подпапках...');

            // Ищем в подпапках (первый уровень вложенности)
            for (const item of tempContents) {
                const itemPath = path.join(tempDir, item);
                if (fs.statSync(itemPath).isDirectory()) {
                    const possiblePath = path.join(itemPath, 'acme.sh');
                    console.log(`🔍 Проверка: ${possiblePath}`);
                    if (fs.existsSync(possiblePath) && fs.statSync(possiblePath).isDirectory()) {
                        acmeTempPath = possiblePath;
                        console.log(`✅ Найдена в: ${item}/acme.sh`);
                        break;
                    }
                }
            }
        }

        if (acmeTempPath && fs.existsSync(acmeTempPath)) {
            console.log('\n🔐 === НАЧАЛО ВОССТАНОВЛЕНИЯ СЕРТИФИКАТОВ ===');
            console.log(`📍 Источник: ${acmeTempPath}`);
            console.log(`📍 Назначение: ${ACME_DIR}`);

            // Проверяем содержимое источника
            const sourceItems = fs.readdirSync(acmeTempPath);
            console.log(`📦 В архиве найдено элементов: ${sourceItems.length}`);
            if (sourceItems.length > 0) {
                console.log('📋 Содержимое архива:');
                sourceItems.forEach(item => console.log(`   - ${item}`));
            }

            // Создаем директорию если не существует
            if (!fs.existsSync(ACME_DIR)) {
                fs.mkdirSync(ACME_DIR, { recursive: true, mode: 0o777 });
                console.log('📁 Создана директория:', ACME_DIR);
            } else {
                console.log('📁 Директория уже существует:', ACME_DIR);

                // Проверяем содержимое перед очисткой
                const beforeClear = fs.readdirSync(ACME_DIR);
                console.log(`📦 До очистки элементов: ${beforeClear.length}`);

                // Очищаем существующую директорию
                console.log('\n🧹 === ОЧИСТКА ДИРЕКТОРИИ ===');
                const clearResult = clearDirImproved(ACME_DIR);

                if (!clearResult.success) {
                    console.error('⚠️  Очистка завершена с ошибками:', clearResult.errors);
                } else {
                    console.log(`✅ Директория успешно очищена (${clearResult.cleared} элементов)`);
                }

                // Проверяем что осталось после очистки
                const afterClear = fs.readdirSync(ACME_DIR);
                console.log(`📦 После очистки осталось элементов: ${afterClear.length}`);
                if (afterClear.length > 0) {
                    console.log('⚠️  Не удалось удалить:');
                    afterClear.forEach(item => console.log(`   - ${item}`));
                }
            }

            // Копируем содержимое
            console.log('\n📋 === КОПИРОВАНИЕ ФАЙЛОВ ===');
            const copyResult = copyFolderRecursiveSyncImproved(acmeTempPath, ACME_DIR);

            if (!copyResult.success) {
                console.error('⚠️  Копирование завершено с ошибками:', copyResult.errors);
            } else {
                console.log(`✅ Успешно скопировано элементов: ${copyResult.copied}`);
            }

            // Проверяем финальное состояние
            const finalItems = fs.readdirSync(ACME_DIR);
            console.log(`\n📦 Финальное содержимое (${finalItems.length} элементов):`);
            finalItems.forEach(item => {
                const itemPath = path.join(ACME_DIR, item);
                const stat = fs.statSync(itemPath);
                const type = stat.isDirectory() ? '📁' : '📄';
                console.log(`   ${type} ${item}`);
            });

            console.log('🔐 === ВОССТАНОВЛЕНИЕ СЕРТИФИКАТОВ ЗАВЕРШЕНО ===\n');
        } else {
            console.log('⚠️  Папка acme.sh не найдена в архиве');
        }

        // Перезагружаем nginx (все конфиги удалены, записи неактивны)
        console.log('🔄 Применение изменений nginx...');
        await applyNginxChanges();

        // Удаляем временные файлы
        fs.unlinkSync(req.file.path);
        fs.rmSync(tempDir, { recursive: true, force: true });
        console.log('🗑️  Временные файлы удалены');

        console.log('✅ Импорт настроек завершен успешно');
        res.json({
            success: true,
            message: 'Настройки успешно загружены! SSL и Active отключены для всех записей. Активируйте нужные записи вручную.'
        });

    } catch (error) {
        console.error('❌ Ошибка при импорте настроек:', error);

        // Очистка временных файлов в случае ошибки
        if (req.file && fs.existsSync(req.file.path)) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (e) {
                console.error('Ошибка удаления загруженного файла:', e.message);
            }
        }
        if (tempDir && fs.existsSync(tempDir)) {
            try {
                fs.rmSync(tempDir, { recursive: true, force: true });
            } catch (e) {
                console.error('Ошибка удаления временной директории:', e.message);
            }
        }

        res.status(500).json({
            error: 'Ошибка при импорте настроек',
            details: error.message
        });
    }
});


// Получение списка существующих сертификатов
app.get('/api/ssl-certificates', requireAuth, async (req, res) => {
    try {
        const acmeDir = '/acme.sh';

        console.log('🔍 Поиск сертификатов в:', acmeDir);

        if (!fs.existsSync(acmeDir)) {
            console.log('❌ Папка не существует:', acmeDir);
            return res.json({ certificates: [] });
        }

        const certificates = [];
        const items = fs.readdirSync(acmeDir);
        console.log('📂 Найдено элементов в папке:', items.length);

        for (const item of items) {
            const itemPath = path.join(acmeDir, item);
            const stats = fs.statSync(itemPath);

            if (!stats.isDirectory()) {
                continue;
            }

            let domain = null;
            let certDir = itemPath;

            if (item.endsWith('_ecc') && item.startsWith('*.')) {
                domain = item.replace('*.', '').replace('_ecc', '');
            } else if (item.startsWith('*.')) {
                domain = item.replace('*.', '');
            } else if (item.endsWith('_ecc')) {
                domain = item.replace('_ecc', '');
            } else if (!item.includes('_') && item.includes('.')) {
                domain = item;
            }

            if (!domain) {
                continue;
            }

            try {
                const certFiles = fs.readdirSync(certDir);
                let certFile = null;

                for (const file of certFiles) {
                    if (file.endsWith('.cer') && !file.includes('ca.cer')) {
                        certFile = path.join(certDir, file);
                        break;
                    }
                }

                if (!certFile || !fs.existsSync(certFile)) {
                    continue;
                }

                const command = `docker exec acme_sh openssl x509 -enddate -noout -in "${certFile}"`;
                const { stdout } = await execPromise(command);

                const match = stdout.match(/notAfter=(.+)/);
                if (match) {
                    const expiryDate = new Date(match[1]);
                    const now = new Date();
                    const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));

                    certificates.push({
                        domain: domain,
                        expiryDate: expiryDate.toISOString(),
                        daysLeft: daysLeft,
                        path: certDir,
                        status: daysLeft > 30 ? 'valid' : daysLeft > 0 ? 'expiring' : 'expired'
                    });
                }
            } catch (error) {
                console.error(`❌ Ошибка при обработке сертификата ${domain}:`, error.message);
            }
        }

        certificates.sort((a, b) => a.daysLeft - b.daysLeft);
        res.json({ certificates });

    } catch (error) {
        console.error('❌ Ошибка при получении списка сертификатов:', error);
        res.status(500).json({
            error: 'Ошибка при получении списка сертификатов',
            details: error.message
        });
    }
});

// Получение SSL-сертификата через Let's Encrypt с CloudFlare DNS
app.post('/api/get-ssl-certificate', requireAuth, async (req, res) => {
    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Домен обязателен для заполнения' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({
            error: 'CloudFlare токен не настроен',
            details: 'Пожалуйста, сначала сохраните CloudFlare API токен в настройках'
        });
    }

    try {
        console.log('🔐 Начало процесса получения SSL-сертификата через CloudFlare...');
        console.log(`   Домен: ${domain}`);

        const issueCommand = `docker exec -e CF_Token='${userData.cf_token}' acme_sh acme.sh --issue --dns dns_cf -d *.${domain} -d ${domain} --server letsencrypt`;

        let issueResult;
        let alreadyExists = false;
        let renewalDate = '';

        try {
            issueResult = await execPromise(issueCommand);
            console.log('✅ Сертификат получен успешно!');
        } catch (error) {
            const errorOutput = error.stdout + error.stderr;

            if (errorOutput.includes('Domains not changed') &&
                errorOutput.includes('Skipping') &&
                errorOutput.includes('Next renewal time is')) {
                console.log('ℹ️  Сертификат уже существует и действителен');
                alreadyExists = true;
                issueResult = { stdout: errorOutput, stderr: '' };

                const renewalMatch = errorOutput.match(/Next renewal time is: ([^\n]+)/);
                if (renewalMatch) {
                    renewalDate = renewalMatch[1];
                }
            } else {
                console.error('❌ Ошибка получения сертификата:', errorOutput);
                return res.status(500).json({
                    error: 'Ошибка при получении SSL-сертификата',
                    details: errorOutput,
                    step: 'certificate'
                });
            }
        }

        const certPath = `/acme.sh/*.${domain}_ecc`;
        const certFiles = {
            fullchain: `${certPath}/fullchain.cer`,
            key: `${certPath}/*.${domain}.key`,
            cert: `${certPath}/*.${domain}.cer`,
            ca: `${certPath}/ca.cer`
        };

        console.log('📁 Сертификаты сохранены в:', certPath);

        res.json({
            success: true,
            message: alreadyExists
                ? 'SSL-сертификат уже существует и действителен!'
                : 'SSL-сертификат успешно получен!',
            alreadyExists: alreadyExists,
            renewalDate: renewalDate,
            domain: domain,
            certPath: certPath,
            certFiles: certFiles,
            output: issueResult.stdout + issueResult.stderr
        });

    } catch (error) {
        console.error('❌ Непредвиденная ошибка:', error);
        res.status(500).json({
            error: 'Непредвиденная ошибка при получении сертификата',
            details: error.message
        });
    }
});

// Получение внешнего IP сервера
app.get('/api/server-external-ip', requireAuth, async (req, res) => {
    try {
        const ip = await getServerExternalIp();
        if (ip) {
            res.json({ success: true, ip });
        } else {
            res.status(500).json({ error: 'Не удалось получить внешний IP' });
        }
    } catch (error) {
        console.error('❌ Ошибка получения внешнего IP:', error);
        res.status(500).json({ error: 'Ошибка получения внешнего IP', details: error.message });
    }
});

// Синхронизация DNS информации для конкретного item
app.post('/api/items/:id/sync-dns', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex === -1) {
        return res.status(404).json({ error: 'Запись не найдена' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const item = items[itemIndex];
        const rootDomain = getRootDomain(item.domain);
        const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

        if (!zoneId) {
            return res.status(404).json({ error: 'Домен не найден в CloudFlare' });
        }

        const record = await getCloudFlareARecord(zoneId, item.domain, userData.cf_token);
        const serverIp = await getServerExternalIp();

        // Обновляем кешированные данные
        items[itemIndex].cf_ip = record ? record.content : null;
        items[itemIndex].cf_record_id = record ? record.id : null;
        items[itemIndex].cf_zone_id = zoneId;
        items[itemIndex].cf_last_sync = new Date().toISOString();
        items[itemIndex].server_ip = serverIp;

        saveItems();

        res.json({
            success: true,
            exists: !!record,
            record: record ? {
                id: record.id,
                name: record.name,
                content: record.content,
                ttl: record.ttl,
                proxied: record.proxied
            } : null,
            serverIp,
            ipMatch: record ? record.content === serverIp : null,
            zoneId
        });
    } catch (error) {
        console.error('❌ Ошибка синхронизации DNS:', error);
        res.status(500).json({ error: 'Ошибка синхронизации DNS', details: error.message });
    }
});

// Синхронизация DNS информации для всех items
app.post('/api/sync-all-dns', requireAuth, async (req, res) => {
    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const serverIp = await getServerExternalIp();
        const results = [];

        for (let i = 0; i < items.length; i++) {
            try {
                const item = items[i];
                const rootDomain = getRootDomain(item.domain);
                const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

                if (zoneId) {
                    const record = await getCloudFlareARecord(zoneId, item.domain, userData.cf_token);

                    items[i].cf_ip = record ? record.content : null;
                    items[i].cf_record_id = record ? record.id : null;
                    items[i].cf_zone_id = zoneId;
                    items[i].cf_last_sync = new Date().toISOString();
                    items[i].server_ip = serverIp;

                    results.push({
                        id: item.id,
                        domain: item.domain,
                        success: true,
                        exists: !!record
                    });
                } else {
                    results.push({
                        id: item.id,
                        domain: item.domain,
                        success: false,
                        error: 'Домен не найден в CloudFlare'
                    });
                }
            } catch (error) {
                console.error(`❌ Ошибка синхронизации DNS для ${items[i].domain}:`, error);
                results.push({
                    id: items[i].id,
                    domain: items[i].domain,
                    success: false,
                    error: error.message
                });
            }
        }

        saveItems();

        res.json({
            success: true,
            serverIp,
            results
        });
    } catch (error) {
        console.error('❌ Ошибка синхронизации всех DNS:', error);
        res.status(500).json({ error: 'Ошибка синхронизации DNS', details: error.message });
    }
});

// Получение информации о DNS записи из CloudFlare
app.post('/api/cloudflare/get-dns-info', requireAuth, async (req, res) => {
    const { domain } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Домен обязателен для заполнения' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const rootDomain = getRootDomain(domain);
        const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

        if (!zoneId) {
            return res.status(404).json({ error: 'Домен не найден в CloudFlare' });
        }

        const record = await getCloudFlareARecord(zoneId, domain, userData.cf_token);
        const serverIp = await getServerExternalIp();

        res.json({
            success: true,
            exists: !!record,
            record: record ? {
                id: record.id,
                name: record.name,
                content: record.content,
                ttl: record.ttl,
                proxied: record.proxied
            } : null,
            serverIp,
            ipMatch: record ? record.content === serverIp : null,
            zoneId
        });
    } catch (error) {
        console.error('❌ Ошибка получения DNS информации:', error);
        res.status(500).json({ error: 'Ошибка получения DNS информации', details: error.message });
    }
});

// Создание DNS записи в CloudFlare
app.post('/api/cloudflare/create-dns', requireAuth, async (req, res) => {
    const { domain, itemId } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Домен обязателен для заполнения' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const rootDomain = getRootDomain(domain);
        const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

        if (!zoneId) {
            return res.status(404).json({ error: 'Домен не найден в CloudFlare' });
        }

        // Проверяем существование записи
        const existingRecord = await getCloudFlareARecord(zoneId, domain, userData.cf_token);
        if (existingRecord) {
            return res.status(400).json({ error: 'DNS запись уже существует' });
        }

        const serverIp = await getServerExternalIp();
        if (!serverIp) {
            return res.status(500).json({ error: 'Не удалось получить внешний IP сервера' });
        }

        const response = await createCloudFlareARecord(zoneId, domain, serverIp, userData.cf_token);

        if (response.success) {
            // Обновляем кеш в items
            if (itemId) {
                const itemIndex = items.findIndex(item => item.id === parseInt(itemId));
                if (itemIndex !== -1) {
                    items[itemIndex].cf_ip = response.result.content;
                    items[itemIndex].cf_record_id = response.result.id;
                    items[itemIndex].cf_zone_id = zoneId;
                    items[itemIndex].cf_last_sync = new Date().toISOString();
                    items[itemIndex].server_ip = serverIp;
                    saveItems();
                }
            }

            res.json({
                success: true,
                message: 'DNS запись успешно создана',
                record: {
                    id: response.result.id,
                    name: response.result.name,
                    content: response.result.content,
                    ttl: response.result.ttl,
                    proxied: response.result.proxied
                }
            });
        } else {
            res.status(500).json({
                error: 'Ошибка создания DNS записи',
                details: response.errors ? JSON.stringify(response.errors) : 'Неизвестная ошибка'
            });
        }
    } catch (error) {
        console.error('❌ Ошибка создания DNS записи:', error);
        res.status(500).json({ error: 'Ошибка создания DNS записи', details: error.message });
    }
});

// Обновление DNS записи в CloudFlare
app.post('/api/cloudflare/update-dns', requireAuth, async (req, res) => {
    const { domain, itemId } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Домен обязателен для заполнения' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const rootDomain = getRootDomain(domain);
        const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

        if (!zoneId) {
            return res.status(404).json({ error: 'Домен не найден в CloudFlare' });
        }

        const existingRecord = await getCloudFlareARecord(zoneId, domain, userData.cf_token);
        if (!existingRecord) {
            return res.status(404).json({ error: 'DNS запись не найдена' });
        }

        const serverIp = await getServerExternalIp();
        if (!serverIp) {
            return res.status(500).json({ error: 'Не удалось получить внешний IP сервера' });
        }

        const response = await updateCloudFlareARecord(
            zoneId,
            existingRecord.id,
            domain,
            serverIp,
            userData.cf_token
        );

        if (response.success) {
            // Обновляем кеш в items
            if (itemId) {
                const itemIndex = items.findIndex(item => item.id === parseInt(itemId));
                if (itemIndex !== -1) {
                    items[itemIndex].cf_ip = response.result.content;
                    items[itemIndex].cf_record_id = response.result.id;
                    items[itemIndex].cf_zone_id = zoneId;
                    items[itemIndex].cf_last_sync = new Date().toISOString();
                    items[itemIndex].server_ip = serverIp;
                    saveItems();
                }
            }

            res.json({
                success: true,
                message: 'DNS запись успешно обновлена',
                record: {
                    id: response.result.id,
                    name: response.result.name,
                    content: response.result.content,
                    ttl: response.result.ttl,
                    proxied: response.result.proxied
                }
            });
        } else {
            res.status(500).json({
                error: 'Ошибка обновления DNS записи',
                details: response.errors ? JSON.stringify(response.errors) : 'Неизвестная ошибка'
            });
        }
    } catch (error) {
        console.error('❌ Ошибка обновления DNS записи:', error);
        res.status(500).json({ error: 'Ошибка обновления DNS записи', details: error.message });
    }
});

// Удаление DNS записи из CloudFlare
app.post('/api/cloudflare/delete-dns', requireAuth, async (req, res) => {
    const { domain, itemId } = req.body;

    if (!domain) {
        return res.status(400).json({ error: 'Домен обязателен для заполнения' });
    }

    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const rootDomain = getRootDomain(domain);
        const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

        if (!zoneId) {
            return res.status(404).json({ error: 'Домен не найден в CloudFlare' });
        }

        const existingRecord = await getCloudFlareARecord(zoneId, domain, userData.cf_token);
        if (!existingRecord) {
            return res.status(404).json({ error: 'DNS запись не найдена' });
        }

        const response = await deleteCloudFlareARecord(zoneId, existingRecord.id, userData.cf_token);

        if (response.success) {
            // Очищаем кеш в items
            if (itemId) {
                const itemIndex = items.findIndex(item => item.id === parseInt(itemId));
                if (itemIndex !== -1) {
                    items[itemIndex].cf_ip = null;
                    items[itemIndex].cf_record_id = null;
                    items[itemIndex].cf_zone_id = zoneId;
                    items[itemIndex].cf_last_sync = new Date().toISOString();
                    saveItems();
                }
            }

            res.json({
                success: true,
                message: 'DNS запись успешно удалена'
            });
        } else {
            res.status(500).json({
                error: 'Ошибка удаления DNS записи',
                details: response.errors ? JSON.stringify(response.errors) : 'Неизвестная ошибка'
            });
        }
    } catch (error) {
        console.error('❌ Ошибка удаления DNS записи:', error);
        res.status(500).json({ error: 'Ошибка удаления DNS записи', details: error.message });
    }
});

// Автоматическая синхронизация DNS записей
async function autoSyncAllDns() {
    console.log('\n🤖 Начало автоматической синхронизации DNS...');

    if (!userData.cf_token) {
        console.error('❌ CloudFlare токен не настроен');
        return {
            success: false,
            updated: 0,
            errors: 1,
            details: [{ error: true, message: 'CloudFlare токен не настроен' }]
        };
    }

    try {
        const serverIp = await getServerExternalIp();
        if (!serverIp) {
            console.error('❌ Не удалось получить внешний IP сервера');
            return {
                success: false,
                updated: 0,
                errors: 1,
                details: [{ error: true, message: 'Не удалось получить внешний IP сервера' }]
            };
        }

        console.log(`📡 Внешний IP сервера: ${serverIp}`);

        let updatedCount = 0;
        let errorCount = 0;
        const details = [];

        for (let i = 0; i < items.length; i++) {
            try {
                const item = items[i];

                // Пропускаем неактивные записи
                if (!item.active) {
                    continue;
                }

                const rootDomain = getRootDomain(item.domain);
                const zoneId = await getCloudFlareZoneId(rootDomain, userData.cf_token);

                if (!zoneId) {
                    console.log(`⚠️  ${item.domain}: домен не найден в CloudFlare`);
                    details.push({
                        domain: item.domain,
                        error: true,
                        message: 'Домен не найден в CloudFlare'
                    });
                    errorCount++;
                    continue;
                }

                const record = await getCloudFlareARecord(zoneId, item.domain, userData.cf_token);

                if (!record) {
                    console.log(`⚠️  ${item.domain}: DNS запись не существует`);
                    details.push({
                        domain: item.domain,
                        error: false,
                        message: 'DNS запись не существует'
                    });

                    // Обновляем кеш
                    items[i].cf_ip = null;
                    items[i].cf_record_id = null;
                    items[i].cf_zone_id = zoneId;
                    items[i].cf_last_sync = new Date().toISOString();
                    items[i].server_ip = serverIp;
                    continue;
                }

                // Проверяем совпадение IP
                const currentIp = record.content;

                if (currentIp === serverIp) {
                    console.log(`✅ ${item.domain}: IP совпадает (${currentIp})`);

                    // Обновляем кеш
                    items[i].cf_ip = currentIp;
                    items[i].cf_record_id = record.id;
                    items[i].cf_zone_id = zoneId;
                    items[i].cf_last_sync = new Date().toISOString();
                    items[i].server_ip = serverIp;

                    details.push({
                        domain: item.domain,
                        error: false,
                        updated: false,
                        message: `IP совпадает (${currentIp})`
                    });
                } else {
                    console.log(`🔄 ${item.domain}: IP изменился ${currentIp} → ${serverIp}, обновляем...`);

                    // Обновляем DNS запись
                    const updateResponse = await updateCloudFlareARecord(
                        zoneId,
                        record.id,
                        item.domain,
                        serverIp,
                        userData.cf_token
                    );

                    if (updateResponse.success) {
                        console.log(`✅ ${item.domain}: DNS успешно обновлен`);

                        // Обновляем кеш
                        items[i].cf_ip = serverIp;
                        items[i].cf_record_id = record.id;
                        items[i].cf_zone_id = zoneId;
                        items[i].cf_last_sync = new Date().toISOString();
                        items[i].server_ip = serverIp;

                        updatedCount++;
                        details.push({
                            domain: item.domain,
                            error: false,
                            updated: true,
                            message: `IP обновлен: ${currentIp} → ${serverIp}`
                        });
                    } else {
                        console.error(`❌ ${item.domain}: ошибка обновления DNS`);
                        errorCount++;
                        details.push({
                            domain: item.domain,
                            error: true,
                            message: 'Ошибка обновления DNS'
                        });
                    }
                }

            } catch (error) {
                console.error(`❌ Ошибка синхронизации для ${items[i].domain}:`, error.message);
                errorCount++;
                details.push({
                    domain: items[i].domain,
                    error: true,
                    message: error.message
                });
            }
        }

        // Сохраняем обновленные данные
        saveItems();

        console.log(`\n✅ Автоматическая синхронизация завершена:`);
        console.log(`   Обновлено записей: ${updatedCount}`);
        console.log(`   Ошибок: ${errorCount}`);

        return {
            success: true,
            updated: updatedCount,
            errors: errorCount,
            serverIp,
            details
        };

    } catch (error) {
        console.error('❌ Критическая ошибка автосинхронизации:', error);
        return {
            success: false,
            updated: 0,
            errors: 1,
            details: [{ error: true, message: error.message }]
        };
    }
}

// ============================================================================
// API ENDPOINTS ДЛЯ УПРАВЛЕНИЯ СИНХРОНИЗАЦИЕЙ
// ============================================================================

// Получение настроек синхронизации
app.get('/api/sync-settings', requireAuth, (req, res) => {
    const status = syncScheduler.getStatus();

    res.json({
        sync_interval: userData.sync_interval || null,
        scheduler_running: status.isRunning,
        last_sync: status.lastSyncTime,
        recent_history: status.recentHistory
    });
});

// Обновление интервала синхронизации
app.post('/api/sync-settings', requireAuth, async (req, res) => {
    const { sync_interval } = req.body;

    // Проверяем корректность значения
    const validIntervals = [null, 30, 60, 720, 1440];
    if (!validIntervals.includes(sync_interval)) {
        return res.status(400).json({
            error: 'Некорректный интервал синхронизации',
            validValues: validIntervals
        });
    }

    try {
        userData.sync_interval = sync_interval;
        saveUserData(userData);

        // Перезапускаем планировщик с новыми настройками
        if (sync_interval && userData.cf_token) {
            syncScheduler.start(sync_interval, autoSyncAllDns, { userData, items });
            console.log(`🔄 Планировщик синхронизации перезапущен с интервалом ${sync_interval} минут`);
        } else {
            syncScheduler.stop();
            console.log('⏹️  Планировщик синхронизации остановлен');
        }

        res.json({
            success: true,
            message: sync_interval
                ? `Автосинхронизация включена (каждые ${sync_interval} минут)`
                : 'Автосинхронизация отключена',
            sync_interval: sync_interval
        });
    } catch (error) {
        console.error('❌ Ошибка при сохранении настроек синхронизации:', error);
        res.status(500).json({ error: 'Ошибка при сохранении настроек', details: error.message });
    }
});

// Ручной запуск синхронизации
app.post('/api/manual-sync', requireAuth, async (req, res) => {
    if (!userData.cf_token) {
        return res.status(400).json({ error: 'CloudFlare токен не настроен' });
    }

    try {
        const result = await autoSyncAllDns();

        res.json({
            success: true,
            message: 'Ручная синхронизация завершена',
            ...result
        });
    } catch (error) {
        console.error('❌ Ошибка при ручной синхронизации:', error);
        res.status(500).json({ error: 'Ошибка при ручной синхронизации', details: error.message });
    }
});

// Получение истории синхронизаций
app.get('/api/sync-history', requireAuth, (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const history = syncScheduler.getHistory(limit);

    res.json({
        history,
        total: history.length
    });
});

// Очистка CloudFlare токена
app.post('/api/clear-cf-token', requireAuth, async (req, res) => {
    try {
        userData.cf_token = '';
        saveUserData(userData);

        // Останавливаем планировщик при удалении токена
        syncScheduler.stop();
        console.log('⏹️  Планировщик синхронизации остановлен из-за удаления токена');

        res.json({
            success: true,
            message: 'CloudFlare токен успешно удален'
        });
    } catch (error) {
        console.error('❌ Ошибка при удалении токена:', error);
        res.status(500).json({ error: 'Ошибка при удалении токена', details: error.message });
    }
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
    console.log(`📝 Логин по умолчанию: admin`);
    console.log(`🔑 Пароль по умолчанию: password123`);
    console.log(`💾 Данные сохраняются в файлы:`);
    console.log(`   - ${USER_DATA_FILE}`);
    console.log(`   - ${ITEMS_DATA_FILE}`);
    console.log(`📁 Nginx конфиги: ${NGINX_CONFIG_DIR}`);
    console.log(`📄 Шаблон nginx: ${NGINX_TEMPLATE_PATH}`);
    console.log(`🔐 Шаблон nginx SSL: ${NGINX_SSL_TEMPLATE_PATH}`);
    console.log(`☁️  CloudFlare токен: ${userData.cf_token ? 'настроен' : 'не настроен'}`);

    // Запускаем планировщик синхронизации, если настроен интервал и есть токен
    if (userData.sync_interval && userData.cf_token) {
        console.log(`\n🔄 Запуск планировщика автосинхронизации DNS...`);
        console.log(`⏰ Интервал: ${userData.sync_interval} минут`);
        syncScheduler.start(userData.sync_interval, autoSyncAllDns, { userData, items });
    } else {
        console.log(`\n⏸️  Автосинхронизация DNS отключена`);
        if (!userData.cf_token) {
            console.log(`   Причина: CloudFlare токен не настроен`);
        } else {
            console.log(`   Причина: интервал синхронизации не установлен`);
        }
    }
});
