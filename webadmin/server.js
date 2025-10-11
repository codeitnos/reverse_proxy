const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const app = express();
const PORT = 8881;

// Путь к папке с данными
// const DATA_DIR = path.join(__dirname, '/data');
const DATA_DIR = "/data";

// Пути к файлам данных
const USER_DATA_FILE = path.join(DATA_DIR, 'user.json');
const ITEMS_DATA_FILE = path.join(DATA_DIR, 'items.json');

// Пути для nginx конфигов
const NGINX_CONFIG_DIR = '/nginx_config';
const NGINX_TEMPLATE_PATH = '/app/nginx/template.conf';
const NGINX_SSL_TEMPLATE_PATH = '/app/nginx/template_ssl.conf';

// Функция для извлечения корневого домена из поддомена
function getRootDomain(fullDomain) {
    const parts = fullDomain.split('.');
    if (parts.length >= 2) {
        return parts.slice(-2).join('.');
    }
    return fullDomain;
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
        passwordHash: bcrypt.hashSync('password123', 10)
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
            return false;
        }

        let template = fs.readFileSync(templatePath, 'utf8');

        // Заменяем параметры
        template = template.replace(/{host}/g, domain);
        template = template.replace(/{destination}/g, dest);

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
        return true;
    } catch (error) {
        console.error('❌ Ошибка при создании nginx конфига:', error);
        return false;
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
    const { domain, dest, item3, ssl, active } = req.body;
    const newItem = {
        id: itemIdCounter++,
        domain,
        dest,
        item3,
        ssl: ssl !== undefined ? ssl : false,
        active: active !== undefined ? active : true
    };
    items.push(newItem);
    saveItems(); // Сохраняем в файл

    // Создаем nginx конфиг, если запись активна
    if (newItem.active) {
        createNginxConfig(domain, dest, newItem.ssl);

        // Проверяем и перезагружаем nginx
        const nginxResult = await applyNginxChanges();
        if (!nginxResult.success) {
            // Если ошибка, откатываем изменения
            items.pop();
            itemIdCounter--;
            saveItems();
            deleteNginxConfig(domain);

            return res.status(500).json({
                error: 'Ошибка конфигурации Nginx',
                details: nginxResult.error
            });
        }
    }

    res.json(newItem);
});

app.put('/api/items/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id);
    const { domain, dest, item3, ssl, active } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        const oldItem = { ...items[itemIndex] };
        const oldDomain = items[itemIndex].domain;
        const oldActive = items[itemIndex].active;

        items[itemIndex] = {
            id,
            domain,
            dest,
            item3,
            ssl: ssl !== undefined ? ssl : items[itemIndex].ssl,
            active: active !== undefined ? active : items[itemIndex].active
        };
        saveItems(); // Сохраняем в файл

        // Удаляем старый конфиг, если домен изменился
        if (oldDomain !== domain) {
            deleteNginxConfig(oldDomain);
        }

        // Управляем конфигом в зависимости от статуса active
        if (items[itemIndex].active) {
            createNginxConfig(domain, dest, items[itemIndex].ssl);
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
                details: nginxResult.error
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
        const oldSsl = items[itemIndex].ssl;
        items[itemIndex].ssl = ssl;
        saveItems(); // Сохраняем в файл

        // Пересоздаем конфиг с новыми параметрами, если запись активна
        if (items[itemIndex].active) {
            createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, items[itemIndex].ssl);

            // Проверяем и перезагружаем nginx
            const nginxResult = await applyNginxChanges();
            if (!nginxResult.success) {
                // Откатываем изменения при ошибке
                items[itemIndex].ssl = oldSsl;
                saveItems();
                createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, oldSsl);

                return res.status(500).json({
                    error: 'Ошибка конфигурации Nginx',
                    details: nginxResult.error
                });
            }
        }

        res.json({ success: true, ssl: items[itemIndex].ssl });
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
        const oldActive = items[itemIndex].active;
        items[itemIndex].active = active;
        saveItems(); // Сохраняем в файл

        // Управляем конфигом в зависимости от нового статуса
        if (active) {
            createNginxConfig(items[itemIndex].domain, items[itemIndex].dest, items[itemIndex].ssl);
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
                details: nginxResult.error
            });
        }

        res.json({ success: true, active: items[itemIndex].active });
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
        saveItems(); // Сохраняем в файл

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
        saveUserData(userData); // Сохраняем в файл
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Неверный текущий пароль' });
    }
});

// Получение SSL-сертификата через Let's Encrypt
app.post('/api/get-ssl-certificate', requireAuth, async (req, res) => {
    const { domain, email, regru_username, regru_password } = req.body;

    if (!domain || !email || !regru_username || !regru_password) {
        return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
    }

    try {
        console.log('🔐 Начало процесса получения SSL-сертификата...');
        console.log(`   Домен: ${domain}`);
        console.log(`   Email: ${email}`);

        // Шаг 1: Регистрация аккаунта
        console.log('📝 Шаг 1: Регистрация аккаунта в Let\'s Encrypt...');
        const registerCommand = `docker exec -e REGRU_API_Username='${regru_username}' -e REGRU_API_Password='${regru_password}' acme_sh acme.sh --register-account -m ${email}`;

        let registerResult;
        try {
            registerResult = await execPromise(registerCommand);
            console.log('✅ Аккаунт зарегистрирован успешно');
        } catch (error) {
            const errorOutput = error.stdout + error.stderr;
            console.error('❌ Ошибка регистрации аккаунта:', errorOutput);

            // Проверяем, может аккаунт уже зарегистрирован
            if (errorOutput.includes('already registered') || errorOutput.includes('Account already exists')) {
                console.log('ℹ️  Аккаунт уже зарегистрирован, продолжаем...');
            } else {
                return res.status(500).json({
                    error: 'Ошибка при регистрации аккаунта Let\'s Encrypt',
                    details: errorOutput,
                    step: 'registration'
                });
            }
        }

        // Шаг 2: Получение сертификата
        console.log('🔒 Шаг 2: Получение SSL-сертификата...');
        const issueCommand = `docker exec -e REGRU_API_Username='${regru_username}' -e REGRU_API_Password='${regru_password}' acme_sh acme.sh --issue --dns dns_regru -d '*.${domain}'  --server letsencrypt`;

        let issueResult;
        let alreadyExists = false;
        let renewalDate = '';

        try {
            issueResult = await execPromise(issueCommand);
            console.log('✅ Сертификат получен успешно!');
        } catch (error) {
            const errorOutput = error.stdout + error.stderr;

            // Проверяем, может сертификат уже существует и действует
            if (errorOutput.includes('Domains not changed') &&
                errorOutput.includes('Skipping') &&
                errorOutput.includes('Next renewal time is')) {
                console.log('ℹ️  Сертификат уже существует и действителен');
                alreadyExists = true;
                issueResult = { stdout: errorOutput, stderr: '' };

                // Извлекаем дату следующего обновления
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

        // Определяем путь к сертификатам
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
});
