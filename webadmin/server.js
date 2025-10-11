const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 8881;

// Путь к папке с данными
// const DATA_DIR = path.join(__dirname, '/data');
const DATA_DIR = "/data";

// Пути к файлам данных
const USER_DATA_FILE = path.join(DATA_DIR, 'user.json');
const ITEMS_DATA_FILE = path.join(DATA_DIR, 'items.json');

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

app.post('/api/items', requireAuth, (req, res) => {
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
    res.json(newItem);
});

app.put('/api/items/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const { domain, dest, item3, ssl, active } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        items[itemIndex] = {
            id,
            domain,
            dest,
            item3,
            ssl: ssl !== undefined ? ssl : items[itemIndex].ssl,
            active: active !== undefined ? active : items[itemIndex].active
        };
        saveItems(); // Сохраняем в файл
        res.json(items[itemIndex]);
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

// Endpoint для переключения SSL
app.patch('/api/items/:id/toggle-ssl', requireAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const { ssl } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        items[itemIndex].ssl = ssl;
        saveItems(); // Сохраняем в файл
        res.json({ success: true, ssl: items[itemIndex].ssl });
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

// Endpoint для переключения активности записи
app.patch('/api/items/:id/toggle-active', requireAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const { active } = req.body;
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        items[itemIndex].active = active;
        saveItems(); // Сохраняем в файл
        res.json({ success: true, active: items[itemIndex].active });
    } else {
        res.status(404).json({ error: 'Запись не найдена' });
    }
});

app.delete('/api/items/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id);
    const itemIndex = items.findIndex(item => item.id === id);

    if (itemIndex !== -1) {
        items.splice(itemIndex, 1);
        saveItems(); // Сохраняем в файл
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

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
    console.log(`📝 Логин по умолчанию: admin`);
    console.log(`🔑 Пароль по умолчанию: password123`);
    console.log(`💾 Данные сохраняются в файлы:`);
    console.log(`   - ${USER_DATA_FILE}`);
    console.log(`   - ${ITEMS_DATA_FILE}`);
});
