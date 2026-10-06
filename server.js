require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json());

const io = new Server(server, { cors: { origin: '*' } });
const db = new sqlite3.Database('./rs_corporativo.db');

// Cria o diretório de uploads se não existir
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Configuração do Multer (Upload de Arquivos)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage, 
    limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const forbidden = ['.exe', '.bat', '.cmd', '.sh', '.js'];
        if (forbidden.includes(ext)) return cb(new Error('Tipo de arquivo não permitido'));
        cb(null, true);
    }
});

// ==========================================
// 1. MODELAGEM DO BANCO DE DADOS
// ==========================================
db.serialize(async () => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(255) NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) CHECK (role IN ('user', 'admin')) NOT NULL,
        status VARCHAR(20) DEFAULT 'Ativo',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER, -- NULL = Chat Geral
        type VARCHAR(20) DEFAULT 'text', -- text, image, file
        content TEXT NOT NULL,
        file_name VARCHAR(255),
        file_size INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        action VARCHAR(255) NOT NULL,
        target_user VARCHAR(255),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Criar Administrador Master padrão caso o banco esteja vazio
    db.get("SELECT id FROM users LIMIT 1", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO users (name, username, email, password_hash, role) VALUES ('Administrador do Sistema', 'admin', 'admin@rsservicos.com.br', ?, 'admin')`, [hash]);
        }
    });
});

// ==========================================
// 2. MIDDLEWARES DE SEGURANÇA
// ==========================================
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Sessão encerrada ou inválida.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'RS_MASTER_KEY_2026');
        db.get("SELECT status FROM users WHERE id = ?", [req.user.id], (err, user) => {
            if (!user || user.status === 'Inativo') return res.status(403).json({ error: 'Usuário desativado.' });
            next();
        });
    } catch (err) { res.status(401).json({ error: 'Token inválido.' }); }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado. Ação restrita a administradores.' });
    next();
};

const logAdminAction = (admin_id, action, target) => {
    db.run(`INSERT INTO admin_logs (admin_id, action, target_user) VALUES (?, ?, ?)`, [admin_id, action, target]);
};

// ==========================================
// 3. ROTAS DA API
// ==========================================

// --- AUTENTICAÇÃO ---
app.post('/api/login', (req, res) => {
    const { identifier, password } = req.body;
    const query = identifier.includes('@') ? "SELECT * FROM users WHERE email = ?" : "SELECT * FROM users WHERE username = ?";
    
    db.get(query, [identifier], async (err, user) => {
        if (!user || user.status === 'Inativo' || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Credenciais inválidas ou usuário inativo.' });
        }
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET || 'RS_MASTER_KEY_2026', { expiresIn: '12h' });
        res.json({ token, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
    });
});

// --- PERFIL E SENHA ---
app.put('/api/profile/password', auth, async (req, res) => {
    const { new_password } = req.body;
    const hash = await bcrypt.hash(new_password, 10);
    db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hash, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Erro ao atualizar senha.' });
        res.json({ success: true, message: 'Senha alterada com sucesso.' });
    });
});

// --- ARQUIVOS E UPLOADS (Protegidos) ---
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    res.json({ 
        filename: req.file.filename, 
        originalname: req.file.originalname, 
        size: req.file.size,
        mimetype: req.file.mimetype
    });
});

// Rota protegida para acessar arquivos (Impede acesso via URL direta sem token)
app.get('/api/files/:filename', (req, res) => {
    // Para simplificar no frontend usando tag <img>, passamos o token via query param
    const token = req.query.token;
    if (!token) return res.status(401).send('Acesso negado.');
    try {
        jwt.verify(token, process.env.JWT_SECRET || 'RS_MASTER_KEY_2026');
        const filepath = path.join(uploadDir, req.params.filename);
        if (fs.existsSync(filepath)) {
            res.sendFile(filepath);
        } else {
            res.status(404).send('Arquivo não encontrado.');
        }
    } catch(err) { res.status(401).send('Token inválido.'); }
});

// --- CHAT MENSAGENS ---
app.get('/api/messages/general', auth, (req, res) => {
    const query = `
        SELECT m.*, u.name as sender_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.receiver_id IS NULL 
        ORDER BY m.created_at ASC LIMIT 200
    `;
    db.all(query, [], (err, rows) => res.json(rows));
});

// --- ADMINISTRAÇÃO OBRIGATÓRIA (SOMENTE ADMIN) ---
app.get('/api/admin/users', [auth, requireAdmin], (req, res) => {
    db.all("SELECT id, name, username, email, role, status, created_at FROM users ORDER BY name", [], (err, rows) => res.json(rows));
});

app.post('/api/admin/users', [auth, requireAdmin], async (req, res) => {
    const { name, username, email, password, role } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (name, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)", 
        [name, username, email, hash, role], function(err) {
        if (err) return res.status(400).json({ error: 'Usuário ou e-mail já existe.' });
        logAdminAction(req.user.id, `Criou o usuário: ${username}`, username);
        res.status(201).json({ success: true });
    });
});

app.put('/api/admin/users/:id', [auth, requireAdmin], async (req, res) => {
    const { name, username, email, role, status, password } = req.body;
    let query = "UPDATE users SET name=?, username=?, email=?, role=?, status=? WHERE id=?";
    let params = [name, username, email, role, status, req.params.id];

    if (password) {
        query = "UPDATE users SET name=?, username=?, email=?, role=?, status=?, password_hash=? WHERE id=?";
        params = [name, username, email, role, status, await bcrypt.hash(password, 10), req.params.id];
    }

    db.run(query, params, (err) => {
        if (err) return res.status(400).json({ error: 'Erro ao atualizar. Dados duplicados?' });
        logAdminAction(req.user.id, `Atualizou o usuário ID: ${req.params.id}`, username);
        res.json({ success: true });
    });
});

app.delete('/api/admin/users/:id', [auth, requireAdmin], (req, res) => {
    // Impede o admin de se deletar e ficar sem administradores
    if (req.user.id == req.params.id) return res.status(400).json({ error: 'Você não pode excluir a própria conta.' });
    
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], (err) => {
        logAdminAction(req.user.id, `Deletou o usuário ID: ${req.params.id}`, `ID: ${req.params.id}`);
        res.json({ success: true });
    });
});

app.get('/api/admin/logs', [auth, requireAdmin], (req, res) => {
    const query = `
        SELECT l.*, u.name as admin_name 
        FROM admin_logs l 
        JOIN users u ON l.admin_id = u.id 
        ORDER BY l.created_at DESC LIMIT 100
    `;
    db.all(query, [], (err, rows) => res.json(rows));
});

// ==========================================
// 4. WEBSOCKETS (CHAT TEMPO REAL)
// ==========================================
io.on('connection', (socket) => {
    socket.on('send_message', (data) => {
        const { sender_id, sender_name, type, content, file_name, file_size } = data;
        
        db.run(`INSERT INTO messages (sender_id, type, content, file_name, file_size) VALUES (?, ?, ?, ?, ?)`,
            [sender_id, type, content, file_name, file_size], function(err) {
            
            const msgObj = {
                id: this.lastID,
                sender_id,
                sender_name,
                type,
                content,
                file_name,
                file_size,
                created_at: new Date().toISOString()
            };
            // Envia para todos conectados
            io.emit('receive_message', msgObj);
        });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Sistema Corporativo na porta ${PORT}`));