const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./rs_corporativo.db');

db.serialize(async () => {
    // Tabela de Usuários
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

    // Tabela de Mensagens do Chat (com suporte a arquivos)
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

    // Tabela de Logs de Auditoria Administrativa
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

module.exports = db;