const jwt = require('jsonwebtoken');
const db = require('./database');

// Middleware 1: Valida se o usuário está logado e ativo
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Sessão encerrada ou inválida.' });
    
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'RS_MASTER_KEY_2026');
        
        // Verifica no banco de dados se um Admin desativou esta conta
        db.get("SELECT status FROM users WHERE id = ?", [req.user.id], (err, user) => {
            if (!user || user.status === 'Inativo') {
                return res.status(403).json({ error: 'Usuário desativado pelo administrador.' });
            }
            next();
        });
    } catch (err) { 
        res.status(401).json({ error: 'Token inválido.' }); 
    }
};

// Middleware 2: Trava absoluta para rotas administrativas
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Ação restrita a administradores.' });
    }
    next();
};

// Função auxiliar de log de auditoria
const logAdminAction = (admin_id, action, target) => {
    db.run(`INSERT INTO admin_logs (admin_id, action, target_user) VALUES (?, ?, ?)`, [admin_id, action, target]);
};

module.exports = { auth, requireAdmin, logAdminAction };