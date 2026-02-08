// database.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'database.sqlite');

// Cria o banco de dados se não existir
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Erro ao conectar ao SQLite:', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        initTables();
    }
});

function initTables() {
    const tables = [
        `CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, data TEXT)`,
        `CREATE TABLE IF NOT EXISTS bots (sessionName TEXT PRIMARY KEY, owner TEXT, data TEXT)`,
        `CREATE TABLE IF NOT EXISTS groups (groupId TEXT PRIMARY KEY, owner TEXT, data TEXT)`,
        `CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id = 1), data TEXT)`,
        `CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, owner TEXT, data TEXT)`,
        `CREATE TABLE IF NOT EXISTS campaigns (id TEXT PRIMARY KEY, owner TEXT, data TEXT)`,
        `CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, owner TEXT, data TEXT)`
    ];

    db.serialize(() => {
        tables.forEach(sql => {
            db.run(sql, (err) => {
                if (err) console.error('Erro ao criar tabela:', err.message);
            });
        });
    });
}

// Helper para converter Promise
function query(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

module.exports = {
    // --- USERS ---
    getAllUsers: async () => {
        const rows = await query("SELECT username, data FROM users");
        const users = {};
        rows.forEach(row => {
            users[row.username] = JSON.parse(row.data);
        });
        return users;
    },
    saveUser: async (user) => {
        await run("INSERT OR REPLACE INTO users (username, data) VALUES (?, ?)", [user.username, JSON.stringify(user)]);
    },
    deleteUser: async (username) => {
        await run("DELETE FROM users WHERE username = ?", [username]);
    },

    // --- BOTS ---
    getAllBots: async () => {
        const rows = await query("SELECT sessionName, data FROM bots");
        const bots = {};
        rows.forEach(row => {
            bots[row.sessionName] = JSON.parse(row.data);
        });
        return bots;
    },
    saveBot: async (bot) => {
        await run("INSERT OR REPLACE INTO bots (sessionName, owner, data) VALUES (?, ?, ?)", [bot.sessionName, bot.owner, JSON.stringify(bot)]);
    },
    deleteBot: async (sessionName) => {
        await run("DELETE FROM bots WHERE sessionName = ?", [sessionName]);
    },

    // --- GROUPS ---
    getAllGroups: async () => {
        const rows = await query("SELECT groupId, data FROM groups");
        const groups = {};
        rows.forEach(row => {
            groups[row.groupId] = JSON.parse(row.data);
        });
        return groups;
    },
    saveGroup: async (group) => {
        await run("INSERT OR REPLACE INTO groups (groupId, owner, data) VALUES (?, ?, ?)", [group.groupId, group.owner, JSON.stringify(group)]);
    },
    deleteGroup: async (groupId) => {
        await run("DELETE FROM groups WHERE groupId = ?", [groupId]);
    },

    // --- SETTINGS ---
    getSettings: async () => {
        const rows = await query("SELECT data FROM settings WHERE id = 1");
        if (rows.length > 0) return JSON.parse(rows[0].data);
        return {};
    },
    saveSettings: async (settings) => {
        await run("INSERT OR REPLACE INTO settings (id, data) VALUES (1, ?)", [JSON.stringify(settings)]);
    },

    // --- CLIENTS ---
    getAllClients: async () => {
        const rows = await query("SELECT data FROM clients");
        return rows.map(row => JSON.parse(row.data));
    },
    saveClient: async (client) => {
        // Gera um ID se não existir
        if (!client.id) client.id = Date.now().toString();
        await run("INSERT OR REPLACE INTO clients (id, owner, data) VALUES (?, ?, ?)", [client.id, client.owner, JSON.stringify(client)]);
    },
    deleteClient: async (id) => {
        await run("DELETE FROM clients WHERE id = ?", [id]);
    },

    // --- CAMPAIGNS ---
    getAllCampaigns: async () => {
        const rows = await query("SELECT data FROM campaigns");
        return rows.map(row => JSON.parse(row.data));
    },
    saveCampaign: async (campaign) => {
        await run("INSERT OR REPLACE INTO campaigns (id, owner, data) VALUES (?, ?, ?)", [campaign.id, campaign.owner, JSON.stringify(campaign)]);
    },
    deleteCampaign: async (id) => {
        await run("DELETE FROM campaigns WHERE id = ?", [id]);
    },

    // --- PAYMENTS ---
    getAllPayments: async () => {
        const rows = await query("SELECT data FROM payments");
        return rows.map(row => JSON.parse(row.data));
    },
    savePayment: async (payment) => {
        // Garante que payment.id seja string
        const id = String(payment.id);
        await run("INSERT OR REPLACE INTO payments (id, owner, data) VALUES (?, ?, ?)", [id, payment.owner, JSON.stringify(payment)]);
    }
};
