const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { MercadoPagoConfig, Payment } = require('mercadopago');
const crypto = require('crypto');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai'); 
const rateLimit = require('express-rate-limit');
const clientRoutes = require('./client-routes');
const db = require('./database'); // Importa o módulo SQLite
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const BASE_DIR = __dirname;
const AUTH_SESSIONS_DIR = path.join(BASE_DIR, 'auth_sessions');
const SESSION_FILES_DIR = path.join(BASE_DIR, 'sessions');
const BOT_SCRIPT_PATH = path.join(BASE_DIR, 'index.js');

// Armazena pagamentos pendentes para verificação manual (Polling)
const pendingPayments = {};

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const upload = multer({ dest: 'uploads/' });

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.trim() : null;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.trim() : null;
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET || 'sua-chave-secreta-muito-forte-e-diferente';
const PUBLIC_URL = process.env.PUBLIC_URL || null; 

// =================================================================================
// CONFIGURAÇÃO DE SEGURANÇA (RATE LIMITING)
// =================================================================================

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: 3, 
    message: { message: "Muitas contas criadas deste IP, tente novamente em uma hora." },
    standardHeaders: true,
    legacyHeaders: false,
});

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 5,
    message: { message: "Muitas tentativas de login. Aguarde um minuto." },
    standardHeaders: true,
    legacyHeaders: false,
});

// =================================================================================
// CONFIGURAÇÃO DA IA DE SUPORTE
// =================================================================================
const API_KEYS_GEMINI = process.env.API_KEYS_GEMINI ? process.env.API_KEYS_GEMINI.split('\n').map(k => k.trim()).filter(Boolean) : [];
let currentApiKeyIndex = 0;
let genAI = API_KEYS_GEMINI.length > 0 ? new GoogleGenerativeAI(API_KEYS_GEMINI[currentApiKeyIndex]) : null;
let supportModel = genAI ? genAI.getGenerativeModel({ model: "gemini-flash-latest" }) : null;

function switchToNextApiKey() {
    if (API_KEYS_GEMINI.length <= 1) return;
    currentApiKeyIndex = (currentApiKeyIndex + 1) % API_KEYS_GEMINI.length;
    console.log(`[SERVER] 🔄 Trocando API Key de Suporte para index: ${currentApiKeyIndex}`);
    genAI = new GoogleGenerativeAI(API_KEYS_GEMINI[currentApiKeyIndex]);
    supportModel = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
}

const SUPPORT_SYSTEM_PROMPT = `
Você é o Assistente Inteligente do painel "zappbot". Sua função é ajudar o usuário a configurar seus robôs de WhatsApp/Telegram e gerenciar suas campanhas de marketing/cobrança.
Seja curto, direto e educado.
[... Prompt mantido ...]
Responda sempre em Português do Brasil.
`;

const activationTokens = {};

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

app.use(express.static(BASE_DIR, {
    etag: false,
    lastModified: false,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

const sessionMiddleware = session({
    store: new FileStore({ 
        path: SESSION_FILES_DIR, 
        logFn: function () { },
        retries: 1,
        ttl: 86400 * 7
    }),
    name: 'zappbot.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

io.engine.use(sessionMiddleware);

if (!fs.existsSync(AUTH_SESSIONS_DIR)) fs.mkdirSync(AUTH_SESSIONS_DIR, { recursive: true });
if (!fs.existsSync(SESSION_FILES_DIR)) fs.mkdirSync(SESSION_FILES_DIR, { recursive: true });

// Inicializa Admin se não existir
async function ensureFirstUserIsAdmin() {
    try {
        const users = await db.getAllUsers();
        const userKeys = Object.keys(users);

        if (userKeys.length > 0) {
            const hasAdmin = userKeys.some(key => users[key].isAdmin === true);
            if (!hasAdmin) {
                const firstUser = userKeys[0];
                console.log(`[SISTEMA] Nenhum admin encontrado. Promovendo o primeiro usuário (${firstUser}) a Admin.`);
                users[firstUser].isAdmin = true;
                users[firstUser].botLimit = 999999;
                await db.saveUser(users[firstUser]);
            }
        }
    } catch (e) {
        console.error("Erro ao verificar admins:", e);
    }
}
// Executa na inicialização
setTimeout(ensureFirstUserIsAdmin, 2000);

// Inicializa Settings
async function initSettings() {
    const defaultSettings = {
        appName: "zappbot",
        allowRegistrations: true, // ATIVADO: Permite novos registros por padrão
        mpAccessToken: "", 
        supportNumber: "5524999842338",
        priceMonthly: "29.90", 
        priceQuarterly: "79.90",
        priceSemiannual: "149.90", 
        priceYearly: "289.90",
        priceResell5: "100.00", 
        priceResell10: "180.00", 
        priceResell20: "300.00", 
        priceResell30: "400.00"
    };
    
    let current = await db.getSettings();
    let updated = false;
    
    for (const key in defaultSettings) {
        if (current[key] === undefined) {
            current[key] = defaultSettings[key];
            updated = true;
        }
    }
    
    if (updated || Object.keys(current).length === 0) {
        await db.saveSettings(current);
    }
}
setTimeout(initSettings, 1000);

async function addUserLog(username, message) {
    try {
        const users = await db.getAllUsers();
        if (users[username]) {
            if (!users[username].log) users[username].log = [];
            users[username].log.push(`[${new Date().toLocaleString('pt-BR')}] ${message}`);
            await db.saveUser(users[username]);
        }
    } catch (e) { }
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

let activeBots = {};

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: CALLBACK_URL,
        passReqToCallback: true,
        proxy: true
    },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const settings = await db.getSettings();
                const users = await db.getAllUsers();
                const username = profile.emails[0].value.toLowerCase();

                if (!users[username] && settings.allowRegistrations === false) {
                    return done(null, false, { message: "Novos registros estão desativados." });
                }

                const userIp = getClientIp(req);

                if (users[username]) {
                    return done(null, users[username]);
                }

                const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
                const isAdmin = Object.keys(users).length === 0;
                const trialUsed = (!isAdmin && deviceUsed) ? true : false;

                const newUser = {
                    username,
                    password: null,
                    googleId: profile.id,
                    displayName: profile.displayName,
                    createdAt: new Date(),
                    isAdmin,
                    botLimit: isAdmin ? 999999 : 1,
                    log: [],
                    trialUsed: trialUsed,
                    trialExpiresAt: null,
                    salvagedTime: null
                };

                await db.saveUser(newUser);
                addUserLog(username, `Conta Google criada. IP: ${userIp} | DeviceUsed: ${deviceUsed}`);
                return done(null, newUser);
            } catch (err) { return done(err, null); }
        }));

    passport.serializeUser((user, done) => done(null, user.username));

    passport.deserializeUser(async (username, done) => {
        try {
            const users = await db.getAllUsers();
            const u = users[username.toLowerCase()];
            if (u) {
                done(null, u);
            } else {
                done(null, false);
            }
        } catch (err) {
            done(err, null);
        }
    });
}

async function updatePaymentRecord(paymentData) {
    try {
        const payments = await db.getAllPayments();
        const index = payments.findIndex(p => p.id === paymentData.id);

        if (index !== -1) {
            payments[index].status = 'approved';
            payments[index].date = paymentData.date_approved || new Date().toISOString();
            await db.savePayment(payments[index]);
            
            if (payments[index].owner) {
                const userPayments = payments.filter(p => p.owner === payments[index].owner);
                io.to(payments[index].owner.toLowerCase()).emit('payments:list', userPayments);
            }
        } else {
            const parts = (paymentData.external_reference || '').split('|');
            if (parts.length >= 3 && parts[0] === 'campaign') {
                const campaignId = parts[1];
                const clientNumber = parts[2];
                const campaigns = await db.getAllCampaigns();
                const campaign = campaigns.find(c => c.id === campaignId);
                const clients = await db.getAllClients();
                const client = clients.find(c => c.number === clientNumber && c.owner === (campaign ? campaign.owner : ''));

                const record = {
                    id: paymentData.id,
                    date: paymentData.date_approved || new Date().toISOString(),
                    amount: paymentData.transaction_amount,
                    campaignId: campaignId,
                    campaignName: campaign ? campaign.name : 'Campanha Desconhecida',
                    clientNumber: clientNumber,
                    clientName: client ? client.name : clientNumber,
                    owner: campaign ? campaign.owner : '',
                    status: 'approved'
                };
                await db.savePayment(record);
                if (record.owner) {
                    const allP = await db.getAllPayments();
                    const userPayments = allP.filter(p => p.owner === record.owner);
                    io.to(record.owner.toLowerCase()).emit('payments:list', userPayments);
                }
            }
        }
    } catch (e) {
        console.error("[PAYMENT] Erro ao atualizar histórico:", e);
    }
}

setInterval(async () => {
    const paymentIds = Object.keys(pendingPayments);
    if (paymentIds.length === 0) return;

    for (const id of paymentIds) {
        const data = pendingPayments[id];
        
        if (Date.now() - data.createdAt > 3600000) {
            delete pendingPayments[id];
            continue;
        }

        try {
            const client = new MercadoPagoConfig({ accessToken: data.accessToken });
            const payment = new Payment(client);
            const paymentInfo = await payment.get({ id: id });

            if (paymentInfo.status === 'approved') {
                console.log(`[POLLING] Pagamento ${id} APROVADO!`);
                await updatePaymentRecord(paymentInfo);
                io.emit('bot:send-client-message', {
                    targetBot: data.botSessionName,
                    clientNumber: data.clientJid.replace('@s.whatsapp.net', ''),
                    message: `✅ Pagamento confirmado! Obrigado.`
                });
                delete pendingPayments[id];
            }
        } catch (e) {
            console.error(`[POLLING] Erro ao verificar pagamento ${id}:`, e.message);
        }
    }
}, 10000);

async function generatePix(req, amount, description, external_reference, accessToken = null) {
    let tokenToUse = accessToken;
    
    if (!tokenToUse) {
        const settings = await db.getSettings();
        tokenToUse = settings.mpAccessToken;
    }

    if (!tokenToUse) {
        throw new Error('Token do MercadoPago não configurado.');
    }

    const uniqueId = Date.now().toString().slice(-6);
    const randomPart = Math.floor(Math.random() * 10000);
    const payerEmail = `pagador_${uniqueId}_${randomPart}@temp.com`;

    let host = '';
    let protocol = 'https';

    if (PUBLIC_URL) {
        const urlObj = new URL(PUBLIC_URL);
        host = urlObj.host;
        protocol = urlObj.protocol.replace(':', '');
    } else {
        host = req.headers['x-forwarded-host'] || req.headers.host;
        if (!host || host.includes('localhost') || host.includes('127.0.0.1')) {
            const referer = req.headers['referer'] || req.headers['origin'];
            if (referer) {
                try {
                    const refUrl = new URL(referer);
                    host = refUrl.host;
                    protocol = refUrl.protocol.replace(':', '');
                } catch (e) {}
            }
        }
        if (req.headers['x-forwarded-proto']) {
            protocol = req.headers['x-forwarded-proto'];
        } else if (req.connection && req.connection.encrypted) { 
            protocol = 'https';
        }
        if (host && !host.includes('localhost') && !host.includes('127.0.0.1') && protocol === 'http') {
            protocol = 'https';
        }
    }

    let notificationUrl = `${protocol}://${host}/webhook/mercadopago`;
    
    if (notificationUrl.includes('localhost') || notificationUrl.includes('127.0.0.1')) {
        console.warn(`[PIX] Localhost detectado. Webhook desativado. Usando Polling.`);
        notificationUrl = null;
    }

    const client = new MercadoPagoConfig({ accessToken: tokenToUse });
    const payment = new Payment(client);
    
    const body = {
        transaction_amount: Number(amount),
        description: description,
        payment_method_id: 'pix',
        payer: { email: payerEmail, first_name: "Cliente", last_name: "Pagador" },
        external_reference: external_reference
    };

    if (notificationUrl) {
        body.notification_url = notificationUrl;
    }

    const request = { body: body };
    const result = await payment.create(request);

    if (result && result.id) {
        const parts = external_reference.split('|');
        if (parts[0] === 'campaign') {
            pendingPayments[result.id] = {
                accessToken: tokenToUse,
                campaignId: parts[1],
                clientJid: parts[2],
                botSessionName: req.body.botSessionName || 'unknown',
                createdAt: Date.now()
            };
        }
    }

    return result;
}

app.get('/manifest.json', async (req, res) => {
    const settings = await db.getSettings();
    const appName = settings.appName || 'zappbot';
    res.json({
        "name": appName,
        "short_name": appName,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#09090b",
        "theme_color": "#121214",
        "orientation": "portrait",
        "icons": [
            { "src": "/icon-192x192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable" },
            { "src": "/icon-512x512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
        ]
    });
});

app.post('/api/admin/upload-icons', upload.fields([{ name: 'iconSmall' }, { name: 'iconLarge' }]), (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) return res.status(403).json({ success: false, message: 'Acesso negado.' });
    try {
        if (req.files['iconSmall']) {
            const tempPath = req.files['iconSmall'][0].path;
            const targetPath = path.join(BASE_DIR, 'icon-192x192.png');
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }
        if (req.files['iconLarge']) {
            const tempPath = req.files['iconLarge'][0].path;
            const targetPath = path.join(BASE_DIR, 'icon-512x512.png');
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }
        res.json({ success: true, message: 'Ícones atualizados.' });
    } catch (error) { res.status(500).json({ success: false, message: 'Erro ao processar imagens.' }); }
});

// =================================================================================
// ROTAS DE BACKUP E RESTAURAÇÃO (ADAPTADO PARA SQLITE)
// =================================================================================

app.get('/api/admin/backup', async (req, res) => {
    if (!req.session.user) return res.status(401).send('Acesso negado');
    
    const isAdmin = req.session.user.isAdmin;
    const username = req.session.user.username;
    
    const archive = archiver('zip', { zlib: { level: 9 } });
    const fileName = `backup_zappbot_${isAdmin ? 'FULL' : 'USER'}_${new Date().toISOString().split('T')[0]}.zip`;
    
    res.attachment(fileName);
    archive.on('error', (err) => { res.status(500).send({ error: err.message }); });
    archive.pipe(res);

    // Carrega dados do SQLite
    const allUsers = await db.getAllUsers();
    const allBots = await db.getAllBots();
    const allGroups = await db.getAllGroups();
    const allSettings = await db.getSettings();
    const allClients = await db.getAllClients();
    const allCampaigns = await db.getAllCampaigns();
    const allPayments = await db.getAllPayments();

    if (isAdmin) {
        // Admin: Backup Completo
        archive.append(JSON.stringify(allUsers, null, 2), { name: 'users.json' });
        archive.append(JSON.stringify(allBots, null, 2), { name: 'bots.json' });
        archive.append(JSON.stringify(allGroups, null, 2), { name: 'groups.json' });
        archive.append(JSON.stringify(allSettings, null, 2), { name: 'settings.json' });
        archive.append(JSON.stringify(allClients, null, 2), { name: 'clients.json' });
        archive.append(JSON.stringify(allCampaigns, null, 2), { name: 'campaigns.json' });
        archive.append(JSON.stringify(allPayments, null, 2), { name: 'payments.json' });
    } else {
        // Usuário Comum: Backup Filtrado
        const userBots = Object.fromEntries(Object.entries(allBots).filter(([k, v]) => v.owner === username));
        archive.append(JSON.stringify(userBots, null, 2), { name: 'bots.json' });

        const userGroups = Object.fromEntries(Object.entries(allGroups).filter(([k, v]) => v.owner === username));
        archive.append(JSON.stringify(userGroups, null, 2), { name: 'groups.json' });

        const userClients = allClients.filter(c => c.owner === username);
        archive.append(JSON.stringify(userClients, null, 2), { name: 'clients.json' });

        const userCampaigns = allCampaigns.filter(c => c.owner === username);
        archive.append(JSON.stringify(userCampaigns, null, 2), { name: 'campaigns.json' });

        const userPayments = allPayments.filter(p => p.owner === username);
        archive.append(JSON.stringify(userPayments, null, 2), { name: 'payments.json' });
    }

    archive.finalize();
});

app.post('/api/admin/restore', upload.single('backupFile'), async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Acesso negado' });
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

    const isAdmin = req.session.user.isAdmin;
    const username = req.session.user.username;

    try {
        const zip = new AdmZip(req.file.path);
        const zipEntries = zip.getEntries();
        let botsRestartNeeded = false;

        for (const entry of zipEntries) {
            const fileName = entry.entryName;
            const fileContent = entry.getData().toString('utf8');

            try {
                const restoredData = JSON.parse(fileContent);

                if (fileName === 'bots.json') {
                    const currentBots = await db.getAllBots();
                    for (const key in restoredData) {
                        if (!isAdmin) restoredData[key].owner = username; // Força dono
                        await db.saveBot(restoredData[key]);
                    }
                    botsRestartNeeded = true;
                }
                else if (fileName === 'groups.json') {
                    for (const key in restoredData) {
                        if (!isAdmin) restoredData[key].owner = username;
                        await db.saveGroup(restoredData[key]);
                    }
                }
                else if (fileName === 'clients.json') {
                    const list = Array.isArray(restoredData) ? restoredData : [];
                    for (const client of list) {
                        if (!isAdmin) client.owner = username;
                        await db.saveClient(client);
                    }
                }
                else if (fileName === 'campaigns.json') {
                    const list = Array.isArray(restoredData) ? restoredData : [];
                    for (const camp of list) {
                        if (!isAdmin) camp.owner = username;
                        await db.saveCampaign(camp);
                    }
                }
                else if (fileName === 'payments.json') {
                    const list = Array.isArray(restoredData) ? restoredData : [];
                    for (const pay of list) {
                        if (!isAdmin) pay.owner = username;
                        await db.savePayment(pay);
                    }
                }
                else if (fileName === 'users.json' && isAdmin) {
                    for (const key in restoredData) {
                        await db.saveUser(restoredData[key]);
                    }
                }
                else if (fileName === 'settings.json' && isAdmin) {
                    await db.saveSettings(restoredData);
                }

            } catch (parseErr) {
                console.error(`Erro ao processar arquivo ${fileName} do backup:`, parseErr);
            }
        }

        if (botsRestartNeeded) {
            // Reinicia apenas os bots do usuário (ou todos se admin)
            const allBots = await db.getAllBots();
            Object.keys(activeBots).forEach(sessionName => {
                const botData = allBots[sessionName];
                if (botData && (isAdmin || botData.owner === username)) {
                    if (activeBots[sessionName]) {
                        activeBots[sessionName].intentionalStop = true;
                        activeBots[sessionName].process.kill('SIGINT');
                        delete activeBots[sessionName];
                    }
                }
            });
            setTimeout(() => { restartActiveBots(); }, 2000);
        }

        fs.unlinkSync(req.file.path);
        res.json({ success: true, message: 'Backup restaurado com sucesso.' });
    } catch (error) { 
        console.error(error);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: 'Falha ao processar arquivo de backup.' }); 
    }
});

app.post('/api/generate-activation-link', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado.' });
    const token = crypto.randomUUID();
    const ownerEmail = req.session.user.username.toLowerCase();
    const expiresAt = Date.now() + 15 * 60 * 1000; 
    activationTokens[token] = { 
        ownerEmail, 
        expiresAt, 
        processing: false,
        consumed: false,
        consumedByGroupId: null
    }; 
    
    Object.keys(activationTokens).forEach(t => { if (activationTokens[t].expiresAt < Date.now()) delete activationTokens[t]; });
    
    const activationLink = `https://${req.get('host')}/ativar?token=${token}`;
    res.json({ activationLink });
});

app.post('/api/create-payment', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado' });
    const settings = await db.getSettings();
    const { sessionName, planType, groupId } = req.body;

    let amount = 0, desc = '', extRef = '';
    if (planType && planType.startsWith('resell_')) {
        if (planType === 'resell_5') amount = parseFloat(settings.priceResell5);
        if (planType === 'resell_10') amount = parseFloat(settings.priceResell10);
        if (planType === 'resell_20') amount = parseFloat(settings.priceResell20);
        if (planType === 'resell_30') amount = parseFloat(settings.priceResell30);
        desc = `Upgrade: ${planType}`; extRef = `user|${req.session.user.username}|${planType}`;
    } else if (groupId) {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Ativação Grupo: ${groupId}`; extRef = `group|${groupId}|${planType}`;
    } else {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Renova: ${sessionName}`; extRef = `bot|${sessionName}|${planType}`;
    }

    try {
        req.body.botSessionName = sessionName || 'system';
        const result = await generatePix(req, amount, desc, extRef, null);
        res.json({ 
            qr_code: result.point_of_interaction.transaction_data.qr_code, 
            qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64, 
            ticket_url: result.point_of_interaction.transaction_data.ticket_url, 
            amount: amount.toFixed(2).replace('.', ',') 
        });
    } catch (e) { res.status(500).json({ error: 'Erro ao gerar Pix.' }); }
});

app.post('/webhook/mercadopago', async (req, res) => {
    const { data, type } = req.body;
    res.sendStatus(200);
    if (type === 'payment') {
        try {
            const settings = await db.getSettings();
            let paymentData = null;

            if (settings.mpAccessToken) {
                try {
                    const client = new MercadoPagoConfig({ accessToken: settings.mpAccessToken });
                    const payment = new Payment(client);
                    paymentData = await payment.get({ id: data.id });
                } catch (e) { }
            }

            if (paymentData && paymentData.status === 'approved') {
                const parts = (paymentData.external_reference || '').split('|');
                const paymentType = parts[0];
                const referenceId = parts[1];
                const plan = parts[2];

                if (paymentType === 'campaign') {
                    await updatePaymentRecord(paymentData);
                }
                else if (paymentType === 'user') {
                    const users = await db.getAllUsers();
                    if (users[referenceId]) {
                        users[referenceId].botLimit = parseInt(plan.split('_')[1]);
                        users[referenceId].trialUsed = true;
                        users[referenceId].trialExpiresAt = "PAID_USER";
                        await db.saveUser(users[referenceId]);
                        io.to(referenceId.toLowerCase()).emit('update-limit', users[referenceId].botLimit);
                    }
                } else if (paymentType === 'bot') {
                    const bots = await db.getAllBots();
                    const bot = bots[referenceId];
                    if (bot) {
                        const now = new Date();
                        const currentExpire = new Date(bot.trialExpiresAt);
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (!isNaN(currentExpire) && currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        bot.trialExpiresAt = baseDate.toISOString();
                        bot.isTrial = false;
                        if (!bot.activated) bot.activated = true;
                        await db.saveBot(bot);
                        io.emit('bot-updated', bot);
                        io.emit('payment-success', { sessionName: referenceId });
                    }
                } else if (paymentType === 'group') {
                    const groups = await db.getAllGroups();
                    const group = groups[referenceId];
                    if (group) {
                        const now = new Date();
                        const currentExpire = group.expiresAt ? new Date(group.expiresAt) : now;
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        group.status = 'active';
                        group.expiresAt = baseDate.toISOString();
                        await db.saveGroup(group);
                        const updatedGroups = await db.getAllGroups();
                        io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === group.owner));
                        const botSessionName = group.managedByBot;
                        if (activeBots[botSessionName]) {
                            activeBots[botSessionName].intentionalStop = true;
                            activeBots[botSessionName].process.kill('SIGINT');
                            setTimeout(() => {
                                db.getAllBots().then(bots => {
                                    if (bots[botSessionName]) startBotProcess(bots[botSessionName]);
                                });
                            }, 2000);
                        }
                    }
                }
            }
        } catch (e) { console.error("Webhook Error:", e); }
    }
});

app.get('/', (req, res) => { res.sendFile(path.join(BASE_DIR, 'index.html')); });
app.get('/clients.html', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    res.sendFile(path.join(BASE_DIR, 'clients.html'));
});

app.post('/register', registerLimiter, async (req, res) => {
    const settings = await db.getSettings();
    if (settings.allowRegistrations === false) {
        return res.status(403).json({ message: "Novos registros estão desativados pelo administrador." });
    }

    let users = await db.getAllUsers();
    const username = req.body.username ? req.body.username.toLowerCase().trim() : '';
    const password = req.body.password;

    if (!username || username.length < 4) return res.status(400).json({ message: "Usuário deve ter no mínimo 4 caracteres." });
    if (!password || password.length < 6) return res.status(400).json({ message: "Senha deve ter no mínimo 6 caracteres." });

    if (users[username]) return res.status(400).json({ message: "Usuário existente." });

    const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
    const isAdmin = Object.keys(users).length === 0;
    const trialUsed = (!isAdmin && deviceUsed) ? true : false;

    await new Promise(resolve => setTimeout(resolve, 500));

    const newUser = { 
        username, 
        password: await bcrypt.hash(password, 10), 
        createdAt: new Date(), 
        isAdmin, 
        botLimit: isAdmin ? 999999 : 1, 
        log: [], 
        trialUsed: trialUsed, 
        trialExpiresAt: null, 
        salvagedTime: null 
    };
    
    await db.saveUser(newUser);
    res.cookie('zapp_device_used', 'true', { maxAge: 3650 * 24 * 60 * 60 * 1000, httpOnly: true, signed: true });
    res.status(201).json({ message: "OK" });
});

app.post('/login', loginLimiter, async (req, res) => {
    const username = req.body.username ? req.body.username.toLowerCase().trim() : '';
    const users = await db.getAllUsers();
    const u = users[username];
    
    if (!u || !u.password || !await bcrypt.compare(req.body.password, u.password)) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        return res.status(401).json({ message: "Dados incorretos." });
    }
    
    req.session.user = { username: u.username, isAdmin: !!u.isAdmin };
    res.status(200).json({ message: "OK" });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', (req, res, next) => {
    if (req.isAuthenticated()) return res.redirect('/');
    passport.authenticate('google', (err, user, info) => {
        if (err || !user) return res.redirect(`/?error=${encodeURIComponent(err?.message || info?.message || "Erro auth")}`);
        req.logIn(user, (err) => {
            if (err) return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
            res.cookie('zapp_device_used', 'true', { maxAge: 3650 * 24 * 60 * 60 * 1000, httpOnly: true, signed: true });
            req.session.user = { username: user.username, isAdmin: !!user.isAdmin };
            return res.redirect('/');
        });
    })(req, res, next);
});
app.get('/logout', (req, res) => {
    req.session.destroy((err) => { res.clearCookie('zappbot.sid'); res.redirect('/'); });
});
app.get('/check-session', async (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    if (req.session.user) {
        const users = await db.getAllUsers();
        const u = users[req.session.user.username.toLowerCase()];
        if (u) {
            req.session.user.isAdmin = u.isAdmin;
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1 } });
        } else { req.session.destroy(); res.clearCookie('zappbot.sid'); res.status(401).json({ loggedIn: false }); }
    } else { res.status(401).json({ loggedIn: false }); }
});

io.use(async (socket, next) => {
    const sessionUser = socket.request.session.user || (socket.request.session.passport?.user);
    if (sessionUser) {
        const username = (typeof sessionUser === 'object' ? sessionUser.username : sessionUser).toLowerCase();
        const users = await db.getAllUsers();
        const dbUser = users[username];
        if (dbUser) { socket.request.session.user = { username: dbUser.username, isAdmin: dbUser.isAdmin }; next(); } else { next(new Error('User not found in DB')); }
    } else { next(); }
});

// Passa a instância do DB para as rotas de cliente
clientRoutes(io, generatePix, db);

const supportChatHistory = {};

io.on('connection', async (socket) => {
    const user = socket.request.session.user;
    
    socket.on('support-chat-message', async (msg) => {
        if (!supportModel) {
            socket.emit('support-chat-response', { text: "O sistema de IA não está configurado no servidor. Contate o administrador." });
            return;
        }

        const userId = user.username;
        if (!supportChatHistory[userId]) {
            supportChatHistory[userId] = [
                { role: "user", parts: [{ text: SUPPORT_SYSTEM_PROMPT }] },
                { role: "model", parts: [{ text: "Entendido. Estou pronto para ajudar com o ZappBot." }] }
            ];
        }

        supportChatHistory[userId].push({ role: "user", parts: [{ text: msg }] });

        for (let attempt = 0; attempt < API_KEYS_GEMINI.length; attempt++) {
            try {
                const chat = supportModel.startChat({ history: supportChatHistory[userId] });
                const result = await chat.sendMessage(msg);
                const responseText = result.response.text();

                supportChatHistory[userId].push({ role: "model", parts: [{ text: responseText }] });

                if (supportChatHistory[userId].length > 20) {
                    supportChatHistory[userId] = [
                        supportChatHistory[userId][0],
                        supportChatHistory[userId][1],
                        ...supportChatHistory[userId].slice(-18)
                    ];
                }

                let finalResponse = responseText;
                let action = null;

                if (responseText.includes('[ACTION:')) {
                    const match = responseText.match(/\[ACTION:([A-Z_]+)\]/);
                    if (match) {
                        action = match[1];
                        finalResponse = responseText.replace(match[0], '').trim();
                    }
                }

                const typingDelay = Math.floor(Math.random() * 1500) + 1500;

                setTimeout(() => {
                    socket.emit('support-chat-response', { text: finalResponse, action: action });
                }, typingDelay);
                
                return;

            } catch (error) {
                console.error(`[SERVER] Erro IA (Tentativa ${attempt + 1}/${API_KEYS_GEMINI.length}):`, error.message);
                if (error.message.includes('429') || error.message.includes('Quota') || error.status === 429) {
                    switchToNextApiKey();
                } else {
                    socket.emit('support-chat-response', { text: "Desculpe, tive um erro técnico ao processar sua mensagem." });
                    return;
                }
            }
        }
        socket.emit('support-chat-response', { text: "O sistema de IA está sobrecarregado no momento. Tente novamente em alguns instantes." });
    });

    socket.on('clear-support-history', () => {
        const userId = user.username;
        if (supportChatHistory[userId]) {
            delete supportChatHistory[userId];
        }
    });

    socket.on('get-public-prices', async () => {
        const s = await db.getSettings();
        socket.emit('public-prices', { appName: s.appName || 'zappbot', supportNumber: s.supportNumber, priceMonthly: s.priceMonthly, priceQuarterly: s.priceQuarterly, priceSemiannual: s.priceSemiannual, priceYearly: s.priceYearly, priceResell5: s.priceResell5, priceResell10: s.priceResell10, priceResell20: s.priceResell20, priceResell30: s.priceResell30 });
    });
    socket.on('bot-online', ({ sessionName }) => { updateBotStatus(sessionName, 'Online', { setActivated: true }); });
    socket.on('bot-identified', async ({ sessionName, publicName }) => {
        const bots = await db.getAllBots();
        if (bots[sessionName]) { 
            bots[sessionName].publicName = publicName; 
            await db.saveBot(bots[sessionName]); 
            io.emit('bot-updated', bots[sessionName]); 
        }
    });
    socket.on('update-group-settings', async (data) => {
        const groups = await db.getAllGroups();
        if (groups[data.groupId]) {
            groups[data.groupId] = { ...groups[data.groupId], ...data.settings };
            await db.saveGroup(groups[data.groupId]);
            const updatedGroups = await db.getAllGroups();
            io.to(groups[data.groupId].owner.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === groups[data.groupId].owner));
            io.emit('group-settings-changed', { botSessionName: groups[data.groupId].managedByBot, groupId: data.groupId, settings: groups[data.groupId] });
            
            const botSessionName = groups[data.groupId].managedByBot;
            if (activeBots[botSessionName]) {
                try {
                    activeBots[botSessionName].intentionalStop = true;
                    activeBots[botSessionName].process.kill('SIGINT');
                    delete activeBots[botSessionName];
                    setTimeout(async () => {
                        const currentBots = await db.getAllBots();
                        if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]);
                    }, 1000);
                } catch (e) {
                    console.error("Erro ao reiniciar bot após update de grupo:", e);
                }
            }
        }
    });

    socket.on('bot-update-ignored', async ({ sessionName, type, value }) => {
        const bots = await db.getAllBots();
        const bot = bots[sessionName];
        if (bot) {
            if (!bot.ignoredIdentifiers) bot.ignoredIdentifiers = [];
            const exists = bot.ignoredIdentifiers.some(i => i.type === type && i.value.toLowerCase() === value.toLowerCase());
            if (!exists) {
                bot.ignoredIdentifiers.push({ type, value });
                await db.saveBot(bot);
                io.emit('bot-updated', bot);
            }
        }
    });

    socket.on('group-activation-request', async ({ groupId, groupName, activationToken, botSessionName }) => {
        const tokenData = activationTokens[activationToken];
        
        if (!tokenData || tokenData.expiresAt < Date.now()) { 
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Token expirado/inválido.' }); 
            return; 
        }

        if (!activeBots[botSessionName]) {
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Bot offline. Inicie o bot primeiro.' });
            return;
        }
        
        if (tokenData.consumed) {
            if (tokenData.consumedByGroupId === groupId) {
                const groups = await db.getAllGroups();
                if (groups[groupId]) {
                    io.emit('group-activation-result', { success: true, groupId: groupId, botSessionName: botSessionName, expiresAt: groups[groupId].expiresAt, message: 'Grupo já ativado (Retry).' });
                }
                return;
            } else {
                io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Token já utilizado.' });
                return;
            }
        }

        if (tokenData.processing) return;
        tokenData.processing = true;

        setTimeout(async () => {
            const { ownerEmail } = tokenData;
            
            if (!activationTokens[activationToken]) return;

            const users = await db.getAllUsers();
            const groups = await db.getAllGroups();
            
            if (!users[ownerEmail]) { 
                io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Usuário não encontrado.' }); 
                delete activationTokens[activationToken]; 
                return; 
            }

            tokenData.consumed = true;
            tokenData.consumedByGroupId = groupId;
            
            setTimeout(() => {
                if (activationTokens[activationToken]) delete activationTokens[activationToken];
            }, 60000);

            if (groups[groupId]) { 
                if (groups[groupId].owner === ownerEmail) {
                    groups[groupId].managedByBot = botSessionName;
                    groups[groupId].status = 'active';
                    groups[groupId].groupName = groupName; 
                    
                    await db.saveGroup(groups[groupId]);
                    const updatedGroups = await db.getAllGroups();
                    
                    io.to(ownerEmail.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === ownerEmail));
                    io.to(ownerEmail.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${groupName}" atualizado e vinculado!` });
                    
                    io.emit('group-activation-result', { success: true, groupId: groupId, botSessionName: botSessionName, expiresAt: groups[groupId].expiresAt, message: 'Grupo reativado/atualizado.' });
                    return;
                } else {
                    io.to(ownerEmail.toLowerCase()).emit('feedback', { success: false, message: `O grupo "${groupName}" já está registrado por outro usuário.` }); 
                    io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Grupo já cadastrado por outro.' }); 
                    delete activationTokens[activationToken]; 
                    return; 
                }
            }

            const now = new Date();
            const trialExpire = new Date(now.getTime() + 24 * 60 * 60 * 1000); 
            const newGroup = { groupId, groupName, owner: ownerEmail, managedByBot: botSessionName, status: "active", antiLink: false, createdAt: now.toISOString(), expiresAt: trialExpire.toISOString(), prompt: "", silenceTime: 0, botName: "", isPaused: false };
            await db.saveGroup(newGroup);
            const updatedGroups = await db.getAllGroups();
            
            io.to(ownerEmail.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === ownerEmail));
            io.to(ownerEmail.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${groupName}" ativado!` });
            io.emit('group-activation-result', { success: true, groupId: groupId, botSessionName: botSessionName, expiresAt: newGroup.expiresAt, message: 'Grupo ativado.' });

        }, 1000);
    });

    socket.on('client:request-pix', async (data) => {
        const { campaignId, clientJid, botSessionName } = data;
        const campaigns = await db.getAllCampaigns();
        
        const campaign = campaigns.find(c => c.id === campaignId);

        if (!campaign || campaign.type !== 'cobranca') {
            io.emit('pix:generation-failed', { clientJid, botSessionName, message: 'Campanha não encontrada.' });
            return;
        }

        try {
            const ownerUsername = campaign.owner;
            const users = await db.getAllUsers();
            const ownerData = users[ownerUsername];
            const userMpToken = ownerData ? ownerData.mpAccessToken : null;

            if (!userMpToken) {
                io.emit('pix:generation-failed', { clientJid, botSessionName, message: 'Erro: O recebedor não configurou o Mercado Pago na área de Clientes.' });
                return;
            }

            const amount = parseFloat(campaign.value);
            const description = `Pagamento: ${campaign.name}`;
            const external_reference = `campaign|${campaign.id}|${clientJid}`;
            
            const reqMock = { 
                headers: socket.request.headers, 
                body: { botSessionName },
                connection: socket.request.connection || {} 
            };
            
            const result = await generatePix(reqMock, amount, description, external_reference, userMpToken);
            
            if (result && result.id) {
                const clients = await db.getAllClients();
                const client = clients.find(c => c.number === clientJid.replace('@s.whatsapp.net', '') && c.owner === ownerUsername);
                
                const payments = await db.getAllPayments();
                if (!payments.some(p => p.id === result.id)) {
                    const newPayment = {
                        id: result.id,
                        date: new Date().toISOString(),
                        amount: amount,
                        campaignId: campaignId,
                        campaignName: campaign.name,
                        clientNumber: clientJid.replace('@s.whatsapp.net', ''),
                        clientName: client ? client.name : clientJid.replace('@s.whatsapp.net', ''),
                        owner: ownerUsername,
                        status: 'pending'
                    };
                    await db.savePayment(newPayment);
                    const allP = await db.getAllPayments();
                    const userPayments = allP.filter(p => p.owner === ownerUsername);
                    io.to(ownerUsername.toLowerCase()).emit('payments:list', userPayments);
                }
            }

            const pixData = {
                qr_code: result.point_of_interaction.transaction_data.qr_code,
                qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64,
            };

            io.emit('pix:generated-for-client', {
                pixData,
                clientJid,
                botSessionName
            });

        } catch (e) {
            console.error("Erro ao gerar PIX para cliente:", e);
            let errorMsg = e.message;
            if (e.response && e.response.data && e.response.data.message) {
                errorMsg = e.response.data.message;
            } else if (e.cause) {
                errorMsg = JSON.stringify(e.cause);
            }
            io.emit('pix:generation-failed', { clientJid, botSessionName, message: `Erro MP: ${errorMsg}` });
        }
    });

    socket.on('campaign:feedback', async (data) => {
        const bots = await db.getAllBots();
        const bot = Object.values(bots).find(b => b.sessionName === data.botSessionName);
        if (bot && bot.owner) {
            io.to(bot.owner.toLowerCase()).emit('feedback', {
                success: data.success,
                message: data.message
            });
        }
    });

    if (user) {
        socket.join(user.username.toLowerCase());
        const users = await db.getAllUsers();
        const uData = users[user.username];
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1 });

        socket.on('user:save-mp-token', async ({ token }) => {
            const users = await db.getAllUsers();
            if (users[user.username]) {
                users[user.username].mpAccessToken = token;
                await db.saveUser(users[user.username]);
                socket.emit('feedback', { success: true, message: 'Token Mercado Pago salvo!' });
            }
        });

        socket.on('user:get-mp-token', async () => {
            const users = await db.getAllUsers();
            if (users[user.username] && users[user.username].mpAccessToken) {
                socket.emit('user:mp-token', { token: users[user.username].mpAccessToken });
            }
        });

        if (user.isAdmin) {
            socket.on('admin-settings', async (s) => socket.emit('admin-settings', await db.getSettings()));
            socket.on('save-settings', async (ns) => { 
                await db.saveSettings(ns); 
                socket.emit('feedback', { success: true, message: 'Salvo' }); 
                io.emit('public-prices', { appName: ns.appName, supportNumber: ns.supportNumber, priceMonthly: ns.priceMonthly, priceQuarterly: ns.priceQuarterly, priceSemiannual: ns.priceSemiannual, priceYearly: ns.priceYearly, priceResell5: ns.priceResell5, priceResell10: ns.priceResell10, priceResell20: ns.priceResell20, priceResell30: ns.priceResell30 }); 
            });
            socket.on('admin-set-days', async ({ sessionName, days }) => {
                const bots = await db.getAllBots();
                const bot = bots[sessionName];
                if (bot) {
                    const d = parseInt(days);
                    const now = new Date();
                    const newDate = new Date(now);
                    newDate.setDate(newDate.getDate() + d);
                    newDate.setMinutes(newDate.getMinutes() - 10);
                    bot.trialExpiresAt = newDate.toISOString();
                    bot.activated = true;
                    bot.isTrial = false;
                    await db.saveBot(bot);
                    io.emit('bot-updated', bot);
                }
            });
            socket.on('admin-set-group-days', async ({ groupId, days }) => {
                const groups = await db.getAllGroups();
                const group = groups[groupId];
                if (group) {
                    const d = parseInt(days);
                    const now = new Date();
                    const baseDate = new Date(now);
                    baseDate.setDate(baseDate.getDate() + d);
                    baseDate.setMinutes(baseDate.getMinutes() - 10);
                    group.expiresAt = baseDate.toISOString();
                    group.status = 'active'; 
                    await db.saveGroup(group);
                    const updatedGroups = await db.getAllGroups();
                    io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === group.owner));
                    socket.emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === group.owner));
                    socket.emit('feedback', { success: true, message: 'Dias definidos.' });
                    const botSessionName = group.managedByBot;
                    if (activeBots[botSessionName]) {
                        activeBots[botSessionName].intentionalStop = true;
                        activeBots[botSessionName].process.kill('SIGINT');
                        delete activeBots[botSessionName];
                        setTimeout(async () => { const currentBots = await db.getAllBots(); if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]); }, 1000);
                    }
                }
            });
            socket.on('admin-get-users', async () => {
                const users = await db.getAllUsers();
                socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r));
            });
            socket.on('admin-delete-user', async ({ username }) => { 
                await db.deleteUser(username);
                const users = await db.getAllUsers();
                socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r)); 
            });
            socket.on('admin-get-bots-for-user', async ({ username }) => {
                const bots = await db.getAllBots();
                socket.emit('initial-bots-list', Object.values(bots).filter(b => b.owner === username));
            });
        }

        socket.on('get-my-bots', async () => { 
            const bots = await db.getAllBots();
            socket.emit('initial-bots-list', Object.values(bots).filter(b => b.owner === user.username)); 
        });
        socket.on('get-my-groups', async () => { 
            const groups = await db.getAllGroups();
            socket.emit('initial-groups-list', Object.values(groups).filter(g => g.owner === user.username)); 
        });

        socket.on('delete-group', async ({ groupId }) => {
            const groups = await db.getAllGroups();
            const group = groups[groupId];
            if (!group) return socket.emit('feedback', { success: false, message: 'Grupo não encontrado.' });
            const bots = await db.getAllBots();
            const bot = bots[group.managedByBot];
            const isBotOwner = bot && bot.owner === user.username;
            const isGroupOwner = group.owner === user.username;
            if (!user.isAdmin && !isBotOwner && !isGroupOwner) return socket.emit('feedback', { success: false, message: 'Permissão negada.' });
            const botSessionName = group.managedByBot;
            await db.deleteGroup(groupId);
            const updatedGroups = await db.getAllGroups();
            io.emit('group-removed', { botSessionName, groupId });
            socket.emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === user.username));
            socket.emit('feedback', { success: true, message: 'Grupo removido.' });
            if (activeBots[botSessionName]) {
                activeBots[botSessionName].intentionalStop = true;
                activeBots[botSessionName].process.kill('SIGINT');
                delete activeBots[botSessionName];
                setTimeout(async () => { const currentBots = await db.getAllBots(); if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]); }, 1000);
            }
        });

        socket.on('create-bot', async (d) => {
            try {
                const bots = await db.getAllBots();
                let users = await db.getAllUsers();
                const owner = (user.isAdmin && d.owner) ? d.owner : user.username;
                const ownerData = users[owner];
                if (!ownerData) return socket.emit('feedback', { success: false, message: 'Dono não encontrado.' });
                if (bots[d.sessionName]) return socket.emit('feedback', { success: false, message: 'Nome em uso.' });
                if (d.botType !== 'group' && Object.values(bots).filter(b => b.owner === owner && b.botType !== 'group').length >= (ownerData.botLimit || 1) && !ownerData.isAdmin) return socket.emit('feedback', { success: false, error: 'limit_reached' });

                const now = new Date();
                let trialEndDate = new Date(0);
                let isTrial = false;
                let feedbackMessage = 'Criado. Pague para ativar.';
                
                if (d.botType !== 'group') {
                    if (ownerData.salvagedTime && new Date(ownerData.salvagedTime.expiresAt) > now) {
                        trialEndDate = new Date(ownerData.salvagedTime.expiresAt);
                        isTrial = ownerData.salvagedTime.isTrial;
                        ownerData.salvagedTime = null;
                        await db.saveUser(ownerData);
                        feedbackMessage = 'Restaurado tempo anterior.';
                    } else {
                        if (ownerData.isAdmin || !ownerData.trialUsed) {
                            trialEndDate = new Date(now);
                            trialEndDate.setHours(trialEndDate.getHours() + 24);
                            isTrial = true;
                            feedbackMessage = 'Criado (Teste Grátis).';
                        }
                    }
                } else {
                    trialEndDate = new Date(now);
                    trialEndDate.setFullYear(trialEndDate.getFullYear() + 10);
                    isTrial = false;
                    feedbackMessage = 'Agregador criado!';
                }
                
                const newBot = { sessionName: d.sessionName, prompt: d.prompt, status: 'Offline', owner, activated: false, isTrial: isTrial, createdAt: now.toISOString(), trialExpiresAt: trialEndDate.toISOString(), ignoredIdentifiers: [], botType: d.botType || 'individual', botName: d.botName || '', silenceTime: d.silenceTime || 0, platform: d.platform || 'whatsapp', token: d.token || '', notificationNumber: '', publicName: '' };
                await db.saveBot(newBot);
                io.emit('bot-updated', newBot);
                if (new Date(newBot.trialExpiresAt) > new Date()) startBotProcess(newBot);
                socket.emit('feedback', { success: true, message: feedbackMessage });
            } catch (err) { console.error("Erro criar bot:", err); socket.emit('feedback', { success: false, message: 'Erro interno.' }); }
        });

        socket.on('start-bot', async ({ sessionName, phoneNumber }) => {
            const bots = await db.getAllBots();
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (new Date(bot.trialExpiresAt) < new Date()) return socket.emit('feedback', { success: false, message: 'Expirado.' });
            if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'Já rodando.' });
            
            let cleanPhone = phoneNumber ? phoneNumber.replace(/\D/g, '') : null;
            if (cleanPhone && (cleanPhone.length === 10 || cleanPhone.length === 11)) {
                cleanPhone = '55' + cleanPhone;
            }

            startBotProcess(bot, cleanPhone);
            socket.emit('feedback', { success: true, message: 'Iniciando...' });
        });

        socket.on('stop-bot', async ({ sessionName }) => {
            if (activeBots[sessionName]) { try { activeBots[sessionName].intentionalStop = true; activeBots[sessionName].process.kill('SIGINT'); } catch(e){} delete activeBots[sessionName]; }
            await updateBotStatus(sessionName, 'Offline');
            socket.emit('feedback', { success: true, message: 'Parado.' });
        });

        socket.on('delete-bot', async ({ sessionName }) => {
            let bots = await db.getAllBots();
            let users = await db.getAllUsers();
            const botToDelete = bots[sessionName];
            if (!botToDelete || (!user.isAdmin && botToDelete.owner !== user.username)) return;
            
            if (botToDelete.botType === 'group') {
                let groups = await db.getAllGroups();
                let groupsChanged = false;
                for (const groupId in groups) {
                    if (groups[groupId].managedByBot === sessionName) {
                        await db.deleteGroup(groupId);
                        groupsChanged = true;
                    }
                }
                if (groupsChanged) { 
                    const updatedGroups = await db.getAllGroups();
                    io.emit('group-list-updated', Object.values(updatedGroups)); 
                }
            }

            if (botToDelete.botType !== 'group') {
                const owner = users[botToDelete.owner];
                if (owner && new Date(botToDelete.trialExpiresAt) > new Date()) {
                    owner.salvagedTime = { expiresAt: botToDelete.trialExpiresAt, isTrial: botToDelete.isTrial };
                    await db.saveUser(owner);
                }
            }
            if (activeBots[sessionName]) { activeBots[sessionName].intentionalStop = true; activeBots[sessionName].process.kill('SIGINT'); delete activeBots[sessionName]; }
            await db.deleteBot(sessionName);
            
            const authPath = path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`);
            if (fs.existsSync(authPath)) fs.rmSync(authPath, { recursive: true, force: true });
            io.emit('bot-deleted', { sessionName });
            socket.emit('feedback', { success: true, message: 'Excluído.' });
        });

        socket.on('update-bot', async (d) => {
            const bots = await db.getAllBots();
            const bot = bots[d.sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (bot) {
                bot.prompt = d.newPrompt;
                if (d.botType !== undefined) bot.botType = d.botType;
                bot.botName = d.botName;
                bot.silenceTime = d.silenceTime;
                bot.notificationNumber = d.notificationNumber;
                await db.saveBot(bot);
                io.emit('bot-updated', bot);
                if (activeBots[d.sessionName]) {
                    try { activeBots[d.sessionName].intentionalStop = true; activeBots[d.sessionName].process.kill('SIGINT'); } catch (e) {}
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Salvo. Reiniciando...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else { socket.emit('feedback', { success: true, message: 'Salvo.' }); }
            }
        });

        socket.on('update-ignored-identifiers', async ({ sessionName, ignoredIdentifiers }) => {
            const bots = await db.getAllBots();
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            bot.ignoredIdentifiers = ignoredIdentifiers;
            await db.saveBot(bot);
            io.emit('bot-updated', bot);
            socket.emit('feedback', { success: true, message: 'Ignorados salvos. Reiniciando...' });
            if (activeBots[sessionName]) {
                activeBots[sessionName].intentionalStop = true;
                activeBots[sessionName].process.kill('SIGINT');
                setTimeout(() => startBotProcess(bot), 1000);
            }
        });
    }
});

async function startBotProcess(bot, phoneNumber = null) {
    if (activeBots[bot.sessionName]) return; 
    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    
    let finalPrompt = bot.prompt || '';
    if (bot.botName && bot.botName.trim() !== "") {
         finalPrompt = `Seu nome é ${bot.botName}. ${finalPrompt}`;
    }
    const promptBase64 = Buffer.from(finalPrompt).toString('base64');
    
    const ignoredBase64 = Buffer.from(JSON.stringify(bot.ignoredIdentifiers || [])).toString('base64');
    const phoneArg = phoneNumber ? phoneNumber : 'null';

    let authorizedGroupsArg = '[]';
    if (bot.botType === 'group') {
        const allGroups = await db.getAllGroups();
        const authorizedGroups = Object.values(allGroups)
            .filter(g => g.managedByBot === bot.sessionName && g.status === 'active')
            .map(g => {
                let effectivePrompt = g.prompt || '';
                if (g.botName && g.botName.trim() !== "") {
                    effectivePrompt = `Seu nome é ${g.botName}. ${effectivePrompt}`;
                }

                return { 
                    groupId: g.groupId, 
                    expiresAt: g.expiresAt, 
                    antiLink: g.antiLink, 
                    prompt: effectivePrompt, 
                    silenceTime: g.silenceTime, 
                    botName: g.botName, 
                    isPaused: g.isPaused,
                    welcomeEnabled: g.welcomeEnabled,
                    welcomeMessage: g.welcomeMessage
                };
            });
        authorizedGroupsArg = JSON.stringify(authorizedGroups);
    }
    const groupsBase64 = Buffer.from(authorizedGroupsArg).toString('base64');
    
    const args = [BOT_SCRIPT_PATH, bot.sessionName, promptBase64, ignoredBase64, phoneArg, groupsBase64, bot.botType || 'individual', bot.botName || '', (bot.silenceTime || '0').toString(), bot.platform || 'whatsapp', bot.token || '', bot.notificationNumber || ''];
    const p = spawn('node', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    activeBots[bot.sessionName] = { process: p, intentionalStop: false };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();
        if (msg.startsWith('QR_CODE:')) updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg.replace('QR_CODE:', '') });
        else if (msg.startsWith('PAIRING_CODE:')) updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg });
        else if (msg.includes('ONLINE!') || msg.includes('Conectado ao servidor via Socket.IO')) updateBotStatus(bot.sessionName, 'Online', { setActivated: true });
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });
    p.stderr.on('data', (d) => io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${d}` }));
    p.on('close', (code) => { if (activeBots[bot.sessionName]?.intentionalStop) updateBotStatus(bot.sessionName, 'Offline'); delete activeBots[bot.sessionName]; });
}

async function updateBotStatus(name, status, options = {}) {
    const bots = await db.getAllBots();
    const bot = bots[name];
    if (bot) {
        bot.status = status;
        if (options.qr !== undefined) bot.qr = options.qr; else if (status !== 'Aguardando QR Code') bot.qr = null;
        if (options.setActivated && !bot.activated) {
            bot.activated = true;
            const users = await db.getAllUsers();
            const ownerData = users[bot.owner];
            if (ownerData && !ownerData.isAdmin && bot.isTrial && !ownerData.trialUsed) { 
                ownerData.trialUsed = true; 
                await db.saveUser(ownerData); 
            }
        }
        await db.saveBot(bot);
        io.emit('bot-updated', bot);
    }
}

async function restartActiveBots() {
    const bots = await db.getAllBots();
    Object.values(bots).forEach(bot => {
        if (bot.status === 'Online' || bot.status.includes('Iniciando') || bot.status.includes('Aguardando')) {
            const now = new Date();
            const expires = new Date(bot.trialExpiresAt);
            if (expires > now) startBotProcess(bot); else {
                bot.status = 'Offline';
                db.saveBot(bot);
            }
        }
    });
}

const gracefulShutdown = () => {
    Object.keys(activeBots).forEach(sessionName => { if (activeBots[sessionName]) { try { activeBots[sessionName].process.kill('SIGINT'); } catch (e) { } } });
    process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

server.listen(3000, () => {
    console.log('Painel ON: http://localhost:3000');
    restartActiveBots();
});
