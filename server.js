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
const clientRoutes = require('./client-routes');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const BASE_DIR = __dirname;
const BOTS_DB_PATH = path.join(BASE_DIR, 'bots.json');
const USERS_DB_PATH = path.join(BASE_DIR, 'users.json');
const SETTINGS_DB_PATH = path.join(BASE_DIR, 'settings.json');
const GROUPS_DB_PATH = path.join(BASE_DIR, 'groups.json');
const CAMPAIGNS_DB_PATH = path.join(BASE_DIR, 'campaigns.json');
const CLIENTS_DB_PATH = path.join(BASE_DIR, 'clients.json');
const PAYMENTS_DB_PATH = path.join(BASE_DIR, 'payments.json');
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
// CONFIGURAÇÃO DA IA DE SUPORTE (COM ROTAÇÃO DE CHAVES)
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

// Prompt do Sistema para o Suporte
const SUPPORT_SYSTEM_PROMPT = `
Você é o Assistente Inteligente do painel "zappbot". Sua função é ajudar o usuário a configurar seus robôs de WhatsApp/Telegram e gerenciar suas campanhas de marketing/cobrança.
Seja curto, direto e educado.

CONHECIMENTO SOBRE O GERENCIADOR DE CLIENTES E CAMPANHAS:
O painel possui uma área dedicada a CRM e Cobranças (Página de Clientes).
1. **Configuração Financeira**: Para receber Pix, o usuário deve inserir o "Token de Produção" do Mercado Pago na aba de Clientes.
2. **Adicionar Clientes**: É possível adicionar individualmente, colar uma lista (Nome, Número), subir arquivo .txt ou importar da agenda do celular.
3. **Campanhas**:
   - Tipos: "Aviso" (apenas texto) ou "Cobrança" (envia texto + Pix Copia e Cola + QR Code).
   - Variáveis na mensagem: Use {nome} para o nome do cliente e {valor} para o valor da cobrança.
   - Agendamento: Envio imediato, Agendado (Data/Hora específica) ou Mensal (todo dia X).
   - Requer um robô conectado para enviar.

REGRAS DE AÇÕES (ATALHOS):
Se a resposta envolver uma ação que o usuário pode fazer no painel, você DEVE adicionar uma tag especial no final da resposta.
As tags disponíveis são:
[ACTION:OPEN_CREATE] -> Se o usuário quer criar um novo robô.
[ACTION:OPEN_RESELL] -> Se o usuário quer aumentar o limite ou revender.
[ACTION:OPEN_BACKUP] -> Se o usuário fala sobre backup ou configurações gerais.
[ACTION:OPEN_CLIENTS] -> Se o usuário pergunta sobre clientes, campanhas, cobranças, Pix, importar contatos ou agendamentos.

EXEMPLOS:
Usuário: "Como crio um bot?"
Resposta: "Para criar um bot, clique no botão 'Novo Robô' no topo da tela e escolha entre Atendimento Privado ou Grupos. [ACTION:OPEN_CREATE]"

Usuário: "Como faço cobrança automática?"
Resposta: "Vá em Clientes, configure seu Token do Mercado Pago e crie uma Campanha do tipo 'Cobrança'. Você pode agendar para todo mês. [ACTION:OPEN_CLIENTS]"

Usuário: "Posso importar contatos?"
Resposta: "Sim, na tela de Clientes clique em 'Adicionar' e escolha 'Agenda' ou 'Colar Lista'. [ACTION:OPEN_CLIENTS]"

Usuário: "Meu limite acabou."
Resposta: "Você pode aumentar seu limite adquirindo um pacote de revenda. [ACTION:OPEN_RESELL]"

Responda sempre em Português do Brasil.
`;

const activationTokens = {};

app.set('trust proxy', true);
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

const readDB = (filePath) => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : {};
const writeDB = (filePath, data) => fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');

if (!fs.existsSync(GROUPS_DB_PATH)) writeDB(GROUPS_DB_PATH, {});
if (!fs.existsSync(PAYMENTS_DB_PATH)) writeDB(PAYMENTS_DB_PATH, []);

function ensureFirstUserIsAdmin() {
    try {
        const users = readDB(USERS_DB_PATH);
        const userKeys = Object.keys(users);

        if (userKeys.length > 0) {
            const hasAdmin = userKeys.some(key => users[key].isAdmin === true);
            if (!hasAdmin) {
                const firstUser = userKeys[0];
                console.log(`[SISTEMA] Nenhum admin encontrado. Promovendo o primeiro usuário (${firstUser}) a Admin.`);
                users[firstUser].isAdmin = true;
                users[firstUser].botLimit = 999999;
                writeDB(USERS_DB_PATH, users);
            }
        }
    } catch (e) {
        console.error("Erro ao verificar admins:", e);
    }
}
ensureFirstUserIsAdmin();

const defaultSettings = {
    appName: "zappbot",
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

let currentSettings = {};
if (fs.existsSync(SETTINGS_DB_PATH)) {
    try {
        currentSettings = readDB(SETTINGS_DB_PATH);
    } catch (e) {
        console.error("Erro ao ler settings.json, recriando...", e);
        currentSettings = {};
    }
}

let settingsUpdated = false;
for (const key in defaultSettings) {
    if (!currentSettings[key]) {
        currentSettings[key] = defaultSettings[key];
        settingsUpdated = true;
    }
}

if (settingsUpdated || !fs.existsSync(SETTINGS_DB_PATH)) {
    console.log("[SISTEMA] Configurações/Preços restaurados para o padrão.");
    writeDB(SETTINGS_DB_PATH, currentSettings);
}

function addUserLog(username, message) {
    try {
        const users = readDB(USERS_DB_PATH);
        if (users[username]) {
            if (!users[username].log) users[username].log = [];
            users[username].log.push(`[${new Date().toLocaleString('pt-BR')}] ${message}`);
            writeDB(USERS_DB_PATH, users);
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
                const users = readDB(USERS_DB_PATH);
                const userIp = getClientIp(req);
                const username = profile.emails[0].value.toLowerCase();

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

                users[username] = newUser;
                writeDB(USERS_DB_PATH, users);
                addUserLog(username, `Conta Google criada. IP: ${userIp} | DeviceUsed: ${deviceUsed}`);
                return done(null, newUser);
            } catch (err) { return done(err, null); }
        }));

    passport.serializeUser((user, done) => done(null, user.username));

    passport.deserializeUser((username, done) => {
        try {
            const users = readDB(USERS_DB_PATH);
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

function updatePaymentRecord(paymentData) {
    try {
        const payments = readDB(PAYMENTS_DB_PATH);
        const index = payments.findIndex(p => p.id === paymentData.id);

        if (index !== -1) {
            payments[index].status = 'approved';
            payments[index].date = paymentData.date_approved || new Date().toISOString();
            writeDB(PAYMENTS_DB_PATH, payments);
            
            if (payments[index].owner) {
                const userPayments = payments.filter(p => p.owner === payments[index].owner);
                io.to(payments[index].owner.toLowerCase()).emit('payments:list', userPayments);
            }
        } else {
            const parts = (paymentData.external_reference || '').split('|');
            if (parts.length >= 3 && parts[0] === 'campaign') {
                const campaignId = parts[1];
                const clientNumber = parts[2];
                const campaigns = readDB(CAMPAIGNS_DB_PATH);
                const campaign = campaigns.find(c => c.id === campaignId);
                const clients = readDB(CLIENTS_DB_PATH);
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
                payments.push(record);
                writeDB(PAYMENTS_DB_PATH, payments);
                if (record.owner) {
                    const userPayments = payments.filter(p => p.owner === record.owner);
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
                updatePaymentRecord(paymentInfo);
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
        const settings = readDB(SETTINGS_DB_PATH);
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


app.get('/manifest.json', (req, res) => {
    const settings = readDB(SETTINGS_DB_PATH);
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
            if(fs.existsSync(path.join(BASE_DIR, 'icon-192×192.png'))) fs.unlinkSync(path.join(BASE_DIR, 'icon-192×192.png'));
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }
        if (req.files['iconLarge']) {
            const tempPath = req.files['iconLarge'][0].path;
            const targetPath = path.join(BASE_DIR, 'icon-512x512.png');
            if(fs.existsSync(path.join(BASE_DIR, 'icon-512×512.png'))) fs.unlinkSync(path.join(BASE_DIR, 'icon-512×512.png'));
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }
        res.json({ success: true, message: 'Ícones atualizados.' });
    } catch (error) { res.status(500).json({ success: false, message: 'Erro ao processar imagens.' }); }
});

app.get('/api/admin/backup', (req, res) => {
    if (!req.session.user) return res.status(401).send('Acesso negado');
    const archive = archiver('zip', { zlib: { level: 9 } });
    const fileName = `backup_zappbot_${new Date().toISOString().split('T')[0]}.zip`;
    res.attachment(fileName);
    archive.on('error', (err) => { res.status(500).send({ error: err.message }); });
    archive.pipe(res);
    if (fs.existsSync(USERS_DB_PATH)) archive.file(USERS_DB_PATH, { name: 'users.json' });
    if (fs.existsSync(BOTS_DB_PATH)) archive.file(BOTS_DB_PATH, { name: 'bots.json' });
    if (fs.existsSync(GROUPS_DB_PATH)) archive.file(GROUPS_DB_PATH, { name: 'groups.json' });
    if (fs.existsSync(SETTINGS_DB_PATH)) archive.file(SETTINGS_DB_PATH, { name: 'settings.json' });
    if (fs.existsSync(CLIENTS_DB_PATH)) archive.file(CLIENTS_DB_PATH, { name: 'clients.json' });
    if (fs.existsSync(CAMPAIGNS_DB_PATH)) archive.file(CAMPAIGNS_DB_PATH, { name: 'campaigns.json' });
    if (fs.existsSync(PAYMENTS_DB_PATH)) archive.file(PAYMENTS_DB_PATH, { name: 'payments.json' });
    archive.finalize();
});

app.post('/api/admin/restore', upload.single('backupFile'), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Acesso negado' });
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    try {
        const zip = new AdmZip(req.file.path);
        zip.extractAllTo(BASE_DIR, true);
        fs.unlinkSync(req.file.path);
        Object.keys(activeBots).forEach(sessionName => {
            if (activeBots[sessionName]) {
                activeBots[sessionName].intentionalStop = true; 
                activeBots[sessionName].process.kill('SIGINT');
                delete activeBots[sessionName];
            }
        });
        setTimeout(() => { restartActiveBots(); }, 2000);
        res.json({ success: true, message: 'Backup restaurado.' });
    } catch (error) { res.status(500).json({ error: 'Falha ao processar ZIP.' }); }
});

app.post('/api/generate-activation-link', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado.' });
    const token = crypto.randomUUID();
    const ownerEmail = req.session.user.username.toLowerCase();
    const expiresAt = Date.now() + 15 * 60 * 1000; 
    activationTokens[token] = { ownerEmail, expiresAt };
    Object.keys(activationTokens).forEach(t => { if (activationTokens[t].expiresAt < Date.now()) delete activationTokens[t]; });
    const activationLink = `https://${req.get('host')}/ativar?token=${token}`;
    res.json({ activationLink });
});

app.post('/api/create-payment', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado' });
    const settings = readDB(SETTINGS_DB_PATH);
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
            const settings = readDB(SETTINGS_DB_PATH);
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
                    updatePaymentRecord(paymentData);
                }
                else if (paymentType === 'user') {
                    const users = readDB(USERS_DB_PATH);
                    if (users[referenceId]) {
                        users[referenceId].botLimit = parseInt(plan.split('_')[1]);
                        users[referenceId].trialUsed = true;
                        users[referenceId].trialExpiresAt = "PAID_USER";
                        writeDB(USERS_DB_PATH, users);
                        io.to(referenceId.toLowerCase()).emit('update-limit', users[referenceId].botLimit);
                    }
                } else if (paymentType === 'bot') {
                    const bots = readDB(BOTS_DB_PATH);
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
                        writeDB(BOTS_DB_PATH, bots);
                        io.emit('bot-updated', bot);
                        io.emit('payment-success', { sessionName: referenceId });
                    }
                } else if (paymentType === 'group') {
                    const groups = readDB(GROUPS_DB_PATH);
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
                        writeDB(GROUPS_DB_PATH, groups);
                        io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                        const botSessionName = group.managedByBot;
                        if (activeBots[botSessionName]) {
                            activeBots[botSessionName].intentionalStop = true;
                            activeBots[botSessionName].process.kill('SIGINT');
                            setTimeout(() => {
                                const bots = readDB(BOTS_DB_PATH);
                                if (bots[botSessionName]) startBotProcess(bots[botSessionName]);
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
app.post('/register', async (req, res) => {
    let users = readDB(USERS_DB_PATH);
    const username = req.body.username.toLowerCase().trim();
    const password = req.body.password;
    if (users[username]) return res.status(400).json({ message: "Usuário existente." });
    const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
    const isAdmin = Object.keys(users).length === 0;
    const trialUsed = (!isAdmin && deviceUsed) ? true : false;
    users[username] = { username, password: await bcrypt.hash(password, 10), createdAt: new Date(), isAdmin, botLimit: isAdmin ? 999999 : 1, log: [], trialUsed: trialUsed, trialExpiresAt: null, salvagedTime: null };
    writeDB(USERS_DB_PATH, users);
    res.cookie('zapp_device_used', 'true', { maxAge: 3650 * 24 * 60 * 60 * 1000, httpOnly: true, signed: true });
    res.status(201).json({ message: "OK" });
});
app.post('/login', async (req, res) => {
    const username = req.body.username.toLowerCase().trim();
    const u = readDB(USERS_DB_PATH)[username];
    if (!u || !u.password || !await bcrypt.compare(req.body.password, u.password)) return res.status(401).json({ message: "Dados incorretos." });
    req.session.user = { username: u.username, isAdmin: !!u.isAdmin };
    res.status(200).json({ message: "OK" });
});
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', (req, res, next) => {
    if (req.isAuthenticated()) return res.redirect('/');
    passport.authenticate('google', (err, user, info) => {
        if (err || !user) return res.redirect(`/?error=${encodeURIComponent(err?.message || "Erro auth")}`);
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
app.get('/check-session', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    if (req.session.user) {
        const users = readDB(USERS_DB_PATH);
        const u = users[req.session.user.username.toLowerCase()];
        if (u) {
            req.session.user.isAdmin = u.isAdmin;
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1 } });
        } else { req.session.destroy(); res.clearCookie('zappbot.sid'); res.status(401).json({ loggedIn: false }); }
    } else { res.status(401).json({ loggedIn: false }); }
});

io.use((socket, next) => {
    const sessionUser = socket.request.session.user || (socket.request.session.passport?.user);
    if (sessionUser) {
        const username = (typeof sessionUser === 'object' ? sessionUser.username : sessionUser).toLowerCase();
        const dbUser = readDB(USERS_DB_PATH)[username];
        if (dbUser) { socket.request.session.user = { username: dbUser.username, isAdmin: dbUser.isAdmin }; next(); } else { next(new Error('Authentication error')); }
    } else { next(); }
});

clientRoutes(io, generatePix);

// Histórico de chat de suporte em memória (limpo ao reiniciar)
const supportChatHistory = {};

io.on('connection', (socket) => {
    const user = socket.request.session.user;
    
    // --- Lógica do Chat de Suporte (COM RETRY LOOP) ---
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

        // Adiciona mensagem do usuário
        supportChatHistory[userId].push({ role: "user", parts: [{ text: msg }] });

        // Loop de tentativas para rotacionar chaves em caso de erro 429
        for (let attempt = 0; attempt < API_KEYS_GEMINI.length; attempt++) {
            try {
                // Inicia o chat com o modelo ATUAL
                const chat = supportModel.startChat({ history: supportChatHistory[userId] });
                const result = await chat.sendMessage(msg);
                const responseText = result.response.text();

                // Adiciona resposta da IA ao histórico
                supportChatHistory[userId].push({ role: "model", parts: [{ text: responseText }] });

                // Limita histórico para não estourar tokens
                if (supportChatHistory[userId].length > 20) {
                    supportChatHistory[userId] = [
                        supportChatHistory[userId][0],
                        supportChatHistory[userId][1],
                        ...supportChatHistory[userId].slice(-18)
                    ];
                }

                // Processa Ações (Atalhos)
                let finalResponse = responseText;
                let action = null;

                if (responseText.includes('[ACTION:')) {
                    const match = responseText.match(/\[ACTION:([A-Z_]+)\]/);
                    if (match) {
                        action = match[1];
                        finalResponse = responseText.replace(match[0], '').trim();
                    }
                }

                // SIMULAÇÃO DE DIGITAÇÃO (DELAY ARTIFICIAL)
                // Gera um delay aleatório entre 1500ms e 3000ms
                const typingDelay = Math.floor(Math.random() * 1500) + 1500;

                setTimeout(() => {
                    socket.emit('support-chat-response', { text: finalResponse, action: action });
                }, typingDelay);
                
                // Se chegou aqui, deu certo, sai do loop
                return;

            } catch (error) {
                console.error(`[SERVER] Erro IA (Tentativa ${attempt + 1}/${API_KEYS_GEMINI.length}):`, error.message);
                
                // Se for erro de cota (429) ou QuotaFailure, troca a chave e tenta de novo
                if (error.message.includes('429') || error.message.includes('Quota') || error.status === 429) {
                    switchToNextApiKey();
                    // O loop vai rodar de novo com a nova chave
                } else {
                    // Se for outro erro (ex: prompt inválido), desiste
                    socket.emit('support-chat-response', { text: "Desculpe, tive um erro técnico ao processar sua mensagem." });
                    return;
                }
            }
        }
        
        // Se saiu do loop sem retornar, é porque todas as chaves falharam
        socket.emit('support-chat-response', { text: "O sistema de IA está sobrecarregado no momento (todas as chaves atingiram o limite). Tente novamente em alguns instantes." });
    });

    // --- NOVO EVENTO: Limpar histórico do servidor ---
    socket.on('clear-support-history', () => {
        const userId = user.username;
        if (supportChatHistory[userId]) {
            delete supportChatHistory[userId];
        }
    });

    socket.on('get-public-prices', () => {
        const s = readDB(SETTINGS_DB_PATH);
        socket.emit('public-prices', { appName: s.appName || 'zappbot', supportNumber: s.supportNumber, priceMonthly: s.priceMonthly, priceQuarterly: s.priceQuarterly, priceSemiannual: s.priceSemiannual, priceYearly: s.priceYearly, priceResell5: s.priceResell5, priceResell10: s.priceResell10, priceResell20: s.priceResell20, priceResell30: s.priceResell30 });
    });
    socket.on('bot-online', ({ sessionName }) => { updateBotStatus(sessionName, 'Online', { setActivated: true }); });
    socket.on('bot-identified', ({ sessionName, publicName }) => {
        const bots = readDB(BOTS_DB_PATH);
        if (bots[sessionName]) { bots[sessionName].publicName = publicName; writeDB(BOTS_DB_PATH, bots); io.emit('bot-updated', bots[sessionName]); }
    });
    socket.on('update-group-settings', (data) => {
        const groups = readDB(GROUPS_DB_PATH);
        if (groups[data.groupId]) {
            groups[data.groupId] = { ...groups[data.groupId], ...data.settings };
            writeDB(GROUPS_DB_PATH, groups);
            io.to(groups[data.groupId].owner.toLowerCase()).emit('group-list-updated', Object.values(groups).filter(g => g.owner === groups[data.groupId].owner));
            io.emit('group-settings-changed', { botSessionName: groups[data.groupId].managedByBot, groupId: data.groupId, settings: groups[data.groupId] });
        }
    });

    socket.on('bot-update-ignored', ({ sessionName, type, value }) => {
        const bots = readDB(BOTS_DB_PATH);
        const bot = bots[sessionName];
        if (bot) {
            if (!bot.ignoredIdentifiers) bot.ignoredIdentifiers = [];
            const exists = bot.ignoredIdentifiers.some(i => i.type === type && i.value.toLowerCase() === value.toLowerCase());
            if (!exists) {
                bot.ignoredIdentifiers.push({ type, value });
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
            }
        }
    });

    socket.on('group-activation-request', ({ groupId, groupName, activationToken, botSessionName }) => {
        const tokenData = activationTokens[activationToken];
        if (!tokenData || tokenData.expiresAt < Date.now()) { io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Token expirado/inválido.' }); return; }
        const { ownerEmail } = tokenData;
        delete activationTokens[activationToken]; 
        const users = readDB(USERS_DB_PATH);
        const groups = readDB(GROUPS_DB_PATH);
        if (!users[ownerEmail]) { io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Usuário não encontrado.' }); return; }
        if (groups[groupId]) { io.to(ownerEmail.toLowerCase()).emit('feedback', { success: false, message: `O grupo "${groupName}" já existe.` }); io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Grupo já cadastrado.' }); return; }
        const now = new Date();
        const trialExpire = new Date(now.getTime() + 24 * 60 * 60 * 1000); 
        const newGroup = { groupId, groupName, owner: ownerEmail, managedByBot: botSessionName, status: "active", antiLink: false, createdAt: now.toISOString(), expiresAt: trialExpire.toISOString(), prompt: "", silenceTime: 0, botName: "", isPaused: false };
        groups[groupId] = newGroup;
        writeDB(GROUPS_DB_PATH, groups);
        io.to(ownerEmail.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === ownerEmail));
        io.to(ownerEmail.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${groupName}" ativado!` });
        io.emit('group-activation-result', { success: true, groupId: groupId, botSessionName: botSessionName, expiresAt: newGroup.expiresAt, message: 'Grupo ativado.' });
    });

    socket.on('client:request-pix', async (data) => {
        const { campaignId, clientJid, botSessionName } = data;
        const campaigns = readDB(CAMPAIGNS_DB_PATH);
        
        const campaignsList = Array.isArray(campaigns) ? campaigns : [];
        const campaign = campaignsList.find(c => c.id === campaignId);

        if (!campaign || campaign.type !== 'cobranca') {
            console.log(`[PIX] Campanha ${campaignId} não encontrada ou não é cobrança.`);
            io.emit('pix:generation-failed', { clientJid, botSessionName, message: 'Campanha não encontrada.' });
            return;
        }

        try {
            const ownerUsername = campaign.owner;
            const users = readDB(USERS_DB_PATH);
            const ownerData = users[ownerUsername];
            const userMpToken = ownerData ? ownerData.mpAccessToken : null;

            if (!userMpToken) {
                console.error(`[PIX] Usuário ${ownerUsername} não configurou token MP em Clients.`);
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
                const clients = readDB(CLIENTS_DB_PATH);
                const client = clients.find(c => c.number === clientJid.replace('@s.whatsapp.net', '') && c.owner === ownerUsername);
                
                const payments = readDB(PAYMENTS_DB_PATH);
                if (!payments.some(p => p.id === result.id)) {
                    payments.push({
                        id: result.id,
                        date: new Date().toISOString(),
                        amount: amount,
                        campaignId: campaignId,
                        campaignName: campaign.name,
                        clientNumber: clientJid.replace('@s.whatsapp.net', ''),
                        clientName: client ? client.name : clientJid.replace('@s.whatsapp.net', ''),
                        owner: ownerUsername,
                        status: 'pending'
                    });
                    writeDB(PAYMENTS_DB_PATH, payments);
                    const userPayments = payments.filter(p => p.owner === ownerUsername);
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

    socket.on('campaign:feedback', (data) => {
        const bots = readDB(BOTS_DB_PATH);
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
        const uData = readDB(USERS_DB_PATH)[user.username];
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1 });

        socket.on('user:save-mp-token', ({ token }) => {
            const users = readDB(USERS_DB_PATH);
            if (users[user.username]) {
                users[user.username].mpAccessToken = token;
                writeDB(USERS_DB_PATH, users);
                socket.emit('feedback', { success: true, message: 'Token Mercado Pago salvo!' });
            }
        });

        socket.on('user:get-mp-token', () => {
            const users = readDB(USERS_DB_PATH);
            if (users[user.username] && users[user.username].mpAccessToken) {
                socket.emit('user:mp-token', { token: users[user.username].mpAccessToken });
            }
        });

        if (user.isAdmin) {
            socket.on('admin-settings', (s) => socket.emit('admin-settings', readDB(SETTINGS_DB_PATH)));
            socket.on('save-settings', (ns) => { writeDB(SETTINGS_DB_PATH, ns); socket.emit('feedback', { success: true, message: 'Salvo' }); io.emit('public-prices', { appName: ns.appName, supportNumber: ns.supportNumber, priceMonthly: ns.priceMonthly, priceQuarterly: ns.priceQuarterly, priceSemiannual: ns.priceSemiannual, priceYearly: ns.priceYearly, priceResell5: ns.priceResell5, priceResell10: ns.priceResell10, priceResell20: ns.priceResell20, priceResell30: ns.priceResell30 }); });
            socket.on('admin-set-days', ({ sessionName, days }) => {
                const bots = readDB(BOTS_DB_PATH);
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
                    writeDB(BOTS_DB_PATH, bots);
                    io.emit('bot-updated', bot);
                }
            });
            socket.on('admin-set-group-days', ({ groupId, days }) => {
                const groups = readDB(GROUPS_DB_PATH);
                const group = groups[groupId];
                if (group) {
                    const d = parseInt(days);
                    const now = new Date();
                    const baseDate = new Date(now);
                    baseDate.setDate(baseDate.getDate() + d);
                    baseDate.setMinutes(baseDate.getMinutes() - 10);
                    group.expiresAt = baseDate.toISOString();
                    group.status = 'active'; 
                    writeDB(GROUPS_DB_PATH, groups);
                    io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('feedback', { success: true, message: 'Dias definidos.' });
                    const botSessionName = group.managedByBot;
                    if (activeBots[botSessionName]) {
                        activeBots[botSessionName].intentionalStop = true;
                        activeBots[botSessionName].process.kill('SIGINT');
                        delete activeBots[botSessionName];
                        setTimeout(() => { const currentBots = readDB(BOTS_DB_PATH); if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]); }, 1000);
                    }
                }
            });
            socket.on('admin-get-users', () => socket.emit('admin-users-list', Object.values(readDB(USERS_DB_PATH)).map(({ password, ...r }) => r)));
            socket.on('admin-delete-user', ({ username }) => { const users = readDB(USERS_DB_PATH); delete users[username]; writeDB(USERS_DB_PATH, users); socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r)); });
            socket.on('admin-get-bots-for-user', ({ username }) => socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === username)));
        }

        socket.on('get-my-bots', () => { socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === user.username)); });
        socket.on('get-my-groups', () => { socket.emit('initial-groups-list', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === user.username)); });

        socket.on('delete-group', ({ groupId }) => {
            const groups = readDB(GROUPS_DB_PATH);
            const group = groups[groupId];
            if (!group) return socket.emit('feedback', { success: false, message: 'Grupo não encontrado.' });
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[group.managedByBot];
            const isBotOwner = bot && bot.owner === user.username;
            const isGroupOwner = group.owner === user.username;
            if (!user.isAdmin && !isBotOwner && !isGroupOwner) return socket.emit('feedback', { success: false, message: 'Permissão negada.' });
            const botSessionName = group.managedByBot;
            delete groups[groupId];
            writeDB(GROUPS_DB_PATH, groups);
            io.emit('group-removed', { botSessionName, groupId });
            socket.emit('group-list-updated', Object.values(groups).filter(g => g.owner === user.username));
            socket.emit('feedback', { success: true, message: 'Grupo removido.' });
            if (activeBots[botSessionName]) {
                activeBots[botSessionName].intentionalStop = true;
                activeBots[botSessionName].process.kill('SIGINT');
                delete activeBots[botSessionName];
                setTimeout(() => { const currentBots = readDB(BOTS_DB_PATH); if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]); }, 1000);
            }
        });

        socket.on('create-bot', (d) => {
            try {
                const bots = readDB(BOTS_DB_PATH);
                let users = readDB(USERS_DB_PATH);
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
                        users[owner] = ownerData;
                        writeDB(USERS_DB_PATH, users);
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
                bots[d.sessionName] = newBot;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', newBot);
                if (new Date(newBot.trialExpiresAt) > new Date()) startBotProcess(newBot);
                socket.emit('feedback', { success: true, message: feedbackMessage });
            } catch (err) { console.error("Erro criar bot:", err); socket.emit('feedback', { success: false, message: 'Erro interno.' }); }
        });

        socket.on('start-bot', ({ sessionName, phoneNumber }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (new Date(bot.trialExpiresAt) < new Date()) return socket.emit('feedback', { success: false, message: 'Expirado.' });
            if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'Já rodando.' });
            startBotProcess(bot, phoneNumber ? phoneNumber.replace(/\D/g, '') : null);
            socket.emit('feedback', { success: true, message: 'Iniciando...' });
        });

        socket.on('stop-bot', ({ sessionName }) => {
            if (activeBots[sessionName]) { try { activeBots[sessionName].intentionalStop = true; activeBots[sessionName].process.kill('SIGINT'); } catch(e){} delete activeBots[sessionName]; }
            updateBotStatus(sessionName, 'Offline');
            socket.emit('feedback', { success: true, message: 'Parado.' });
        });

        socket.on('delete-bot', ({ sessionName }) => {
            let bots = readDB(BOTS_DB_PATH);
            let users = readDB(USERS_DB_PATH);
            const botToDelete = bots[sessionName];
            if (!botToDelete || (!user.isAdmin && botToDelete.owner !== user.username)) return;
            
            if (botToDelete.botType === 'group') {
                let groups = readDB(GROUPS_DB_PATH);
                let groupsChanged = false;
                Object.keys(groups).forEach(groupId => { if (groups[groupId].managedByBot === sessionName) { delete groups[groupId]; groupsChanged = true; } });
                if (groupsChanged) { writeDB(GROUPS_DB_PATH, groups); io.emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH))); }
            }

            if (botToDelete.botType !== 'group') {
                const owner = users[botToDelete.owner];
                if (owner && new Date(botToDelete.trialExpiresAt) > new Date()) {
                    owner.salvagedTime = { expiresAt: botToDelete.trialExpiresAt, isTrial: botToDelete.isTrial };
                    users[botToDelete.owner] = owner;
                    writeDB(USERS_DB_PATH, users);
                }
            }
            if (activeBots[sessionName]) { activeBots[sessionName].intentionalStop = true; activeBots[sessionName].process.kill('SIGINT'); delete activeBots[sessionName]; }
            delete bots[sessionName];
            writeDB(BOTS_DB_PATH, bots);
            const authPath = path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`);
            if (fs.existsSync(authPath)) fs.rmSync(authPath, { recursive: true, force: true });
            io.emit('bot-deleted', { sessionName });
            socket.emit('feedback', { success: true, message: 'Excluído.' });
        });

        socket.on('update-bot', (d) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[d.sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (bot) {
                bot.prompt = d.newPrompt;
                if (d.botType !== undefined) bot.botType = d.botType;
                bot.botName = d.botName;
                bot.silenceTime = d.silenceTime;
                bot.notificationNumber = d.notificationNumber;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
                if (activeBots[d.sessionName]) {
                    try { activeBots[d.sessionName].intentionalStop = true; activeBots[d.sessionName].process.kill('SIGINT'); } catch (e) {}
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Salvo. Reiniciando...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else { socket.emit('feedback', { success: true, message: 'Salvo.' }); }
            }
        });

        socket.on('update-ignored-identifiers', ({ sessionName, ignoredIdentifiers }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            bot.ignoredIdentifiers = ignoredIdentifiers;
            writeDB(BOTS_DB_PATH, bots);
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

function startBotProcess(bot, phoneNumber = null) {
    if (activeBots[bot.sessionName]) return; 
    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    const promptBase64 = Buffer.from(bot.prompt || '').toString('base64');
    const ignoredBase64 = Buffer.from(JSON.stringify(bot.ignoredIdentifiers || [])).toString('base64');
    const phoneArg = phoneNumber ? phoneNumber : 'null';

    let authorizedGroupsArg = '[]';
    if (bot.botType === 'group') {
        const allGroups = readDB(GROUPS_DB_PATH);
        const authorizedGroups = Object.values(allGroups)
            .filter(g => g.managedByBot === bot.sessionName && g.status === 'active')
            .map(g => ({ groupId: g.groupId, expiresAt: g.expiresAt, antiLink: g.antiLink, prompt: g.prompt, silenceTime: g.silenceTime, botName: g.botName, isPaused: g.isPaused }));
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

function updateBotStatus(name, status, options = {}) {
    const bots = readDB(BOTS_DB_PATH);
    const bot = bots[name];
    if (bot) {
        bot.status = status;
        if (options.qr !== undefined) bot.qr = options.qr; else if (status !== 'Aguardando QR Code') bot.qr = null;
        if (options.setActivated && !bot.activated) {
            bot.activated = true;
            const users = readDB(USERS_DB_PATH);
            const ownerData = users[bot.owner];
            if (ownerData && !ownerData.isAdmin && bot.isTrial && !ownerData.trialUsed) { ownerData.trialUsed = true; writeDB(USERS_DB_PATH, users); }
        }
        writeDB(BOTS_DB_PATH, bots);
        io.emit('bot-updated', bot);
    }
}

function restartActiveBots() {
    const bots = readDB(BOTS_DB_PATH);
    Object.values(bots).forEach(bot => {
        if (bot.status === 'Online' || bot.status.includes('Iniciando') || bot.status.includes('Aguardando')) {
            const now = new Date();
            const expires = new Date(bot.trialExpiresAt);
            if (expires > now) startBotProcess(bot); else bot.status = 'Offline';
        }
    });
    writeDB(BOTS_DB_PATH, bots);
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

