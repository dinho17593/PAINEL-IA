//server.js

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
const { MercadoPagoConfig, Payment, Preference } = require('mercadopago');
const crypto = require('crypto');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const multer = require('multer');
const PDFParser = require('pdf2json');
const { GoogleGenerativeAI } = require('@google/generative-ai'); 
const rateLimit = require('express-rate-limit');
const webpush = require('web-push');
const clientRoutes = require('./client-routes');
const db = require('./database'); // Importa o módulo SQLite
const EventEmitter = require('events'); // Adicionado para comunicação interna
require('dotenv').config();

// Emissor de eventos global para comunicação entre o bot e as rotas de campanha
global.botEvents = new EventEmitter();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e7 // 10 MB para permitir salvar bases de conhecimento grandes
});

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
Você é o Assistente Inteligente de Suporte do painel "zappbot". Sua missão é ajudar os usuários a configurarem seus robôs de WhatsApp/Telegram, tirar dúvidas sobre o painel e guiar os revendedores.
Seja sempre cordial, profissional, direto e responda EXCLUSIVAMENTE em Português do Brasil.

Abaixo está o manual de como o sistema funciona. Use essas informações para responder às dúvidas:

1. TIPOS DE ROBÔS:
- Atendimento Privado: Atende clientes no 1 a 1 (PV). Possui IA (Prompt/Personalidade), leitura de PDF/TXT/Site (Base de Conhecimento) e "Respostas Rápidas" (Gatilhos de palavras-chave que ignoram a IA).
- Gestor de Grupos: Administra grupos de WhatsApp/Telegram. Possui sistema Anti-link, Boas-vindas e comandos para o Admin (ex: !ban, !kick, !mute, !unmute, !promover, !rebaixar, !todos, !apagar).
- Se o usuário perguntar como criar um robô ou quiser começar, explique rapidamente e coloque na última linha da sua resposta a tag mágica: [ACTION:OPEN_CREATE]

2. CHAT AO VIVO (LIVE CHAT):
- Os usuários podem assumir o controle do robô e falar com os clientes em tempo real através do botão "Ao Vivo" no card do robô conectado.
- Se o usuário mandar uma mensagem por lá, a IA é pausada por 10 minutos automaticamente para aquele cliente.
- O usuário ou o cliente final também podem digitar "!stop X" (X = minutos) para pausar a IA, ou "!stopsempre" para ignorar o número para sempre.

3. GESTOR DE COBRANÇAS E CAMPANHAS:
- Existe um "Gestor de Cobranças" no menu lateral. Lá, o usuário cadastra seus clientes e cria campanhas de cobrança ou marketing em massa.
- Ele pode enviar Pix gerados automaticamente integrados à conta do Mercado Pago dele. A baixa do pagamento é automática e avisa o cliente.
- Se ele perguntar sobre envio em massa, cobranças ou clientes, adicione na última linha da sua resposta a tag: [ACTION:OPEN_CLIENTS]

4. SISTEMA DE REVENDA E LIMITES (WHITE-LABEL):
- Qualquer usuário pode virar um "Revendedor" e ter sua própria plataforma com a própria logo e nome.
- Os pagamentos de renovação dos clientes do revendedor caem DIRETO no Mercado Pago do revendedor. Nós não cobramos taxas.
- O revendedor só gasta seus "créditos de limite de robôs" para ativar clientes.
- Se alguém quiser revender, aumentar limite ou perguntar sobre White-label, adicione na última linha a tag: [ACTION:OPEN_RESELL]

5. BACKUP E CONFIGURAÇÕES:
- O usuário pode baixar backups completos e ativar notificações visuais/sonoras de mensagens no PC/Celular.
- O Revendedor também altera a logo, o nome do sistema, e cadastra o Token do Mercado Pago na tela de Configurações.
- Se ele perguntar onde muda a logo, o token MP, ou como faz backup, adicione na última linha a tag: [ACTION:OPEN_BACKUP]

INSTRUÇÕES FINAIS E REGRAS:
- Nunca invente funcionalidades. Se perguntarem algo fora disso, diga que o sistema foca em Automação de Chat, IA e Cobranças.
- Só use as tags de [ACTION] se fizer sentido para a pergunta, e elas DEVEM ficar isoladas no final do seu texto. O sistema as transformará em botões clicáveis para o usuário.
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

// Inicializa Admin se não existir e gera refCodes para usuários antigos
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
            
            // Gera um código de indicação curto para usuários que ainda não têm
            for (const key of userKeys) {
                if (!users[key].refCode) {
                    users[key].refCode = Math.random().toString(36).substring(2, 8).toUpperCase();
                    await db.saveUser(users[key]);
                }
            }
        }
    } catch (e) {
        console.error("Erro ao verificar admins/refCodes:", e);
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
    
    // Gera chaves VAPID automaticamente para o Web Push se não existirem
    if (!current.vapidPublicKey || !current.vapidPrivateKey) {
        const vapidKeys = webpush.generateVAPIDKeys();
        current.vapidPublicKey = vapidKeys.publicKey;
        current.vapidPrivateKey = vapidKeys.privateKey;
        updated = true;
    }
    
    if (updated || Object.keys(current).length === 0) {
        await db.saveSettings(current);
    }

    // Configura o Web Push
    webpush.setVapidDetails(
        'mailto:admin@zappbot.com',
        current.vapidPublicKey,
        current.vapidPrivateKey
    );
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
                    // SE O USUÁRIO JÁ EXISTE: Atualiza o banco de dados com a foto e o nome do Google
                    let needUpdate = false;
                    
                    if (profile.photos && profile.photos.length > 0 && users[username].avatar !== profile.photos[0].value) {
                        users[username].avatar = profile.photos[0].value;
                        needUpdate = true;
                    }
                    if (profile.displayName && users[username].displayName !== profile.displayName) {
                        users[username].displayName = profile.displayName;
                        needUpdate = true;
                    }
                    
                    if (needUpdate) {
                        await db.saveUser(users[username]);
                    }
                    
                    return done(null, users[username]);
                }

                const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
                const isAdmin = Object.keys(users).length === 0;
                const trialUsed = (!isAdmin && deviceUsed) ? true : false;

                const refCookie = req.cookies['zappbot_ref'];
                let parentId = null;
                
                // Busca o dono do código de indicação
                if (refCookie && !isAdmin) {
                    const parentUser = Object.values(users).find(u => u.refCode && u.refCode.toLowerCase() === refCookie.toLowerCase().trim());
                    if (parentUser) parentId = parentUser.username;
                }

                const newUser = {
                    username,
                    password: null,
                    googleId: profile.id,
                    displayName: profile.displayName,
                    avatar: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null,
                    createdAt: new Date(),
                    isAdmin,
                    botLimit: isAdmin ? 999999 : 1,
                    log: [],
                    trialUsed: trialUsed,
                    trialExpiresAt: null,
                    salvagedTime: null,
                    parentId: parentId,
                    refCode: Math.random().toString(36).substring(2, 8).toUpperCase(),
                    prices: {}
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

let isPollingMP = false;
setInterval(async () => {
    if (isPollingMP) return; // Se a verificação anterior ainda não acabou, não atropela
    const paymentIds = Object.keys(pendingPayments);
    if (paymentIds.length === 0) return;

    isPollingMP = true;
    try {
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
    } finally {
        isPollingMP = false; // Libera para a próxima verificação
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

async function generatePreference(req, amount, description, external_reference, accessToken = null) {
    let tokenToUse = accessToken;
    if (!tokenToUse) {
        const settings = await db.getSettings();
        tokenToUse = settings.mpAccessToken;
    }
    if (!tokenToUse) throw new Error('Token do MercadoPago não configurado.');

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
        if (req.headers['x-forwarded-proto']) protocol = req.headers['x-forwarded-proto'];
    }

    let notificationUrl = `${protocol}://${host}/webhook/mercadopago`;
    if (notificationUrl.includes('localhost') || notificationUrl.includes('127.0.0.1')) notificationUrl = null;

    const client = new MercadoPagoConfig({ accessToken: tokenToUse });
    const preference = new Preference(client);

    const body = {
        items:[{
            id: 'item-ID-1234',
            title: description,
            quantity: 1,
            unit_price: Number(amount)
        }],
        payer: { 
            name: "Cliente",
            surname: "Avulso",
            email: payerEmail 
        },
        external_reference: external_reference,
        payment_methods: {
            default_payment_type_id: "credit_card" // Força abrir direto a tela de digitar o cartão (Guest Checkout)
        }
    };

    if (notificationUrl) body.notification_url = notificationUrl;

    const result = await preference.create({ body });
    return result.init_point; // Retorna o link de pagamento do Mercado Pago
}

// --- ROTA DINÂMICA DE LOGO (WHITE-LABEL) ---
app.get('/api/logo/:size', async (req, res) => {
    try {
        const users = await db.getAllUsers();
        let targetOwner = null;

        // 1. Tenta identificar pelo link de indicação (cookie ou query)
        const refParam = req.query.ref || req.cookies['zappbot_ref'];
        if (refParam) {
            const parentUser = Object.values(users).find(u => u.refCode && u.refCode.toLowerCase() === refParam.toLowerCase().trim());
            if (parentUser) targetOwner = parentUser.username;
        }

        // 2. Tenta identificar se o usuário já está logado
        if (!targetOwner && req.session && req.session.user) {
            const u = users[req.session.user.username.toLowerCase()];
            if (u) {
                if (u.botLimit > 1 && !u.isAdmin) {
                    targetOwner = u.username; // É o próprio revendedor
                } else if (u.parentId) {
                    targetOwner = u.parentId; // É cliente de um revendedor
                }
            }
        }

        // 3. Se encontrou o dono (revendedor), verifica se ele fez upload de logo própria
        if (targetOwner) {
            const customLogoPath = path.join(BASE_DIR, 'uploads', `logo_${targetOwner}.png`);
            if (fs.existsSync(customLogoPath)) {
                return res.sendFile(customLogoPath); // Retorna a logo do revendedor
            }
        }

        // Fallback: Retorna a logo padrão do Admin
        const size = req.params.size === '192' ? '192x192' : '512x512';
        const defaultPath = path.join(BASE_DIR, `icon-${size}.png`);
        
        if (fs.existsSync(defaultPath)) {
            return res.sendFile(defaultPath);
        } else {
            return res.status(404).send('Logo não encontrada');
        }
    } catch (e) {
        res.status(500).send('Erro ao carregar logo');
    }
});

app.get('/manifest.json', async (req, res) => {
    const settings = await db.getSettings();
    let appName = settings.appName || 'zappbot';
    let refParam = req.query.ref || req.cookies['zappbot_ref']; // Corrigido para evitar o ReferenceError
    
    try {
        const users = await db.getAllUsers();
        
        // 1. Verifica se há um código de indicação na URL ou no Cookie
        if (refParam) {
            const parentUser = Object.values(users).find(u => u.refCode && u.refCode.toLowerCase() === refParam.toLowerCase().trim());
            if (parentUser && parentUser.appName) {
                appName = parentUser.appName;
            }
        }
        
        // 2. Verifica se o usuário já está logado (sobrescreve a regra anterior se necessário)
        if (req.session && req.session.user) {
            const u = users[req.session.user.username.toLowerCase()];
            if (u) {
                if (u.botLimit > 1 && !u.isAdmin && u.appName) {
                    appName = u.appName; // É o próprio revendedor
                } else if (u.parentId && users[u.parentId] && users[u.parentId].appName) {
                    appName = users[u.parentId].appName; // É cliente de um revendedor
                }
            }
        }
    } catch (e) {
        console.error("Erro ao gerar manifest.json dinâmico:", e);
    }

    res.json({
        "name": appName,
        "short_name": appName,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#09090b",
        "theme_color": "#121214",
        "orientation": "portrait",
        "icons": [
            { "src": `/api/logo/192${refParam ? '?ref='+refParam : ''}`, "sizes": "192x192", "type": "image/png", "purpose": "any maskable" },
            { "src": `/api/logo/512${refParam ? '?ref='+refParam : ''}`, "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
        ]
    });
});

app.post('/api/admin/upload-icons', upload.single('icon'), async (req, res) => {
    if (!req.session.user) return res.status(403).json({ success: false, message: 'Acesso negado.' });
    
    const username = req.session.user.username;
    const isAdmin = req.session.user.isAdmin;
    
    // Verifica se é admin ou revendedor
    const users = await db.getAllUsers();
    const u = users[username];
    if (!isAdmin && (!u || u.botLimit <= 1)) {
        return res.status(403).json({ success: false, message: 'Acesso negado. Apenas revendedores podem alterar a logo.' });
    }

    try {
        if (req.file) {
            const tempPath = req.file.path;
            
            if (isAdmin) {
                // Admin: Substitui a logo padrão do sistema
                const targetPathSmall = path.join(BASE_DIR, 'icon-192x192.png');
                const targetPathLarge = path.join(BASE_DIR, 'icon-512x512.png');
                
                if(fs.existsSync(targetPathSmall)) fs.unlinkSync(targetPathSmall);
                if(fs.existsSync(targetPathLarge)) fs.unlinkSync(targetPathLarge);
                
                fs.copyFileSync(tempPath, targetPathSmall);
                fs.renameSync(tempPath, targetPathLarge);
            } else {
                // Revendedor: Salva a logo personalizada dele em "uploads/logo_usuario.png"
                const targetPath = path.join(BASE_DIR, 'uploads', `logo_${username}.png`);
                if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
                fs.renameSync(tempPath, targetPath);
            }
        }
        res.json({ success: true, message: 'Logo atualizada com sucesso!' });
    } catch (error) { 
        res.status(500).json({ success: false, message: 'Erro ao processar a imagem.' }); 
    }
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
    archive.on('error', (err) => { 
        if (!res.headersSent) {
            res.status(500).send({ error: err.message }); 
        } else {
            console.error('[BACKUP] Erro silencioso ignorado no stream do zip:', err.message);
        }
    });
    archive.pipe(res);

    // Carrega dados do SQLite
    const allUsers = await db.getAllUsers();
    const allBots = await db.getAllBots();
    const allGroups = await db.getAllGroups();
    const allSettings = await db.getSettings();
    const allClients = await db.getAllClients();
    const allCampaigns = await db.getAllCampaigns();
    const allPayments = await db.getAllPayments();

    // Otimização de RAM e Armazenamento: Removido o "null, 2" do JSON.stringify.
    // Isso evita a criação de strings gigantescas na memória e reduz o tamanho do arquivo ZIP final.
    if (isAdmin) {
        // Admin: Backup Completo
        archive.append(JSON.stringify(allUsers), { name: 'users.json' });
        archive.append(JSON.stringify(allBots), { name: 'bots.json' });
        archive.append(JSON.stringify(allGroups), { name: 'groups.json' });
        archive.append(JSON.stringify(allSettings), { name: 'settings.json' });
        archive.append(JSON.stringify(allClients), { name: 'clients.json' });
        archive.append(JSON.stringify(allCampaigns), { name: 'campaigns.json' });
        archive.append(JSON.stringify(allPayments), { name: 'payments.json' });
    } else {
        // Usuário Comum: Backup Filtrado
        const userBots = Object.fromEntries(Object.entries(allBots).filter(([k, v]) => v.owner === username));
        archive.append(JSON.stringify(userBots), { name: 'bots.json' });

        const userGroups = Object.fromEntries(Object.entries(allGroups).filter(([k, v]) => v.owner === username));
        archive.append(JSON.stringify(userGroups), { name: 'groups.json' });

        const userClients = allClients.filter(c => c.owner === username);
        archive.append(JSON.stringify(userClients), { name: 'clients.json' });

        const userCampaigns = allCampaigns.filter(c => c.owner === username);
        archive.append(JSON.stringify(userCampaigns), { name: 'campaigns.json' });

        const userPayments = allPayments.filter(p => p.owner === username);
        archive.append(JSON.stringify(userPayments), { name: 'payments.json' });
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
                        try { activeBots[sessionName].process.kill('SIGINT'); } catch(e){}
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

    const users = await db.getAllUsers();
    const u = users[req.session.user.username];
    const parent = u && u.parentId ? users[u.parentId] : null;

    let tokenToUse = settings.mpAccessToken;
    let pricesToUse = settings;

    if (parent) {
        if (parent.mpAccessToken) tokenToUse = parent.mpAccessToken;
        if (parent.prices && Object.keys(parent.prices).length > 0) {
            pricesToUse = { ...settings, ...parent.prices };
        }
    }

    let amount = 0, desc = '', extRef = '';
    let requiredCredits = 0;
    
    if (planType === 'monthly') requiredCredits = 1;
    if (planType === 'quarterly') requiredCredits = 3;
    if (planType === 'semiannual') requiredCredits = 6;
    if (planType === 'yearly') requiredCredits = 12;

    // Dicionário para traduzir os planos para o cliente
    const planNames = {
        'monthly': 'Plano Mensal',
        'quarterly': 'Plano Trimestral',
        'semiannual': 'Plano Semestral',
        'yearly': 'Plano Anual'
    };

    if (planType && planType.startsWith('resell_')) {
        const amountBots = parseInt(planType.split('_')[1]);
        if (parent && !parent.isAdmin) {
            if ((parent.botLimit || 0) < amountBots) {
                return res.status(400).json({ error: 'Seu fornecedor não possui limite de robôs suficiente no momento, escolha um plano menor.' });
            }
        }
        if (planType === 'resell_5') amount = parseFloat(pricesToUse.priceResell5 || settings.priceResell5);
        if (planType === 'resell_10') amount = parseFloat(pricesToUse.priceResell10 || settings.priceResell10);
        if (planType === 'resell_20') amount = parseFloat(pricesToUse.priceResell20 || settings.priceResell20);
        if (planType === 'resell_30') amount = parseFloat(pricesToUse.priceResell30 || settings.priceResell30);
        
        // Nome amigável para pacotes de revenda
        desc = `Pacote Revenda: ${amountBots} Robôs`; 
        extRef = `user|${req.session.user.username}|${planType}`;
        
    } else if (groupId) {
        if (parent && !parent.isAdmin) {
            if ((parent.botLimit || 0) < requiredCredits) {
                return res.status(400).json({ error: 'Seu fornecedor não possui saldo de créditos suficiente para esta transação.' });
            }
        }
        if (planType === 'monthly') amount = parseFloat(pricesToUse.priceMonthly || settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(pricesToUse.priceQuarterly || settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(pricesToUse.priceSemiannual || settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(pricesToUse.priceYearly || settings.priceYearly);
        
        // Nome amigável para grupos
        const friendlyPlan = planNames[planType] || planType;
        desc = `Ativação de Grupo (${friendlyPlan})`; 
        extRef = `group|${groupId}|${planType}`;
        
    } else {
        if (parent && !parent.isAdmin) {
            if ((parent.botLimit || 0) < requiredCredits) {
                return res.status(400).json({ error: 'Seu fornecedor não possui saldo de créditos suficiente para esta transação.' });
            }
        }
        if (planType === 'monthly') amount = parseFloat(pricesToUse.priceMonthly || settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(pricesToUse.priceQuarterly || settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(pricesToUse.priceSemiannual || settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(pricesToUse.priceYearly || settings.priceYearly);
        
        // Nome amigável para robôs individuais
        const friendlyPlan = planNames[planType] || planType;
        desc = `Renovação Robô: ${sessionName} (${friendlyPlan})`; 
        extRef = `bot|${sessionName}|${planType}`;
    }

    try {
        req.body.botSessionName = sessionName || 'system';
        // Gera o PIX Copia e Cola direto
        const resultPix = await generatePix(req, amount, desc, extRef, tokenToUse);
        // Gera o Link de Checkout (Cartão/Boleto)
        const checkoutUrl = await generatePreference(req, amount, desc, extRef, tokenToUse);
        
        res.json({ 
            qr_code: resultPix.point_of_interaction.transaction_data.qr_code, 
            qr_code_base64: resultPix.point_of_interaction.transaction_data.qr_code_base64, 
            checkout_url: checkoutUrl, 
            amount: amount.toFixed(2).replace('.', ',') 
        });
    } catch (e) { res.status(500).json({ error: 'Erro ao gerar Pagamento.' }); }
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
                        const amountBots = parseInt(plan.split('_')[1]);
                        const u = users[referenceId];
                        
                        if (u.parentId && users[u.parentId]) {
                            const parent = users[u.parentId];
                            if (!parent.isAdmin) {
                                parent.botLimit = Math.max(0, (parent.botLimit || 0) - amountBots);
                                await db.saveUser(parent);
                                io.to(parent.username.toLowerCase()).emit('update-limit', parent.botLimit);
                            }
                        }

                        u.botLimit = (u.botLimit || 1) + amountBots;
                        u.trialUsed = true;
                        u.trialExpiresAt = "PAID_USER";
                        await db.saveUser(u);
                        io.to(referenceId.toLowerCase()).emit('update-limit', u.botLimit);
                    }
                } else if (paymentType === 'bot') {
                    const bots = await db.getAllBots();
                    const bot = bots[referenceId];
                    if (bot) {
                        const now = new Date();
                        const currentExpire = new Date(bot.trialExpiresAt);
                        let days = 30;
                        let requiredCredits = 1;
                        if (plan === 'quarterly') { days = 90; requiredCredits = 3; }
                        if (plan === 'semiannual') { days = 180; requiredCredits = 6; }
                        if (plan === 'yearly') { days = 365; requiredCredits = 12; }
                        
                        const users = await db.getAllUsers();
                        const ownerData = users[bot.owner];
                        if (ownerData && ownerData.parentId) {
                            const parent = users[ownerData.parentId];
                            if (parent && !parent.isAdmin) {
                                parent.botLimit = Math.max(0, (parent.botLimit || 0) - requiredCredits);
                                await db.saveUser(parent);
                                io.to(parent.username.toLowerCase()).emit('update-limit', parent.botLimit);
                            }
                        }

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
                        let requiredCredits = 1;
                        if (plan === 'quarterly') { days = 90; requiredCredits = 3; }
                        if (plan === 'semiannual') { days = 180; requiredCredits = 6; }
                        if (plan === 'yearly') { days = 365; requiredCredits = 12; }
                        
                        const users = await db.getAllUsers();
                        const ownerData = users[group.owner];
                        if (ownerData && ownerData.parentId) {
                            const parent = users[ownerData.parentId];
                            if (parent && !parent.isAdmin) {
                                parent.botLimit = Math.max(0, (parent.botLimit || 0) - requiredCredits);
                                await db.saveUser(parent);
                                io.to(parent.username.toLowerCase()).emit('update-limit', parent.botLimit);
                            }
                        }

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
                            try { activeBots[botSessionName].process.kill('SIGINT'); } catch(e){}
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

    const ref = req.body.ref ? req.body.ref.toLowerCase().trim() : null;
    let parentId = null;
    
    // Busca o dono do código de indicação
    if (ref && !isAdmin) {
        const parentUser = Object.values(users).find(u => u.refCode && u.refCode.toLowerCase() === ref);
        if (parentUser) parentId = parentUser.username;
    }

    const newUser = { 
        username, 
        password: await bcrypt.hash(password, 10), 
        createdAt: new Date(), 
        isAdmin, 
        botLimit: isAdmin ? 999999 : 1, 
        log: [], 
        trialUsed: trialUsed, 
        trialExpiresAt: null, 
        salvagedTime: null,
        parentId: parentId,
        refCode: Math.random().toString(36).substring(2, 8).toUpperCase(),
        prices: {}
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
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1, refCode: u.refCode, displayName: u.displayName, avatar: u.avatar } });
        } else { req.session.destroy(); res.clearCookie('zappbot.sid'); res.status(401).json({ loggedIn: false }); }
    } else { res.status(401).json({ loggedIn: false }); }
});
// --- ROTAS PARA WEB PUSH (NOTIFICAÇÕES EM SEGUNDO PLANO) ---
app.get('/api/vapid-public-key', async (req, res) => {
    const settings = await db.getSettings();
    res.send(settings.vapidPublicKey);
});

app.post('/api/save-subscription', async (req, res) => {
    if (!req.session.user) return res.status(401).send('Não autorizado');
    const users = await db.getAllUsers();
    const u = users[req.session.user.username];
    if (u) {
        u.pushSubscription = req.body;
        await db.saveUser(u);
        res.status(201).json({ success: true });
    }
});
app.post('/api/upload-knowledge', upload.single('file'), async (req, res) => {
    if (!req.session.user) return res.status(401).json({ success: false, message: 'Não autorizado.' });
    if (!req.file) return res.status(400).json({ success: false, message: 'Nenhum arquivo enviado.' });

    try {
        const filePath = req.file.path;
        const ext = path.extname(req.file.originalname).toLowerCase();

        if (ext === '.txt') {
            const extractedText = fs.readFileSync(filePath, 'utf8');
            fs.unlinkSync(filePath);
            return res.json({ success: true, extractedText });
        } else if (ext === '.pdf') {
            // Usando pdf2json (muito mais estável e à prova de falhas)
            const pdfParser = new PDFParser(null, 1); // 1 = Extrair apenas texto
            
            pdfParser.on("pdfParser_dataError", errData => {
                console.error('Erro no PDFParser:', errData.parserError);
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                res.status(500).json({ success: false, message: 'Erro ao ler o PDF.' });
            });

            pdfParser.on("pdfParser_dataReady", pdfData => {
                const extractedText = pdfParser.getRawTextContent();
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                res.json({ success: true, extractedText });
            });

            pdfParser.loadPDF(filePath);
        } else {
            fs.unlinkSync(filePath);
            return res.status(400).json({ success: false, message: 'Formato não suportado. Use .txt ou .pdf' });
        }
    } catch (error) {
        console.error('Erro ao processar arquivo:', error);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ success: false, message: 'Erro ao extrair texto do arquivo.' });
    }
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

// Passa a instância do DB, controles do bot e o emissor de eventos para as rotas de cliente
clientRoutes(io, generatePix, db, { startBotProcess, activeBots, updateBotStatus }, botEvents);

const supportChatHistory = {};

io.on('connection', async (socket) => {
    const user = socket.request.session.user;

    // Registra Sockets dos Processos Filhos (index.js)
    socket.on('bot-register', (data) => {
        socket.join('bot_' + data.sessionName);
    });

    // Função auxiliar para validar dono
    const checkBotOwnership = async (sessionName) => {
        if (!user) return false;
        const bots = await db.getAllBots();
        const bot = bots[sessionName];
        if (!bot) return false;
        // Privacidade Master: Apenas o dono exato do robô pode ver as conversas (bloqueia admin e revendedor)
        return bot.owner === user.username;
    };

    // Ponte: Frontend -> Bot Process
    socket.on('livechat:request-chats', async (data) => {
        if (await checkBotOwnership(data.sessionName)) {
            io.to('bot_' + data.sessionName).emit('bot:get-chats', { frontendId: socket.id });
        }
    });

    socket.on('livechat:request-messages', async (data) => {
        if (await checkBotOwnership(data.sessionName)) {
            io.to('bot_' + data.sessionName).emit('bot:get-messages', { frontendId: socket.id, jid: data.jid });
        }
    });

    socket.on('livechat:send-message', async (data) => {
        if (await checkBotOwnership(data.sessionName)) {
            io.to('bot_' + data.sessionName).emit('bot:send-message', { jid: data.jid, text: data.text });
        }
    });

    socket.on('livechat:pause-ai', async (data) => {
        if (await checkBotOwnership(data.sessionName)) {
            io.to('bot_' + data.sessionName).emit('bot:pause-ai', { jid: data.jid });
        }
    });

    // Recebe a confirmação de envio do index.js e repassa para o client-routes.js
    socket.on('bot:message-status', (data) => {
        global.botEvents.emit(`status-${data.messageId}`, data);
    });

    // Ponte: Bot Process -> Frontend
    socket.on('bot:return-chats', (data) => {
        io.to(data.frontendId).emit('livechat:receive-chats', data.chats);
    });

    socket.on('bot:return-messages', (data) => {
        io.to(data.frontendId).emit('livechat:receive-messages', data);
    });

    socket.on('bot:new-message', async (data) => {
        console.log(`[DEBUG SERVER] Mensagem recebida do WhatsApp. Sessão: ${data.sessionName} | fromMe: ${data.message.fromMe}`);
        const bots = await db.getAllBots();
        const bot = bots[data.sessionName];
        if (bot && bot.owner) {
            console.log(`[DEBUG SERVER] Disparando evento para o celular do dono: ${bot.owner}`);
            io.to(bot.owner.toLowerCase()).emit('livechat:incoming-message', data);

            // DISPARO DE NOTIFICAÇÃO EM SEGUNDO PLANO (WEB PUSH)
            if (!data.message.fromMe && !data.jid.endsWith('@g.us')) {
                const users = await db.getAllUsers();
                const ownerData = users[bot.owner];
                
                if (ownerData && ownerData.pushSubscription) {
                    let clientName = data.jid.split('@')[0];
                    let msgText = data.message.text || 'Nova mensagem';

                    // O sistema interno envia o texto no formato "Nome: Mensagem" ou "Nome enviou: 📷 Imagem". 
                    // Vamos separar para ficar com o visual idêntico ao WhatsApp nativo.
                    if (msgText.includes(': ')) {
                        const parts = msgText.split(': ');
                        clientName = parts[0]; // Pega apenas o nome
                        msgText = parts.slice(1).join(': '); // Pega apenas a mensagem
                        
                        // Limpa o sufixo caso seja uma imagem, vídeo ou áudio
                        if (clientName.endsWith(' enviou')) {
                            clientName = clientName.replace(' enviou', '');
                        }
                    }

                    const payload = JSON.stringify({
                        title: clientName, // Título igual ao WhatsApp (Só o nome do cliente)
                        body: msgText,     // Corpo igual ao WhatsApp (Só o texto da mensagem)
                        icon: data.profilePicUrl || '/api/logo/192',
                        tag: `chat-${data.jid}` // Agrupa mensagens da mesma pessoa
                    });

                    webpush.sendNotification(ownerData.pushSubscription, payload).catch(err => {
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            // Inscrição expirou ou usuário bloqueou as notificações no celular
                            ownerData.pushSubscription = null;
                            db.saveUser(ownerData);
                        }
                    });
                }
            }
        } else {
            console.log(`[DEBUG SERVER] Falha: Dono do bot não encontrado.`);
        }
    });
    
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

        for (let attempt = 0; attempt < API_KEYS_GEMINI.length; attempt++) {
            try {
                const chat = supportModel.startChat({ history: supportChatHistory[userId] });
                const result = await chat.sendMessage(msg);
                const responseText = result.response.text();

                supportChatHistory[userId].push({ role: "user", parts: [{ text: msg }] });
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
                
                // Força a troca de API Key e continua tentando para qualquer tipo de erro
                switchToNextApiKey();
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

    socket.on('get-public-prices', async (data) => {
        const s = await db.getSettings();
        // Agora incluímos o appUpdateMessage na resposta para quando o usuário carregar a página
        let prices = { appName: s.appName || 'zappbot', appVersion: s.appVersion, appUpdateMessage: s.appUpdateMessage, supportNumber: s.supportNumber, priceMonthly: s.priceMonthly, priceQuarterly: s.priceQuarterly, priceSemiannual: s.priceSemiannual, priceYearly: s.priceYearly, priceResell5: s.priceResell5, priceResell10: s.priceResell10, priceResell20: s.priceResell20, priceResell30: s.priceResell30 };
        
        const users = await db.getAllUsers();
        
        // Se não estiver logado mas tiver um ref (link de indicação)
        if (!user && data && data.ref) {
            const parent = Object.values(users).find(u => u.refCode && u.refCode.toLowerCase() === data.ref.toLowerCase());
            if (parent) {
                if (parent.prices && Object.keys(parent.prices).length > 0) {
                    prices = { ...prices, ...parent.prices };
                }
                if (parent.appName) prices.appName = parent.appName;
                if (parent.supportNumber) prices.supportNumber = parent.supportNumber;
            }
        }
        
        if (user) {
            const u = users[user.username];
            
            // Se o usuário for um revendedor, ele vê a PRÓPRIA marca no painel dele
            if (u && u.botLimit > 1 && !u.isAdmin) {
                if (u.appName) prices.appName = u.appName;
                if (u.supportNumber) prices.supportNumber = u.supportNumber;
            }

            // Se o usuário tiver um pai (revendedor acima dele)
            if (u && u.parentId && users[u.parentId]) {
                const parent = users[u.parentId];
                // Ele paga os preços do pai
                if (parent.prices && Object.keys(parent.prices).length > 0) {
                    prices = { ...prices, ...parent.prices };
                }
                // Se for cliente final (botLimit <= 1), vê a marca do pai
                if (u.botLimit <= 1) {
                    if (parent.appName) prices.appName = parent.appName;
                    if (parent.supportNumber) prices.supportNumber = parent.supportNumber;
                }
            }
        }
        socket.emit('public-prices', prices);
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
            // Garante que o autoResponder seja mesclado e salvo corretamente
            groups[data.groupId] = { 
                ...groups[data.groupId], 
                ...data.settings,
                autoResponder: data.settings.autoResponder || groups[data.groupId].autoResponder || [] 
            };
            
            await db.saveGroup(groups[data.groupId]);
            const updatedGroups = await db.getAllGroups();
            
            // Atualiza a lista para o usuário (Frontend)
            io.to(groups[data.groupId].owner.toLowerCase()).emit('group-list-updated', Object.values(updatedGroups).filter(g => g.owner === groups[data.groupId].owner));
            
            // Envia atualização em tempo real para o Bot (Backend -> Bot Process)
            io.emit('group-settings-changed', { 
                botSessionName: groups[data.groupId].managedByBot, 
                groupId: data.groupId, 
                settings: groups[data.groupId] 
            });
            
            // NÃO REINICIA O BOT AQUI. 
            // O index.js agora é capaz de atualizar as regras em tempo real sem reiniciar.
            // Reiniciar causava delay e desconexão desnecessária.
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
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1, refCode: uData?.refCode });

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

        if (user.isAdmin || (uData && uData.botLimit > 1)) {
            socket.on('admin-settings', async () => {
                const s = await db.getSettings();
                if (user.isAdmin) {
                    socket.emit('admin-settings', s);
                } else {
                    const users = await db.getAllUsers();
                    const u = users[user.username];
                    const customSettings = { 
                        ...s, 
                        ...(u.prices || {}), 
                        mpAccessToken: u.mpAccessToken || '',
                        appName: u.appName || s.appName,
                        supportNumber: u.supportNumber || s.supportNumber
                    };
                    socket.emit('admin-settings', customSettings);
                }
            });
            
            socket.on('save-settings', async (ns) => { 
                if (user.isAdmin) {
                    await db.saveSettings(ns); 
                    io.emit('public-prices', { appName: ns.appName, supportNumber: ns.supportNumber, priceMonthly: ns.priceMonthly, priceQuarterly: ns.priceQuarterly, priceSemiannual: ns.priceSemiannual, priceYearly: ns.priceYearly, priceResell5: ns.priceResell5, priceResell10: ns.priceResell10, priceResell20: ns.priceResell20, priceResell30: ns.priceResell30 }); 
                } else {
                    const users = await db.getAllUsers();
                    const u = users[user.username];
                    u.prices = {
                        priceMonthly: ns.priceMonthly, priceQuarterly: ns.priceQuarterly, priceSemiannual: ns.priceSemiannual, priceYearly: ns.priceYearly,
                        priceResell5: ns.priceResell5, priceResell10: ns.priceResell10, priceResell20: ns.priceResell20, priceResell30: ns.priceResell30
                    };
                    u.mpAccessToken = ns.mpAccessToken;
                    u.appName = ns.appName;
                    u.supportNumber = ns.supportNumber;
                    await db.saveUser(u);
                    
                    // Atualiza a interface do próprio revendedor na hora
                    socket.emit('public-prices', { 
                        appName: ns.appName, supportNumber: ns.supportNumber, 
                        ...u.prices 
                    });
                }
                socket.emit('feedback', { success: true, message: 'Salvo' }); 
            });
            
            // Rota para forçar atualização global com Mensagem Customizada
            socket.on('admin-force-update', async (data) => {
                if (!user.isAdmin) return; 
                const settings = await db.getSettings();
                
                const customMessage = (data && data.message) ? data.message : 'Nova versão disponível! Atualize o painel.';
                
                settings.appVersion = Date.now().toString(); // Cria uma nova versão baseada na hora
                settings.appUpdateMessage = customMessage; // SALVA A MENSAGEM NO BANCO DE DADOS
                await db.saveSettings(settings);

                // Dispara evento via Socket com a Versão + Mensagem customizada
                io.emit('app-update-available', { 
                    version: settings.appVersion, 
                    message: customMessage 
                }); 

                socket.emit('feedback', { success: true, message: 'Aviso customizado de atualização enviado!' });
            });

            socket.on('admin-set-days', async ({ sessionName, days }) => {
                if (!user.isAdmin) return; // TRAVA DE SEGURANÇA MÁXIMA: Só o dono do painel passa daqui
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
                if (!user.isAdmin) return; // TRAVA DE SEGURANÇA MÁXIMA: Só o dono do painel passa daqui
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
                        try { activeBots[botSessionName].process.kill('SIGINT'); } catch(e){}
                        delete activeBots[botSessionName];
                        setTimeout(async () => { const currentBots = await db.getAllBots(); if (currentBots[botSessionName]) startBotProcess(currentBots[botSessionName]); }, 1000);
                    }
                }
            });
            
            const sendAdminUsersList = async () => {
                const users = await db.getAllUsers();
                const bots = await db.getAllBots();
                const now = new Date();

                let visibleUsers = Object.values(users);
                if (!user.isAdmin) {
                    visibleUsers = visibleUsers.filter(u => u.parentId === user.username);
                }

                const usersList = visibleUsers.map(({ password, ...r }) => {
                    const userBots = Object.values(bots).filter(b => b.owner === r.username);
                    r.totalBots = userBots.length;
                    
                    let hasActive = false;
                    let hasPending = false;
                    let activeCount = 0;
                    let pendingCount = 0;

                    userBots.forEach(b => {
                        const isExpired = new Date(b.trialExpiresAt) < now;
                        const status = b.status || '';

                        if (status === 'Online' || (!isExpired && status === 'Offline')) {
                            hasActive = true;
                            activeCount++;
                        } else if (status.includes('Aguardando') || status.includes('Iniciando')) {
                            hasPending = true;
                            pendingCount++;
                        }
                    });
                    
                    if (r.totalBots === 0) {
                        r.userStatus = 'empty';
                    } else if (hasActive) {
                        r.userStatus = 'active';
                        r.badgeText = `${activeCount} Ativo(s)`;
                    } else if (hasPending) {
                        r.userStatus = 'pending';
                        r.badgeText = `${pendingCount} Pendente(s)`;
                    } else {
                        r.userStatus = 'inactive';
                        r.badgeText = `Inativo`;
                    }
                    
                    return r;
                });
                socket.emit('admin-users-list', usersList);
            };

            socket.on('admin-get-users', async () => {
                await sendAdminUsersList();
            });
            
            socket.on('admin-delete-user', async ({ username }) => { 
                const users = await db.getAllUsers();
                if (!user.isAdmin && users[username]?.parentId !== user.username) return;
                await db.deleteUser(username);
                await sendAdminUsersList();
            });
            
            socket.on('admin-get-bots-for-user', async ({ username }) => {
                const users = await db.getAllUsers();
                if (!user.isAdmin && users[username]?.parentId !== user.username) return;
                const bots = await db.getAllBots();
                const groups = await db.getAllGroups();
                
                socket.emit('initial-bots-list', Object.values(bots).filter(b => b.owner === username));
                socket.emit('initial-groups-list', Object.values(groups).filter(g => g.owner === username));
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
                try { activeBots[botSessionName].process.kill('SIGINT'); } catch(e){}
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
                
                const userBots = Object.values(bots).filter(b => b.owner === owner && b.botType !== 'group');

                let isConsumingCredit = false;
                let hasSalvagedTime = ownerData.salvagedTime && new Date(ownerData.salvagedTime.expiresAt) > new Date();

                if (d.botType !== 'group' && !ownerData.isAdmin) {
                    // Se NÃO tiver tempo salvo para resgatar, verificamos os limites/créditos
                    if (!hasSalvagedTime) {
                        if (ownerData.botLimit > 1) {
                            // O usuário tem créditos comprados no saldo. Consome 1 crédito.
                            isConsumingCredit = true;
                        } else if (userBots.length >= 1) {
                            // Usuário grátis (saldo base) que já usou sua vaga. Limite alcançado.
                            return socket.emit('feedback', { success: false, error: 'limit_reached' });
                        }
                    }
                }

                const now = new Date();
                let trialEndDate = new Date(0);
                let isTrial = false;
                let isActivated = false;
                let feedbackMessage = 'Criado. Pague para ativar.';
                
                if (d.botType !== 'group') {
                    if (ownerData.isAdmin) {
                        trialEndDate = new Date(now);
                        trialEndDate.setFullYear(trialEndDate.getFullYear() + 10);
                        isTrial = false;
                        isActivated = true;
                        feedbackMessage = 'Criado (Admin).';
                    } else if (hasSalvagedTime) {
                        trialEndDate = new Date(ownerData.salvagedTime.expiresAt);
                        isTrial = ownerData.salvagedTime.isTrial;
                        ownerData.salvagedTime = null;
                        await db.saveUser(ownerData);
                        isActivated = true;
                        feedbackMessage = 'Restaurado tempo anterior.';
                    } else if (isConsumingCredit) {
                        // Consome 1 crédito do saldo e dá 30 dias de acesso
                        ownerData.botLimit -= 1;
                        await db.saveUser(ownerData);
                        // Atualiza o limite na tela do usuário em tempo real
                        io.to(owner.toLowerCase()).emit('update-limit', ownerData.botLimit);

                        trialEndDate = new Date(now);
                        trialEndDate.setDate(trialEndDate.getDate() + 30);
                        isTrial = false;
                        isActivated = true;
                        feedbackMessage = 'Criado com sucesso (30 dias ativados)!';
                    } else {
                        // Usuário grátis criando seu primeiro e único bot (Teste de 24h)
                        if (!ownerData.trialUsed) {
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
                    isActivated = true;
                    feedbackMessage = 'Agregador criado!';
                }
                
                const newBot = { 
                    sessionName: d.sessionName, 
                    prompt: d.prompt, 
                    knowledgeBaseFiles: d.knowledgeBaseFiles || [],
                    knowledgeBaseText: (d.knowledgeBaseFiles ||[]).map(f => f.text).join('\n\n'),
                    autoResponder: d.autoResponder ||[],
                    owner: owner, 
                    status: 'Offline',
                    activated: isActivated, 
                    isTrial: isTrial, 
                    createdAt: now.toISOString(), 
                    trialExpiresAt: trialEndDate.toISOString(), 
                    ignoredIdentifiers: [] };
                await db.saveBot(newBot);
                io.emit('bot-updated', newBot);
                
                if (new Date(newBot.trialExpiresAt) > new Date()) startBotProcess(newBot);
                
                socket.emit('feedback', { success: true, message: feedbackMessage });
            } catch (err) { 
                console.error("Erro criar bot:", err); 
                socket.emit('feedback', { success: false, message: 'Erro interno.' }); 
            }
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
            if (activeBots[sessionName]) { try { activeBots[sessionName].intentionalStop = true; try { activeBots[sessionName].process.kill('SIGINT'); } catch(e){} } catch(e){} delete activeBots[sessionName]; }
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
            if (activeBots[sessionName]) { activeBots[sessionName].intentionalStop = true; try { activeBots[sessionName].process.kill('SIGINT'); } catch(e){} delete activeBots[sessionName]; }
            await db.deleteBot(sessionName);
            
            const authPath = path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`);
            if (fs.existsSync(authPath)) fs.rmSync(authPath, { recursive: true, force: true });
            
            // Otimização de Armazenamento: Limpa os caches órfãos do bot excluído para não lotar o HD
            const livechatPath = path.join(AUTH_SESSIONS_DIR, `livechat_cache_${sessionName}.json`);
            if (fs.existsSync(livechatPath)) fs.unlinkSync(livechatPath);
            const kbPath = path.join(AUTH_SESSIONS_DIR, `kb_cache_${sessionName}.json`);
            if (fs.existsSync(kbPath)) fs.unlinkSync(kbPath);

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
                bot.autoResponder = d.autoResponder ||[];
                bot.aiFallbackEnabled = d.aiFallbackEnabled;
                if (d.knowledgeBaseFiles !== undefined) {
                    bot.knowledgeBaseFiles = d.knowledgeBaseFiles;
                    bot.knowledgeBaseText = d.knowledgeBaseFiles.map(f => f.text).join('\n\n');
                } else {
                    if (d.knowledgeBaseText !== undefined) bot.knowledgeBaseText = d.knowledgeBaseText;
                    if (d.knowledgeBaseName !== undefined) bot.knowledgeBaseName = d.knowledgeBaseName;
                }
                
                await db.saveBot(bot);
                io.emit('bot-updated', bot);
                
                if (activeBots[d.sessionName]) {
                    try { activeBots[d.sessionName].intentionalStop = true; activeBots[d.sessionName].process.kill('SIGINT'); } catch (e) {}
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Salvo. Reiniciando...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else { 
                    socket.emit('feedback', { success: true, message: 'Salvo.' }); 
                }
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
                try { activeBots[sessionName].process.kill('SIGINT'); } catch(e){}
                setTimeout(() => startBotProcess(bot), 1000);
            }
        });
    }
});

const botRestartAttempts = {}; // Controle para evitar loop infinito de reinicialização

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
                    welcomeMessage: g.welcomeMessage,
                    autoResponder: g.autoResponder || [],
                    aiFallbackEnabled: g.aiFallbackEnabled // <--- Passa config do grupo
                };
            });
        authorizedGroupsArg = JSON.stringify(authorizedGroups);
    }
    const groupsBase64 = Buffer.from(authorizedGroupsArg).toString('base64');
    const autoResponderBase64 = Buffer.from(JSON.stringify(bot.autoResponder ||[])).toString('base64');
    
    // Converte o booleano para string 'true'/'false'
    const aiFallbackArg = bot.aiFallbackEnabled !== false ? 'true' : 'false'; 

    const knowledgeBaseBase64 = Buffer.from(bot.knowledgeBaseText || '').toString('base64');

    // Adiciona aiFallbackArg no final do array (índice 14) e knowledgeBaseBase64 (índice 15)
    const args =[BOT_SCRIPT_PATH, bot.sessionName, promptBase64, ignoredBase64, phoneArg, groupsBase64, bot.botType || 'individual', bot.botName || '', (bot.silenceTime || '0').toString(), bot.platform || 'whatsapp', bot.token || '', bot.notificationNumber || '', autoResponderBase64, aiFallbackArg, knowledgeBaseBase64];
    
    const p = spawn('node', args, { env, stdio:['pipe', 'pipe', 'pipe'] });
    
    p.on('error', (err) => {
        console.error(`[ERRO CRÍTICO] Falha ao iniciar processo do bot ${bot.sessionName}:`, err.message);
        if (activeBots[bot.sessionName]) delete activeBots[bot.sessionName];
        updateBotStatus(bot.sessionName, 'Offline');
    });

    activeBots[bot.sessionName] = { process: p, intentionalStop: false };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();
        
        // Filtro para ignorar logs inúteis e erros de criptografia do WhatsApp (libsignal)
        if (
            msg.includes('Session error:') || 
            msg.includes('Bad MAC') || 
            msg.includes('MessageCounterError') || 
            msg.includes('Failed to decrypt message') || 
            msg.includes('libsignal') ||
            msg.includes('Closing open session') ||
            msg.includes('SessionEntry') ||
            msg.includes('currentRatchet') ||
            msg.includes('ephemeralKeyPair')
        ) {
            return;
        }

        if (msg.startsWith('QR_CODE:') || msg.startsWith('PAIRING_CODE:')) {
             const code = msg.replace('QR_CODE:', '');
             updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: code });
        }
        else if (msg.includes('ONLINE!') || msg.includes('Conectado ao servidor via Socket.IO')) {
             updateBotStatus(bot.sessionName, 'Online', { setActivated: true });
             // Bot conectou com sucesso, zera o contador de falhas!
             if (botRestartAttempts[bot.sessionName]) {
                 botRestartAttempts[bot.sessionName].count = 0; 
             }
        }
        
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });

    p.stderr.on('data', (d) => {
        const msg = d.toString().trim();
        
        // Filtro para ignorar logs inúteis e erros de criptografia no STDERR
        if (
            msg.includes('Session error:') || 
            msg.includes('Bad MAC') || 
            msg.includes('MessageCounterError') || 
            msg.includes('Failed to decrypt message') || 
            msg.includes('libsignal') ||
            msg.includes('Closing open session') ||
            msg.includes('SessionEntry') ||
            msg.includes('currentRatchet') ||
            msg.includes('ephemeralKeyPair')
        ) {
            return;
        }
        
        io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${msg}` });
    });

    p.on('close', async (code) => { 
        let isIntentional = false;
        
        // Verifica se o processo que está fechando é o mesmo que está registrado como ativo
        if (activeBots[bot.sessionName] && activeBots[bot.sessionName].process === p) {
            isIntentional = activeBots[bot.sessionName].intentionalStop;
            delete activeBots[bot.sessionName]; 
        } else {
            // Se já foi deletado na mão (ex: botão desligar/salvar) ou é um processo fantasma
            isIntentional = true; 
        }

        if (isIntentional) {
            // Se o usuário clicou para parar, apenas fica Offline
            // Só muda para offline se não tiver um novo bot reiniciando na mesma hora
            if (!activeBots[bot.sessionName]) {
                updateBotStatus(bot.sessionName, 'Offline');
            }
        } else {
            // Parada inesperada (Crash)
            if (!botRestartAttempts[bot.sessionName]) {
                botRestartAttempts[bot.sessionName] = { count: 0, lastCrash: 0 };
            }

            const attempts = botRestartAttempts[bot.sessionName];
            const now = Date.now();

            // Se a última falha foi há mais de 5 minutos, o bot estava rodando bem. Zeramos o contador.
            if (now - attempts.lastCrash > 5 * 60 * 1000) {
                attempts.count = 0;
            }

            attempts.count++;
            attempts.lastCrash = now;

            if (attempts.count <= 5) {
                console.log(`[SERVER] Bot ${bot.sessionName} parou inesperadamente. Reiniciando (Tentativa ${attempts.count}/5)...`);
                updateBotStatus(bot.sessionName, 'Reiniciando...');
                
                // Aguarda 5 segundos antes de reabrir o processo do bot
                setTimeout(async () => {
                    const currentBots = await db.getAllBots();
                    if (currentBots[bot.sessionName]) {
                        startBotProcess(currentBots[bot.sessionName], phoneNumber);
                    }
                }, 5000);
            } else {
                console.error(`[SERVER] Bot ${bot.sessionName} falhou 5 vezes seguidas. Auto-restart abortado.`);
                updateBotStatus(bot.sessionName, 'Offline (Erro Crítico)');
            }
        }
    });
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
        if (!bot) return; // Proteção extra
        const status = String(bot.status || ''); // Força a ser uma string sempre
        if (status === 'Online' || status.includes('Iniciando') || status.includes('Aguardando')) {
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
    Object.keys(activeBots).forEach(sessionName => { if (activeBots[sessionName]) { try { try { activeBots[sessionName].process.kill('SIGINT'); } catch(e){} } catch (e) { } } });
    process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

server.listen(3000, () => {
    console.log('Painel ON: http://localhost:3000');
    restartActiveBots();
});
