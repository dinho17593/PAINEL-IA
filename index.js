//index.js

const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    delay,
    downloadMediaMessage,
    makeCacheableSignalKeyStore,
    jidNormalizedUser
} = require('@whiskeysockets/baileys');
const { Telegraf } = require('telegraf');
const pino = require('pino');
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');
const fs = require('fs');
const io = require('socket.io-client');
const axios = require('axios');

// =================================================================================
// CLASSE AUXILIAR DE CACHE
// =================================================================================
class SimpleCache {
    constructor(maxSize = 5000) {
        this.cache = new Map();
        this.maxSize = maxSize;
    }
    get(key) {
        return this.cache.get(key);
    }
    set(key, value) {
        this.cache.set(key, value);
        // Proteção contra vazamento de RAM: limpa os mais antigos se passar do limite
        if (this.cache.size > this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
    }
    del(key) {
        this.cache.delete(key);
    }
    flushAll() {
        this.cache.clear();
    }
}
const msgRetryCounterCache = new SimpleCache();

// =================================================================================
// MEMÓRIA PARA O LIVE CHAT (WHATSAPP WEB CLONE)
// =================================================================================
const MAX_CHATS = 20; // Reduzido para economizar RAM
const MAX_MSGS_PER_CHAT = 30; // Reduzido para economizar RAM
let recentChats = new Map();
let recentMessages = new Map();

// Controle para evitar gravação excessiva no disco (Debounce)
let saveCacheTimeout = null;

// Função para pegar o caminho dinamicamente sem depender da variável nomeSessao
function getLiveChatPath() {
    return `./auth_sessions/livechat_cache_${process.argv[2]}.json`;
}

// Carrega as mensagens do disco quando o robô liga
function loadLiveChatCache() {
    try {
        const pathCache = getLiveChatPath();
        if (fs.existsSync(pathCache)) {
            const data = JSON.parse(fs.readFileSync(pathCache, 'utf8'));
            if (data.chats) recentChats = new Map(data.chats);
            if (data.messages) recentMessages = new Map(data.messages);
        }
    } catch(e) {
        console.log(`[${process.argv[2]}] Iniciando memória do Live Chat limpa.`);
    }
}
loadLiveChatCache();

// Salva as mensagens no disco com Debounce (Evita fritar o SSD e travar a RAM)
function saveLiveChatCache() {
    if (saveCacheTimeout) clearTimeout(saveCacheTimeout);
    saveCacheTimeout = setTimeout(() => {
        try {
            fs.writeFileSync(getLiveChatPath(), JSON.stringify({
                chats: Array.from(recentChats.entries()),
                messages: Array.from(recentMessages.entries())
            }));
        } catch(e) { }
    }, 5000); // Salva no máximo a cada 5 segundos, em vez de a cada mensagem
}

async function saveLiveMessage(sock, jid, name, msgObj) {
    if (!recentChats.has(jid)) {
        if (recentChats.size >= MAX_CHATS) {
            const oldestJid = recentChats.keys().next().value;
            recentChats.delete(oldestJid);
            recentMessages.delete(oldestJid);
        }
        let initialName = name;
        if (msgObj.fromMe && (name.includes('Bot') || name === 'Você')) {
            initialName = jid.split('@')[0];
        }
        recentChats.set(jid, { jid, name: initialName || jid.split('@')[0], unreadCount: 0 });
    }
    const chat = recentChats.get(jid);
    chat.lastMessage = msgObj.text;
    chat.timestamp = msgObj.timestamp;
    
    if (!msgObj.fromMe) {
        chat.name = name || chat.name;
        chat.unreadCount += 1;
    }

    if (chat.profilePicUrl === undefined && sock) {
        try {
            chat.profilePicUrl = await sock.profilePictureUrl(jid, 'image');
        } catch (e) {
            chat.profilePicUrl = null;
        }
    }

   if (!recentMessages.has(jid)) {
        recentMessages.set(jid, new Array());
    }
    
    const msgs = recentMessages.get(jid);
    msgs.push(msgObj);
    
    if (msgs.length > MAX_MSGS_PER_CHAT) {
        msgs.shift();
    }

    // Chama a função para salvar no arquivo do disco
    saveLiveChatCache();

    socket.emit('bot:new-message', { sessionName: nomeSessao, jid, message: msgObj, profilePicUrl: chat.profilePicUrl });
}

// --- NOVO: MINI-STORE OTIMIZADO (Substitui a função removida do Baileys) ---
class MessageStore {
    constructor(maxSize = 500) { // Reduzido de 2000 para 500 para poupar muita RAM por bot
        this.messages = new Map();
        this.maxSize = maxSize;
    }
    add(key, message) {
        if (!key || !key.id || !message) return;
        this.messages.set(key.id, message);
        if (this.messages.size > this.maxSize) {
            const firstKey = this.messages.keys().next().value;
            this.messages.delete(firstKey);
        }
    }
    get(key) {
        return this.messages.get(key.id);
    }
}
const messageStore = new MessageStore();

// =================================================================================
// CONFIGURAÇÃO E ARGUMENTOS
// =================================================================================

const nomeSessao = process.argv[2];
const promptSistemaGlobal = Buffer.from(process.argv[3] || '', 'base64').toString('utf-8');
const ignoredIdentifiersArg = Buffer.from(process.argv[4] || 'W10=', 'base64').toString('utf-8'); 
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = Buffer.from(process.argv[6] || 'W10=', 'base64').toString('utf-8'); 

const botType = process.argv[7] || 'individual'; 
const botNameGlobal = process.argv[8] || ''; 
const silenceTimeMinutesGlobal = parseInt(process.argv[9] || '0'); 
const platform = process.argv[10] || 'whatsapp';
const telegramToken = process.argv[11] || '';
const notificationNumber = process.argv[12] || '';

// --- NOVO: RECEBENDO O AUTO RESPONDER ---
// ... (argumentos anteriores) ...
const autoResponderArg = Buffer.from(process.argv[13] || 'W10=', 'base64').toString('utf-8');
let autoResponder = [];
try { 
    autoResponder = JSON.parse(autoResponderArg); 
} catch (e) { 
    console.error("Erro parse autoResponder:", e); 
}

// Lê o novo argumento (índice 14). Se não vier, assume true (ligado).
const aiFallbackEnabledGlobal = process.argv[14] !== 'false';

const knowledgeBaseTextGlobal = Buffer.from(process.argv[15] || '', 'base64').toString('utf-8');

if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const modeloGemini = 'gemini-3-flash-preview'; 

// =================================================================================
// CONEXÃO SOCKET.IO
// =================================================================================

const socket = io('http://localhost:3000');

socket.on('connect', () => {
    console.log(`[${nomeSessao}] Conectado ao servidor via Socket.IO.`);
    socket.emit('bot-register', { sessionName: nomeSessao });
});
socket.on('disconnect', () => {
    console.log(`[${nomeSessao}] Desconectado do servidor.`);
});

socket.on('group-settings-changed', (data) => {
    if (data.botSessionName === nomeSessao && data.groupId) {
        console.log(`[${nomeSessao}] Atualizando configurações locais (incluindo regras) para o grupo ${data.groupId}`);
        
        // Atualiza a memória local do bot com as novas regras imediatamente
        authorizedGroups[data.groupId] = {
            ...authorizedGroups[data.groupId],
            ...data.settings,
            expiresAt: data.settings.expiresAt ? new Date(data.settings.expiresAt) : null,
            autoResponder: data.settings.autoResponder || [] // Garante que as novas regras entrem
        };
    }
});

// ESCUTA PARA REMOÇÃO IMEDIATA DO GRUPO DA MEMÓRIA
socket.on('group-removed', (data) => {
    if (data.botSessionName === nomeSessao && data.groupId) {
        console.log(`[${nomeSessao}] ⚠️ ALERTA: Grupo ${data.groupId} removido do painel. Parando respostas imediatamente.`);
        delete authorizedGroups[data.groupId];
    }
});

socket.on('ignored-list-updated', (data) => {
    if (data.sessionName === nomeSessao) {
        ignoredIdentifiers = data.ignoredIdentifiers;
        console.log(`[${nomeSessao}] Lista de ignorados atualizada via servidor.`);
    }
});

// =================================================================================
// VARIÁVEIS DE ESTADO E AUXILIARES
// =================================================================================

const pausados = {};
const lastResponseTimes = {};

let ignoredIdentifiers = [];
try { ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg); } catch (e) { console.error("Erro parse ignored:", e); }

let authorizedGroups = {};
try {
    const groupsArray = JSON.parse(authorizedGroupsArg);
    groupsArray.forEach(group => {
        authorizedGroups[group.groupId] = {
            expiresAt: group.expiresAt ? new Date(group.expiresAt) : null,
            antiLink: group.antiLink === true,
            prompt: group.prompt || '',
            silenceTime: group.silenceTime !== undefined ? parseInt(group.silenceTime) : 0,
            botName: group.botName || '',
            isPaused: group.isPaused === true,
            welcomeMessage: group.welcomeMessage || null,
            autoResponder: group.autoResponder || [] // <--- LÊ AS REGRAS DO GRUPO
        };
    });
} catch (e) {
    console.error('❌ Erro ao ler grupos:', e);
}

// Helper para formatar mensagem de boas-vindas
function formatWelcomeMessage(template, userName, groupName) {
    if (!template) return '';
    return template
        .replace(/#nome/gi, userName)
        .replace(/\{nome\}/gi, userName)
        .replace(/#user/gi, userName)
        .replace(/\{user\}/gi, userName)
        .replace(/#grupo/gi, groupName)
        .replace(/\{grupo\}/gi, groupName);
}

// =================================================================================
// CONFIGURAÇÃO GEMINI (IA)
// =================================================================================

const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING) {
    console.error("❌ ERRO FATAL: Nenhuma API KEY do Gemini encontrada nas variáveis de ambiente.");
    process.exit(1);
}

const API_KEYS = API_KEYS_STRING.split('\n').map(k => k.trim()).filter(Boolean);
console.log(`[DEBUG] Total de API Keys carregadas: ${API_KEYS.length}`);

let currentApiKeyIndex = 0;

const safetySettings = [
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
];

let genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
let model = genAI.getGenerativeModel({ model: modeloGemini, safetySettings });

const logger = pino({ level: 'silent' }); // Mantido silent para privacidade no debug

const historicoConversa = {};
const MAX_HISTORICO_POR_USUARIO = 10; // Reduzido para economizar RAM (mantém contexto suficiente para a IA)

// --- NOVO: VARIÁVEL E FUNÇÃO PARA RESUMIR A BASE DE CONHECIMENTO COM CACHE ---
const crypto = require('crypto');
let processedKnowledgeBase = "";

async function prepareKnowledgeBase() {
    if (!knowledgeBaseTextGlobal || knowledgeBaseTextGlobal.trim() === '') {
        processedKnowledgeBase = "";
        return;
    }
    
    // Cria uma assinatura única (Hash) do texto atual do PDF
    const currentHash = crypto.createHash('md5').update(knowledgeBaseTextGlobal).digest('hex');
    const cachePath = `./auth_sessions/kb_cache_${nomeSessao}.json`;

    // 1. Tenta carregar do cache se o arquivo não mudou
    if (fs.existsSync(cachePath)) {
        try {
            const cacheData = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            if (cacheData.hash === currentHash) {
                console.log(`[${nomeSessao}] 📚 Resumo da Base de Conhecimento carregado do cache (Gasto ZERO de tokens).`);
                processedKnowledgeBase = cacheData.summary;
                return;
            }
        } catch (e) {
            console.log(`[${nomeSessao}] ⚠️ Erro ao ler cache, gerando novo resumo...`);
        }
    }
    
    // 2. Se não tem cache ou o PDF mudou, processa com a IA
    console.log(`[${nomeSessao}] 📚 Arquivo novo/alterado detectado. Resumindo a Base de Conhecimento...`);
    
    const promptResumo = `
    Abaixo está o conteúdo bruto de um documento da empresa (PDF/TXT). 
    Sua tarefa é ler tudo e criar um resumo otimizado e estruturado contendo APENAS as informações úteis para um assistente virtual de atendimento.
    Mantenha:
    - Nomes de produtos/serviços e seus preços.
    - Regras, horários de funcionamento e contatos.
    - Políticas da empresa e links importantes.
    Remova:
    - Textos longos desnecessários, introduções e formatações inúteis.
    
    DOCUMENTO BRUTO:
    ${knowledgeBaseTextGlobal}
    `;

    let sucesso = false;

    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            const result = await model.generateContent(promptResumo);
            processedKnowledgeBase = result.response.text().trim();
            
            // 3. Salva o novo resumo e a assinatura no disco para as próximas vezes
            fs.writeFileSync(cachePath, JSON.stringify({
                hash: currentHash,
                summary: processedKnowledgeBase
            }));
            
            console.log(`[${nomeSessao}] ✅ Base de Conhecimento resumida e salva no cache com sucesso!`);
            sucesso = true;
            break; // Sai do loop se deu certo
        } catch (e) {
            console.error(`[${nomeSessao}] ⚠️ Erro ao resumir (Tentativa ${attempt + 1}/${API_KEYS.length}):`, e.message);
            switchToNextApiKey(); // Rotaciona para a próxima API KEY e tenta de novo
        }
    }

    // Se passou pelo loop inteiro (todas as chaves) e ainda assim falhou:
    if (!sucesso) {
        console.error(`[${nomeSessao}] ❌ Todas as chaves falharam ao resumir a base. Usando o texto original como fallback.`);
        processedKnowledgeBase = knowledgeBaseTextGlobal; 
    }
}

function switchToNextApiKey() {
    currentApiKeyIndex = (currentApiKeyIndex + 1) % API_KEYS.length;
    console.log(`[${nomeSessao}] 🔄 Trocando API Key para index: ${currentApiKeyIndex}`);
    genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
    model = genAI.getGenerativeModel({ model: modeloGemini, safetySettings });
}

async function processarComGemini(jid, input, isAudio = false, promptEspecifico = null) {
    // PRIVACIDADE: Não logar o conteúdo da mensagem
    console.log(`[DEBUG IA] Iniciando processamento para ${jid}.`);
    
    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            if (!historicoConversa[jid]) historicoConversa[jid] =[];
            
            let promptFinal = promptEspecifico || promptSistemaGlobal;
            
            // Usa o resumo processado na inicialização em vez do PDF gigante
            if (processedKnowledgeBase && processedKnowledgeBase.trim() !== '') {
                promptFinal += "\n\n[MEMÓRIA DA EMPRESA (RESUMO)]\n" + processedKnowledgeBase + "\n[FIM DA MEMÓRIA]\nUse as informações acima para responder o cliente, se necessário.";
            }

            const chatHistory =[
                { role: "user", parts:[{ text: `System Instruction:\n${promptFinal}` }] },
                { role: "model", parts:[{ text: "Entendido." }] },
                ...historicoConversa[jid]
            ];

            let resposta = "";
            
            if (isAudio) {
                const parts =[{ inlineData: { mimeType: "audio/ogg", data: input } }, { text: "Responda a este áudio." }];
                const result = await model.generateContent({
                    contents: [{ role: "user", parts:[{ text: `System: ${promptFinal}` }, ...parts] }]
                });
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts:[{ text: "[Áudio]" }] });
            } else {
                const chat = model.startChat({ history: chatHistory });
                
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout Gemini")), 90000));
                const apiPromise = chat.sendMessage(input);
                
                const result = await Promise.race([apiPromise, timeoutPromise]);
                
                if (!result || !result.response) {
                    throw new Error("Resposta da API veio vazia ou nula.");
                }
                
                try {
                    resposta = result.response.text();
                } catch (textErr) {
                    console.log(`[DEBUG IA] Resposta bloqueada pelos filtros do Google (Safety) ou formato inválido.`);
                    resposta = "Desculpe, não posso gerar uma resposta para isso devido às políticas de segurança.";
                }
                
                if (!resposta) resposta = ""; 
                resposta = resposta.trim();
                
                historicoConversa[jid].push({ role: "user", parts: [{ text: input }] });
            }

            console.log(`[DEBUG IA] Resposta gerada com sucesso para ${jid}.`);

            historicoConversa[jid].push({ role: "model", parts: [{ text: resposta }] });
            if (historicoConversa[jid].length > MAX_HISTORICO_POR_USUARIO) historicoConversa[jid] = historicoConversa[jid].slice(-MAX_HISTORICO_POR_USUARIO);
            
            return resposta;

        } catch (err) {
            const errorMsg = err.toString();
            console.error(`[DEBUG IA] Erro na tentativa ${attempt}:`, errorMsg);
            
            // Força a troca de API Key e continua tentando para qualquer tipo de erro
            // (ex: se a chave 12 estiver inválida/revogada, ele pula para a 13)
            switchToNextApiKey();
        }
    }
    return "";
}

// --- NOVA FUNÇÃO: INJETAR REGRAS NA IA ---
function buildEnhancedPrompt(basePrompt, groupConfig) {
    let enhancedPrompt = basePrompt || '';
    let rulesToInject =[];

    // Adiciona regras do grupo (se houver)
    if (groupConfig && groupConfig.autoResponder && groupConfig.autoResponder.length > 0) {
        rulesToInject = rulesToInject.concat(groupConfig.autoResponder);
    }
    // Adiciona regras globais
    if (autoResponder && autoResponder.length > 0) {
        rulesToInject = rulesToInject.concat(autoResponder);
    }

    // Filtra regras vazias
    rulesToInject = rulesToInject.filter(r => r && r.response && r.response.trim() !== '');

    if (rulesToInject.length > 0) {
        enhancedPrompt += "\n\n[INFORMAÇÕES EXTRAS (MENSAGENS RÁPIDAS DO USUÁRIO)]\nO usuário configurou gatilhos de mensagens rápidas. Use as informações abaixo como sua base de conhecimento prioritária para responder dúvidas sobre esses assuntos:\n";
        
        const addedRules = new Set();
        rulesToInject.forEach(rule => {
            const ruleText = rule.response.trim();
            // Evita adicionar a mesma resposta duplicada
            if (!addedRules.has(ruleText)) {
                addedRules.add(ruleText);
                const keywordContext = rule.matchType === 'all' ? 'Para assuntos gerais/boas-vindas' : `Se o assunto envolver "${rule.keyword}"`;
                enhancedPrompt += `- ${keywordContext}, a informação correta é: "${ruleText}"\n`;
            }
        });
        enhancedPrompt += "[FIM DAS INFORMAÇÕES EXTRAS]";
    }

    return enhancedPrompt;
}

// =================================================================================
// FUNÇÕES AUXILIARES (ADMINISTRAÇÃO)
// =================================================================================

function areJidsSameUser(jid1, jid2) {
    if (!jid1 || !jid2) return false;
    return jidNormalizedUser(jid1) === jidNormalizedUser(jid2);
}

async function isGroupAdminWA(sock, jid, participant) {
    try {
        const metadata = await sock.groupMetadata(jid);
        const admin = metadata.participants.find(p => {
            return areJidsSameUser(p.id, participant) && (p.admin === 'admin' || p.admin === 'superadmin');
        });
        return !!admin;
    } catch (e) { 
        return false; 
    }
}

async function isBotAdminWA(sock, jid) {
    try {
        const me = sock.user || sock.authState.creds.me;
        if (!me) return false;

        const myJid = jidNormalizedUser(me.id);
        const myLid = me.lid ? jidNormalizedUser(me.lid) : null;
        const metadata = await sock.groupMetadata(jid);
        
        const amIAdmin = metadata.participants.find(p => {
            if (p.admin !== 'admin' && p.admin !== 'superadmin') return false;
            const pJid = jidNormalizedUser(p.id);
            if (myLid && pJid === myLid) return true;
            if (pJid === myJid) return true;
            return false;
        });

        return !!amIAdmin;
    } catch (e) { return false; }
}

// =================================================================================
// LÓGICA TELEGRAM
// =================================================================================
if (platform === 'telegram') {
    if (!telegramToken) { console.error('❌ Token do Telegram não fornecido.'); process.exit(1); }
    const bot = new Telegraf(telegramToken);
    
    (async () => {
        try {
            // Prepara a base de conhecimento antes de ligar o bot
            await prepareKnowledgeBase();
            
            // Registrar comandos no Telegram
            const commands = [
                { command: 'id', description: 'Mostrar ID do Chat' },
                { command: 'menu', description: 'Mostrar todos os comandos' },
                { command: 'ping', description: 'Verificar status' },
                { command: 'stop', description: 'Pausar bot (ex: /stop10)' },
                { command: 'stopsempre', description: 'Ignorar usuário atual' }
            ];

            if (botType === 'group') {
                commands.push(
                    { command: 'ban', description: 'Banir usuário' },
                    { command: 'kick', description: 'Expulsar usuário' },
                    { command: 'mute', description: 'Mutar usuário' },
                    { command: 'unmute', description: 'Desmutar usuário' },
                    { command: 'promover', description: 'Promover a Admin' },
                    { command: 'rebaixar', description: 'Remover Admin' },
                    { command: 'antilink', description: 'Configurar Anti-Link' },
                    { command: 'boasvindas', description: 'Configurar mensagem de entrada' },
                    { command: 'todos', description: 'Chamar todos' },
                    { command: 'apagar', description: 'Apagar mensagem respondida' },
                    { command: 'fixar', description: 'Fixar mensagem' },
                    { command: 'desfixar', description: 'Desfixar mensagem' },
                    { command: 'titulo', description: 'Alterar título do grupo' },
                    { command: 'descricao', description: 'Alterar descrição' },
                    { command: 'link', description: 'Pegar link do grupo' },
                    { command: 'reset', description: 'Reiniciar memória da IA' }
                );
            }

            await bot.telegram.setMyCommands(commands);
            console.log(`[${nomeSessao}] Comandos do Telegram registrados.`);

            await bot.launch({ dropPendingUpdates: true });
            console.log('\nONLINE!'); 
            socket.emit('bot-online', { sessionName: nomeSessao });

            // Puxar nome do bot no Telegram para exibir no painel
            try {
                const botInfo = await bot.telegram.getMe();
                const publicName = botInfo.first_name || botInfo.username || '';
                if (publicName) {
                    socket.emit('bot-identified', { sessionName: nomeSessao, publicName });
                }
            } catch (e) {
                console.error('Erro ao buscar nome do bot no Telegram:', e);
            }

        } catch (err) { console.error('Erro Telegram:', err); process.exit(1); }
    })();

    // Listener para confirmação de ativação de grupo (Telegram)
    socket.off('group-activation-result');
    socket.on('group-activation-result', async (data) => {
        if (data.botSessionName === nomeSessao && data.groupId) {
            const msg = data.success ? '✅ Grupo ativado com sucesso!' : `❌ Falha: ${data.message}`;
            try {
                await bot.telegram.sendMessage(data.groupId, msg);
                if(data.success) {
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null
                    };
                }
            } catch (e) { console.error('Erro ao enviar msg Telegram:', e); }
        }
    });

    // --- // --- INÍCIO: LISTENERS PARA GESTOR DE COBRANÇAS E CAMPANHAS ---
        socket.off('bot:send-client-message');
        socket.on('bot:send-client-message', async (data) => { // <--- O ASYNC AQUI É OBRIGATÓRIO
            console.log(`\n[DEBUG CAMPANHA - ${nomeSessao}] Ordem de mensagem recebida do painel! Payload:`, JSON.stringify(data));
            
            const target = data.targetBot || data.botSessionName || data.sessionName || data.botName;
            
            if (target === nomeSessao) {
                try {
                    let num = data.clientNumber || data.clientJid || data.phone;
                    if (!num) {
                        return console.log(`[${nomeSessao}] ❌ Erro: O painel não enviou o número do cliente.`);
                    }
                    
                    num = String(num).replace(/[^0-9]/g, '');
                    const jid = `${num}@s.whatsapp.net`;
                    
                    console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${jid}...`);
                    await sock.sendMessage(jid, { text: data.message + '\u200B' });
                    console.log(`[${nomeSessao}] ✅ Mensagem de campanha enviada com sucesso para ${jid}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar mensagem de campanha:`, e);
                }
            }
        });

        socket.off('pix:generated-for-client');
        socket.on('pix:generated-for-client', async (data) => { // <--- O ASYNC AQUI É OBRIGATÓRIO
            console.log(`\n[DEBUG PIX - ${nomeSessao}] Ordem de PIX recebida do painel!`);
            
            const target = data.botSessionName || data.targetBot || data.sessionName;
            
            if (target === nomeSessao) {
                try {
                    let num = data.clientJid || data.clientNumber;
                    if (!num) return console.log(`[${nomeSessao}] ❌ Número do cliente faltando no payload do Pix.`);
                    
                    num = String(num).replace(/[^0-9]/g, '');
                    const jid = `${num}@s.whatsapp.net`;
                    
                    const imageBuffer = Buffer.from(data.pixData.qr_code_base64, 'base64');
                    
                    console.log(`[${nomeSessao}] ⏳ Enviando QR Code PIX para ${jid}...`);
                    await sock.sendMessage(jid, {
                        image: imageBuffer,
                        caption: `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`
                    });
                    
                    await sock.sendMessage(jid, { text: data.pixData.qr_code });
                    console.log(`[${nomeSessao}] ✅ PIX enviado com sucesso para ${jid}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar PIX:`, e);
                }
            }
        });
        // --- FIM: LISTENERS PARA GESTOR DE COBRANÇAS ---
  
    // =================================================================================
    // 👋 BOAS-VINDAS NO TELEGRAM
    // =================================================================================
    bot.on('new_chat_members', async (ctx) => {
        try {
            const chatId = ctx.chat.id.toString();
            // Verificação de autorização (se for bot de grupo)
            if (botType === 'group') {
                if (!authorizedGroups[chatId]) return;
                if (authorizedGroups[chatId].expiresAt && new Date() > authorizedGroups[chatId].expiresAt) return;
                if (authorizedGroups[chatId].isPaused) return;
            }

            // Verificar configuração de mensagem personalizada
            const customWelcome = authorizedGroups[chatId]?.welcomeMessage;
            if (customWelcome === 'off') return; // Desativado pelo admin

            const newMembers = ctx.message.new_chat_members;
            const groupName = ctx.chat.title || 'Grupo';

            for (const member of newMembers) {
                if (member.is_bot) continue; 
                const name = member.first_name || 'Novo Membro';
                
                let textToSend = '';
                if (customWelcome) {
                    textToSend = formatWelcomeMessage(customWelcome, name, groupName);
                } else {
                    textToSend = `👋 Olá, *${name}*! Seja bem-vindo(a) ao *${groupName}*!`;
                }
                
                // Adiciona o caractere invisível \u200B no final para identificação
                await ctx.reply(textToSend + '\u200B', { parse_mode: 'Markdown' });
            }
        } catch (e) {
            console.error(`[${nomeSessao}] Erro ao enviar boas-vindas no Telegram:`, e);
        }
    });
    
    bot.command('id', (ctx) => {
        ctx.reply(`ID deste chat: \`${ctx.chat.id}\``, { parse_mode: 'Markdown' });
    });

    bot.on('message', async (ctx) => {
        const texto = ctx.message.text || ctx.message.caption || '';
        
        // Ignora mensagens de outros robôs do mesmo sistema (identificados pelo caractere invisível)
        if (texto.includes('\u200B')) return;
        // Ignora outros bots do Telegram nativamente
        if (ctx.from && ctx.from.is_bot) return;

        if(!texto && !ctx.message.voice && !ctx.message.audio) return;

        const chatId = ctx.chat.id.toString();
        const isGroup = ctx.chat.type === 'group' || ctx.chat.type === 'supergroup';
        const senderName = ctx.from.first_name || 'User';
        const userId = ctx.from.id.toString();
        const isAudio = !!(ctx.message.voice || ctx.message.audio);

        // --- COMANDO !stopsempre (Ignorar Permanente) ---
        if (texto.match(/^[\/!]stopsempre$/i)) {
            let nameToIgnore = null;
            let canExecute = false;

            if (isGroup) {
                const member = await ctx.getChatMember(userId);
                if (member.status === 'administrator' || member.status === 'creator') {
                     if (ctx.message.reply_to_message) {
                         nameToIgnore = ctx.message.reply_to_message.from.first_name;
                         canExecute = true;
                     }
                }
            } else {
                nameToIgnore = ctx.chat.first_name;
                canExecute = true;
            }
            
            if (canExecute && nameToIgnore) {
                if (!ignoredIdentifiers.some(i => i.type === 'name' && i.value.toLowerCase() === nameToIgnore.toLowerCase())) {
                    ignoredIdentifiers.push({ type: 'name', value: nameToIgnore });
                    socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'name', value: nameToIgnore });
                    console.log(`[${nomeSessao}] 🚫 Usuário ${nameToIgnore} ignorado permanentemente.`);
                }
                try { await ctx.deleteMessage(); } catch(e) {}
                return;
            }
        }

        // --- COMANDO !stop (Manual Pause Temporário) ---
        const stopMatch = texto.match(/^[\/!]stop(\d*)$/i);
        if (stopMatch) {
            let isAuth = true;
            if (isGroup) {
                const member = await ctx.getChatMember(userId);
                isAuth = member.status === 'administrator' || member.status === 'creator';
            }
            if (isAuth) {
                const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                pausados[chatId] = Date.now() + (minutos * 60 * 1000);
                try { await ctx.deleteMessage(); } catch(e) {}
                return;
            }
        }

        // --- VERIFICAÇÃO DE PAUSA ---
        if (pausados[chatId] && Date.now() < pausados[chatId]) return;

        // 1. Verificar Link de Ativação
        if (isGroup && texto.includes('/ativar?token=')) {
            const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            if (token) {
                console.log(`[${nomeSessao}] Link de ativação detectado no grupo Telegram ${chatId}`);
                const groupTitle = ctx.chat.title || 'Grupo Telegram';
                socket.emit('group-activation-request', { 
                    groupId: chatId, 
                    groupName: groupTitle, 
                    activationToken: token, 
                    botSessionName: nomeSessao 
                });
                return; 
            }
        }

        // 2. Lógica de Autorização de Grupo
        let groupConfig = null;
        if (botType === 'group') {
            if (!isGroup || !authorizedGroups[chatId]) return;
            if (authorizedGroups[chatId].expiresAt && new Date() > authorizedGroups[chatId].expiresAt) return;
            groupConfig = authorizedGroups[chatId];
            if (groupConfig.isPaused) return;
        } else if (isGroup) {
            return;
        }

        // 3. Lógica de Administração (Anti-Link e Comandos)
        if (isGroup && botType === 'group') {
            // --- ANTI-LINK ---
            if (groupConfig && groupConfig.antiLink) {
                // Regex super forte que pega qualquer tipo de domínio/URL
                const linkRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|([a-zA-Z0-9_-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi;
                if (linkRegex.test(texto)) {
                    try {
                        const member = await ctx.getChatMember(userId);
                        const senderIsAdm = member.status === 'administrator' || member.status === 'creator';
                        
                        if (!senderIsAdm) {
                            await ctx.deleteMessage();
                            await ctx.reply('🚫 *Anti-Link:* Mensagem apagada. Links não são permitidos neste grupo.', { parse_mode: 'Markdown' });
                            return;
                        }
                    } catch (e) { console.error('Erro antilink telegram:', e); }
                }
            }

            // --- COMANDOS ADMIN ---
            if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                const args = texto.trim().split(/ +/);
                let rawCmd = args.shift().toLowerCase();
                
                if (rawCmd.startsWith('/') || rawCmd.startsWith('!') || rawCmd.startsWith('.')) {
                    rawCmd = rawCmd.substring(1);
                }
                
                const comando = rawCmd.split('@')[0];

                try {
                    const member = await ctx.getChatMember(userId);
                    const senderIsAdm = member.status === 'administrator' || member.status === 'creator';

                    // Comandos Públicos
                    if (comando === 'ping') {
                        const start = Date.now();
                        const msg = await ctx.reply('🏓 Pong!');
                        const end = Date.now();
                        await ctx.telegram.editMessageText(chatId, msg.message_id, null, `🏓 Pong! Latência: ${end - start}ms`);
                        return;
                    }

                    if (comando === 'menu' || comando === 'ajuda') {
                        let menu = `🤖 *MENU DE COMANDOS*\n\n`;
                        menu += `👤 *Públicos:*\n`;
                        menu += `/menu - Exibe esta lista detalhada de comandos.\n`;
                        menu += `/ping - Verifica se o bot está online e a latência.\n`;
                        menu += `/stop - Pausa o bot por 10 minutos (interrompe respostas da IA).\n`;
                        menu += `/stopsempre - Faz o bot ignorar você ou o usuário respondido permanentemente.\n`;
                        menu += `/id - Ver ID do chat.\n`;

                        if (senderIsAdm) {
                            menu += `\n👮 *Administração (Apenas Admins):*\n`;
                            menu += `/ban (responda) - Bane o usuário da mensagem respondida.\n`;
                            menu += `/kick (responda) - Remove (expulsa) o usuário.\n`;
                            menu += `/mute (responda) - Impede o usuário de enviar mensagens.\n`;
                            menu += `/unmute (responda) - Permite que o usuário fale novamente.\n`;
                            menu += `/promover (responda) - Torna o usuário administrador.\n`;
                            menu += `/rebaixar (responda) - Remove o admin do usuário.\n`;
                            menu += `/boasvindas <texto> - Configura mensagem (use #nome, #grupo) ou 'off'.\n`;
                            menu += `/apagar (responda) - Apaga a mensagem respondida e o comando.\n`;
                            menu += `/fixar (responda) - Fixa a mensagem no topo do grupo.\n`;
                            menu += `/desfixar - Desfixa a mensagem.\n`;
                            menu += `/todos - Marca todos os membros do grupo.\n`;
                            menu += `/titulo <nome> - Altera o título do grupo.\n`;
                            menu += `/descricao <texto> - Altera a descrição do grupo.\n`;
                            menu += `/link - Gera/Exibe o link de convite do grupo.\n`;
                            menu += `/antilink <on/off> - Ativa ou desativa a remoção automática de links.\n`;
                            menu += `/reset - Limpa a memória de conversa da IA neste chat.\n`;
                        }
                        await ctx.reply(menu, { parse_mode: 'Markdown' });
                        return;
                    }

                    // Comandos de Admin
                    if (senderIsAdm) {
                        const replyTo = ctx.message.reply_to_message;
                        const targetUser = replyTo ? replyTo.from : null;

                        switch (comando) {
                            case 'ban':
                            case 'banir':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja banir.');
                                await ctx.kickChatMember(targetUser.id);
                                await ctx.reply('✅ Usuário banido.');
                                return;

                            case 'kick':
                            case 'expulsar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja expulsar.');
                                await ctx.unbanChatMember(targetUser.id); // Kick no telegram é ban + unban
                                await ctx.reply('✅ Usuário expulso.');
                                return;

                            case 'mute':
                            case 'mutar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja mutar.');
                                await ctx.restrictChatMember(targetUser.id, { can_send_messages: false });
                                await ctx.reply('✅ Usuário mutado.');
                                return;

                            case 'unmute':
                            case 'desmutar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja desmutar.');
                                await ctx.restrictChatMember(targetUser.id, { can_send_messages: true, can_send_media_messages: true, can_send_other_messages: true });
                                await ctx.reply('✅ Usuário desmutado.');
                                return;

                            case 'promover':
                            case 'admin':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja promover.');
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: true, can_delete_messages: true, can_invite_users: true, can_restrict_members: true, can_pin_messages: true });
                                await ctx.reply('✅ Usuário promovido a ADM.');
                                return;

                            case 'rebaixar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja rebaixar.');
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: false, can_delete_messages: false, can_invite_users: false, can_restrict_members: false, can_pin_messages: false });
                                await ctx.reply('✅ ADM removido.');
                                return;
                            
                            case 'todos':
                            case 'everyone':
                                await ctx.reply('📢 *Atenção todos!*', { parse_mode: 'Markdown' });
                                return;

                            case 'apagar':
                            case 'del':
                                if (!replyTo) return ctx.reply('❌ Responda a mensagem que deseja apagar.');
                                await ctx.deleteMessage(replyTo.message_id);
                                await ctx.deleteMessage(); // Apaga o comando também
                                return;

                            case 'fixar':
                            case 'pin':
                                if (!replyTo) return ctx.reply('❌ Responda a mensagem que deseja fixar.');
                                await ctx.pinChatMessage(replyTo.message_id);
                                return;

                            case 'desfixar':
                            case 'unpin':
                                await ctx.unpinChatMessage();
                                await ctx.reply('✅ Mensagem desfixada.');
                                return;

                            case 'titulo':
                                if (!args.length) return ctx.reply('❌ Digite o novo título.');
                                await ctx.setChatTitle(args.join(' '));
                                await ctx.reply('✅ Título alterado.');
                                return;

                            case 'descricao':
                                if (!args.length) return ctx.reply('❌ Digite a nova descrição.');
                                await ctx.setChatDescription(args.join(' '));
                                await ctx.reply('✅ Descrição alterada.');
                                return;

                            case 'link':
                                const invite = await ctx.exportChatInviteLink();
                                await ctx.reply(`🔗 Link do grupo: ${invite}`);
                                return;

                            case 'reset':
                                historicoConversa[chatId] = [];
                                await ctx.reply('🧠 Memória da IA reiniciada para este grupo.');
                                return;

                            case 'antilink':
                                if (!args[0]) return ctx.reply('Use: /antilink on ou /antilink off');
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[chatId].antiLink = novoEstado;
                                socket.emit('update-group-settings', { groupId: chatId, settings: { antiLink: novoEstado } });
                                await ctx.reply(`🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*`, { parse_mode: 'Markdown' });
                                return;

                            case 'boasvindas':
                                if (!args.length) return ctx.reply('❌ Digite a mensagem ou "off". Ex: /boasvindas Olá #nome!');
                                const novaMsg = args.join(' ');
                                const valueToSave = novaMsg.toLowerCase() === 'off' ? 'off' : novaMsg;
                                authorizedGroups[chatId].welcomeMessage = valueToSave;
                                socket.emit('update-group-settings', { groupId: chatId, settings: { welcomeMessage: valueToSave } });
                                if (valueToSave === 'off') await ctx.reply('🔕 Mensagem de boas-vindas desativada.');
                                else await ctx.reply('✅ Mensagem de boas-vindas configurada.');
                                return;
                        }
                    }
                } catch (e) { console.error('Erro comando telegram:', e); }
            }
        }

        // 4. Verificação de Ignorados (Nome)
        if (ignoredIdentifiers.some(i => i.type === 'name' && senderName.toLowerCase() === i.value.toLowerCase())) return;

        // 5. Lógica de Silêncio e Chamada por Nome
        let shouldRespond = true;
        const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
        const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());
        const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

        if (silenceTime > 0) {
            const lastTime = lastResponseTimes[chatId] || 0;
            const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);
            if (!isNameCalled && timeDiffMinutes < silenceTime) shouldRespond = false;
        }

        // --- VERIFICAÇÃO DE DISPAROS POR PALAVRAS (AUTO-RESPONDER) ---
        let triggeredResponse = null;
        let fallbackResponse = null;

        // 1. Verifica Regras ESPECÍFICAS DO GRUPO (Prioridade Alta)
        if (groupConfig && groupConfig.autoResponder && groupConfig.autoResponder.length > 0 && !isAudio) {
            const lowerText = texto.toLowerCase().trim();
            for (const trigger of groupConfig.autoResponder) {
                if (!trigger.response) continue;
                if (trigger.matchType === 'all') {
                    if (!fallbackResponse) fallbackResponse = trigger.response;
                    continue;
                }
                if (!trigger.keyword) continue;
                const lowerKeyword = trigger.keyword.toLowerCase().trim();
                
                if (trigger.matchType === 'exact' && lowerText === lowerKeyword) {
                    triggeredResponse = trigger.response; 
                    break;
                } else if (trigger.matchType === 'contains' && lowerText.includes(lowerKeyword)) {
                    triggeredResponse = trigger.response; 
                    break;
                }
            }
        }

        // 2. Se não achou no grupo, verifica Regras GLOBAIS do Bot (Prioridade Média)
        if (!triggeredResponse && autoResponder && autoResponder.length > 0 && !isAudio) {
            const lowerText = texto.toLowerCase().trim();
            for (const trigger of autoResponder) {
                if (!trigger.response) continue;
                if (trigger.matchType === 'all') {
                    if (!fallbackResponse) fallbackResponse = trigger.response;
                    continue;
                }
                if (!trigger.keyword) continue;
                const lowerKeyword = trigger.keyword.toLowerCase().trim();
                
                if (trigger.matchType === 'exact' && lowerText === lowerKeyword) {
                    triggeredResponse = trigger.response; 
                    break;
                } else if (trigger.matchType === 'contains' && lowerText.includes(lowerKeyword)) {
                    triggeredResponse = trigger.response; 
                    break;
                }
            }
        }

        // Se achou palavra-chave ESPECÍFICA (Grupo ou Global), responde na hora
        if (triggeredResponse) {
            await ctx.reply(triggeredResponse + '\u200B', { reply_to_message_id: ctx.message.message_id });
            lastResponseTimes[chatId] = Date.now();
            return; 
        }

        // Se NÃO achou palavra-chave, verifica se o bot deve ficar em silêncio
        if (!shouldRespond) return;

        // Se tem resposta padrão (Qualquer Mensagem) e o bot NÃO está em silêncio
        if (fallbackResponse) {
            await ctx.reply(fallbackResponse + '\u200B', { reply_to_message_id: ctx.message.message_id });
            lastResponseTimes[chatId] = Date.now();
            return;
        }

        // 6. Processamento IA
        
        // VERIFICAÇÃO SE A IA DEVE RESPONDER
        let useAI = true;
        if (groupConfig) {
            // Se for grupo, respeita a config do grupo (se undefined, assume true)
            useAI = groupConfig.aiFallbackEnabled !== false;
        } else {
            // Se for individual, usa a config global
            useAI = aiFallbackEnabledGlobal;
        }

        if (!useAI) return; // SE A IA ESTIVER DESLIGADA, PARA AQUI.

        try {
            ctx.sendChatAction('typing'); 
            let audioBuffer = null;
            if (isAudio) {
                const fileId = ctx.message.voice ? ctx.message.voice.file_id : ctx.message.audio.file_id;
                const fileLink = await ctx.telegram.getFileLink(fileId);
                const response = await axios.get(fileLink.href, { responseType: 'arraybuffer' });
                audioBuffer = Buffer.from(response.data).toString('base64');
            }

            let basePrompt = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;
            const promptToUse = buildEnhancedPrompt(basePrompt, groupConfig);
            
            const resposta = await processarComGemini(chatId, isAudio ? audioBuffer : texto, isAudio, promptToUse);
            
            if(resposta && resposta.trim().length > 0) {
                await ctx.reply(resposta + '\u200B', { reply_to_message_id: ctx.message.message_id });
                lastResponseTimes[chatId] = Date.now();
            }
        } catch (e) {
            console.error("Erro ao responder no Telegram:", e);
        }
    });
    
    bot.catch((err, ctx) => {
        console.log(`Erro Telegram para ${ctx.updateType}`, err);
    });

    process.once('SIGINT', () => { bot.stop('SIGINT'); process.exit(0); });
    process.once('SIGTERM', () => { bot.stop('SIGTERM'); process.exit(0); });

} else {
    // =================================================================================
    // LÓGICA WHATSAPP
    // =================================================================================
    async function ligarBot() {
        console.log(`🚀 Iniciando ${nomeSessao} (WhatsApp)...`);
        
        // Prepara a base de conhecimento antes de ligar o bot
        await prepareKnowledgeBase();
        
        const authPath = `./auth_sessions/auth_${nomeSessao}`;
        const { state, saveCreds } = await useMultiFileAuthState(authPath);
        
        let versionWA =[2, 3000, 1015901307];
        try {
            // Adicionado limite de 5 segundos. Se travar, ele usa a versão fallback.
            const fetchRef = await Promise.race([
                fetchLatestBaileysVersion(),
                new Promise((_, rej) => setTimeout(() => rej(new Error('Timeout')), 5000))
            ]);
            versionWA = fetchRef.version;
        } catch (e) {
            console.log(`[${nomeSessao}] Usando versão WA Web de fallback.`);
        }

        const sock = makeWASocket({
            version: versionWA, 
            logger, 
            auth: { 
                creds: state.creds, 
                keys: makeCacheableSignalKeyStore(state.keys, logger) 
            },
            syncFullHistory: false, 
            markOnlineOnConnect: true,
            generateHighQualityLinkPreview: true, 
            browser: ["Ubuntu", "Chrome", "20.0.04"],
            msgRetryCounterCache,
            retryRequestDelayMs: 250,
            getMessage: async (key) => {
                return messageStore.get(key) || undefined;
            }
        });

        // --- LISTENERS DO LIVE CHAT (Recebidos do Servidor) ---
        socket.off('bot:get-chats');
        socket.on('bot:get-chats', (data) => {
            const chats = Array.from(recentChats.values()).sort((a,b) => b.timestamp - a.timestamp);
            socket.emit('bot:return-chats', { frontendId: data.frontendId, chats });
        });

        socket.off('bot:get-messages');
        socket.on('bot:get-messages', (data) => {
            if (recentChats.has(data.jid)) recentChats.get(data.jid).unreadCount = 0;
            const msgs = recentMessages.get(data.jid) ||[];
            socket.emit('bot:return-messages', { frontendId: data.frontendId, jid: data.jid, messages: msgs });
        });

        socket.off('bot:send-message');
        socket.on('bot:send-message', async (data) => {
            try {
                if (sock) {
                    const sent = await sock.sendMessage(data.jid, { text: data.text });
                    await saveLiveMessage(sock, data.jid, 'Você', { id: sent.key.id, fromMe: true, text: data.text, timestamp: Date.now() });
                }
            } catch (e) {
                console.error("Erro ao enviar mensagem manual:", e);
            }
        });

        socket.off('bot:pause-ai');
        socket.on('bot:pause-ai', (data) => {
            pausados[data.jid] = Date.now() + (10 * 60 * 1000);
            console.log(`[${nomeSessao}] 🔇 IA pausada manualmente pelo Live Chat para: ${data.jid}`);
        });

        // --- INÍCIO: LISTENERS PARA GESTOR DE COBRANÇAS E CAMPANHAS (WHATSAPP) ---
        socket.off('bot:send-client-message');
        socket.on('bot:send-client-message', async (data) => {
            const target = data.targetBot || data.botSessionName || data.sessionName || data.botName;
            if (target === nomeSessao) {
                try {
                    let num = data.clientNumber || data.clientJid || data.phone;
                    if (!num) {
                        if (data.messageId) socket.emit('bot:message-status', { messageId: data.messageId, success: false, error: 'Número não fornecido' });
                        return;
                    }
                    
                    num = String(num).replace(/[^0-9]/g, '');
                    const jid = `${num}@s.whatsapp.net`;
                    
                    console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${jid}...`);
                    
                    // Verifica se o número realmente existe no WhatsApp antes de enviar
                    const[result] = await sock.onWhatsApp(jid);
                    if (!result || !result.exists) {
                        throw new Error("O número não possui WhatsApp registrado.");
                    }

                    // Envia a mensagem de texto
                    await sock.sendMessage(jid, { text: data.message + '\u200B' });
                    
                    // Se tiver PIX embutido no payload, envia logo em seguida
                    if (data.pixData && data.pixData.qr_code_base64) {
                        const imageBuffer = Buffer.from(data.pixData.qr_code_base64, 'base64');
                        await sock.sendMessage(jid, {
                            image: imageBuffer,
                            caption: `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`
                        });
                        await sock.sendMessage(jid, { text: data.pixData.qr_code });
                    }

                    console.log(`[${nomeSessao}] ✅ Mensagem de campanha enviada com sucesso para ${jid}!\n`);
                    
                    // Confirma o sucesso para o servidor
                    if (data.messageId) {
                        socket.emit('bot:message-status', { messageId: data.messageId, success: true });
                    }

                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar mensagem de campanha:`, e.message);
                    // Confirma a falha para o servidor
                    if (data.messageId) {
                        socket.emit('bot:message-status', { messageId: data.messageId, success: false, error: e.message });
                    }
                }
            }
        });
        // --- FIM: LISTENERS PARA GESTOR DE COBRANÇAS ---

        socket.off('group-activation-result');
        socket.on('group-activation-result', async (data) => {
            if (data.botSessionName === nomeSessao && data.groupId) {
                const msg = data.success ? '✅ Grupo ativado!' : `❌ Falha: ${data.message}`;
                await sock.sendMessage(data.groupId, { text: msg });
                if(data.success) {
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null
                    };
                }
            }
        });

        if (phoneNumberArg && !sock.authState.creds.registered) {
            setTimeout(async () => {
                try {
                    const code = await sock.requestPairingCode(phoneNumberArg);
                    console.log(`PAIRING_CODE:${code}`);
                } catch (err) { console.error(`Erro Pairing Code:`, err); }
            }, 4000);
        }

        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;
            
            // Só emite o QR se realmente estiver pedindo login (sessão vazia)
            if (qr && !phoneNumberArg) console.log(`QR_CODE:${qr}`);
            
            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                
                // Reconecta em TODOS os casos, EXCETO se o usuário deslogou manualmente pelo celular
                const shouldReconnect = statusCode !== DisconnectReason.loggedOut;

                console.log(`[${nomeSessao}] Conexão caiu. Código do Erro: ${statusCode} | Vai reconectar? ${shouldReconnect}`);

                if (shouldReconnect) {
                    console.log(`[${nomeSessao}] Tentando reconectar automaticamente em 5 segundos...`);
                    // NÃO APAGA A SESSÃO AQUI. Apenas reinicia a função para reconectar de forma invisível.
                    setTimeout(ligarBot, 5000);
                } else {
                    // Se foi desconectado manualmente no celular (loggedOut)
                    console.log(`[${nomeSessao}] Dispositivo desconectado no celular. Limpando sessão para ler um novo QR Code...`);
                    try { 
                        if (fs.existsSync(authPath)) {
                            fs.rmSync(authPath, { recursive: true, force: true }); 
                        }
                    } catch(e) {}
                    
                    // Em vez de matar o processo (process.exit), tentamos ligar novamente para cuspir o novo QR
                    setTimeout(ligarBot, 2000); 
                }
            } else if (connection === 'open') {
                console.log('\nONLINE!'); 
                socket.emit('bot-online', { sessionName: nomeSessao });
                
                // Puxar o nome do perfil do WhatsApp para exibir no painel
                setTimeout(() => {
                    const me = sock.authState?.creds?.me || sock.user;
                    const publicName = me?.name || me?.verifiedName || me?.notify || '';
                    if (publicName) {
                        socket.emit('bot-identified', { sessionName: nomeSessao, publicName });
                    }
                }, 3000);
            }
        });

        sock.ev.on('creds.update', async () => {
            try {
                await saveCreds();
            } catch (err) {
                console.error(`[${nomeSessao}] Erro ignorado ao salvar credenciais (I/O de disco ocupado):`, err.message);
            }
            // Tenta puxar o nome do perfil caso ele seja atualizado depois
            const me = sock.authState?.creds?.me || sock.user;
            const publicName = me?.name || me?.verifiedName || me?.notify || '';
            if (publicName) {
                socket.emit('bot-identified', { sessionName: nomeSessao, publicName });
            }
        });

        // =================================================================================
        // 👋 BOAS-VINDAS NO WHATSAPP
        // =================================================================================
        sock.ev.on('group-participants.update', async (update) => {
            try {
                const { id, participants, action } = update;
                if (action === 'add') {
                    // Verificação de autorização (se for bot de grupo)
                    if (botType === 'group') {
                        if (!authorizedGroups[id]) return;
                        if (authorizedGroups[id].expiresAt && new Date() > authorizedGroups[id].expiresAt) return;
                        if (authorizedGroups[id].isPaused) return;
                    }

                    const customWelcome = authorizedGroups[id]?.welcomeMessage;
                    if (customWelcome === 'off') return;

                    // Tentar obter metadados do grupo para pegar o nome
                    let groupName = "Grupo";
                    try {
                        // Tentativa 1: Busca direta
                        const metadata = await sock.groupMetadata(id);
                        if (metadata && metadata.subject) groupName = metadata.subject;
                    } catch (e) {
                        try {
                            // Tentativa 2 (Plano B): Busca no cache
                            const allGroups = await sock.groupFetchAllParticipating();
                            if (allGroups[id] && allGroups[id].subject) {
                                groupName = allGroups[id].subject;
                            }
                        } catch (err2) {
                            console.error(`[${nomeSessao}] Falha ao obter nome do grupo para boas-vindas.`);
                        }
                    }

                    let text = '';
                    if (customWelcome) {
                         // Pega o número da pessoa e formata como Menção (ex: @5511999999999)
                         const firstJid = participants[0];
                         const userMention = `@${firstJid.split('@')[0]}`;
                         text = formatWelcomeMessage(customWelcome, userMention, groupName); 
                    } else {
                        text = `👋 Olá! Seja bem-vindo(a) ao grupo *${groupName}*!`;
                    }
                    
                    // Adiciona o caractere invisível \u200B no final para identificação
                    await sock.sendMessage(id, { 
                        text: text + '\u200B', 
                        mentions: participants 
                    });
                }
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao enviar boas-vindas no WhatsApp:`, e);
            }
        });

        sock.ev.on('messages.upsert', async ({ messages, type }) => {
            // Salva as mensagens recentes no nosso mini-store para o getMessage funcionar
            for (const m of messages) {
                if (m.message) messageStore.add(m.key, m.message);
            }

            if (type !== 'notify') return;
            const msg = messages[0];
            if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

            const jid = msg.key.remoteJid;
            const isGroup = jid.endsWith('@g.us');
            const sender = msg.key.participant || jid;

            let texto = msg.message.conversation || msg.message.extendedTextMessage?.text || 
                        msg.message.imageMessage?.caption || msg.message.videoMessage?.caption || '';
            let isAudio = !!msg.message.audioMessage;

            // Ignora mensagens de outros robôs do mesmo sistema (identificados pelo caractere invisível)
            if (texto.includes('\u200B')) {
                console.log(`[${nomeSessao}] Mensagem de outro robô ignorada para evitar loop.`);
                return;
            }
            
            // Ignora mensagens geradas por outras instâncias do Baileys (opcional, mas recomendado)
            if (msg.key.id && msg.key.id.startsWith('BAE5') && msg.key.id.length === 16 && !msg.key.fromMe) {
                console.log(`[${nomeSessao}] Mensagem de outro bot Baileys ignorada.`);
                return;
            }

            // Salva na memória do Live Chat
            const senderName = msg.pushName || sender.split('@')[0];
            let liveChatText = texto;
if (!msg.key.fromMe) {
liveChatText = senderName + ': ' + liveChatText;
}
if (isAudio) liveChatText = (!msg.key.fromMe ? senderName + ' enviou: ' : '') + '🎤 Áudio Recebido';
else if (msg.message.imageMessage) liveChatText = (!msg.key.fromMe ? senderName + ' enviou: ' : '') + '📷 Imagem Recebida';
else if (msg.message.videoMessage) liveChatText = (!msg.key.fromMe ? senderName + ' enviou: ' : '') + '🎥 Vídeo Recebido';
else if (msg.message.documentMessage) liveChatText = (!msg.key.fromMe ? senderName + ' enviou: ' : '') + '📄 Documento Recebido';
            
            await saveLiveMessage(sock, jid, senderName, {
                id: msg.key.id,
                fromMe: msg.key.fromMe,
                text: liveChatText,
                timestamp: (msg.messageTimestamp * 1000) || Date.now()
            });

            // --- 1. COMANDO !stopsempre (Ignorar Permanente) ---
            if (texto.toLowerCase() === '!stopsempre') {
                let valueToIgnore = null;
                let typeToIgnore = 'number';

                if (msg.key.fromMe) {
                    if (isGroup) {
                         const context = msg.message?.extendedTextMessage?.contextInfo;
                         if (context?.participant) {
                             const pJid = jidNormalizedUser(context.participant);
                             valueToIgnore = pJid.split('@')[0];
                         }
                    } else {
                        const target = jidNormalizedUser(jid);
                        valueToIgnore = target.split('@')[0];
                    }
                } else {
                    const target = jidNormalizedUser(sender);
                    valueToIgnore = target.split('@')[0];
                }
                
                if (valueToIgnore) {
                    const exists = ignoredIdentifiers.some(i => i.type === 'number' && i.value === valueToIgnore);
                    
                    if (!exists) {
                        ignoredIdentifiers.push({ type: 'number', value: valueToIgnore });
                        socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'number', value: valueToIgnore });
                        console.log(`[${nomeSessao}] 🚫 Número ${valueToIgnore} adicionado à lista de ignorados.`);
                    }
                    
                    try {
                        const deleteKey = {
                            remoteJid: msg.key.remoteJid,
                            fromMe: msg.key.fromMe,
                            id: msg.key.id
                        };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        
                        await sock.sendMessage(jid, { delete: deleteKey });
                    } catch (e) {}
                }
                return; // Interrompe fluxo
            }

            // --- 2. COMANDO !stop (Pausa Temporária) ---
            // CORREÇÃO AQUI: Regex mais flexível e deleção correta
            const stopMatch = texto.trim().match(/^!stop\s*(\d*)$/i);
            if (stopMatch) {
                let isAuth = false;
                if (msg.key.fromMe) isAuth = true;
                else if (isGroup) isAuth = await isGroupAdminWA(sock, jid, sender);
                else if (!isGroup && !msg.key.fromMe) isAuth = true; 

                if (isAuth) {
                    const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                    const duracaoMs = minutos * 60 * 1000;
                    
                    // 1. Aplica a pausa imediatamente
                    pausados[jid] = Date.now() + duracaoMs;
                    console.log(`[${nomeSessao}] 🔇 Pausado por ${minutos} min em ${jid}.`);

                    // 2. Tenta reagir e deletar (Try/Catch para não travar se não for admin)
                    try {
                        await sock.sendMessage(jid, { react: { text: "🔇", key: msg.key } }); // Feedback visual
                        
                        const deleteKey = {
                            remoteJid: msg.key.remoteJid,
                            fromMe: msg.key.fromMe,
                            id: msg.key.id
                        };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        
                        await sock.sendMessage(jid, { delete: deleteKey });
                    } catch (e) {
                        // Se falhar ao deletar (ex: não é admin), a pausa já foi aplicada acima.
                    }
                    return; 
                }
            }

            // --- 3. AUTO-SILÊNCIO AO RESPONDER ---
            if (msg.key.fromMe) {
                if (silenceTimeMinutesGlobal > 0) {
                    const autoSilenceMs = silenceTimeMinutesGlobal * 60 * 1000;
                    pausados[jid] = Date.now() + autoSilenceMs;
                    console.log(`[${nomeSessao}] 🔇 Auto-silêncio ativado por ${silenceTimeMinutesGlobal} min em ${jid} (intervenção humana).`);
                }
                return;
            }

            // --- VERIFICAÇÃO DE ATIVAÇÃO ---
            if (isGroup && texto.includes('/ativar?token=')) {
                const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
                if (token) {
                    console.log(`[${nomeSessao}] Link de ativação detectado no grupo ${jid}`);
                    
                    let gName = "Grupo Ativado";
                    try {
                        // Tentativa 1: Busca direta (tempo real)
                        const meta = await sock.groupMetadata(jid);
                        if (meta && meta.subject) gName = meta.subject;
                    } catch (err) {
                        try {
                            // Tentativa 2 (Plano B): Busca no cache interno de grupos participados (Altamente confiável)
                            const allGroups = await sock.groupFetchAllParticipating();
                            if (allGroups[jid] && allGroups[jid].subject) {
                                gName = allGroups[jid].subject;
                            }
                        } catch (err2) {
                            console.log(`[${nomeSessao}] Aviso: Usando nome padrão. WhatsApp não liberou o nome.`);
                        }
                    }
                    
                    // Emite pro painel salvar o grupo
                    socket.emit('group-activation-request', { 
                        groupId: jid, 
                        groupName: gName, 
                        activationToken: token, 
                        botSessionName: nomeSessao 
                    });
                    return; 
                }
            }

            let groupConfig = null;
            if (botType === 'group') {
                if (!isGroup || !authorizedGroups[jid]) return;
                if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
                groupConfig = authorizedGroups[jid];
                if (groupConfig.isPaused) return;
            } else if (isGroup) {
                return;
            }

            // --- LÓGICA DE ADMINISTRAÇÃO (WHATSAPP) ---
            if (isGroup && botType === 'group') {
                
                // 1. Anti-Link
                if (groupConfig && groupConfig.antiLink) {
                    // Regex super forte que pega qualquer tipo de domínio/URL
                    const linkRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|([a-zA-Z0-9_-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi;
                    if (linkRegex.test(texto)) {
                        const botIsAdm = await isBotAdminWA(sock, jid);
                        const senderIsAdm = await isGroupAdminWA(sock, jid, sender);

                        if (botIsAdm && !senderIsAdm) {
                            try {
                                const deleteKey = {
                                    remoteJid: msg.key.remoteJid,
                                    fromMe: false,
                                    id: msg.key.id,
                                    participant: msg.key.participant || sender
                                };
                                await sock.sendMessage(jid, { delete: deleteKey });
                                await sock.sendMessage(jid, { text: '🚫 *Anti-Link:* Mensagem apagada. Links não são permitidos neste grupo.' });
                            } catch (errDel) {
                                console.error(`[${nomeSessao}] Falha ao apagar link (perda de admin ou instabilidade):`, errDel.message);
                            }
                            return; 
                        }
                    }
                }

                // 2. Comandos Admin
                if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                    const args = texto.slice(1).trim().split(/ +/);
                    const comando = args.shift().toLowerCase();
                    const senderIsAdm = await isGroupAdminWA(sock, jid, sender);
                    const botIsAdm = await isBotAdminWA(sock, jid);

                    // Comandos Públicos
                    if (comando === 'ping') {
                        const start = Date.now();
                        await sock.sendMessage(jid, { text: `🏓 Pong! Latência: ${start - (msg.messageTimestamp * 1000)}ms` }, { quoted: msg });
                        return;
                    }

                    if (comando === 'menu' || comando === 'ajuda') {
                        let menu = `🤖 *MENU DE COMANDOS*\n\n`;
                        menu += `👤 *Públicos:*\n`;
                        menu += `!menu - Exibe esta lista detalhada de comandos.\n`;
                        menu += `!ping - Verifica se o bot está online e a latência.\n`;
                        menu += `!stop - Pausa a IA por 10 minutos.\n`;
                        menu += `!stopsempre - Ignora o usuário/grupo permanentemente.\n`;

                        if (senderIsAdm) {
                            menu += `\n👮 *Administração (Apenas Admins):*\n`;
                            menu += `!ban @user - Bane (remove) o usuário do grupo.\n`;
                            menu += `!kick @user - O mesmo que banir.\n`;
                            menu += `!promover @user - Torna um usuário administrador.\n`;
                            menu += `!rebaixar @user - Remove o admin de um usuário.\n`;
                            menu += `!boasvindas <texto> - Configura mensagem (use #nome, #grupo) ou 'off'.\n`;
                            menu += `!apagar (responda) - Apaga a mensagem respondida.\n`;
                            menu += `!fechar - Fecha o grupo para que apenas admins falem.\n`;
                            menu += `!abrir - Abre o grupo para todos falarem.\n`;
                            menu += `!todos - Marca todos os membros do grupo.\n`;
                            menu += `!titulo <nome> - Altera o nome do grupo.\n`;
                            menu += `!descricao <texto> - Altera a descrição do grupo.\n`;
                            menu += `!link - Exibe o link de convite do grupo.\n`;
                            menu += `!antilink <on/off> - Ativa/Desativa remoção de links.\n`;
                            menu += `!reset - Limpa a memória da conversa com a IA.\n`;
                            menu += `!sair - O bot sai do grupo.\n`;
                        }
                        await sock.sendMessage(jid, { text: menu }, { quoted: msg });
                        return;
                    }

                    if (senderIsAdm) {
                        let targetUser = null;
                        const mentions = msg.message.extendedTextMessage?.contextInfo?.mentionedJid;
                        if (mentions && mentions.length > 0) targetUser = mentions[0];
                        else if (msg.message.extendedTextMessage?.contextInfo?.participant) targetUser = msg.message.extendedTextMessage.contextInfo.participant;
                        else if (args[0]) {
                            const potentialNum = args[0].replace(/[^0-9]/g, '');
                            if (potentialNum.length >= 10) targetUser = potentialNum + '@s.whatsapp.net';
                        }

                        try { // <--- PROTEÇÃO MASTER ADICIONADA AQUI
                        switch (comando) {
                            case 'ban':
                            case 'banir':
                            case 'kick':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'remove');
                                await sock.sendMessage(jid, { text: '✅ Usuário removido.' });
                                return;

                            case 'promover':
                            case 'admin':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'promote');
                                await sock.sendMessage(jid, { text: '✅ Usuário promovido.' });
                                return;

                            case 'rebaixar':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'demote');
                                await sock.sendMessage(jid, { text: '✅ ADM removido.' });
                                return;

                            case 'apagar':
                            case 'del':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!msg.message.extendedTextMessage?.contextInfo?.stanzaId) return sock.sendMessage(jid, { text: '❌ Responda a mensagem.' }, { quoted: msg });
                                const key = {
                                    remoteJid: jid,
                                    fromMe: false,
                                    id: msg.message.extendedTextMessage.contextInfo.stanzaId,
                                    participant: msg.message.extendedTextMessage.contextInfo.participant
                                };
                                await sock.sendMessage(jid, { delete: key });
                                return;

                            case 'fechar':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                await sock.groupSettingUpdate(jid, 'announcement');
                                await sock.sendMessage(jid, { text: '🔒 Grupo fechado.' });
                                return;

                            case 'abrir':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                await sock.groupSettingUpdate(jid, 'not_announcement');
                                await sock.sendMessage(jid, { text: '🔓 Grupo aberto.' });
                                return;
                            
                            case 'todos':
                            case 'everyone':
                                if (!botIsAdm) return; 
                                const groupMeta = await sock.groupMetadata(jid);
                                const mentionsAll = groupMeta.participants.map(p => p.id);
                                await sock.sendMessage(jid, { text: '📢 *Atenção todos!*', mentions: mentionsAll });
                                return;

                            case 'titulo':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite o novo nome.' }, { quoted: msg });
                                await sock.groupUpdateSubject(jid, args.join(' '));
                                await sock.sendMessage(jid, { text: '✅ Nome alterado.' });
                                return;

                            case 'descricao':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite a descrição.' }, { quoted: msg });
                                await sock.groupUpdateDescription(jid, args.join(' '));
                                await sock.sendMessage(jid, { text: '✅ Descrição alterada.' });
                                return;

                            case 'link':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                const code = await sock.groupInviteCode(jid);
                                await sock.sendMessage(jid, { text: `🔗 Link: https://chat.whatsapp.com/${code}` }, { quoted: msg });
                                return;

                            case 'reset':
                                historicoConversa[jid] = [];
                                await sock.sendMessage(jid, { text: '🧠 Memória da IA reiniciada.' }, { quoted: msg });
                                return;

                            case 'sair':
                                await sock.sendMessage(jid, { text: '👋 Adeus!' });
                                await sock.groupLeave(jid);
                                return;

                            case 'antilink':
                                if (!args[0]) return sock.sendMessage(jid, { text: 'Use: !antilink on ou !antilink off' });
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[jid].antiLink = novoEstado;
                                socket.emit('update-group-settings', { groupId: jid, settings: { antiLink: novoEstado } });
                                await sock.sendMessage(jid, { text: `🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*` });
                                return;

                            case 'boasvindas':
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite a mensagem ou "off". Ex: !boasvindas Olá #nome!' }, { quoted: msg });
                                const novaMsg = args.join(' ');
                                const valueToSave = novaMsg.toLowerCase() === 'off' ? 'off' : novaMsg;
                                authorizedGroups[jid].welcomeMessage = valueToSave;
                                socket.emit('update-group-settings', { groupId: jid, settings: { welcomeMessage: valueToSave } });
                                if (valueToSave === 'off') await sock.sendMessage(jid, { text: '🔕 Mensagem de boas-vindas desativada.' });
                                else await sock.sendMessage(jid, { text: '✅ Mensagem de boas-vindas configurada.' });
                                return;
                        }
                        } catch (errAdmin) {
                            console.error(`[${nomeSessao}] Erro ao tentar executar comando (${comando}):`, errAdmin.message);
                            await sock.sendMessage(jid, { text: '⚠️ Falha ao executar comando. Verifique minhas permissões.' });
                        } // <--- FECHAMENTO DA PROTEÇÃO MASTER
                    }
                }
            }

            if (pausados[jid] && Date.now() < pausados[jid]) return;
            if (ignoredIdentifiers.some(i => (i.type === 'number' && sender.includes(i.value)) || (i.type === 'name' && msg.pushName?.toLowerCase() === i.value.toLowerCase()))) return;

            // 5. Lógica de Silêncio e Chamada por Nome
            let shouldRespond = true;
            const myId = sock.user?.id || sock.authState.creds.me?.id;
            const isMentioned = msg.message.extendedTextMessage?.contextInfo?.mentionedJid?.some(m => areJidsSameUser(m, myId));
            const isQuoted = msg.message.extendedTextMessage?.contextInfo?.participant && areJidsSameUser(msg.message.extendedTextMessage.contextInfo.participant, myId);
            const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
            const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());
            const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

            if (silenceTime > 0) {
                const lastTime = lastResponseTimes[jid] || 0;
                const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);
                if (!isMentioned && !isQuoted && !isNameCalled && timeDiffMinutes < silenceTime) shouldRespond = false;
            }

            // --- VERIFICAÇÃO DE DISPAROS POR PALAVRAS (AUTO-RESPONDER) ---
            let triggeredResponse = null;
            let fallbackResponse = null;

            // 1. Verifica Regras ESPECÍFICAS DO GRUPO (Prioridade Alta)
            if (groupConfig && groupConfig.autoResponder && groupConfig.autoResponder.length > 0 && !isAudio) {
                const lowerText = texto.toLowerCase().trim();
                for (const trigger of groupConfig.autoResponder) {
                    if (!trigger.response) continue;
                    if (trigger.matchType === 'all') {
                        if (!fallbackResponse) fallbackResponse = trigger.response;
                        continue;
                    }
                    if (!trigger.keyword) continue;
                    const lowerKeyword = trigger.keyword.toLowerCase().trim();
                    
                    if (trigger.matchType === 'exact' && lowerText === lowerKeyword) {
                        triggeredResponse = trigger.response; 
                        break;
                    } else if (trigger.matchType === 'contains' && lowerText.includes(lowerKeyword)) {
                        triggeredResponse = trigger.response; 
                        break;
                    }
                }
            }

            // 2. Se não achou no grupo, verifica Regras GLOBAIS do Bot (Prioridade Média)
            if (!triggeredResponse && autoResponder && autoResponder.length > 0 && !isAudio) {
                const lowerText = texto.toLowerCase().trim();
                for (const trigger of autoResponder) {
                    if (!trigger.response) continue;
                    if (trigger.matchType === 'all') {
                        if (!fallbackResponse) fallbackResponse = trigger.response;
                        continue;
                    }
                    if (!trigger.keyword) continue;
                    const lowerKeyword = trigger.keyword.toLowerCase().trim();
                    
                    if (trigger.matchType === 'exact' && lowerText === lowerKeyword) {
                        triggeredResponse = trigger.response; 
                        break;
                    } else if (trigger.matchType === 'contains' && lowerText.includes(lowerKeyword)) {
                        triggeredResponse = trigger.response; 
                        break;
                    }
                }
            }

            // Se achou palavra-chave ESPECÍFICA (Grupo ou Global), responde na hora
            if (triggeredResponse) {
                await sock.readMessages([msg.key]);
                await sock.sendPresenceUpdate('composing', jid);
                await delay(1000);
                const sentTrig = await sock.sendMessage(jid, { text: triggeredResponse + '\u200B' }, { quoted: msg });
                if (sentTrig) {
                    messageStore.add(sentTrig.key, sentTrig.message);
                    await saveLiveMessage(sock, jid, 'Bot (Gatilho)', { id: sentTrig.key.id, fromMe: true, text: triggeredResponse, timestamp: Date.now() });
                }
                lastResponseTimes[jid] = Date.now();
                await sock.sendPresenceUpdate('paused', jid);
                return; 
            }

            // Se NÃO achou palavra-chave, verifica se o bot deve ficar em silêncio
            if (!shouldRespond) return;

            // Se tem resposta padrão (Qualquer Mensagem) e o bot NÃO está em silêncio
            if (fallbackResponse) {
                await sock.readMessages([msg.key]);
                await sock.sendPresenceUpdate('composing', jid);
                await delay(1000);
                const sentFall = await sock.sendMessage(jid, { text: fallbackResponse + '\u200B' }, { quoted: msg });
                if (sentFall) {
                    messageStore.add(sentFall.key, sentFall.message);
                    await saveLiveMessage(sock, jid, 'Bot (Regra)', { id: sentFall.key.id, fromMe: true, text: fallbackResponse, timestamp: Date.now() });
                }
                lastResponseTimes[jid] = Date.now();
                await sock.sendPresenceUpdate('paused', jid);
                return;
            }

            // VERIFICAÇÃO SE A IA DEVE RESPONDER
            let useAI = true;
            if (groupConfig) {
                // Se for grupo, respeita a config do grupo (se undefined, assume true)
                useAI = groupConfig.aiFallbackEnabled !== false;
            } else {
                // Se for individual, usa a config global
                useAI = aiFallbackEnabledGlobal;
            }

            if (!useAI) return; // SE A IA ESTIVER DESMARCADA, PARA AQUI E O ROBO FICA EM SILÊNCIO

            // 6. Processamento IA
            try {
                console.log(`[DEBUG] Mensagem recebida de ${jid}. Enviando 'composing'...`);
                await sock.readMessages([msg.key]);
                await sock.sendPresenceUpdate('composing', jid);
                await delay(1000); 
                
                let audioBuffer = null;
                if (isAudio) {
                    console.log(`[DEBUG] Baixando áudio...`);
                    audioBuffer = (await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage })).toString('base64');
                }

                let basePrompt = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;
                const promptToUse = buildEnhancedPrompt(basePrompt, groupConfig);

                const resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio, promptToUse);
                
                if (resposta && resposta.trim().length > 0) {
                    try {
                        const sentIA = await sock.sendMessage(jid, { text: resposta + '\u200B' }, { quoted: msg });
                        if (sentIA) {
                            messageStore.add(sentIA.key, sentIA.message);
                            await saveLiveMessage(sock, jid, 'Bot (IA)', { id: sentIA.key.id, fromMe: true, text: resposta, timestamp: Date.now() });
                        }
                        lastResponseTimes[jid] = Date.now();
                    } catch (sendErr) {
                        console.error(`[${nomeSessao}] Falha ao enviar resposta da IA (usuário bloqueou ou erro de rede):`, sendErr.message);
                    }

                    if (notificationNumber) {
                        try {
                            const adminJid = notificationNumber.replace(/\D/g, '') + '@s.whatsapp.net';
                            const clientName = msg.pushName || sender.split('@')[0];
                            const msgNotif = `🔔 O cliente ${clientName} mandou uma mensagem e eu respondi.`;
                            await sock.sendMessage(adminJid, { text: msgNotif });
                        } catch (errNotif) { console.error(`[ERRO NOTIFICAÇÃO]`, errNotif); }
                    }
                }
                await sock.sendPresenceUpdate('paused', jid);
            } catch (e) { 
                console.error('[ERRO CRÍTICO NO LOOP]:', e.message || e); 
                try {
                    // Tenta tirar o "digitando...", mas não quebra o bot se a conexão tiver caído
                    await sock.sendPresenceUpdate('paused', jid);
                } catch (errPresence) {
                    // Ignora silenciosamente, pois a conexão já foi fechada/reiniciada
                }
            }
        });
    }

    ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
}

process.on('uncaughtException', (err) => { console.error('Exceção não tratada:', err); });
process.on('unhandledRejection', (reason, promise) => { console.error('Rejeição não tratada:', reason); });
