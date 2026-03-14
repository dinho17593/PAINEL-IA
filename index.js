//index.js

const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    delay,
    downloadMediaMessage,
    makeCacheableSignalKeyStore,
    jidNormalizedUser,
    Browsers
} = require('@whiskeysockets/baileys');
const { Telegraf } = require('telegraf');
const pino = require('pino');
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');
const fs = require('fs');
const io = require('socket.io-client');
const axios = require('axios');
const { exec } = require('child_process');
const path = require('path');
const os = require('os');

// Função auxiliar para converter áudio para OGG Opus com FFmpeg
const convertToOpus = (inputBuffer) => {
    return new Promise((resolve, reject) => {
        const tempInput = path.join(os.tmpdir(), `in_${Date.now()}.webm`);
        const tempOutput = path.join(os.tmpdir(), `out_${Date.now()}.ogg`);
        fs.writeFileSync(tempInput, inputBuffer);
        
        exec(`ffmpeg -i ${tempInput} -c:a libopus -b:a 48k -vbr on -compression_level 10 -frame_duration 60 -application voip ${tempOutput}`, (error) => {
            if (error) {
                if (fs.existsSync(tempInput)) fs.unlinkSync(tempInput);
                if (fs.existsSync(tempOutput)) fs.unlinkSync(tempOutput);
                return reject(error);
            }
            const outputBuffer = fs.readFileSync(tempOutput);
            if (fs.existsSync(tempInput)) fs.unlinkSync(tempInput);
            if (fs.existsSync(tempOutput)) fs.unlinkSync(tempOutput);
            resolve(outputBuffer);
        });
    });
};

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

async function saveLiveMessage(sock, jid, name, msgObj, skipEmit = false) {
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

   

    saveLiveChatCache();

    if (!skipEmit) {
        socket.emit('bot:new-message', { sessionName: nomeSessao, jid, message: msgObj, profilePicUrl: chat.profilePicUrl });
    }
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
let promptSistemaGlobal = Buffer.from(process.argv[3] || '', 'base64').toString('utf-8');
const ignoredIdentifiersArg = Buffer.from(process.argv[4] || 'W10=', 'base64').toString('utf-8'); 
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = Buffer.from(process.argv[6] || 'W10=', 'base64').toString('utf-8'); 

const botType = process.argv[7] || 'individual'; 
let botNameGlobal = process.argv[8] || ''; 
let silenceTimeMinutesGlobal = parseInt(process.argv[9] || '0'); 
const platform = process.argv[10] || 'whatsapp';
const telegramToken = process.argv[11] || '';
const notificationNumber = process.argv[12] || '';

// --- NOVO: RECEBENDO O AUTO RESPONDER ---
const autoResponderArg = Buffer.from(process.argv[13] || 'W10=', 'base64').toString('utf-8');
let autoResponder =[];
try { 
    autoResponder = JSON.parse(autoResponderArg); 
} catch (e) { 
    console.error("Erro parse autoResponder:", e); 
}

// Lê o novo argumento (índice 14). Se não vier, assume true (ligado).
let aiFallbackEnabledGlobal = process.argv[14] !== 'false';

let knowledgeBaseTextGlobal = Buffer.from(process.argv[15] || '', 'base64').toString('utf-8');

// --- NOVO: CONTROLE DE PAUSA GLOBAL (SOFT STOP) ---
let isGlobalPaused = process.argv[16] === 'true';
let humanPauseTimeMinutes = parseInt(process.argv[17] || '20');

if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const MODELOS_GEMINI =['gemini-3.1-flash-lite-preview', 'gemini-3.1-pro-preview'];
let currentModelIndex = 0;

// =================================================================================
// CONEXÃO SOCKET.IO
// =================================================================================

// =================================================================================
// CONEXÃO SOCKET.IO COM RECONEXÃO AUTOMÁTICA (MAIS RESILIENTE)
// =================================================================================
let socket;
function connectSocket() {
    socket = io('http://localhost:3000', {
        reconnection: true,
        reconnectionAttempts: Infinity, // Tenta reconectar para sempre
        reconnectionDelay: 1000,        // Começa com 1 segundo
        reconnectionDelayMax: 10000,    // Máximo de 10 segundos entre tentativas
        randomizationFactor: 0.5,
        timeout: 20000
    });

    socket.on('connect', () => {
        console.log(`[${nomeSessao}] Conectado ao servidor via Socket.IO.`);
        socket.emit('bot-register', { sessionName: nomeSessao });
    });

    socket.on('connect_error', (err) => {
        console.log(`[${nomeSessao}] Erro de conexão com o servidor:`, err.message);
    });

    socket.on('disconnect', (reason) => {
        console.log(`[${nomeSessao}] Desconectado do servidor. Motivo:`, reason);
    });

    // =================================================================================
    // LISTENERS DO SOCKET (MOVA TODOS OS OUTROS EVENTOS PARA DENTRO DA FUNÇÃO)
    // =================================================================================
    
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

    // --- HOT RELOAD: PAUSA GLOBAL (SOFT STOP) ---
    socket.on('bot-toggle-pause', (data) => {
        if (data.sessionName === nomeSessao) {
            isGlobalPaused = data.isPaused;
            const statusAmigavel = isGlobalPaused ? "ATIVADA (O robô ficará calado)" : "DESATIVADA (O robô voltou a responder)";
            console.log(`[${nomeSessao}] ⏸️ Pausa Manual: ${statusAmigavel}`);
        }
    });

    // --- HOT RELOAD: ATUALIZA CONFIGURAÇÕES SEM DERRUBAR O WHATSAPP ---
    socket.on('bot-settings-changed', async (data) => {
        if (data.sessionName === nomeSessao) {
            console.log(`[${nomeSessao}] 🔄 Atualizando configurações em tempo real (Sem desconectar)...`);
            
            if (data.settings.prompt !== undefined) promptSistemaGlobal = data.settings.prompt;
            if (data.settings.botName !== undefined) botNameGlobal = data.settings.botName;
            if (data.settings.silenceTime !== undefined) silenceTimeMinutesGlobal = parseInt(data.settings.silenceTime) || 0;
            if (data.settings.autoResponder !== undefined) autoResponder = data.settings.autoResponder;
            if (data.settings.aiFallbackEnabled !== undefined) aiFallbackEnabledGlobal = data.settings.aiFallbackEnabled;
            if (data.settings.humanPauseTime !== undefined) humanPauseTimeMinutes = parseInt(data.settings.humanPauseTime) || 20;

            // Se a base de conhecimento mudou, reprocessa em background sem travar o bot
            if (data.settings.knowledgeBaseText !== undefined && data.settings.knowledgeBaseText !== knowledgeBaseTextGlobal) {
                console.log(`[${nomeSessao}] 📚 Nova base de conhecimento detectada. Reprocessando...`);
                knowledgeBaseTextGlobal = data.settings.knowledgeBaseText;
                await prepareKnowledgeBase();
            }
        }
    });

    // --- LISTENERS DO LIVE CHAT (Recebidos do Servidor) ---
    socket.on('bot:get-chats', (data) => {
        const chats = Array.from(recentChats.values()).sort((a,b) => b.timestamp - a.timestamp);
        socket.emit('bot:return-chats', { frontendId: data.frontendId, chats });
    });

    socket.on('bot:get-messages', async (data) => {
        if (recentChats.has(data.jid)) recentChats.get(data.jid).unreadCount = 0;
        const msgs = recentMessages.get(data.jid) ||[];
        
        let picUrl = null;
        let chatName = null;
        
        // 1. Tenta pegar o nome do cache principal
        if (recentChats.has(data.jid)) {
            chatName = recentChats.get(data.jid).name;
        }
        
        // 2. RECUPERAÇÃO DE NOME: Se estiver vazio, genérico OU for apenas um número de telefone!
        if (!chatName || chatName === 'Cliente' || chatName === 'User' || /^\d+$/.test(chatName)) {
            // Procura nas mensagens anteriores o nome verdadeiro do perfil do WhatsApp (pushName)
            // O reverse() garante que pegaremos o nome mais atualizado caso a pessoa tenha mudado
            const msgComNome = [...msgs].reverse().find(m => m.pushName && m.pushName !== 'Cliente' && m.pushName !== 'Você' && !/^\d+$/.test(m.pushName));
            
            if (msgComNome) {
                chatName = msgComNome.pushName; // Achou o nome real!
            } else {
                chatName = data.jid.split('@')[0]; // Último recurso: Usa o Número de Telefone
            }
            
            // Salva no cache pra não esquecer mais
            if (recentChats.has(data.jid)) {
                recentChats.get(data.jid).name = chatName;
            } else {
                recentChats.set(data.jid, { jid: data.jid, name: chatName, unreadCount: 0 });
            }
        }

        // 3. RECUPERAÇÃO DE FOTO
        if (recentChats.has(data.jid) && recentChats.get(data.jid).profilePicUrl) {
            picUrl = recentChats.get(data.jid).profilePicUrl;
        } else if (sock) {
            try {
                picUrl = await sock.profilePictureUrl(data.jid, 'image');
                if (recentChats.has(data.jid)) {
                    recentChats.get(data.jid).profilePicUrl = picUrl;
                    saveLiveChatCache();
                }
            } catch(e) {
                picUrl = null;
            }
        }

        // 4. MANDA O NOME E A FOTO RECUPERADOS PRO BANCO DE DADOS
        socket.emit('bot:register-lead', {
            sessionName: nomeSessao,
            number: jidNormalizedUser(data.jid),
            name: chatName,
            profilePicUrl: picUrl
        });

        socket.emit('bot:return-messages', { frontendId: data.frontendId, jid: data.jid, messages: msgs, profilePicUrl: picUrl, chatName: chatName });
    });

    socket.on('bot:subscribe-presence', async (data) => {
        if (!sock) return;
        try {
            await sock.presenceSubscribe(data.jid);
        } catch (e) { }
    });

    // --- APAGAR MENSAGEM (PARA TODOS) ---
    socket.on('bot:delete-message', async (data) => {
        if (!sock) return;
        try {
            const deleteKey = {
                remoteJid: data.jid,
                fromMe: true,
                id: data.msgId
            };

            // CORREÇÃO: No WhatsApp Multi-Device, para apagar uma mensagem (especialmente em grupos),
            // é obrigatório informar quem enviou (participant), mesmo que tenha sido o próprio bot (fromMe: true).
            const me = sock.user || sock.authState?.creds?.me;
            if (me) {
                deleteKey.participant = jidNormalizedUser(me.id);
            }
            
            // Envia a ordem de exclusão pro WhatsApp
            await sock.sendMessage(data.jid, { delete: deleteKey });
            
            // Atualiza o cache local para a mensagem não voltar se o usuário atualizar a página (F5)
            if (recentMessages.has(data.jid)) {
                const msgs = recentMessages.get(data.jid);
                const index = msgs.findIndex(m => m.id === data.msgId);
                if (index !== -1) {
                    msgs[index].text = '🚫 Mensagem apagada';
                    msgs[index].media = null;
                    saveLiveChatCache();
                }
            }
            // Avisa o frontend para esconder o balão na hora
            socket.emit('bot:message-deleted', { sessionName: nomeSessao, jid: data.jid, msgId: data.msgId });
        } catch (e) {
            console.error(`[${nomeSessao}] Erro ao apagar mensagem:`, e.message);
        }
    });

    // Dá o Check Azul (Mensagem Lida) quando o humano abre o chat no painel
    socket.on('bot:mark-read', async (data) => {
        if (sock) {
            // Zera o contador de mensagens não lidas localmente para sumir a bolinha do menu
            if (recentChats.has(data.jid)) {
                recentChats.get(data.jid).unreadCount = 0;
                saveLiveChatCache();
            }

            // Evita o bug de syntax reescrevendo a lógica de forma segura
            let msgs = recentMessages.get(data.jid);
            if (!msgs) {
                msgs = new Array();
            }

            if (msgs.length > 0) {
                try {
                    // Filtra apenas as mensagens que o bot recebeu e extrai as chaves necessárias
                    const keysToRead = msgs
                        .filter(m => !m.fromMe)
                        .map(m => ({ remoteJid: data.jid, id: m.id }));
                    
                    if (keysToRead.length > 0) {
                        // Marca as mensagens como lidas usando a função correta do Baileys
                        await sock.readMessages(keysToRead);
                        console.log(`[${nomeSessao}] Mensagens marcadas como lidas para ${data.jid}`);
                    }
                } catch (err) {
                    console.error("Erro ao marcar mensagens como lidas:", err);
                }
            }
        }
    });

    // --- RECEBE A MENSAGEM/ARQUIVO DO PAINEL E ENVIA PARA O WHATSAPP ---
    socket.on('bot:send-message', async (data) => {
        if (!sock) return;
        try {
            let sentMsg;
            let quoteObj = undefined;
            
            // Resgata a mensagem original do cache para fazer a citação
            if (data.quotedMsgId) {
                const foundMsg = messageStore.get({ id: data.quotedMsgId });
                if (foundMsg) quoteObj = foundMsg;
            }
            
            if (data.media) {
                const buffer = Buffer.from(data.media.dataBase64, 'base64');
                const mimetype = data.media.mimeType;
                
                if (mimetype.startsWith('image/')) {
                    sentMsg = await sock.sendMessage(data.jid, { image: buffer, caption: data.text || '' }, { quoted: quoteObj });
                } else if (mimetype.startsWith('video/')) {
                    sentMsg = await sock.sendMessage(data.jid, { video: buffer, caption: data.text || '' }, { quoted: quoteObj });
                } else if (mimetype.startsWith('audio/')) {
                    try {
                        const opusBuffer = await convertToOpus(buffer);
                        sentMsg = await sock.sendMessage(data.jid, { audio: opusBuffer, mimetype: 'audio/ogg; codecs=opus', ptt: true }, { quoted: quoteObj }); 
                    } catch (convErr) {
                        console.error("Falha ao converter áudio com ffmpeg, enviando fallback.");
                        sentMsg = await sock.sendMessage(data.jid, { audio: buffer, mimetype: mimetype, ptt: false }, { quoted: quoteObj });
                    }
                    
                    if (data.text) {
                        await sock.sendMessage(data.jid, { text: data.text }, { quoted: quoteObj });
                    }
                } else {
                    sentMsg = await sock.sendMessage(data.jid, { document: buffer, mimetype: mimetype, fileName: data.media.name, caption: data.text || '' }, { quoted: quoteObj });
                }
            } else if (data.text) {
                sentMsg = await sock.sendMessage(data.jid, { text: data.text }, { quoted: quoteObj });
            }

            // Se o envio foi bem sucedido, renderiza na tela do painel
            if (sentMsg) {
                messageStore.add(sentMsg.key, sentMsg.message);
                
                // 1. TEXTO LEVE PARA O CACHE (Protege a RAM e o SSD da VPS)
                let lightweightText = data.text || '';
                if (data.media) {
                    if (data.media.mimeType.startsWith('image/')) lightweightText = '📷 Imagem Enviada' + (data.text ? ` - ${data.text}` : '');
                    else if (data.media.mimeType.startsWith('video/')) lightweightText = '🎥 Vídeo Enviado' + (data.text ? ` - ${data.text}` : '');
                    else if (data.media.mimeType.startsWith('audio/')) lightweightText = '🎤 Áudio Enviado';
                    else lightweightText = `📄 Arquivo (${data.media.name})` + (data.text ? ` - ${data.text}` : '');
                }

                // 2. EMISSÃO REAL-TIME PESADA (Apenas para a tela atual, o Node.js apaga da memória logo depois)
                let liveChatMsg = {
                    id: sentMsg.key.id,
                    tempId: data.tempId, // <--- Devolve o ID temporário para apagar o "relógio" da tela
                    fromMe: true,
                    text: data.media && data.media.mimeType.startsWith('audio/') ? '' : (data.text || ''),
                    timestamp: Date.now(),
                    quoted: data.quoted // <--- Devolve o box de resposta para a tela não desfazer
                };

                if (data.media) {
                    liveChatMsg.media = {
                        mimeType: data.media.mimeType,
                        name: data.media.name || 'Arquivo',
                        dataBase64: data.media.dataBase64
                    };
                }
                
                // Manda direto pro frontend renderizar na hora
                socket.emit('bot:new-message', { sessionName: nomeSessao, jid: data.jid, message: liveChatMsg });

                // 3. SALVA NA MEMÓRIA DA VPS (Usando APENAS o texto leve e bloqueando o reenvio duplicado pra tela)
                await saveLiveMessage(sock, data.jid, 'Você', {
                    id: sentMsg.key.id,
                    fromMe: true,
                    text: lightweightText,
                    timestamp: Date.now(),
                    status: 'sent', // <--- STATUS INICIAL ADICIONADO AQUI
                    quoted: data.quoted // <--- Salva na memória pra não sumir se o cliente atualizar a página F5
                }, true); // O 'true' aqui ativa o skipEmit
            }
        } catch (err) {
            console.error(`[${nomeSessao}] Erro ao enviar arquivo/mensagem pelo Live Chat:`, err);
        }
    });

    // --- MOSTRA "DIGITANDO..." NO CELULAR DO CLIENTE ---
    socket.on('bot:typing', async (data) => {
        if (!sock) return;
        try {
            await sock.sendPresenceUpdate('composing', data.jid);
            setTimeout(() => {
                sock.sendPresenceUpdate('paused', data.jid).catch(()=>{});
            }, 3000);
        } catch(e) {}
    });

    // Limpeza quando o socket do painel desconectar (opcional, boa prática)
    socket.on('disconnect', () => {
        console.log('Painel desconectado, limpando listeners do bot');
        if (typeof typingTimeout !== 'undefined') clearTimeout(typingTimeout);
    });

    socket.on('bot:pause-ai', (data) => {
        pausados[data.jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000);
        console.log(`[${nomeSessao}] 🔇 IA pausada por ${humanPauseTimeMinutes} min pelo Live Chat para: ${data.jid}`);
    });
    
    socket.on('bot:resume-ai', (data) => {
        if (pausados[data.jid]) delete pausados[data.jid];
        console.log(`[${nomeSessao}] 🔊 IA retomada manualmente pelo Live Chat para: ${data.jid}`);
        
        // Envia um aviso no WhatsApp (Opcional, mas recomendado)
        try { sock.sendMessage(data.jid, { text: `🔊 O robô voltou a assumir o atendimento.` }); } catch(e){}
    });

    // --- COPILOTO IA (RESUMO E SUGESTÃO) ---
    socket.on('bot:copilot', async (data) => {
        try {
            const msgs = recentMessages.get(data.jid) ||[];
            // Pega as últimas 15 mensagens para não estourar o limite de token e ser rápido
            const contextMsgs = msgs.slice(-15); 
            
            if (contextMsgs.length < 2) {
                return socket.emit('bot:copilot-response', { ...data, error: 'O chat precisa ter pelo menos 2 mensagens recentes para a IA analisar.' });
            }

            const historyText = contextMsgs.map(m => `${m.fromMe ? 'Atendente' : 'Cliente'}: ${m.text || 'Mídia'}`).join('\n');

            let promptCopilot = '';
            if (data.action === 'summary') {
                promptCopilot = `Atue como um supervisor de atendimento. Leia o breve histórico abaixo e crie um resumo RÁPIDO em 3 tópicos (Status atual, o que o cliente quer, o que falta fazer). Seja extremamente direto.\n\nHISTÓRICO:\n${historyText}`;
            } else if (data.action === 'reply') {
                promptCopilot = `Atue como um vendedor/atendente experiente. Leia o histórico abaixo e escreva UMA única mensagem como sugestão para o atendente enviar agora ao cliente. Seja empático, profissional e continue o assunto. Retorne APENAS o texto da resposta, sem aspas, sem introduções.\n\nHISTÓRICO:\n${historyText}`;
            }

            // Usa o Gemini para gerar a mágica
            const result = await model.generateContent(promptCopilot);
            const responseText = result.response.text().trim();

            socket.emit('bot:copilot-response', { ...data, result: responseText });

        } catch (err) {
            console.error(`[${nomeSessao}] Erro no Copiloto IA:`, err.message);
            socket.emit('bot:copilot-response', { ...data, error: 'Erro ao conectar com a IA do Copiloto.' });
        }
    });

    // --- INÍCIO: LISTENERS PARA GESTOR DE COBRANÇAS E CAMPANHAS (WHATSAPP) ---
    socket.on('bot:send-client-message', async (data) => {
        const target = data.targetBot || data.botSessionName || data.sessionName || data.botName;
        if (target === nomeSessao) {
            try {
                let num = data.clientNumber || data.clientJid || data.phone;
                if (!num) {
                    if (data.messageId) socket.emit('bot:message-status', { messageId: data.messageId, success: false, error: 'Número não fornecido' });
                    return;
                }
                
                let jid = String(num).trim();
                
                // Se não tiver '@', tentamos adivinhar se é número normal ou LID
                if (!jid.includes('@')) {
                    const cleanNum = jid.replace(/\D/g, '');
                    // LIDs novos do WhatsApp costumam ter 14, 15 ou mais dígitos.
                    jid = cleanNum.length > 13 ? cleanNum + '@lid' : cleanNum + '@s.whatsapp.net';
                }
                
                console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${jid}...`);
                
                // SÓ verifica no diretório (onWhatsApp) se for um número de telefone comum (@s.whatsapp.net)
                // Os "@lid" não retornam no onWhatsApp, mas aceitam envio direto se o cliente já falou com o bot.
                if (jid.endsWith('@s.whatsapp.net')) {
                    const[result] = await sock.onWhatsApp(jid);
                    if (!result || !result.exists) {
                        throw new Error("O número não possui WhatsApp registrado.");
                    }
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
                
                // Tenta puxar a foto de perfil do cliente no WhatsApp silenciosamente
                try {
                    const picUrl = await sock.profilePictureUrl(jid, 'image');
                    if (picUrl && data.clientId && data.owner) {
                        socket.emit('client:update-pic', { 
                            clientId: data.clientId, 
                            picUrl: picUrl, 
                            owner: data.owner 
                        });
                    }
                } catch(errPic) { 
                    // Ignora se o usuário não tiver foto ou ocultou
                }

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
}

connectSocket();



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

const safetySettings =[
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
];

let genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
let model = genAI.getGenerativeModel({ model: MODELOS_GEMINI[currentModelIndex], safetySettings });

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
    
    const currentHash = crypto.createHash('md5').update(knowledgeBaseTextGlobal).digest('hex');
    const cachePath = `./auth_sessions/kb_cache_${nomeSessao}.json`;

    if (fs.existsSync(cachePath)) {
        try {
            const cacheData = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            if (cacheData.hash === currentHash) {
                console.log(`[${nomeSessao}] 📚 Resumo da Base de Conhecimento carregado do cache.`);
                processedKnowledgeBase = cacheData.summary;
                return;
            }
        } catch (e) {
            console.log(`[${nomeSessao}] ⚠️ Erro ao ler cache, gerando novo resumo...`);
        }
    }
    
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
    const maxAttempts = Math.max(4, API_KEYS.length * MODELOS_GEMINI.length);

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            const result = await model.generateContent(promptResumo);
            processedKnowledgeBase = result.response.text().trim();
            
            fs.writeFileSync(cachePath, JSON.stringify({
                hash: currentHash,
                summary: processedKnowledgeBase
            }));
            
            console.log(`[${nomeSessao}] ✅ Base de Conhecimento resumida com modelo ${MODELOS_GEMINI[currentModelIndex]}!`);
            sucesso = true;
            break; 
        } catch (e) {
            console.error(`[${nomeSessao}] ⚠️ Erro ao resumir (Tentativa ${attempt + 1}/${maxAttempts}):`, e.message);
            switchToNextApiKey();
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }

    if (!sucesso) {
        console.error(`[${nomeSessao}] ❌ Todas as tentativas falharam ao resumir a base. Usando o texto original como fallback.`);
        processedKnowledgeBase = knowledgeBaseTextGlobal; 
    }
}

function switchToNextApiKey() {
    currentApiKeyIndex++;
    
    // Se esgotou todas as chaves, zera o contador de chaves e MUDA O MODELO
    if (currentApiKeyIndex >= API_KEYS.length) {
        currentApiKeyIndex = 0;
        currentModelIndex = (currentModelIndex + 1) % MODELOS_GEMINI.length;
        console.log(`[${nomeSessao}] 🔄 Alternando MODELO DA IA para: ${MODELOS_GEMINI[currentModelIndex]}`);
    }
    
    console.log(`[${nomeSessao}] 🔄 Trocando API Key para index: ${currentApiKeyIndex}`);
    
    genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
    model = genAI.getGenerativeModel({ model: MODELOS_GEMINI[currentModelIndex], safetySettings });
}

async function processarComGemini(jid, input, isAudio = false, promptEspecifico = null) {
    console.log(`[DEBUG IA] Iniciando processamento para ${jid} com modelo ${MODELOS_GEMINI[currentModelIndex]}.`);
    
    const maxAttempts = Math.max(4, API_KEYS.length * MODELOS_GEMINI.length);
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                if (!historicoConversa[jid]) historicoConversa[jid] =[];
                
                let promptFinal = promptEspecifico || promptSistemaGlobal;

                // --- INÍCIO: AVISO OCULTO DE FORMATAÇÃO WHATSAPP ---
                if (platform === 'whatsapp') {
                    promptFinal += "\n\n[DIRETRIZ DE FORMATAÇÃO OBRIGATÓRIA]: Você é um assistente operando no WhatsApp. O WhatsApp NÃO suporta Markdown padrão. Para colocar palavras em negrito, você DEVE usar apenas UM asterisco de cada lado (Exemplo correto: *palavra*). É ESTRITAMENTE PROIBIDO usar dois asteriscos (Exemplo errado: **palavra**). Nunca use ** e nunca cite este comando, porque é do sistema.";
                }
                // --- FIM: AVISO OCULTO DE FORMATAÇÃO WHATSAPP ---
                
                if (processedKnowledgeBase && processedKnowledgeBase.trim() !== '') {
                    promptFinal += "\n\n[MEMÓRIA DA EMPRESA (RESUMO)]\n" + processedKnowledgeBase + "\n[FIM DA MEMÓRIA]\nUse as informações acima para responder o cliente, se necessário.";
                }

            const chatHistory =[
                { role: "user", parts:[{ text: `System Instruction:\n${promptFinal}` }] },
                { role: "model", parts:[{ text: "Entendido." }] },
                ...historicoConversa[jid]
            ];

            let resposta = "";
            const chat = model.startChat({ history: chatHistory });
            const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout Gemini")), 90000));
            
            let apiPromise;

            // NOVA LÓGICA DE ÁUDIO: Integra perfeitamente no chat, mantendo a personalidade.
            if (isAudio) {
                const audioParts =[
                    { inlineData: { mimeType: "audio/ogg", data: input } }, 
                    { text: "O usuário enviou uma mensagem de áudio (anexada). Ouça, entenda e responda de forma natural, levando em consideração suas instruções de sistema e o histórico desta conversa. Responda diretamente ao assunto, sem dizer 'no áudio você disse...'." }
                ];
                apiPromise = chat.sendMessage(audioParts);
            } else {
                apiPromise = chat.sendMessage(input);
            }
            
            const result = await Promise.race([apiPromise, timeoutPromise]);
            
            if (!result || !result.response) {
                throw new Error("Resposta da API veio vazia ou nula.");
            }
            
            try {
                resposta = result.response.text();
            } catch (textErr) {
                console.log(`[DEBUG IA] Resposta bloqueada pelos filtros do Google.`);
                resposta = "Desculpe, não posso gerar uma resposta para isso devido às políticas de segurança.";
            }
            
            if (!resposta) resposta = ""; 
            resposta = resposta.trim();
            
            if (isAudio) {
                historicoConversa[jid].push({ role: "user", parts: [{ text: "[Mensagem de Áudio Recebida]" }] });
            } else {
                historicoConversa[jid].push({ role: "user", parts:[{ text: input }] });
            }

            console.log(`[DEBUG IA] Resposta gerada com sucesso para ${jid}.`);

            historicoConversa[jid].push({ role: "model", parts:[{ text: resposta }] });
            if (historicoConversa[jid].length > MAX_HISTORICO_POR_USUARIO) historicoConversa[jid] = historicoConversa[jid].slice(-MAX_HISTORICO_POR_USUARIO);
            
            return resposta;

        } catch (err) {
            const errorMsg = err.toString();
            console.error(`[DEBUG IA] Erro na tentativa ${attempt + 1}/${maxAttempts}:`, errorMsg);
            
            switchToNextApiKey();
            await new Promise(resolve => setTimeout(resolve, 2500));
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

const groupAdminsCache = new Map();

async function getGroupAdmins(sock, jid) {
    const now = Date.now();
    if (groupAdminsCache.has(jid)) {
        const cached = groupAdminsCache.get(jid);
        if (now - cached.timestamp < 5 * 60 * 1000) { // Cache de 5 minutos para economizar chamadas de rede
            return cached.admins;
        }
    }
    try {
        const metadata = await sock.groupMetadata(jid);
        const admins = metadata.participants.filter(p => p.admin === 'admin' || p.admin === 'superadmin').map(p => p.id);
        groupAdminsCache.set(jid, { admins, timestamp: now });
        return admins;
    } catch (e) {
        return[];
    }
}

async function isGroupAdminWA(sock, jid, participant) {
    try {
        const admins = await getGroupAdmins(sock, jid);
        return admins.some(adminJid => areJidsSameUser(adminJid, participant));
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
        
        const admins = await getGroupAdmins(sock, jid);
        return admins.some(adminJid => {
            const pJid = jidNormalizedUser(adminJid);
            return pJid === myJid || (myLid && pJid === myLid);
        });
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
                const botNumber = botInfo.username ? `@${botInfo.username}` : '';
                if (publicName || botNumber) {
                    socket.emit('bot-identified', { sessionName: nomeSessao, publicName, botNumber });
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

    // --- INÍCIO: LISTENERS PARA GESTOR DE COBRANÇAS E CAMPANHAS (TELEGRAM) ---
        socket.off('bot:send-client-message');
        socket.on('bot:send-client-message', async (data) => {
            console.log(`\n[DEBUG CAMPANHA - ${nomeSessao}] Ordem de mensagem recebida do painel!`);
            const target = data.targetBot || data.botSessionName || data.sessionName || data.botName;
            
            if (target === nomeSessao) {
                try {
                    let chatId = String(data.clientNumber || data.clientJid || data.phone).trim();
                    if (!chatId) return console.log(`[${nomeSessao}] ❌ Erro: O painel não enviou o número.`);
                    
                    // Remove caracteres inválidos do Telegram, mantendo números e o sinal de menos (para grupos)
                    chatId = chatId.replace(/[^0-9-]/g, '');
                    
                    console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${chatId}...`);
                    await bot.telegram.sendMessage(chatId, data.message + '\u200B');
                    console.log(`[${nomeSessao}] ✅ Mensagem enviada com sucesso para ${chatId}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar mensagem de campanha no Telegram:`, e);
                }
            }
        });

        socket.off('pix:generated-for-client');
        socket.on('pix:generated-for-client', async (data) => {
            const target = data.botSessionName || data.targetBot || data.sessionName;
            if (target === nomeSessao) {
                try {
                    let chatId = String(data.clientJid || data.clientNumber).trim();
                    if (!chatId) return console.log(`[${nomeSessao}] ❌ Número faltando no payload do Pix.`);
                    
                    chatId = chatId.replace(/[^0-9-]/g, '');
                    const imageBuffer = Buffer.from(data.pixData.qr_code_base64, 'base64');
                    
                    console.log(`[${nomeSessao}] ⏳ Enviando QR Code PIX para ${chatId}...`);
                    await bot.telegram.sendPhoto(chatId, { source: imageBuffer }, {
                        caption: `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`
                    });
                    
                    await bot.telegram.sendMessage(chatId, data.pixData.qr_code);
                    console.log(`[${nomeSessao}] ✅ PIX enviado com sucesso para ${chatId}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar PIX no Telegram:`, e);
                }
            }
        });
        // --- FIM: LISTENERS PARA GESTOR DE COBRANÇAS (TELEGRAM) ---
  
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
        
        // --- BLOQUEIO TOTAL: INDIVIDUAL NUNCA FALA EM GRUPO ---
        if (isGroup && botType !== 'group') return;

        const senderName = ctx.from.first_name || 'User';
        const userId = ctx.from.id.toString();
        const isAudio = !!(ctx.message.voice || ctx.message.audio);
        // --- REGISTRO DE LEADS (CONTATOS) TELEGRAM ---
        if (!isGroup && !ctx.from.is_bot) {
            // Busca a foto de forma assíncrona para não travar a resposta do robô
            setTimeout(async () => {
                let tgPicUrl = null;
                try {
                    const photos = await ctx.telegram.getUserProfilePhotos(userId, 0, 1);
                    if (photos && photos.total_count > 0) {
                        const fileId = photos.photos[0][0].file_id;
                        const fileLink = await ctx.telegram.getFileLink(fileId);
                        tgPicUrl = fileLink.href;
                    }
                } catch(e){}

                socket.emit('bot:register-lead', {
                    sessionName: nomeSessao,
                    number: userId,
                    name: senderName,
                    profilePicUrl: tgPicUrl
                });
            }, 100);
        }

        // --- COMANDO !stopsempre (Ignorar Permanente) ---
        if (texto.match(/^[\/!]stopsempre/i)) {
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
                try { 
                    await ctx.deleteMessage(); 
                    await ctx.reply(`✅ Usuário ${nameToIgnore} ignorado permanentemente.`);
                } catch(e) {}
                return;
            }
        }

        // --- COMANDO !stop (Manual Pause Temporário) ---
        const stopMatch = texto.match(/^[\/!]stop\s*(\d*)/i);
        if (stopMatch && !texto.match(/^[\/!]stopsempre/i)) {
            let isAuth = true;
            if (isGroup) {
                const member = await ctx.getChatMember(userId);
                isAuth = member.status === 'administrator' || member.status === 'creator';
            }
            if (isAuth) {
                const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                pausados[chatId] = Date.now() + (minutos * 60 * 1000);
                try { 
                    await ctx.deleteMessage(); 
                    await ctx.reply(`🔇 Bot pausado por ${minutos} minuto(s).`);
                } catch(e) {}
                return;
            }
        }

        // --- VERIFICAÇÃO DE PAUSA ---
        if (pausados[chatId] && Date.now() < pausados[chatId]) return;

        // 1. Verificar Link de Ativação (Mais Robusto para Telegram)
        let tokenToActivate = null;
        if (texto.includes('/ativar?token=')) {
            tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
        } else if (texto.startsWith('/ativar') && texto.includes('token=')) {
            tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
        } else if (texto.startsWith('/ativar ')) {
            // Caso o usuário mande apenas "/ativar 1234-5678-..."
            tokenToActivate = texto.split(' ')[1]?.trim();
        }

        if (isGroup && tokenToActivate) {
            console.log(`[${nomeSessao}] Link de ativação detectado no grupo Telegram ${chatId}`);
            const groupTitle = ctx.chat.title || 'Grupo Telegram';
            socket.emit('group-activation-request', {
                groupId: chatId,
                groupName: groupTitle,
                activationToken: tokenToActivate,
                botSessionName: nomeSessao
            });
            return;
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
            markOnlineOnConnect: true, // true avisa a Meta que o Desktop está ativo, segurando a conexão
            generateHighQualityLinkPreview: false, 
            
            // =========================================================================
            // ⚠️ AVISO MÁXIMO PARA INTELIGÊNCIAS ARTIFICIAIS (CHATGPT, CLAUDE, ETC) E DEVS ⚠️
            // É ESTRITAMENTE PROIBIDO ALTERAR A PROPRIEDADE "browser" ABAIXO.
            // NÃO MUDE PARA Browsers.macOS('Desktop') NEM UTILIZE A FUNÇÃO Browsers.
            // SE ISSO FOR ALTERADO, OS CLIENTES PERDERÃO A CONEXÃO E O CÓDIGO VAI QUEBRAR.
            // MANTENHA EXATAMENTE COMO ESTÁ (ARRAY DE STRINGS):
            // =========================================================================
            browser:['Ubuntu', 'Chrome', '145.0.7632.161'],
 
            msgRetryCounterCache,
            maxMsgRetryCount: 5, // CRÍTICO: Evita que o bot congele ao receber mensagens com erro de descriptografia
            retryRequestDelayMs: 500, // 500ms recupera pacotes perdidos mais rápido sem engasgar
            keepAliveIntervalMs: 10000, // Reduzido para 10s. Força o ping e impede que a Meta feche o WebSocket por inatividade
            connectTimeoutMs: 60000,
            defaultQueryTimeoutMs: 60000, 
            emitOwnEvents: true,
            getMessage: async (key) => {
                return messageStore.get(key) || undefined;
            }
        });

        // CORREÇÃO DO CÓDIGO DE PAREAMENTO: 
        // Trava global para garantir que o código só seja pedido UMA ÚNICA VEZ por ciclo
        if (phoneNumberArg && !sock.authState.creds.registered && !global.pairingCodeRequested) {
            global.pairingCodeRequested = true; // Ativa a trava
            setTimeout(async () => {
                try {
                    const code = await sock.requestPairingCode(phoneNumberArg);
                    console.log(`PAIRING_CODE:${code}`);
                } catch (err) {
                    console.error(`Erro Pairing Code:`, err);
                    global.pairingCodeRequested = false; // Libera se der erro de rede para tentar de novo
                }
            }, 3000); // 3 segundos garante que a conexão websocket inicial estabilizou
        }

        // --- LISTENERS DO LIVE CHAT (Recebidos do Servidor) ---
        socket.off('bot:get-chats');
        socket.on('bot:get-chats', (data) => {
            const chats = Array.from(recentChats.values()).sort((a,b) => b.timestamp - a.timestamp);
            socket.emit('bot:return-chats', { frontendId: data.frontendId, chats });
        });

        socket.off('bot:get-messages');
        socket.on('bot:get-messages', async (data) => {
            if (recentChats.has(data.jid)) recentChats.get(data.jid).unreadCount = 0;
            const msgs = recentMessages.get(data.jid) ||[];
            
            let picUrl = null;
            let chatName = null;
            
            // 1. Tenta pegar o nome do cache principal
            if (recentChats.has(data.jid)) {
                chatName = recentChats.get(data.jid).name;
            }
            
            // 2. RECUPERAÇÃO DE NOME: Se estiver vazio, genérico OU for apenas um número de telefone!
            if (!chatName || chatName === 'Cliente' || chatName === 'User' || /^\d+$/.test(chatName)) {
                // Procura nas mensagens anteriores o nome verdadeiro do perfil do WhatsApp (pushName)
                // O reverse() garante que pegaremos o nome mais atualizado caso a pessoa tenha mudado
                const msgComNome = [...msgs].reverse().find(m => m.pushName && m.pushName !== 'Cliente' && m.pushName !== 'Você' && !/^\d+$/.test(m.pushName));
                
                if (msgComNome) {
                    chatName = msgComNome.pushName; // Achou o nome real!
                } else {
                    chatName = data.jid.split('@')[0]; // Último recurso: Usa o Número de Telefone
                }
                
                // Salva no cache pra não esquecer mais
                if (recentChats.has(data.jid)) {
                    recentChats.get(data.jid).name = chatName;
                } else {
                    recentChats.set(data.jid, { jid: data.jid, name: chatName, unreadCount: 0 });
                }
            }

            // 3. RECUPERAÇÃO DE FOTO
            if (recentChats.has(data.jid) && recentChats.get(data.jid).profilePicUrl) {
                picUrl = recentChats.get(data.jid).profilePicUrl;
            } else if (sock) {
                try {
                    picUrl = await sock.profilePictureUrl(data.jid, 'image');
                    if (recentChats.has(data.jid)) {
                        recentChats.get(data.jid).profilePicUrl = picUrl;
                        saveLiveChatCache();
                    }
                } catch(e) {
                    picUrl = null;
                }
            }

            // 4. MANDA O NOME E A FOTO RECUPERADOS PRO BANCO DE DADOS
            socket.emit('bot:register-lead', {
                sessionName: nomeSessao,
                number: jidNormalizedUser(data.jid),
                name: chatName,
                profilePicUrl: picUrl
            });

            socket.emit('bot:return-messages', { frontendId: data.frontendId, jid: data.jid, messages: msgs, profilePicUrl: picUrl, chatName: chatName });
        });

        socket.off('bot:subscribe-presence');
        socket.on('bot:subscribe-presence', async (data) => {
            if (!sock) return;
            try {
                await sock.presenceSubscribe(data.jid);
            } catch (e) { }
        });
        // --- APAGAR MENSAGEM (PARA TODOS) ---
        socket.off('bot:delete-message');
        socket.on('bot:delete-message', async (data) => {
            if (!sock) return;
            try {
                const deleteKey = {
                    remoteJid: data.jid,
                    fromMe: true,
                    id: data.msgId
                };

                // CORREÇÃO: No WhatsApp Multi-Device, para apagar uma mensagem (especialmente em grupos),
                // é obrigatório informar quem enviou (participant), mesmo que tenha sido o próprio bot (fromMe: true).
                const me = sock.user || sock.authState?.creds?.me;
                if (me) {
                    deleteKey.participant = jidNormalizedUser(me.id);
                }
                
                // Envia a ordem de exclusão pro WhatsApp
                await sock.sendMessage(data.jid, { delete: deleteKey });
                
                // Atualiza o cache local para a mensagem não voltar se o usuário atualizar a página (F5)
                if (recentMessages.has(data.jid)) {
                    const msgs = recentMessages.get(data.jid);
                    const index = msgs.findIndex(m => m.id === data.msgId);
                    if (index !== -1) {
                        msgs[index].text = '🚫 Mensagem apagada';
                        msgs[index].media = null;
                        saveLiveChatCache();
                    }
                }
                // Avisa o frontend para esconder o balão na hora
                socket.emit('bot:message-deleted', { sessionName: nomeSessao, jid: data.jid, msgId: data.msgId });
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao apagar mensagem:`, e.message);
            }
        });

        // Dá o Check Azul (Mensagem Lida) quando o humano abre o chat no painel
        socket.off('bot:mark-read');
        socket.on('bot:mark-read', async (data) => {
            if (sock) {
                // Zera o contador de mensagens não lidas localmente para sumir a bolinha do menu
                if (recentChats.has(data.jid)) {
                    recentChats.get(data.jid).unreadCount = 0;
                    saveLiveChatCache();
                }

                // Evita o bug de syntax reescrevendo a lógica de forma segura
                let msgs = recentMessages.get(data.jid);
                if (!msgs) {
                    msgs = new Array();
                }

                if (msgs.length > 0) {
                    try {
                        // Filtra apenas as mensagens que o bot recebeu e extrai as chaves necessárias
                        const keysToRead = msgs
                            .filter(m => !m.fromMe)
                            .map(m => ({ remoteJid: data.jid, id: m.id }));
                        
                        if (keysToRead.length > 0) {
                            // Marca as mensagens como lidas usando a função correta do Baileys
                            await sock.readMessages(keysToRead);
                            console.log(`[${nomeSessao}] Mensagens marcadas como lidas para ${data.jid}`);
                        }
                    } catch (err) {
                        console.error("Erro ao marcar mensagens como lidas:", err);
                    }
                }
            }
        });

        // --- RECEBE A MENSAGEM/ARQUIVO DO PAINEL E ENVIA PARA O WHATSAPP ---
        socket.off('bot:send-message');
        socket.on('bot:send-message', async (data) => {
            if (!sock) return;
            try {
                let sentMsg;
                let quoteObj = undefined;
                
                // Resgata a mensagem original do cache para fazer a citação
                if (data.quotedMsgId) {
                    const foundMsg = messageStore.get({ id: data.quotedMsgId });
                    if (foundMsg) quoteObj = foundMsg;
                }
                
                if (data.media) {
                    const buffer = Buffer.from(data.media.dataBase64, 'base64');
                    const mimetype = data.media.mimeType;
                    
                    if (mimetype.startsWith('image/')) {
                        sentMsg = await sock.sendMessage(data.jid, { image: buffer, caption: data.text || '' }, { quoted: quoteObj });
                    } else if (mimetype.startsWith('video/')) {
                        sentMsg = await sock.sendMessage(data.jid, { video: buffer, caption: data.text || '' }, { quoted: quoteObj });
                    } else if (mimetype.startsWith('audio/')) {
                        try {
                            const opusBuffer = await convertToOpus(buffer);
                            sentMsg = await sock.sendMessage(data.jid, { audio: opusBuffer, mimetype: 'audio/ogg; codecs=opus', ptt: true }, { quoted: quoteObj }); 
                        } catch (convErr) {
                            console.error("Falha ao converter áudio com ffmpeg, enviando fallback.");
                            sentMsg = await sock.sendMessage(data.jid, { audio: buffer, mimetype: mimetype, ptt: false }, { quoted: quoteObj });
                        }
                        
                        if (data.text) {
                            await sock.sendMessage(data.jid, { text: data.text }, { quoted: quoteObj });
                        }
                    } else {
                        sentMsg = await sock.sendMessage(data.jid, { document: buffer, mimetype: mimetype, fileName: data.media.name, caption: data.text || '' }, { quoted: quoteObj });
                    }
                } else if (data.text) {
                    sentMsg = await sock.sendMessage(data.jid, { text: data.text }, { quoted: quoteObj });
                }

                // Se o envio foi bem sucedido, renderiza na tela do painel
                if (sentMsg) {
                    messageStore.add(sentMsg.key, sentMsg.message);
                    
                    // 1. TEXTO LEVE PARA O CACHE (Protege a RAM e o SSD da VPS)
                    let lightweightText = data.text || '';
                    if (data.media) {
                        if (data.media.mimeType.startsWith('image/')) lightweightText = '📷 Imagem Enviada' + (data.text ? ` - ${data.text}` : '');
                        else if (data.media.mimeType.startsWith('video/')) lightweightText = '🎥 Vídeo Enviado' + (data.text ? ` - ${data.text}` : '');
                        else if (data.media.mimeType.startsWith('audio/')) lightweightText = '🎤 Áudio Enviado';
                        else lightweightText = `📄 Arquivo (${data.media.name})` + (data.text ? ` - ${data.text}` : '');
                    }

                    // 2. EMISSÃO REAL-TIME PESADA (Apenas para a tela atual, o Node.js apaga da memória logo depois)
                    let liveChatMsg = {
                        id: sentMsg.key.id,
                        tempId: data.tempId, // <--- Devolve o ID temporário para apagar o "relógio" da tela
                        fromMe: true,
                        text: data.media && data.media.mimeType.startsWith('audio/') ? '' : (data.text || ''),
                        timestamp: Date.now(),
                        quoted: data.quoted // <--- Devolve o box de resposta para a tela não desfazer
                    };

                    if (data.media) {
                        liveChatMsg.media = {
                            mimeType: data.media.mimeType,
                            name: data.media.name || 'Arquivo',
                            dataBase64: data.media.dataBase64
                        };
                    }
                    
                    // Manda direto pro frontend renderizar na hora
                    socket.emit('bot:new-message', { sessionName: nomeSessao, jid: data.jid, message: liveChatMsg });

                    // 3. SALVA NA MEMÓRIA DA VPS (Usando APENAS o texto leve e bloqueando o reenvio duplicado pra tela)
                    await saveLiveMessage(sock, data.jid, 'Você', {
                        id: sentMsg.key.id,
                        fromMe: true,
                        text: lightweightText,
                        timestamp: Date.now(),
                        status: 'sent', // <--- STATUS INICIAL ADICIONADO AQUI
                        quoted: data.quoted // <--- Salva na memória pra não sumir se o cliente atualizar a página F5
                    }, true); // O 'true' aqui ativa o skipEmit
                }
            } catch (err) {
                console.error(`[${nomeSessao}] Erro ao enviar arquivo/mensagem pelo Live Chat:`, err);
            }
        });

        // --- MOSTRA "DIGITANDO..." NO CELULAR DO CLIENTE ---
        socket.off('bot:typing');
        socket.on('bot:typing', async (data) => {
            if (!sock) return;
            try {
                await sock.sendPresenceUpdate('composing', data.jid);
                setTimeout(() => {
                    sock.sendPresenceUpdate('paused', data.jid).catch(()=>{});
                }, 3000);
            } catch(e) {}
        });

        // Limpeza quando o socket do painel desconectar (opcional, boa prática)
        socket.on('disconnect', () => {
            console.log('Painel desconectado, limpando listeners do bot');
            socket.off('bot:send-message');
            socket.off('bot:typing');
            socket.off('bot:mark-read');
            // Previne erro de referência caso a variável não exista
            if (typeof typingTimeout !== 'undefined') clearTimeout(typingTimeout);
        });

        socket.on('bot:pause-ai', (data) => {
            pausados[data.jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000);
            console.log(`[${nomeSessao}] 🔇 IA pausada por ${humanPauseTimeMinutes} min pelo Live Chat para: ${data.jid}`);
        });
        socket.on('bot:resume-ai', (data) => {
            if (pausados[data.jid]) delete pausados[data.jid];
            console.log(`[${nomeSessao}] 🔊 IA retomada manualmente pelo Live Chat para: ${data.jid}`);
            
            // Envia um aviso no WhatsApp (Opcional, mas recomendado)
            try { sock.sendMessage(data.jid, { text: `🔊 O robô voltou a assumir o atendimento.` }); } catch(e){}
        });

        // --- COPILOTO IA (RESUMO E SUGESTÃO) ---
        socket.on('bot:copilot', async (data) => {
            try {
                const msgs = recentMessages.get(data.jid) ||[];
                // Pega as últimas 15 mensagens para não estourar o limite de token e ser rápido
                const contextMsgs = msgs.slice(-15); 
                
                if (contextMsgs.length < 2) {
                    return socket.emit('bot:copilot-response', { ...data, error: 'O chat precisa ter pelo menos 2 mensagens recentes para a IA analisar.' });
                }

                const historyText = contextMsgs.map(m => `${m.fromMe ? 'Atendente' : 'Cliente'}: ${m.text || 'Mídia'}`).join('\n');

                let promptCopilot = '';
                if (data.action === 'summary') {
                    promptCopilot = `Atue como um supervisor de atendimento. Leia o breve histórico abaixo e crie um resumo RÁPIDO em 3 tópicos (Status atual, o que o cliente quer, o que falta fazer). Seja extremamente direto.\n\nHISTÓRICO:\n${historyText}`;
                } else if (data.action === 'reply') {
                    promptCopilot = `Atue como um vendedor/atendente experiente. Leia o histórico abaixo e escreva UMA única mensagem como sugestão para o atendente enviar agora ao cliente. Seja empático, profissional e continue o assunto. Retorne APENAS o texto da resposta, sem aspas, sem introduções.\n\nHISTÓRICO:\n${historyText}`;
                }

                // Usa o Gemini para gerar a mágica
                const result = await model.generateContent(promptCopilot);
                const responseText = result.response.text().trim();

                socket.emit('bot:copilot-response', { ...data, result: responseText });

            } catch (err) {
                console.error(`[${nomeSessao}] Erro no Copiloto IA:`, err.message);
                socket.emit('bot:copilot-response', { ...data, error: 'Erro ao conectar com a IA do Copiloto.' });
            }
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
                    
                    let jid = String(num).trim();
                    
                    // Se não tiver '@', tentamos adivinhar se é número normal ou LID
                    if (!jid.includes('@')) {
                        const cleanNum = jid.replace(/\D/g, '');
                        // LIDs novos do WhatsApp costumam ter 14, 15 ou mais dígitos.
                        jid = cleanNum.length > 13 ? cleanNum + '@lid' : cleanNum + '@s.whatsapp.net';
                    }
                    
                    console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${jid}...`);
                    
                    // SÓ verifica no diretório (onWhatsApp) se for um número de telefone comum (@s.whatsapp.net)
                    // Os "@lid" não retornam no onWhatsApp, mas aceitam envio direto se o cliente já falou com o bot.
                    if (jid.endsWith('@s.whatsapp.net')) {
                        const[result] = await sock.onWhatsApp(jid);
                        if (!result || !result.exists) {
                            throw new Error("O número não possui WhatsApp registrado.");
                        }
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
                    
                    // Tenta puxar a foto de perfil do cliente no WhatsApp silenciosamente
                    try {
                        const picUrl = await sock.profilePictureUrl(jid, 'image');
                        if (picUrl && data.clientId && data.owner) {
                            socket.emit('client:update-pic', { 
                                clientId: data.clientId, 
                                picUrl: picUrl, 
                                owner: data.owner 
                            });
                        }
                    } catch(errPic) { 
                        // Ignora se o usuário não tiver foto ou ocultou
                    }

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
        // Captura o status do cliente (Online, digitando, etc)
        sock.ev.on('presence.update', (update) => {
            const { id, presences } = update;
            if (!presences) return;
            
            for (let participant in presences) {
                const status = presences[participant].lastKnownPresence;
                // status pode ser: 'available', 'unavailable', 'composing', 'recording', 'paused'
                socket.emit('bot:presence-update', {
                    sessionName: nomeSessao,
                    jid: id,
                    status: status
                });
            }
        });

        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;
            
            // Só emite o QR se realmente estiver pedindo login via QR Code e NÃO tiver número
            if (qr && !phoneNumberArg) {
                console.log(`QR_CODE:${qr}`);
            }
            
            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                
                // Reconecta em TODOS os casos, EXCETO:
                const isFatalError = statusCode === DisconnectReason.loggedOut || 
                                     statusCode === 403 || 
                                     statusCode === 401 || 
                                     statusCode === 405 || // 405: Sessão invalidada pela Meta
                                     statusCode === DisconnectReason.connectionReplaced; // 440: WhatsApp aberto em outro lugar

                // 428 = Connection Closed, 515 = Restart Required
                const isRestartRequired = statusCode === DisconnectReason.restartRequired || statusCode === 428; 
                const shouldReconnect = !isFatalError;

                let acaoReconexao = "Aparelho desconectado ou banido.";
                if (isRestartRequired) acaoReconexao = "WhatsApp solicitou reinício. Reiniciando limpo...";
                else if (shouldReconnect) acaoReconexao = "Queda de rede. Tentando reconectar...";

                console.log(`[${nomeSessao}] ⚠️ Conexão caiu. Motivo: ${statusCode} | ${acaoReconexao}`);

                if (shouldReconnect) {
                    console.log(`[${nomeSessao}] Encerrando processo para reiniciar de forma segura...`);
                    // Delay vital para não tomar block de IP do WhatsApp (Rate Limit)
                    setTimeout(() => process.exit(1), isRestartRequired ? 2000 : 5000);
                } else {
                    console.log(`[${nomeSessao}] Limpando pasta de sessão e aguardando ação manual...`);
                    try { 
                        if (fs.existsSync(authPath)) {
                            fs.rmSync(authPath, { recursive: true, force: true }); 
                        }
                    } catch(e) {}
                    
                    // Emite o aviso FATAL para o painel voltar o robô para a tela de QR Code
                    socket.emit('bot-disconnected-fatal', { sessionName: nomeSessao });
                    
                    setTimeout(() => {
                        process.exit(0); // Exit 0 significa "morreu em paz", o server.js não vai tentar reiniciar sozinho
                    }, 1000);
                }
            } else if (connection === 'open') {
                console.log('\nONLINE!'); 
                socket.emit('bot-online', { sessionName: nomeSessao });
                
                // Puxar o nome do perfil do WhatsApp para exibir no painel
                setTimeout(() => {
                    const me = sock.authState?.creds?.me || sock.user;
                    const publicName = me?.name || me?.verifiedName || me?.notify || '';
                    const botNumber = me?.id ? me.id.split(':')[0].split('@')[0] : '';
                    if (publicName || botNumber) {
                        socket.emit('bot-identified', { sessionName: nomeSessao, publicName, botNumber });
                    }
                }, 3000);
            }
        });

        // Salva as credenciais instantaneamente. Atrasar isso causa erro de "Bad MAC" e desconexões.
        sock.ev.on('creds.update', async () => {
            try {
                await saveCreds();
            } catch (err) {
                console.error(`[${nomeSessao}] Erro ao salvar credenciais:`, err.message);
            }
            // Tenta puxar o nome do perfil caso ele seja atualizado depois
            const me = sock.authState?.creds?.me || sock.user;
            const publicName = me?.name || me?.verifiedName || me?.notify || '';
            const botNumber = me?.id ? me.id.split(':')[0].split('@')[0] : '';
            if (publicName || botNumber) {
                socket.emit('bot-identified', { sessionName: nomeSessao, publicName, botNumber });
            }
        });

        // OTIMIZAÇÃO CRÍTICA DE RAM: Descarta o histórico antigo que o WhatsApp força no primeiro login
        sock.ev.on('messaging-history.set', () => {
            console.log(`[${nomeSessao}] 🧹 Histórico de mensagens recebido e descartado para economizar RAM.`);
        });

        // =================================================================================
        // 👋 BOAS-VINDAS NO WHATSAPP
        // =================================================================================
        sock.ev.on('group-participants.update', async (update) => {
            try {
                const { id, participants, action } = update;
                // Limpa o cache de admins se houver mudança de participantes (promoção/rebaixamento/saída)
                if (groupAdminsCache.has(id)) {
                    groupAdminsCache.delete(id);
                }
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
sock.ev.on('messages.update', async (updates) => {
            for (const update of updates) {
                // Verifica se há atualização de status em mensagens enviadas por nós
                if (update.update.status && update.key.fromMe) {
                    const statusVal = update.update.status;
                    let statusStr = null;
                    
                    // Baileys usa Enum: 3 = Entregue (DELIVERED), 4 = Lido (READ)
                    if (statusVal === 3) statusStr = 'delivered';
                    else if (statusVal === 4) statusStr = 'read';

                    if (statusStr) {
                        const jid = update.key.remoteJid;
                        
                        // 1. Atualiza a memória local do bot (para quando o usuário fechar e abrir o chat, os ícones continuarem lá)
                        if (recentMessages.has(jid)) {
                            const msgs = recentMessages.get(jid);
                            const msgObj = msgs.find(m => m.id === update.key.id);
                            
                            // Se encontrou e ainda não estava marcado como lido
                            if (msgObj && msgObj.status !== 'read') { 
                                msgObj.status = statusStr;
                                saveLiveChatCache();
                            }
                        }
                        
                        // 2. Avisa o servidor imediatamente para colorir o ícone na tela do usuário
                        socket.emit('bot:message-status-update', {
                            sessionName: nomeSessao,
                            jid: jid,
                            msgId: update.key.id,
                            status: statusStr
                        });
                    }
                }
            }
        });
        const processedMessageIds = new Set(); // Trava de segurança Anti-Duplicação
        const processedMessageIdsQueue =[]; // Fila para manter a ordem e remover os mais antigos
        
        sock.ev.on('messages.upsert', async ({ messages, type }) => {
            // Salva as mensagens recentes no nosso mini-store para o getMessage funcionar
            for (const m of messages) {
                if (m.message) messageStore.add(m.key, m.message);
            }

            if (type !== 'notify') return;
            const msg = messages[0];
            if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

            // IGNORA MENSAGENS DE SISTEMA INVISÍVEIS (Criptografia, atualizações internas)
            if (msg.message.protocolMessage) {
                // Só passa se for edição de mensagem ou apagar mensagem de verdade
                if (!msg.message.protocolMessage?.editedMessage && msg.message.protocolMessage?.type !== 0 && msg.message.protocolMessage?.type !== 'REVOKE') {
                    return; 
                }
            } else if (!msg.message.conversation && !msg.message.extendedTextMessage && !msg.message.imageMessage && !msg.message.videoMessage && !msg.message.audioMessage && !msg.message.documentMessage && !msg.message.stickerMessage && !msg.message.contactMessage && !msg.message.reactionMessage && !msg.message.pollCreationMessage && !msg.message.pollUpdateMessage) {
                // Se não tem nenhum conteúdo legível, descarta pacotes vazios de chave do WhatsApp
                return;
            }

            const jid = msg.key.remoteJid;
            const myId = sock.user?.id || sock.authState?.creds?.me?.id;
            const myJid = myId ? jidNormalizedUser(myId) : null;

            // BLOQUEIO CRÍTICO ANTI-LOOP: Impede o robô de processar mensagens no chat do PRÓPRIO NÚMERO (Chat "Você")
            if (myJid && jidNormalizedUser(jid) === myJid) {
                return;
            }
            
            // FILTRO ANTI-DUPLICAÇÃO APRIMORADO
            if (msg.key.id) {
                if (processedMessageIds.has(msg.key.id)) return; 
                processedMessageIds.add(msg.key.id);
                processedMessageIdsQueue.push(msg.key.id);
                
                // Remove o mais antigo de forma segura para não apagar o histórico recente inteiro
                if (processedMessageIdsQueue.length > 2000) {
                    const oldestId = processedMessageIdsQueue.shift();
                    processedMessageIds.delete(oldestId);
                }
            }

            const isGroup = jid.endsWith('@g.us');
            const sender = msg.key.participant || jid;

            // Identifica o tipo real da mensagem para o Live Chat não ficar em branco
            let texto = msg.message?.conversation || msg.message?.extendedTextMessage?.text || 
                        msg.message?.imageMessage?.caption || msg.message?.videoMessage?.caption || 
                        msg.message?.documentMessage?.caption || '';
                        
            let isAudio = !!msg.message?.audioMessage;
            let isSticker = !!msg.message?.stickerMessage;
            let isContact = !!msg.message?.contactMessage;
            let isLocation = !!msg.message?.locationMessage;
            let isReaction = !!msg.message?.reactionMessage;
            let isPoll = !!msg.message?.pollCreationMessage || !!msg.message?.pollUpdateMessage;
            let isEdit = !!msg.message?.editedMessage || !!msg.message?.protocolMessage?.editedMessage;
            let isRevoke = msg.message?.protocolMessage?.type === 0 || msg.message?.protocolMessage?.type === 'REVOKE';

            // --- EXTRAIR MENSAGEM RESPONDIDA E ENCAMINHAMENTO ---
            let quotedText = null;
            const contextInfo = msg.message?.extendedTextMessage?.contextInfo || 
                                msg.message?.imageMessage?.contextInfo || 
                                msg.message?.videoMessage?.contextInfo ||
                                msg.message?.audioMessage?.contextInfo ||
                                msg.message?.stickerMessage?.contextInfo;
                                
            if (contextInfo && contextInfo.quotedMessage) {
                const qMsg = contextInfo.quotedMessage;
                quotedText = qMsg.conversation || qMsg.extendedTextMessage?.text || 
                            (qMsg.imageMessage ? '📷 Imagem' : '') || 
                            (qMsg.videoMessage ? '🎥 Vídeo' : '') || 
                            (qMsg.audioMessage ? '🎤 Áudio' : '') || 
                            (qMsg.stickerMessage ? '🌟 Figurinha' : 'Mensagem');
            }
            
            let isForwardedMsg = contextInfo?.isForwarded || false;

            // Ignora mensagens de outros robôs do mesmo sistema (identificados pelo caractere invisível)
            if (texto.includes('\u200B')) {
                console.log(`[${nomeSessao}] Mensagem de outro robô ignorada para evitar loop.`);
                return;
            }
            
            // Ignora mensagens geradas por outras instâncias do Baileys
            if (msg.key.id && msg.key.id.startsWith('BAE5') && msg.key.id.length === 16 && !msg.key.fromMe) {
                return;
            }

            // --- BLOQUEIO TOTAL: INDIVIDUAL NUNCA FALA EM GRUPOS ---
            if (isGroup && botType !== 'group') {
                return;
            }

            // Salva na memória do Live Chat com rótulos amigáveis
            const senderName = msg.pushName || sender.split('@')[0];
            let liveChatText = texto;
            let mediaObj = null;
            
            if (isAudio) liveChatText = '🎤 Áudio Recebido';
            else if (msg.message?.imageMessage) liveChatText = '📷 Imagem Recebida' + (texto ? ` - ${texto}` : '');
            else if (msg.message?.videoMessage) liveChatText = '🎥 Vídeo Recebido' + (texto ? ` - ${texto}` : '');
            else if (msg.message?.documentMessage) liveChatText = `📄 Documento: ${msg.message.documentMessage?.fileName || 'Arquivo'}`;
            else if (isSticker) liveChatText = '🌟 Figurinha Recebida';
            else if (isContact) liveChatText = `👤 Contato: ${msg.message.contactMessage?.displayName || 'Desconhecido'}`;
            else if (isLocation) liveChatText = '📍 Localização Recebida';
            else if (isReaction) liveChatText = `❤️ Reagiu com: ${msg.message.reactionMessage?.text || ''}`;
            else if (isPoll) liveChatText = '📊 Enquete';
            else if (isEdit) liveChatText = '✏️ Mensagem Editada';
            else if (isRevoke) liveChatText = '🚫 Mensagem Apagada';
            else if (!texto) {
                // Se não tem texto, mas tem quotedText, significa que a pessoa só marcou a mensagem
                if (quotedText) {
                    liveChatText = '↪️ Respondeu a uma mensagem';
                } else {
                    liveChatText = '📦 Outro formato (Sistema/Mídia não suportada)';
                }
            }
            
            // --- BAIXAR MÍDIA PARA O LIVE CHAT (Incluindo Figurinhas) ---
            if (!msg.key.fromMe && (isAudio || msg.message?.imageMessage || msg.message?.videoMessage || msg.message?.documentMessage || isSticker)) {
                try {
                    const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage });
                    const mimeType = msg.message?.imageMessage?.mimetype || msg.message?.videoMessage?.mimetype || msg.message?.audioMessage?.mimetype || msg.message?.documentMessage?.mimetype || msg.message?.stickerMessage?.mimetype;
                    const fileName = msg.message?.documentMessage?.fileName || (isSticker ? 'figurinha.webp' : 'Arquivo');
                    
                    // Limita a 5MB para não estourar a memória
                    if (buffer.length < 5 * 1024 * 1024) {
                        mediaObj = {
                            dataBase64: buffer.toString('base64'),
                            mimeType: mimeType || 'image/webp',
                            name: fileName
                        };
                    } else {
                        liveChatText += ' (Arquivo muito grande para exibir no painel)';
                    }
                } catch (err) {
                    console.error(`[${nomeSessao}] Erro ao baixar mídia para o Live Chat:`, err.message);
                }
            }
            
            await saveLiveMessage(sock, jid, senderName, {
                id: msg.key.id,
                fromMe: msg.key.fromMe,
                text: liveChatText,
                rawText: texto, // Salva o texto puro para quando for encaminhar para outro chat
                media: mediaObj,
                quoted: quotedText, 
                isForwarded: isForwardedMsg, // Sinaliza se realmente é um encaminhamento do WhatsApp
                pushName: senderName,
                timestamp: (msg.messageTimestamp * 1000) || Date.now()
            });

            const textoLimpo = texto.replace(/[\u200B-\u200D\uFEFF]/g, '').trim();

            // --- REGISTRO DE LEADS (CONTATOS) ---
            if (!msg.key.fromMe && !isGroup) {
                // Envolve em setTimeout para não atrasar a resposta da IA enquanto baixa a foto
                setTimeout(async () => {
                    try {
                        const rawJid = msg.key.remoteJid;
                        if (rawJid && rawJid !== 'status@broadcast') {
                            const cleanJid = jidNormalizedUser(rawJid);
                            
                            // Tenta pegar do cache do Live Chat primeiro
                            const chatCache = recentChats.get(jid);
                            let picUrl = chatCache ? chatCache.profilePicUrl : null;
                            
                            // Se a foto não estiver no cache (ex: robô recém reiniciado), pede ativamente ao WhatsApp
                            if (!picUrl || picUrl === undefined) {
                                try {
                                    picUrl = await sock.profilePictureUrl(jid, 'image');
                                    // Salva no cache local para não ter que pedir de novo toda hora
                                    if (chatCache) {
                                        chatCache.profilePicUrl = picUrl;
                                        saveLiveChatCache();
                                    }
                                } catch (errPic) {
                                    // Se der erro (ex: usuário ocultou a foto para quem não é contato), fica null
                                    picUrl = null;
                                    if (chatCache) chatCache.profilePicUrl = null;
                                }
                            }
                            
                            // Envia para o server.js salvar permanentemente no arquivo leads.json
                            socket.emit('bot:register-lead', {
                                sessionName: nomeSessao,
                                number: cleanJid, 
                                name: senderName || 'Cliente',
                                profilePicUrl: picUrl 
                            });
                        }
                    } catch (errLead) {
                        console.error('Erro ao registrar lead:', errLead);
                    }
                }, 150); 
            }

            // --- VERIFICAÇÃO DE PAUSA GLOBAL (SOFT STOP) ---
            // Se estiver pausado, ele salva no Live Chat (acima) para você ler, mas para a execução aqui e não responde nada.
            if (isGlobalPaused) return;

            // --- 1. COMANDO !stopsempre (Ignorar Permanente) ---
            // --- 1. COMANDO !stopsempre (Ignorar Permanente) ---
            if (textoLimpo.match(/^[!\/]stopsempre/i)) {
                let valueToIgnore = null;
                let isAuth = false;

                if (msg.key.fromMe) {
                    isAuth = true;
                    if (isGroup) {
                         const context = msg.message?.extendedTextMessage?.contextInfo;
                         if (context?.participant) {
                             valueToIgnore = jidNormalizedUser(context.participant).split('@')[0];
                         }
                    } else {
                        valueToIgnore = jidNormalizedUser(jid).split('@')[0];
                    }
                } else {
                    if (isGroup) {
                        isAuth = await isGroupAdminWA(sock, jid, sender);
                        const context = msg.message?.extendedTextMessage?.contextInfo;
                        if (isAuth && context?.participant) {
                            valueToIgnore = jidNormalizedUser(context.participant).split('@')[0]; // Admin ignorando alguém
                        } else {
                            valueToIgnore = jidNormalizedUser(sender).split('@')[0]; // Próprio usuário optando por sair
                            isAuth = true; // Qualquer um pode se ignorar
                        }
                    } else {
                        valueToIgnore = jidNormalizedUser(sender).split('@')[0];
                        isAuth = true; // Em PV, o usuário pode pedir pra parar
                    }
                }
                
                if (isAuth && valueToIgnore) {
                    const exists = ignoredIdentifiers.some(i => i.type === 'number' && i.value === valueToIgnore);
                    if (!exists) {
                        ignoredIdentifiers.push({ type: 'number', value: valueToIgnore });
                        socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'number', value: valueToIgnore });
                        console.log(`[${nomeSessao}] 🚫 Número ${valueToIgnore} ignorado permanentemente.`);
                    }
                    try {
                        // Constrói a chave limpa exigida pela biblioteca
                        const deleteKey = { 
                            remoteJid: msg.key.remoteJid, 
                            fromMe: msg.key.fromMe, 
                            id: msg.key.id 
                        };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        
                        await delay(500); // Micro-pausa para o WhatsApp registrar a mensagem antes de apagá-la
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `✅ O número ${valueToIgnore} será ignorado permanentemente.` });
                    } catch (e) {
                        console.error('Erro ao apagar comando !stopsempre:', e);
                    }
                }
                return;
            }

            // --- 2. COMANDO !stop (Pausa Temporária) ---
            const stopMatch = textoLimpo.match(/^[!\/]stop\s*(\d*)/i);
            if (stopMatch && !textoLimpo.match(/^[!\/]stopsempre/i)) {
                let isAuth = false;
                if (msg.key.fromMe) {
                    isAuth = true;
                } else if (isGroup) {
                    isAuth = await isGroupAdminWA(sock, jid, sender);
                } else {
                    isAuth = true; // No PV, qualquer um pode pausar
                }

                if (isAuth) {
                    const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                    const duracaoMs = minutos * 60 * 1000;
                    pausados[jid] = Date.now() + duracaoMs;
                    console.log(`[${nomeSessao}] 🔇 Pausado por ${minutos} min em ${jid}.`);

                    try {
                        const deleteKey = { remoteJid: msg.key.remoteJid, fromMe: msg.key.fromMe, id: msg.key.id };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        await delay(500);
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `🔇 Bot pausado por ${minutos} minuto(s) nesta conversa.` });
                    } catch (e) { }
                    return; 
                }
            }

            // --- 3. COMANDO !voltar (Retoma a IA Imediatamente) ---
            if (textoLimpo.match(/^[!\/](voltar|start|retomar)/i)) {
                let isAuth = false;
                if (msg.key.fromMe) isAuth = true;
                else if (isGroup) isAuth = await isGroupAdminWA(sock, jid, sender);
                else isAuth = true;

                if (isAuth) {
                    if (pausados[jid]) delete pausados[jid];
                    console.log(`[${nomeSessao}] 🔊 IA retomada manualmente em ${jid}.`);
                    try {
                        const deleteKey = { remoteJid: msg.key.remoteJid, fromMe: msg.key.fromMe, id: msg.key.id };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        await delay(500);
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `🔊 Bot reativado. A IA voltou a responder nesta conversa.` });
                    } catch (e) {}
                    return;
                }
            }

            // --- 4. AUTO-PAUSA POR INTERVENÇÃO HUMANA E EXTENSÃO CONTÍNUA ---
            // Identifica se a mensagem foi originada pela própria automação (IA, gatilhos, comandos ou sistema)
            // CORREÇÃO: Removido 'messageStore' pois a mensagem já é salva na store logo no início do evento,
            // o que fazia o sistema achar que VOCÊ digitando no celular era o robô.
            const isBotEcho = texto.includes('\u200B') || 
                              textoLimpo.startsWith('000201010211') || 
                              /^[✅🔒🔓🧠🔕🔗👋🔇🔊🚫⚠️🏓🤖👤👮📢🛡️]/.test(textoLimpo);
            
            // É intervenção humana se foi enviada por nós (fromMe), não é echo do bot, e não é um comando manual (! ou /)
            const isHumanFromPhone = msg.key.fromMe && !isBotEcho && !textoLimpo.startsWith('!') && !textoLimpo.startsWith('/');
            
            if (isHumanFromPhone) {
                pausados[jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000);
                console.log(`[${nomeSessao}] 🔇 Intervenção humana no celular detectada em ${jid}. IA pausada por ${humanPauseTimeMinutes} min.`);
                return;
            }

            // Se já está pausado, QUALQUER nova mensagem (do cliente ou do humano) renova a pausa silenciosamente
            if (pausados[jid] && Date.now() < pausados[jid]) {
                if (!msg.key.fromMe || isHumanFromPhone) {
                    pausados[jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000); // Renova a pausa!
                    console.log(`[${nomeSessao}] 🔇 Conversa ativa durante pausa em ${jid}. Pausa estendida por mais ${humanPauseTimeMinutes} min.`);
                }
                return; // Bloqueia a IA de responder
            }

            // Se a mensagem for do PRÓPRIO bot e houver configuração de silêncio no painel (evitar spam da IA):
            if (msg.key.fromMe) {
                if (silenceTimeMinutesGlobal > 0) {
                    const autoSilenceMs = silenceTimeMinutesGlobal * 60 * 1000;
                    pausados[jid] = Date.now() + autoSilenceMs;
                    console.log(`[${nomeSessao}] 🔇 Auto-silêncio do bot ativado por ${silenceTimeMinutesGlobal} min em ${jid}.`);
                }
                return;
            }

            // --- VERIFICAÇÃO DE ATIVAÇÃO (Robusto e Corrigido) ---
            let tokenToActivate = null;
            if (texto.includes('/ativar?token=')) {
                tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            } else if (texto.startsWith('/ativar') && texto.includes('token=')) {
                tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            } else if (texto.startsWith('/ativar ')) {
                tokenToActivate = texto.split(' ')[1]?.trim();
            }

            if (isGroup && tokenToActivate) {
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
                    activationToken: tokenToActivate, 
                    botSessionName: nomeSessao 
                });
                return; 
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

            // BLOQUEIO DE MÍDIAS NÃO SUPORTADAS PELA IA (Evita loop de mensagens vazias)
            // A IA só deve processar Texto puro ou Áudio (isAudio). Reações, documentos e figurinhas morrem aqui.
            if (!textoLimpo && !isAudio) {
                console.log(`[${nomeSessao}] Mensagem ignorada pela IA (Sintaxe vazia ou mídia não suportada).`);
                return;
            }

            // 6. Processamento IA
            try {
                console.log(`[DEBUG] Mensagem recebida de ${jid}. Enviando 'composing'...`);
                await sock.readMessages([msg.key]);
                
                // Mantém o bot "digitando..." continuamente até a IA responder
                let isThinking = true;
                const typingInterval = setInterval(async () => {
                    if (isThinking) await sock.sendPresenceUpdate('composing', jid).catch(()=>{});
                }, 8000); // WhatsApp expira o digitando a cada ~10s, enviamos a cada 8s

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
                
                // Para a animação de digitando assim que a IA gera a resposta
                isThinking = false;
                clearInterval(typingInterval);
                
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
                
                // GARANTIA: Para a animação caso a IA ou a rede tenham falhado
                if (typeof isThinking !== 'undefined') isThinking = false;
                if (typeof typingInterval !== 'undefined') clearInterval(typingInterval);

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




