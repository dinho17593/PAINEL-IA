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
    const isGroup = jid.endsWith('@g.us');
    
    if (!recentChats.has(jid)) {
        if (recentChats.size >= MAX_CHATS) {
            const oldestJid = recentChats.keys().next().value;
            recentChats.delete(oldestJid);
            recentMessages.delete(oldestJid);
        }
        
        let initialName = name;
        
        // Se for grupo, tenta pegar o nome real do grupo em vez do nome de quem mandou a msg
        if (isGroup && sock) {
            try {
                const groupMeta = await sock.groupMetadata(jid);
                initialName = groupMeta.subject;
            } catch (e) {
                initialName = "Grupo";
            }
        } else if (msgObj.fromMe && (name.includes('Bot') || name === 'Você')) {
            initialName = jid.split('@')[0];
        }
        
        recentChats.set(jid, { jid, name: initialName || jid.split('@')[0], unreadCount: 0 });
    }
    
    const chat = recentChats.get(jid);
    chat.lastMessage = msgObj.text;
    chat.timestamp = msgObj.timestamp;
    
    if (!msgObj.fromMe) {
        // Se NÃO for grupo, atualiza o nome (PV). Se FOR grupo, mantém o nome do grupo salvo acima.
        if (!isGroup) {
            chat.name = name || chat.name;
        }
        chat.unreadCount += 1;
    }

    if ((chat.profilePicUrl === undefined || chat.profilePicUrl === null) && sock) {
        try {
            // Busca a foto do grupo ou do contato
            const pic = await sock.profilePictureUrl(jid, 'image');
            chat.profilePicUrl = pic;
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

// Lendo configurações de IPTV repassadas pelo servidor
let iptvSettings = { enabled: false, webhookUrl: '', successMsg: '' };
try {
    const iptvArg = Buffer.from(process.argv[18] || 'eyJlbmFibGVkIjpmYWxzZX0=', 'base64').toString('utf-8');
    iptvSettings = JSON.parse(iptvArg);
} catch(e) { console.error("Erro parse IPTV settings:", e); }

if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const MODELOS_GEMINI =['gemini-2.5-flash', 'gemini-2.5-flash-lite','gemini-3.1-flash-lite-preview', 'gemini-3.1-pro-preview'];
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

    socket.on('log-action', (data) => {
        console.log(data.msg);
    });

    socket.on('bot-iptv-changed', (data) => {
        if (data.sessionName === nomeSessao) {
            console.log(`[${nomeSessao}] 📺 Configurações de IPTV atualizadas em tempo real!`);
            iptvSettings = data.iptvSettings || { enabled: false };
        }
    });

    
    socket.on('bot:get-chats', async (data) => {
        let chats = Array.from(recentChats.values());
        
        // Se for WhatsApp, tenta buscar todos os grupos participantes, mesmo os antigos
        if (platform === 'whatsapp' && global.sock) {
            try {
                const allGroups = await global.sock.groupFetchAllParticipating();
                Object.values(allGroups).forEach(g => {
                    // Adiciona à lista se já não estiver nos chats recentes
                    if (!recentChats.has(g.id)) {
                        chats.push({
                            jid: g.id,
                            name: g.subject,
                            timestamp: g.creation || Date.now()
                        });
                    }
                });
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao buscar grupos participantes:`, e.message);
            }
        }
        
        const sortedChats = chats.sort((a,b) => b.timestamp - a.timestamp);
        socket.emit('bot:return-chats', { frontendId: data.frontendId, chats: sortedChats });
    });

    socket.on('bot:get-messages', async (data) => {
        if (recentChats.has(data.jid)) recentChats.get(data.jid).unreadCount = 0;
        const msgs = recentMessages.get(data.jid) ||[];
        const isGroup = data.jid.endsWith('@g.us');
        
        let picUrl = null;
        let chatName = null;
        
        // 1. Tenta pegar o nome do cache principal
        if (recentChats.has(data.jid)) {
            chatName = recentChats.get(data.jid).name;
        }
        
        // 2. RECUPERAÇÃO DE NOME: Se estiver vazio, genérico OU for apenas um número de telefone!
        // IMPORTANTE: Só faz essa recuperação automática de nome de PESSOA se NÃO for um grupo.
        if (!isGroup && (!chatName || chatName === 'Cliente' || chatName === 'User' || /^\d+$/.test(chatName))) {
            const msgComNome = [...msgs].reverse().find(m => m.pushName && m.pushName !== 'Cliente' && m.pushName !== 'Você' && !/^\d+$/.test(m.pushName));
            
            if (msgComNome) {
                chatName = msgComNome.pushName; 
            } else {
                chatName = data.jid.split('@')[0];
            }
            
            if (recentChats.has(data.jid)) {
                recentChats.get(data.jid).name = chatName;
            } else {
                recentChats.set(data.jid, { jid: data.jid, name: chatName, unreadCount: 0 });
            }
        }

        // 2.1 Se for GRUPO e o nome estiver bugado, tenta buscar o subject real
        if (isGroup && (!chatName || chatName === 'Grupo' || chatName.includes('@'))) {
            try {
                const groupMeta = await sock.groupMetadata(data.jid);
                chatName = groupMeta.subject;
                if (recentChats.has(data.jid)) recentChats.get(data.jid).name = chatName;
            } catch (e) {
                chatName = chatName || "Grupo";
            }
        }

        // 3. RECUPERAÇÃO DE FOTO (Funciona para PV e Grupos)
        if (recentChats.has(data.jid) && recentChats.get(data.jid).profilePicUrl) {
            picUrl = recentChats.get(data.jid).profilePicUrl;
        } 
        
        // Se não tem foto no cache ou ela é null, tenta buscar agora
        if (!picUrl && sock) {
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
        const source = data.performer ? `usuário [${data.performer}]` : "atendente";
        console.log(`IA pausada`);
        console.log(`> 💬 INTERVENÇÃO: IA silenciada por ${humanPauseTimeMinutes}min via Live Chat por ${source} para o JID ${data.jid}`);
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
// LÓGICA DE DISPARO STEALTH EM GRUPOS
    socket.on('bot:group-blast', async (data) => {
        if (data.sessionName === nomeSessao && sock) {
            console.log(`[STEALTH] Iniciando sequência de disparos para ${data.groups.length} grupos.`);
            
            for (const groupJid of data.groups) {
                try {
                    if (data.stealthMode) {
                        // 1. Marca como lido (mostra que o bot "viu" o grupo)
                        await sock.readMessages([{ remoteJid: groupJid, id: 'last' }]);
                        await delay(2000);
                        
                        // 2. Simula digitação por um tempo aleatório (5 a 10 segundos)
                        await sock.sendPresenceUpdate('composing', groupJid);
                        const typingTime = Math.floor(Math.random() * 5000) + 5000;
                        await delay(typingTime);
                    }

                    // 3. Envia a mensagem com o caractere invisível anti-loop
                    await sock.sendMessage(groupJid, { text: data.message + '\u200B' });
                    
                    if (data.stealthMode) {
                        await sock.sendPresenceUpdate('paused', groupJid);
                    }

                    // Intervalo entre grupos para não parecer spam em massa
                    await delay(3000); 

                } catch (err) {
                    console.error(`[STEALTH] Falha ao enviar para o grupo ${groupJid}:`, err.message);
                }
            }
            console.log(`[STEALTH] Sequência finalizada.`);
        }
    });
    socket.off('group-activation-result');
        socket.on('group-activation-result', async (data) => {
            if (data.botSessionName === nomeSessao && data.groupId) {
                const msg = data.success ? `✅ ${data.message || 'Grupo ativado!'}` : `❌ Falha: ${data.message}`;
                await sock.sendMessage(data.groupId, { text: msg });
                if(data.success) {
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null,
                        autoResponder: [],
                        aiFallbackEnabled: true
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
let lastRestartTime = null;
let socketListenersMapped = false;
const processedMessageIds = new Set();
const processedMessageIdsQueue = [];

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
            autoResponder: group.autoResponder ||[], 
            aiFallbackEnabled: group.aiFallbackEnabled !== false // <--- AGORA ELE LEMBRA SE A IA ESTÁ LIGADA
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

// --- SISTEMA PROFISSIONAL RAG (BUSCA SEMÂNTICA POR EMBEDDINGS) ---
const crypto = require('crypto');
let knowledgeBaseIndex = []; 

// Função de similaridade de cosseno para comparar vetores
function cosineSimilarity(vecA, vecB) {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vecA.length; i++) {
        dotProduct += vecA[i] * vecB[i];
        normA += vecA[i] * vecA[i];
        normB += vecB[i] * vecB[i];
    }
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

async function prepareKnowledgeBase() {
    if (!knowledgeBaseTextGlobal || knowledgeBaseTextGlobal.trim() === '') {
        knowledgeBaseIndex = [];
        return;
    }
    
    const currentHash = crypto.createHash('md5').update(knowledgeBaseTextGlobal).digest('hex');
    const cachePath = `./auth_sessions/kb_cache_${nomeSessao}.json`;

    if (fs.existsSync(cachePath)) {
        try {
            const cacheData = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            if (cacheData.hash === currentHash) {
                console.log(`[${nomeSessao}] 🧠 Base de Conhecimento Profissional (RAG) carregada do cache.`);
                knowledgeBaseIndex = cacheData.index;
                return;
            }
        } catch (e) { }
    }
    
    console.log(`[${nomeSessao}] 📚 Indexando Base de Conhecimento (RAG)...`);
    
    // 1. Chunking: Divide o texto em blocos de ~800 caracteres com sobreposição
    const chunks = [];
    const size = 800;
    const overlap = 200;
    for (let i = 0; i < knowledgeBaseTextGlobal.length; i += (size - overlap)) {
        chunks.push(knowledgeBaseTextGlobal.substring(i, i + size));
    }

    const embeddingModel = genAI.getGenerativeModel({ model: "text-embedding-004" });
    const newIndex = [];

    // 2. Embedding: Converte cada bloco em um vetor numérico
    for (const chunk of chunks) {
        let success = false;
        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                const result = await embeddingModel.embedContent(chunk);
                newIndex.push({ text: chunk, embedding: result.embedding.values });
                success = true;
                break;
            } catch (e) {
                switchToNextApiKey();
                await new Promise(r => setTimeout(r, 1000));
            }
        }
    }

    knowledgeBaseIndex = newIndex;
    fs.writeFileSync(cachePath, JSON.stringify({ hash: currentHash, index: newIndex }));
    console.log(`[${nomeSessao}] ✅ Indexação RAG concluída: ${newIndex.length} fragmentos mapeados.`);
}

async function getRelevantContext(query) {
    if (knowledgeBaseIndex.length === 0) return "";

    try {
        const embeddingModel = genAI.getGenerativeModel({ model: "text-embedding-004" });
        const result = await embeddingModel.embedContent(query);
        const queryVector = result.embedding.values;

        // Calcula similaridade e pega os 3 fragmentos mais parecidos
        const ranked = knowledgeBaseIndex.map(item => ({
            text: item.text,
            score: cosineSimilarity(queryVector, item.embedding)
        })).sort((a, b) => b.score - a.score).slice(0, 3);

        // Só retorna se a similaridade for relevante (> 0.4)
        const bestMatches = ranked.filter(r => r.score > 0.4).map(r => r.text).join("\n---\n");
        return bestMatches ? `\n[CONTEXTO RECUPERADO DO DOCUMENTO]:\n${bestMatches}\n` : "";
    } catch (e) {
        return "";
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
                
                // Recupera dinamicamente apenas o que é importante para a pergunta atual (RAG)
                const relevantContext = await getRelevantContext(isAudio ? "Transcrição de áudio" : input);
                if (relevantContext) {
                    promptFinal += "\n\n" + relevantContext + "\nUse o contexto acima para responder com precisão técnica, sem inventar dados.";
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
                console.log(`[DEBUG IA] Falha ao extrair texto. Erro detalhado:`, textErr);
                console.error("Causa provável: Bloqueio de segurança (Safety Filters) ou resposta vazia.");
                resposta = "Desculpe, não posso gerar uma resposta para isso devido às políticas de segurança ou erro na API.";
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
            console.error(`[DEBUG IA] 🚨 ERRO REAL NA TENTATIVA ${attempt + 1}/${maxAttempts}:`);
            console.error(err); // Exibe o objeto de erro completo (stack, status, headers)
            
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

    // INJEÇÃO DA LÓGICA DE WEBHOKS DIRETAMENTE NA MENTE DA IA
    if (iptvSettings && (iptvSettings.enabled || iptvSettings.mensalEnabled)) {
        let iptvInstructions = "";
        
        if (iptvSettings.enabled) {
            let providers = iptvSettings.providers ||[];
            if (providers.length === 0 && iptvSettings.webhookUrl) {
                providers =[{ name: 'Padrão', url: iptvSettings.webhookUrl }]; 
            }
            if (providers.length > 0) {
                iptvInstructions += `\n\n[SISTEMA DE TESTE IPTV ATIVADO]\nO sistema possui os seguintes aplicativos/servidores para TESTE:\n`;
                providers.forEach((p, i) => {
                    iptvInstructions += `- ID ${i}: ${p.name}\n`;
                });
                iptvInstructions += `Se o cliente pedir um TESTE (ou teste grátis), e houver mais de um aplicativo, pergunte qual ele deseja. Ao confirmar a liberação do TESTE, coloque EXATAMENTE a tag secreta [ACTION:GERAR_TESTE:ID] isolada no final da resposta, substituindo "ID" pelo número do aplicativo escolhido. NUNCA invente dados de acesso!\n`;
            }
        }

        if (iptvSettings.mensalEnabled) {
            let mensalProviders = iptvSettings.mensalProviders ||[];
            if (mensalProviders.length > 0) {
                iptvInstructions += `\n\n[SISTEMA DE VENDAS DE ACESSO MENSAL]\nVocê vende os seguintes pacotes/acessos:\n`;
                mensalProviders.forEach((p, i) => {
                    iptvInstructions += `- ID ${i}: ${p.name} - Valor: R$ ${p.price}\n`;
                });
                iptvInstructions += `Se o cliente perguntar os planos, informe-os com clareza. Se o cliente confirmar que deseja COMPRAR/ASSINAR um acesso, pergunte qual pacote ele deseja se ele ainda não tiver especificado. Quando ele escolher o pacote e quiser pagar, você DEVE gerar a cobrança colocando EXATAMENTE a tag secreta[ACTION:COBRAR_MENSAL:ID] isolada no final da sua resposta, substituindo "ID" pelo número do pacote escolhido. O sistema cuidará de enviar a chave PIX e liberar o acesso automaticamente, você não precisa fazer mais nada!\n`;
            }
        }
        
        enhancedPrompt += iptvInstructions;
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
                    if (!chatId) {
                        if (data.messageId) socket.emit('bot:message-status', { messageId: data.messageId, success: false, error: 'Número não fornecido.' });
                        return console.log(`[${nomeSessao}] ❌ Erro: O painel não enviou o número.`);
                    }
                    
                    // Remove caracteres inválidos do Telegram, mantendo números e o sinal de menos (para grupos)
                    chatId = chatId.replace(/[^0-9-]/g, '');
                    
                    console.log(`[${nomeSessao}] ⏳ Tentando enviar campanha para ${chatId}...`);
                    const sentMsg = await bot.telegram.sendMessage(chatId, data.message + '\u200B');
                    
                    if (data.pixData && data.pixData.qr_code_base64) {
                        const imageBuffer = Buffer.from(data.pixData.qr_code_base64, 'base64');
                        await bot.telegram.sendPhoto(chatId, { source: imageBuffer }, {
                            caption: `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`
                        });
                        await bot.telegram.sendMessage(chatId, data.pixData.qr_code);
                    }
                    
                    console.log(`[${nomeSessao}] ✅ Mensagem enviada com sucesso para ${chatId}!\n`);
                    
                    // Confirma sucesso com ID do telegram
                    if (data.messageId) {
                        socket.emit('bot:message-status', { messageId: data.messageId, success: true, realMsgId: String(sentMsg.message_id) });
                    }
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar mensagem de campanha no Telegram:`, e);
                    // Passa o motivo EXATO do erro pro front (ex: chat not found)
                    if (data.messageId) {
                        socket.emit('bot:message-status', { messageId: data.messageId, success: false, error: e.message || 'Erro de permissão no Telegram' });
                    }
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
                    
                    let captionTexto = `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`;
                    if (data.isMensal) {
                        captionTexto = `✅ *Pedido gerado: ${data.productName}*\n\nEfetue o pagamento através do QR Code PIX ou Copia e Cola abaixo. Assim que aprovado, o sistema enviará seu acesso automaticamente por aqui!`;
                    }

                    console.log(`[${nomeSessao}] ⏳ Enviando QR Code PIX para ${chatId}...`);
                    await bot.telegram.sendPhoto(chatId, { source: imageBuffer }, {
                        caption: captionTexto,
                        parse_mode: 'Markdown'
                    });
                    
                    await bot.telegram.sendMessage(chatId, data.pixData.qr_code);
                    console.log(`[${nomeSessao}] ✅ PIX enviado com sucesso para ${chatId}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar PIX no Telegram:`, e);
                }
            }
        });
        
        socket.off('pix:generation-failed');
        socket.on('pix:generation-failed', async (data) => {
            if (data.botSessionName === nomeSessao) {
                let chatId = String(data.clientJid || data.clientNumber).replace(/[^0-9-]/g, '');
                if (chatId) {
                    try {
                        await bot.telegram.sendMessage(chatId, `⚠️ Desculpe, houve um problema ao gerar sua cobrança: ${data.message}`);
                    } catch(e) {}
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
        let possuiGatilhos = false;

        if (groupConfig) {
            useAI = groupConfig.aiFallbackEnabled !== false;
            possuiGatilhos = (groupConfig.autoResponder && groupConfig.autoResponder.length > 0) || (autoResponder && autoResponder.length > 0);
        } else {
            useAI = aiFallbackEnabledGlobal;
            possuiGatilhos = (autoResponder && autoResponder.length > 0);
        }

        // SALVAGUARDA LÓGICA: Se a IA foi desligada, mas não há nenhuma resposta rápida, liga a IA de volta
        if (!useAI && !possuiGatilhos) {
            useAI = true;
        }

        if (!useAI) return; // SE A IA ESTIVER DESLIGADA (E HOUVER REGRAS), PARA AQUI.

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
            
            let resposta = await processarComGemini(chatId, isAudio ? audioBuffer : texto, isAudio, promptToUse);
            
            if(resposta && resposta.trim().length > 0) {
                // INTERCEPTADOR DE TESTE E COBRANÇA MENSAL PARA TELEGRAM
                const iptvMatch = resposta.match(/\[ACTION:GERAR_TESTE(?::(\d+))?\]/);
                const mensalCobrarMatch = resposta.match(/\[ACTION:COBRAR_MENSAL(?::(\d+))?\]/);
                
                if (mensalCobrarMatch) {
                    let cleanText = resposta.replace(/\[ACTION:COBRAR_MENSAL(?::\d+)?\]/g, '').trim();
                    await ctx.reply((cleanText ? cleanText + '\n\n' : '') + '⏳ Gerando sua cobrança PIX automática, só um instante...', { reply_to_message_id: ctx.message.message_id });
                    
                    let pIndex = mensalCobrarMatch[1] ? parseInt(mensalCobrarMatch[1]) : 0;
                    
                    // Emite pro servidor processar a geração do PIX
                    socket.emit('client:request-mensal-pix', {
                        botSessionName: nomeSessao,
                        clientJid: chatId,
                        providerIndex: pIndex
                    });
                    
                    pausados[chatId] = Date.now() + (10 * 60 * 1000); // Pausa a IA para o PIX chegar limpo
                }
                else if (iptvMatch) {
                    let cleanText = resposta.replace(/\[ACTION:GERAR_TESTE(?::\d+)?\]/g, '').trim();
                    await ctx.reply((cleanText ? cleanText + '\n\n' : '') + '⏳ Gerando seu teste grátis, só um instante...', { reply_to_message_id: ctx.message.message_id });
                    
                    try {
                        let providers = (iptvSettings.providers ||[]);
                        if (providers.length === 0 && iptvSettings.webhookUrl) {
                            providers =[{ name: 'Padrão', url: iptvSettings.webhookUrl }];
                        }
                        
                        let pIndex = iptvMatch[1] ? parseInt(iptvMatch[1]) : 0;
                        if (!providers[pIndex]) pIndex = 0; 
                        
                        const targetUrl = providers[pIndex].url;
                        if (!targetUrl) throw new Error("URL de webhook não configurada.");

                        const phoneOnly = userId;
                        const webhookFinalUrl = targetUrl.includes('?') 
                            ? `${targetUrl}&numero=${phoneOnly}&nome=${encodeURIComponent(senderName || 'Cliente')}` 
                            : `${targetUrl}?numero=${phoneOnly}&nome=${encodeURIComponent(senderName || 'Cliente')}`;

                        let response = null;
                        const methodsToTry = ['GET', 'POST'];
                        
                        for (const method of methodsToTry) {
                            response = await axios({
                                method: method,
                                url: webhookFinalUrl,
                                timeout: 15000,
                                validateStatus: () => true // Evita crash
                            });

                            const responseDataStr = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                            if (response.status === 405 || responseDataStr.toLowerCase().includes('method is not supported')) {
                                console.log(`[${nomeSessao}] Método ${method} recusado pelo painel Webhook no Telegram. Tentando o próximo...`);
                                continue; // Pula pro próximo método (ex: POST)
                            }
                            
                            // Se não for erro de método, sai do loop e processa a resposta
                            break;
                        }
                        
                        let iptvResponseText = '';
                        if (typeof response.data === 'object') {
                            if (response.data.reply) iptvResponseText = response.data.reply;
                            else if (response.data.msg) iptvResponseText = response.data.msg;
                            else if (response.data.message) iptvResponseText = response.data.message;
                            else if (response.data.error) iptvResponseText = response.data.error;
                            else if (Array.isArray(response.data.data) && response.data.data.length > 0 && response.data.data[0].message) {
                                iptvResponseText = response.data.data[0].message;
                            }
                            else iptvResponseText = JSON.stringify(response.data, null, 2);
                       } else {
                                    iptvResponseText = String(response.data).replace(/<br>/gi, '\n').replace(/<[^>]*>?/gm, '');
                                }

                                let validadeISO = null;
                                try {
                                    const regexExp = /(?:vencimento|validade|expira|v[áa]lido|at[ée])[^\n\d]*(\d{2})[\/\-](\d{2})[\/\-](\d{4})(?:[^\n\d]*(\d{2}):(\d{2})(?::(\d{2}))?)?/i;
                                    let matchData = iptvResponseText.match(regexExp);
                                    if (!matchData) matchData = iptvResponseText.match(/(\d{2})[\/\-](\d{2})[\/\-](\d{4})(?:[^\n\d]*(\d{2}):(\d{2})(?::(\d{2}))?)?/);
                                    
                                    if (matchData) {
                                        let YYYY = matchData[3];
                                        let MM = matchData[2];
                                        let DD = matchData[1];
                                        let hh = matchData[4] ? matchData[4].padStart(2, '0') : '12';
                                        let mm = matchData[5] ? matchData[5].padStart(2, '0') : '00';
                                        let ss = matchData[6] ? matchData[6].padStart(2, '0') : '00';
                                        
                                        // Cria a data e FORÇA o Fuso Horário do Brasil para não bagunçar horas
                                        validadeISO = new Date(`${YYYY}-${MM}-${DD}T${hh}:${mm}:${ss}-03:00`).toISOString();
                                    }
                                } catch(e) {}

                                let finalIptvMessage = (iptvSettings.successMsg ? iptvSettings.successMsg + "\n\n" : "") + iptvResponseText;
                                resposta = finalIptvMessage; 
                                
                                pausados[chatId] = Date.now() + (10 * 60 * 1000); 
                                console.log(`[${nomeSessao}] 📺 Teste IPTV processado com status: ${response.status} e IA pausada no Telegram.`);
                                
                                // EMITE O EVENTO PARA SALVAR O HISTÓRICO NO GERENCIAMENTO
                                socket.emit('bot:register-iptv-history', {
                                    sessionName: nomeSessao,
                                    jid: chatId,
                                    name: senderName || 'Cliente',
                                    type: 'teste',
                                    providerName: providers[pIndex] ? providers[pIndex].name : 'Padrão',
                                    date: new Date().toISOString(),
                                    validade: validadeISO
                                });

                            } catch (iptvErr) {
                        console.error(`[${nomeSessao}] ❌ Erro ao gerar teste IPTV no Telegram:`, iptvErr.message);
                        resposta = "Desculpe, nosso sistema de testes está temporariamente indisponível no servidor. Verifique o link da integração.";
                    }
                }

                // Só envia a resposta comum se NÃO tiver emitido evento de Pix
                if (!mensalCobrarMatch) {
                    await ctx.reply(resposta + '\u200B', { reply_to_message_id: ctx.message.message_id });
                }
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
        
        const { version } = await fetchLatestBaileysVersion();
        console.log(`[${nomeSessao}] Iniciando com a versão do WhatsApp Web: ${version.join('.')}`);

         const sock = makeWASocket({
            version: version, 
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
            keepAliveIntervalMs: 30000, // Aumentado para 30s para reduzir carga de ping e evitar desconexões
            connectTimeoutMs: 120000, // Aumentado para 2 minutos para redes instáveis
            defaultQueryTimeoutMs: 120000, 
            emitOwnEvents: true,
            getMessage: async (key) => {
                return messageStore.get(key) || undefined;
            }
        });


        // Exporta para o escopo global para garantir acesso contínuo após reconexões
        global.sock = sock;

        // CORREÇÃO DO CÓDIGO DE PAREAMENTO: 
        // Trava global para garantir que o código só seja pedido UMA ÚNICA VEZ por ciclo
        if (phoneNumberArg && !sock.authState.creds.registered && !global.pairingCodeRequested) {
            global.pairingCodeRequested = true; // Ativa a trava
            setTimeout(async () => {
                try {
                    const code = await sock.requestPairingCode(phoneNumberArg);
                    if (code) {
                        console.log('PAIRING_CODE:' + code);
                    }
                } catch (err) {
                    console.error('Erro Pairing Code:', err);
                    global.pairingCodeRequested = false; // Libera se der erro de rede para tentar de novo
                }
            }, 3000); // 3 segundos garante que a conexão websocket inicial estabilizou
        }

        // --- LISTENERS DO LIVE CHAT (Trava de Segurança contra Duplicação) ---
        if (!socketListenersMapped) {
            socketListenersMapped = true;
            
    socket.on('bot:get-chats', async (data) => {
        let chatsMap = new Map();
        
        // 1. Começa com o que está no cache de mensagens recentes
        recentChats.forEach((val, key) => {
            chatsMap.set(key, { ...val });
        });
        
        // 2. Se for WhatsApp, mescla com a lista completa de grupos participantes
        if (platform === 'whatsapp' && global.sock) {
            try {
                const allGroups = await global.sock.groupFetchAllParticipating();
                for (const jid in allGroups) {
                    const g = allGroups[jid];
                    if (!chatsMap.has(jid)) {
                        chatsMap.set(jid, {
                            jid: jid,
                            name: g.subject,
                            timestamp: g.creation || Date.now(),
                            profilePicUrl: null
                        });
                    } else {
                        // Atualiza nome se já existia no cache
                        chatsMap.get(jid).name = g.subject;
                    }
                }

                // 3. Busca fotos de perfil apenas para grupos que ainda não tem no cache
                const finalChats = Array.from(chatsMap.values());
                for (const c of finalChats) {
                    if (c.jid.endsWith('@g.us') && !c.profilePicUrl) {
                        try {
                            const pic = await global.sock.profilePictureUrl(c.jid, 'image');
                            c.profilePicUrl = pic;
                            // Salva no cache para a próxima vez ser instantâneo
                            if (recentChats.has(c.jid)) {
                                recentChats.get(c.jid).profilePicUrl = pic;
                            }
                        } catch (e) {
                            c.profilePicUrl = null;
                        }
                    }
                }
                
                const sortedChats = finalChats.sort((a,b) => (b.timestamp || 0) - (a.timestamp || 0));
                socket.emit('bot:return-chats', { frontendId: data.frontendId, chats: sortedChats });
                return; // Sai aqui para não emitir duplicado abaixo
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao buscar grupos:`, e.message);
            }
        }
        
        // Fallback para Telegram ou se o WA falhar
        const sortedChats = Array.from(chatsMap.values()).sort((a,b) => (b.timestamp || 0) - (a.timestamp || 0));
        socket.emit('bot:return-chats', { frontendId: data.frontendId, chats: sortedChats });
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

                    // Envia a mensagem de texto E CAPTURA O ID DA MENSAGEM DO BAILEYS
                    const sentText = await sock.sendMessage(jid, { text: data.message + '\u200B' });
                    
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

                    // Confirma o sucesso passando o ID VERDADEIRO (realMsgId)
                    if (data.messageId) {
                        socket.emit('bot:message-status', { 
                            messageId: data.messageId, 
                            success: true, 
                            realMsgId: sentText?.key?.id 
                        });
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
        socket.off('pix:generated-for-client');
        socket.on('pix:generated-for-client', async (data) => {
            const target = data.botSessionName || data.targetBot || data.sessionName;
            if (target === nomeSessao) {
                try {
                    let jid = String(data.clientJid || data.clientNumber).trim();
                    if (!jid) return console.log(`[${nomeSessao}] ❌ Número faltando no payload do Pix WhatsApp.`);
                    
                    if (!jid.includes('@')) {
                        const cleanNum = jid.replace(/\D/g, '');
                        jid = cleanNum.length > 13 ? cleanNum + '@lid' : cleanNum + '@s.whatsapp.net';
                    }
                    
                    const imageBuffer = Buffer.from(data.pixData.qr_code_base64, 'base64');
                    
                    let captionTexto = `Aqui está o seu QR Code Pix para pagamento.\n\nCopie o código abaixo se preferir:`;
                    if (data.isMensal) {
                        captionTexto = `✅ *Pedido gerado: ${data.productName}*\n\nEfetue o pagamento através do QR Code PIX ou Copia e Cola abaixo. Assim que aprovado, o sistema enviará seu acesso automaticamente por aqui!`;
                    }

                    console.log(`[${nomeSessao}] ⏳ Enviando QR Code PIX WhatsApp para ${jid}...`);
                    
                    await sock.sendMessage(jid, {
                        image: imageBuffer,
                        caption: captionTexto
                    });
                    
                    await sock.sendMessage(jid, { text: data.pixData.qr_code });
                    console.log(`[${nomeSessao}] ✅ PIX WhatsApp enviado com sucesso para ${jid}!\n`);
                } catch (e) {
                    console.error(`[${nomeSessao}] ❌ Erro crítico ao enviar PIX no WhatsApp:`, e);
                }
            }
        });

        socket.off('pix:generation-failed');
        socket.on('pix:generation-failed', async (data) => {
            if (data.botSessionName === nomeSessao) {
                let jid = String(data.clientJid || data.clientNumber).trim();
                if (!jid.includes('@')) jid = jid.replace(/\D/g, '') + '@s.whatsapp.net';
                if (jid) {
                    try {
                        await sock.sendMessage(jid, { text: `⚠️ Desculpe, houve um problema ao gerar sua cobrança: ${data.message}` });
                    } catch(e) {}
                }
            }
        });

        // --- FIM: LISTENERS PARA GESTOR DE COBRANÇAS ---

        socket.on('group-activation-result', async (data) => {
            if (data.botSessionName === nomeSessao && data.groupId) {
                const msg = data.success ? `✅ ${data.message || 'Grupo ativado!'}` : `❌ Falha: ${data.message}`;
                if (global.sock) {
                    await global.sock.sendMessage(data.groupId, { text: msg }).catch(() => {});
                }
                if(data.success) {
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null,
                        aiFallbackEnabled: true
                    };
                }
            }
        });
        } // Fim da trava if (!socketListenersMapped)
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

        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;
            
            if (qr && !phoneNumberArg) {
                console.log(`QR_CODE:${qr}`);
            }
            
            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                const isFatalError = statusCode === DisconnectReason.loggedOut || 
                                     statusCode === 403 || 
                                     statusCode === 401 || 
                                     statusCode === 405 || 
                                     statusCode === DisconnectReason.connectionReplaced;

                const isRestartRequired = statusCode === DisconnectReason.restartRequired || statusCode === 428; 
                const shouldReconnect = !isFatalError;

                console.log(`[${nomeSessao}] ⚠️ Conexão encerrada (Status: ${statusCode}).`);

                if (shouldReconnect) {
                    sock.ev.removeAllListeners();
                    global.sock = null;
                    
                    const now = Date.now();
                    let delayMs = isRestartRequired ? 10000 : 5000;
                    if (lastRestartTime && (now - lastRestartTime) < 60000) delayMs = 30000;
                    lastRestartTime = now;

                    console.log(`[${nomeSessao}] 🔄 Realizando reconexão interna recursiva em ${delayMs/1000}s...`);
                    setTimeout(() => {
                        ligarBot();
                    }, delayMs);
                } else {
                    console.log(`[${nomeSessao}] ❌ Desconexão fatal detectada. Limpando sessão...`);
                    try { if (fs.existsSync(authPath)) fs.rmSync(authPath, { recursive: true, force: true }); } catch(e) {}
                    socket.emit('bot-disconnected-fatal', { sessionName: nomeSessao });
                    setTimeout(() => process.exit(0), 2000);
                }
            } else if (connection === 'open') {
                console.log('\nONLINE!'); 
                socket.emit('bot-online', { sessionName: nomeSessao });
                
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
            const { id, participants, action } = update;
            
            // Força o ID do grupo a ser string
            const groupId = typeof id === 'string' ? id : (id?.id || String(id));
            
            console.log(`[${nomeSessao}] 📥 Evento de participantes: ${action} no grupo ${groupId}`);

            if (action !== 'add') return;

            try {
                const me = jidNormalizedUser(sock.user?.id || sock.authState?.creds?.me?.id);
                if (groupAdminsCache.has(groupId)) groupAdminsCache.delete(groupId);

                // NORMALIZAÇÃO CRÍTICA: Transforma o array de objetos em array de strings (JIDs)
                const participantJids = participants.map(p => (typeof p === 'string' ? p : (p.id || String(p))));
                
                // Filtra para remover o próprio bot da lista de boas-vindas
                const newMembers = participantJids.filter(p => jidNormalizedUser(p) !== me);
                
                if (newMembers.length === 0) {
                    console.log(`[${nomeSessao}] 🤖 O próprio bot entrou no grupo.`);
                    return;
                }

                if (botType !== 'group') {
                    console.log(`[${nomeSessao}] 🛑 Bloqueio: Este robô é INDIVIDUAL. Não dará boas-vindas.`);
                    return;
                }

                const group = authorizedGroups[groupId];
                if (!group) {
                    console.log(`[${nomeSessao}] ❌ Grupo ${groupId} NÃO ATIVADO no painel.`);
                    return;
                }

                if (group.expiresAt && new Date() > new Date(group.expiresAt)) {
                    console.log(`[${nomeSessao}] ❌ Grupo expirado.`);
                    return;
                }

                if (group.isPaused) {
                    console.log(`[${nomeSessao}] ⏸️ Grupo pausado.`);
                    return;
                }

                const customWelcome = group.welcomeMessage;
                if (customWelcome === 'off') {
                    console.log(`[${nomeSessao}] 🔕 Boas-vindas desativada.`);
                    return;
                }

                console.log(`[${nomeSessao}] ✨ Processando boas-vindas para ${newMembers.length} usuários...`);
                
                await delay(3000);

                let groupName = "Grupo";
                try {
                    const metadata = await sock.groupMetadata(groupId).catch(() => null);
                    groupName = metadata?.subject || "Grupo";
                } catch (e) { }

                let text = '';
                if (customWelcome && customWelcome.trim() !== '') {
                    const firstJidStr = newMembers[0];
                    const userNumber = firstJidStr.split('@')[0];
                    const userMention = `@${userNumber}`;
                    text = formatWelcomeMessage(customWelcome, userMention, groupName);
                } else {
                    text = `👋 Olá! Seja bem-vindo(a) ao grupo *${groupName}*!`;
                }

                // ENVIO SEGURO: Tudo convertido para string explicitamente
                await sock.sendMessage(groupId, { 
                    text: String(text) + '\u200B', 
                    mentions: newMembers.map(m => String(m)) 
                });
                
                console.log(`[${nomeSessao}] ✅ Boas-vindas enviada no grupo: ${groupName}`);

            } catch (err) {
                console.error(`[${nomeSessao}] ❌ Erro ao processar boas-vindas:`, err.message);
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
                rawText: texto, 
                media: mediaObj,
                quoted: quotedText, 
                isForwarded: isForwardedMsg, 
                pushName: senderName,
                timestamp: (msg.messageTimestamp * 1000) || Date.now()
            });

            const textoLimpo = texto.replace(/[\u200B-\u200D\uFEFF]/g, '').trim();

            // --- BLOQUEIO TOTAL: INDIVIDUAL NUNCA FALA EM GRUPOS (MOVIDO PARA O TOPO) ---
            if (isGroup && botType !== 'group') {
                const isActivating = texto.includes('/ativar?token=') || texto.startsWith('/ativar');
                if (!isActivating) {
                   console.log(`[${nomeSessao}] 🛑 Bloqueio: Este robô é INDIVIDUAL. Ignorando atividade no grupo ${jid}`);
                   return;
                }
            }

            // --- VERIFICAÇÃO DE ATIVAÇÃO ---
            let tokenToActivate = null;
            if (texto.includes('/ativar?token=')) {
                tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            } else if (texto.startsWith('/ativar') && texto.includes('token=')) {
                tokenToActivate = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            } else if (texto.startsWith('/ativar ')) {
                tokenToActivate = texto.split(' ')[1]?.trim();
            }

            if (isGroup && tokenToActivate) {
                if (botType !== 'group') {
                    await sock.sendMessage(jid, { text: '❌ Este robô é de "Atendimento Privado". Para grupos, crie um "Gestor de Grupos".' });
                    return;
                }
                
                let gName = "Grupo Ativado";
                try {
                    const meta = await sock.groupMetadata(jid);
                    if (meta && meta.subject) gName = meta.subject;
                } catch (err) {
                    try {
                        const allGroups = await sock.groupFetchAllParticipating();
                        if (allGroups[jid] && allGroups[jid].subject) gName = allGroups[jid].subject;
                    } catch (err2) { }
                }
                
                socket.emit('group-activation-request', { groupId: jid, groupName: gName, activationToken: tokenToActivate, botSessionName: nomeSessao });
                return; 
            }

            // --- REGISTRO DE LEADS (CONTATOS) ---
            if (!msg.key.fromMe && !isGroup) {
                setTimeout(async () => {
                    try {
                        const rawJid = msg.key.remoteJid;
                        if (rawJid && rawJid !== 'status@broadcast') {
                            const cleanJid = jidNormalizedUser(rawJid);
                            const chatCache = recentChats.get(jid);
                            let picUrl = chatCache ? chatCache.profilePicUrl : null;
                            if (!picUrl || picUrl === undefined) {
                                try {
                                    picUrl = await sock.profilePictureUrl(jid, 'image');
                                    if (chatCache) { chatCache.profilePicUrl = picUrl; saveLiveChatCache(); }
                                } catch (errPic) { picUrl = null; if (chatCache) chatCache.profilePicUrl = null; }
                            }
                            socket.emit('bot:register-lead', { sessionName: nomeSessao, number: cleanJid, name: senderName || 'Cliente', profilePicUrl: picUrl });
                        }
                    } catch (errLead) { }
                }, 150); 
            }

            if (isGlobalPaused) return;

            // --- 1. COMANDOS DE CONTROLE MANUAL ---
            if (textoLimpo.match(/^[!\/]stopsempre/i)) {
                let valueToIgnore = null;
                let isAuth = false;
                if (msg.key.fromMe) {
                    isAuth = true;
                    if (isGroup) {
                         const context = msg.message?.extendedTextMessage?.contextInfo;
                         if (context?.participant) valueToIgnore = jidNormalizedUser(context.participant).split('@')[0];
                    } else valueToIgnore = jidNormalizedUser(jid).split('@')[0];
                } else {
                    if (isGroup) {
                        isAuth = await isGroupAdminWA(sock, jid, sender);
                        const context = msg.message?.extendedTextMessage?.contextInfo;
                        if (isAuth && context?.participant) valueToIgnore = jidNormalizedUser(context.participant).split('@')[0];
                        else { valueToIgnore = jidNormalizedUser(sender).split('@')[0]; isAuth = true; }
                    } else { valueToIgnore = jidNormalizedUser(sender).split('@')[0]; isAuth = true; }
                }
                if (isAuth && valueToIgnore) {
                    const exists = ignoredIdentifiers.some(i => i.type === 'number' && i.value === valueToIgnore);
                    if (!exists) {
                        ignoredIdentifiers.push({ type: 'number', value: valueToIgnore });
                        socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'number', value: valueToIgnore });
                        console.log(`[${nomeSessao}] 🚫 Número ${valueToIgnore} ignorado permanentemente.`);
                    }
                    try {
                        const deleteKey = { remoteJid: msg.key.remoteJid, fromMe: msg.key.fromMe, id: msg.key.id };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        await delay(500);
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `✅ O número ${valueToIgnore} será ignorado permanentemente.` });
                    } catch (e) { }
                }
                return;
            }

            const stopMatch = textoLimpo.match(/^[!\/]stop\s*(\d*)/i);
            if (stopMatch && !textoLimpo.match(/^[!\/]stopsempre/i)) {
                let isAuth = false;
                if (msg.key.fromMe) isAuth = true;
                else if (isGroup) isAuth = await isGroupAdminWA(sock, jid, sender);
                else isAuth = true;
                if (isAuth) {
                    const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                    pausados[jid] = Date.now() + (minutos * 60 * 1000);
                    console.log(`IA pausada`);
                    console.log(`> 🛑 COMANDO CHAT: IA pausada por ${minutos}min via comando [!stop] enviado por ${senderName}.`);
                    try {
                        const deleteKey = { remoteJid: msg.key.remoteJid, fromMe: msg.key.fromMe, id: msg.key.id };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        await delay(500);
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `🔇 Bot pausado por ${minutos} minuto(s).` });
                    } catch (e) { }
                    return; 
                }
            }

            if (textoLimpo.match(/^[!\/](voltar|start|retomar)/i)) {
                let isAuth = false;
                if (msg.key.fromMe) isAuth = true;
                else if (isGroup) isAuth = await isGroupAdminWA(sock, jid, sender);
                else isAuth = true;
                if (isAuth) {
                    if (pausados[jid]) delete pausados[jid];
                    console.log(`[${nomeSessao}] 🔊 IA retomada manualmente.`);
                    try {
                        const deleteKey = { remoteJid: msg.key.remoteJid, fromMe: msg.key.fromMe, id: msg.key.id };
                        if (msg.key.participant) deleteKey.participant = msg.key.participant;
                        await delay(500);
                        await sock.sendMessage(jid, { delete: deleteKey });
                        await sock.sendMessage(jid, { text: `🔊 Bot reativado.` });
                    } catch (e) {}
                    return;
                }
            }

            // --- 4. AUTO-PAUSA POR INTERVENÇÃO HUMANA (ISOLADA POR CHAT) ---
            const isBotEcho = texto.includes('\u200B') || 
                              textoLimpo.includes('\u200B') ||
                              textoLimpo.startsWith('000201010211') || 
                              /^[✅🔒🔓🧠🔕🔗👋🔇🔊🚫⚠️🏓🤖👤👮📢🛡️]/.test(textoLimpo);
            
            // Só considera intervenção humana se: For do dono (fromMe), NÃO for eco do bot e NÃO for grupo (se for bot individual)
            const isHumanFromPhone = msg.key.fromMe && !isBotEcho && !textoLimpo.startsWith('!') && !textoLimpo.startsWith('/');
            
            if (isHumanFromPhone && !isGroup) {
                // Define a pausa APENAS para este JID específico
                pausados[jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000);
                console.log(`IA pausada`);
                console.log(`> 📱 INTERVENÇÃO MANUAL: Resposta detectada direto no aparelho celular. IA pausada por ${humanPauseTimeMinutes}min para este contato.`); 
                return;
            }

            // Verifica se este chat específico está em tempo de pausa
            if (pausados[jid] && Date.now() < pausados[jid]) {
                // Se o humano continuar falando NO MESMO CHAT, estende a pausa só deste chat
                if (!isGroup && isHumanFromPhone) {
                    pausados[jid] = Date.now() + (humanPauseTimeMinutes * 60 * 1000);
                    console.log(`[${nomeSessao}] 🔇 Conversa ativa durante pausa em ${jid.split('@')[0]}. Pausa renovada por mais ${humanPauseTimeMinutes}min.`);
                }
                return; // Bloqueia a IA apenas para este JID
            }

            // Se a mensagem for do robô (eco), mas ele tem cooldown configurado
            if (msg.key.fromMe) {
                if (silenceTimeMinutesGlobal > 0 && isBotEcho && !isGroup) {
                    const autoSilenceMs = silenceTimeMinutesGlobal * 60 * 1000;
                    pausados[jid] = Date.now() + autoSilenceMs;
                    console.log(`IA em cooldown para ${jid.split('@')[0]}`);
                }
                return;
            }

            let groupConfig = null;
            if (botType === 'group') {
                if (!isGroup || !authorizedGroups[jid]) return;
                if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
                groupConfig = authorizedGroups[jid];
                if (groupConfig.isPaused) return;
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
            let possuiGatilhos = false;

            if (groupConfig) {
                useAI = groupConfig.aiFallbackEnabled !== false;
                possuiGatilhos = (groupConfig.autoResponder && groupConfig.autoResponder.length > 0) || (autoResponder && autoResponder.length > 0);
            } else {
                useAI = aiFallbackEnabledGlobal;
                possuiGatilhos = (autoResponder && autoResponder.length > 0);
            }

            // SALVAGUARDA LÓGICA: Se a IA foi desligada, mas não há nenhuma resposta rápida, liga a IA de volta
            if (!useAI && !possuiGatilhos) {
                useAI = true;
            }

            if (!useAI) return; // SE A IA ESTIVER DESLIGADA (E HOUVER REGRAS), PARA AQUI E O ROBO FICA EM SILÊNCIO

            // BLOQUEIO DE MÍDIAS NÃO SUPORTADAS PELA IA (Evita loop de mensagens vazias)
            // A IA só deve processar Texto puro ou Áudio (isAudio). Reações, documentos e figurinhas morrem aqui.
            if (!textoLimpo && !isAudio) {
                console.log(`[${nomeSessao}] Mensagem ignorada pela IA (Sintaxe vazia ou mídia não suportada).`);
                return;
            }

            // 6. Processamento IA
            try {
                console.log(`[DEBUG] Mensagem recebida de ${jid}. Enviando 'composing'...`);
                
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

                let resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio, promptToUse);
                
                // Para a animação de digitando assim que a IA gera a resposta
                isThinking = false;
                clearInterval(typingInterval);
                
                if (resposta && resposta.trim().length > 0) {
                    try {
                        // INTERCEPTADOR DE TESTE E COBRANÇA MENSAL DA IA
                        const iptvMatch = resposta.match(/\[ACTION:GERAR_TESTE(?::(\d+))?\]/);
                        const mensalCobrarMatch = resposta.match(/\[ACTION:COBRAR_MENSAL(?::(\d+))?\]/);
                        
                        if (mensalCobrarMatch) {
                            let cleanText = resposta.replace(/\[ACTION:COBRAR_MENSAL(?::\d+)?\]/g, '').trim();
                            await sock.sendMessage(jid, { text: (cleanText ? cleanText + '\n\n' : '') + '⏳ Gerando sua cobrança PIX automática, só um instante...' });
                            
                            let pIndex = mensalCobrarMatch[1] ? parseInt(mensalCobrarMatch[1]) : 0;
                            
                            socket.emit('client:request-mensal-pix', {
                                botSessionName: nomeSessao,
                                clientJid: jid,
                                providerIndex: pIndex
                            });
                            
                            pausados[jid] = Date.now() + (10 * 60 * 1000); // Pausa para o bot não se meter e enviar o pix
                        }
                        else if (iptvMatch) {
                            let cleanText = resposta.replace(/\[ACTION:GERAR_TESTE(?::\d+)?\]/g, '').trim();
                            await sock.sendMessage(jid, { text: (cleanText ? cleanText + '\n\n' : '') + '⏳ Gerando seu teste, só um instante...' });
                            
                            try {
                                let providers = iptvSettings.providers ||[];
                                if (providers.length === 0 && iptvSettings.webhookUrl) {
                                    providers =[{ name: 'Padrão', url: iptvSettings.webhookUrl }];
                                }
                                
                                let pIndex = iptvMatch[1] ? parseInt(iptvMatch[1]) : 0;
                                if (!providers[pIndex]) pIndex = 0; // Se a IA inventar ID, usa o primeiro
                                
                                const targetUrl = providers[pIndex].url;
                                if (!targetUrl) throw new Error("URL de webhook não configurada.");

                                const phoneOnly = jid.split('@')[0];
                                const webhookFinalUrl = targetUrl.includes('?') 
                                    ? `${targetUrl}&numero=${phoneOnly}&nome=${encodeURIComponent(msg.pushName || 'Cliente')}` 
                                    : `${targetUrl}?numero=${phoneOnly}&nome=${encodeURIComponent(msg.pushName || 'Cliente')}`;

                                let response = null;
                                const methodsToTry =['GET', 'POST'];
                                
                                for (const method of methodsToTry) {
                                    response = await axios({
                                        method: method,
                                        url: webhookFinalUrl,
                                        timeout: 15000,
                                        validateStatus: () => true // Evita crash
                                    });

                                    // Checa se o painel bloqueou por causa do método (ex: 405 ou texto específico)
                                    const responseDataStr = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                                    if (response.status === 405 || responseDataStr.toLowerCase().includes('method is not supported')) {
                                        console.log(`[${nomeSessao}] Método ${method} recusado pelo painel webhook. Tentando o próximo...`);
                                        continue; // Pula pro próximo método (ex: POST)
                                    }
                                    
                                    // Se não for erro de método, sai do loop e processa a resposta
                                    break;
                                }
                                
                                let iptvResponseText = '';
                                if (typeof response.data === 'object') {
                                    if (response.data.reply) iptvResponseText = response.data.reply;
                                    else if (response.data.msg) iptvResponseText = response.data.msg;
                                    else if (response.data.message) iptvResponseText = response.data.message;
                                    else if (response.data.error) iptvResponseText = response.data.error;
                                    else if (Array.isArray(response.data.data) && response.data.data.length > 0 && response.data.data[0].message) {
                                        iptvResponseText = response.data.data[0].message;
                                    }
                                    else iptvResponseText = JSON.stringify(response.data, null, 2);
                                } else {
                                    iptvResponseText = String(response.data).replace(/<br>/gi, '\n').replace(/<[^>]*>?/gm, '');
                                }

                                let validadeISO = null;
                                try {
                                    const regexExp = /(?:vencimento|validade|expira|v[áa]lido|at[ée])[^\n\d]*(\d{2})[\/\-](\d{2})[\/\-](\d{4})(?:[^\n\d]*(\d{2}):(\d{2})(?::(\d{2}))?)?/i;
                                    let matchData = iptvResponseText.match(regexExp);
                                    if (!matchData) matchData = iptvResponseText.match(/(\d{2})[\/\-](\d{2})[\/\-](\d{4})(?:[^\n\d]*(\d{2}):(\d{2})(?::(\d{2}))?)?/);
                                    
                                    if (matchData) {
                                        let YYYY = matchData[3];
                                        let MM = matchData[2];
                                        let DD = matchData[1];
                                        let hh = matchData[4] ? matchData[4].padStart(2, '0') : '12';
                                        let mm = matchData[5] ? matchData[5].padStart(2, '0') : '00';
                                        let ss = matchData[6] ? matchData[6].padStart(2, '0') : '00';
                                        
                                        // Cria a data e FORÇA o Fuso Horário do Brasil para não bagunçar horas
                                        validadeISO = new Date(`${YYYY}-${MM}-${DD}T${hh}:${mm}:${ss}-03:00`).toISOString();
                                    }
                                } catch(e) {}

                                let finalIptvMessage = (iptvSettings.successMsg ? iptvSettings.successMsg + "\n\n" : "") + iptvResponseText;
                                resposta = finalIptvMessage; 
                                
                                // Pausa a IA por 10 minutos para que ela não interrompa o cliente testando
                                pausados[jid] = Date.now() + (10 * 60 * 1000); 
                                console.log(`[${nomeSessao}] 📺 Teste IPTV processado com status: ${response.status} e IA pausada.`);

                                // EMITE O EVENTO PARA SALVAR O HISTÓRICO NO GERENCIAMENTO
                                socket.emit('bot:register-iptv-history', {
                                    sessionName: nomeSessao,
                                    jid: jid,
                                    name: msg.pushName || 'Cliente',
                                    type: 'teste',
                                    providerName: providers[pIndex] ? providers[pIndex].name : 'Padrão',
                                    date: new Date().toISOString(),
                                    validade: validadeISO
                                });

                            } catch (iptvErr) {
                                console.error(`[${nomeSessao}] ❌ Erro ao gerar teste IPTV:`, iptvErr.message);
                                resposta = "Desculpe, nosso sistema de testes está temporariamente indisponível no servidor. Verifique a integração.";
                            }
                        }

                        if (!mensalCobrarMatch) {
                            const sentIA = await sock.sendMessage(jid, { text: resposta + '\u200B' }, { quoted: msg });
                            if (sentIA) {
                                messageStore.add(sentIA.key, sentIA.message);
                                await saveLiveMessage(sock, jid, 'Bot (IA)', { id: sentIA.key.id, fromMe: true, text: resposta, timestamp: Date.now() });
                            }
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






