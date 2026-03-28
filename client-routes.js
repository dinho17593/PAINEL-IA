//client-routes.js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cron = require('node-cron');

const BASE_DIR = __dirname;
const CLIENTS_DB_PATH = path.join(BASE_DIR, 'clients.json');
const CAMPAIGNS_DB_PATH = path.join(BASE_DIR, 'campaigns.json');
const PAYMENTS_DB_PATH = path.join(BASE_DIR, 'payments.json');

// --- Funções Auxiliares de Arquivo (Garantia de funcionamento) ---
const readJSON = (filePath) => {
    try {
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf-8').trim();
            return content ? JSON.parse(content) : [];
        }
        return[];
    } catch (e) {
        console.error(`Erro ao ler ${filePath}:`, e);
        return[];
    }
};

const writeJSON = (filePath, data) => {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (e) {
        console.error(`Erro ao escrever em ${filePath}:`, e);
    }
};

// Inicializa arquivos se não existirem
if (!fs.existsSync(CLIENTS_DB_PATH)) writeJSON(CLIENTS_DB_PATH,[]);
if (!fs.existsSync(CAMPAIGNS_DB_PATH)) writeJSON(CAMPAIGNS_DB_PATH,[]);
if (!fs.existsSync(PAYMENTS_DB_PATH)) writeJSON(PAYMENTS_DB_PATH,[]);

// Função auxiliar para formatar número (Preserva IDs do WhatsApp como @lid)
function formatNumber(num) {
    if (!num) return '';
    const strNum = String(num).trim();
    
    // Se já é um ID interno do WhatsApp (@s.whatsapp.net ou @lid), NÃO formata!
    if (strNum.includes('@')) return strNum;
    
    let cleanNum = strNum.replace(/\D/g, '');
    if (cleanNum.length >= 10 && cleanNum.length <= 11) {
        return '55' + cleanNum;
    }
    return cleanNum;
}

// Função auxiliar para salvar pagamento pendente
function savePendingPayment(paymentData, campaign, clientNumber, clientName) {
    try {
        const payments = readJSON(PAYMENTS_DB_PATH);
        if (payments.some(p => p.id === paymentData.id)) return;

        const record = {
            id: paymentData.id,
            date: new Date().toISOString(),
            amount: paymentData.transaction_amount,
            campaignId: campaign.id,
            campaignName: campaign.name,
            clientNumber: clientNumber,
            clientName: clientName,
            owner: campaign.owner,
            status: 'pending'
        };

        payments.push(record);
        writeJSON(PAYMENTS_DB_PATH, payments);
        return record;
    } catch (e) {
        console.error("[PAYMENT] Erro ao salvar pagamento pendente:", e);
    }
}

// Função auxiliar para aguardar a confirmação do bot
const sendMessageWithAck = (io, targetBot, payload, timeoutMs = 20000) => {
    return new Promise((resolve) => {
        const messageId = crypto.randomUUID();
        payload.messageId = messageId;

        const timeout = setTimeout(() => {
            global.botEvents.removeAllListeners(`status-${messageId}`);
            resolve({ success: false, error: 'Timeout: O robô demorou muito para responder.' });
        }, timeoutMs);

        global.botEvents.once(`status-${messageId}`, (data) => {
            clearTimeout(timeout);
            resolve(data);
        });

        // Envia a ordem DIRETAMENTE para o processo do robô correto (Evita gargalo)
        io.to('bot_' + targetBot).emit('bot:send-client-message', payload);
    });
};

// Lógica de envio
async function executeCampaign(io, campaign, generatePix, db, botController, generatePaypalOrder) {
    const clients = readJSON(CLIENTS_DB_PATH);
    const targetClients = clients.filter(c => campaign.clients.includes(c.id));

    // --- LÓGICA DE AUTO-LIGAR O BOT ---
    let wasOffline = false;
    if (botController && botController.activeBots) {
        if (!botController.activeBots[campaign.targetBot]) {
            wasOffline = true;
            console.log(`[CAMPANHA] Bot ${campaign.targetBot} está offline. Ligando temporariamente para a campanha...`);
            const allBots = await db.getAllBots();
            const botData = allBots[campaign.targetBot];
            if (botData) {
                botController.startBotProcess(botData);
                
                // Aguarda até 20 segundos verificando se o bot realmente ficou Online
                let isOnline = false;
                for (let i = 0; i < 10; i++) {
                    await new Promise(resolve => setTimeout(resolve, 2000)); // Checa a cada 2s
                    const checkBots = await db.getAllBots();
                    if (checkBots[campaign.targetBot] && checkBots[campaign.targetBot].status === 'Online') {
                        isOnline = true;
                        break;
                    }
                }

                // Se não conectou (ex: precisa ler QR Code ou banido), aborta a campanha!
                if (!isOnline) {
                    console.log(`[CAMPANHA] Bot ${campaign.targetBot} não conectou a tempo. Abortando campanha.`);
                    
                    // Desliga o processo que tentou iniciar
                    const activeProcess = botController.activeBots[campaign.targetBot];
                    if (activeProcess) {
                        activeProcess.intentionalStop = true;
                        try { activeProcess.process.kill('SIGINT'); } catch(e){}
                        delete botController.activeBots[campaign.targetBot];
                    }
                    botController.updateBotStatus(campaign.targetBot, 'Offline');

                    // Marca a campanha como falha e avisa o usuário
                    const allCampaigns = readJSON(CAMPAIGNS_DB_PATH);
                    const campaignIndex = allCampaigns.findIndex(c => c.id === campaign.id);
                    if (campaignIndex !== -1) {
                        allCampaigns[campaignIndex].status = 'failed';
                        writeJSON(CAMPAIGNS_DB_PATH, allCampaigns);
                        io.to(campaign.owner.toLowerCase()).emit('campaigns:list', allCampaigns.filter(c => c.owner === campaign.owner));
                        io.to(campaign.owner.toLowerCase()).emit('feedback', { success: false, message: `Campanha abortada: O robô não conseguiu conectar. Verifique se ele precisa ler o QR Code.` });
                    }
                    return; // Para a execução da função aqui
                }
            }
        }
    }
    // ----------------------------------

    let successCount = 0;
    let failCount = 0;
    let totalClients = targetClients.length;
    let currentIndex = 0;

    for (const client of targetClients) {
        currentIndex++;

        const formattedNumber = formatNumber(client.number);

        // --- INTELIGÊNCIA: PULAR SE JÁ ESTIVER PAGO (Para Mensal Recorrente) ---
        if (campaign.type === 'cobranca' && campaign.scheduleType === 'monthly') {
            const payments = readJSON(PAYMENTS_DB_PATH);
            const now = new Date();
            
            // Verifica se existe um pagamento aprovado para este cliente, nesta campanha, dentro do mês atual
            const alreadyPaid = payments.some(p => 
                p.campaignId === campaign.id && 
                p.clientNumber === formattedNumber && 
                p.status === 'approved' &&
                new Date(p.date).getMonth() === now.getMonth() &&
                new Date(p.date).getFullYear() === now.getFullYear()
            );

            if (alreadyPaid) {
                console.log(`[CAMPANHA] Lembrete pulado para ${client.name} - Já pagou a fatura deste mês.`);
                continue; // Pula para o próximo cliente sem enviar nada
            }
        }
        
        // VERIFICA SE A CAMPANHA FOI CANCELADA PELO BOTÃO DO PAINEL
        const checkCamps = readJSON(CAMPAIGNS_DB_PATH);
        const campState = checkCamps.find(c => c.id === campaign.id);
        if (!campState || campState.status === 'canceled') {
            console.log(`[CAMPANHA] A campanha "${campaign.name}" foi cancelada pelo usuário durante o envio.`);
            break; // Interrompe o loop imediatamente
        }

        // Emite o progresso AO VIVO para a tela do Gestor
        io.to(campaign.owner.toLowerCase()).emit('campaign:progress', {
            campaignId: campaign.id,
            campaignName: campaign.name,
            clientName: client.name,
            clientNumber: client.number,
            profilePicUrl: client.profilePicUrl,
            current: currentIndex,
            total: totalClients
        });

        // --- NOVA VARIÁVEL: {saudacao} COM FUSO HORÁRIO DO BRASIL ---
        const hourStr = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', hourCycle: 'h23' });
        const hour = parseInt(hourStr, 10);
        
        let saudacao = 'Bom dia';
        if (hour >= 12 && hour < 18) saudacao = 'Boa tarde';
        else if (hour >= 18 || hour < 4) saudacao = 'Boa noite';

        let message = campaign.message
            .replace(/{nome}/gi, client.name)
            .replace(/{saudacao}/gi, saudacao);
            
        // Removida a redeclaração de formattedNumber que causava erro
        let pixData = null;
        let pixErrorMsg = "";

        // Se for cobrança, gera o PIX ou Link PayPal antes de tentar enviar
        if (campaign.type === 'cobranca') {
            const valor = parseFloat(campaign.value || 0).toFixed(2);
            message = message.replace(/{valor}/gi, valor);
            message = message.replace(/{link_pagamento}/gi, '');
            
            try {
                const users = await db.getAllUsers();
                const ownerData = users[campaign.owner];
                const amount = parseFloat(campaign.value);
                const description = `Payment: ${campaign.name}`;
                const external_reference = `campaign|${campaign.id}|${formattedNumber}`;

                // Detecta se o dono da campanha usa idioma estrangeiro (ou se não tem token MP mas tem PayPal)
                // Usaremos a lógica: se não for PT, vai de PayPal.
                const isPortuguese = (ownerData.language === 'pt' || !ownerData.language); 

                if (isPortuguese && ownerData.mpAccessToken) {
                    // LÓGICA MERCADO PAGO (PIX)
                    const reqMock = { headers: { host: 'localhost:3000' }, body: { botSessionName: campaign.targetBot }, connection: {} };
                    const result = await generatePix(reqMock, amount, description, external_reference, ownerData.mpAccessToken);
                    
                    if (result && result.id) {
                        if (campaign.generateCardLink !== false) {
                            try {
                                const { MercadoPagoConfig, Preference } = require('mercadopago');
                                const clientMP = new MercadoPagoConfig({ accessToken: ownerData.mpAccessToken });
                                const preference = new Preference(clientMP);
                                const prefResult = await preference.create({
                                    body: {
                                        items:[{ id: 'cobranca', title: description, quantity: 1, unit_price: amount }],
                                        external_reference: external_reference
                                    }
                                });
                                if (prefResult && prefResult.init_point) {
                                    message += `\n\n💳 *Pagar com Cartão ou Boleto:*\n${prefResult.init_point}`;
                                }
                            } catch (prefErr) { }
                        }
                        savePendingPayment({ id: result.id, transaction_amount: amount }, campaign, formattedNumber, client.name);
                        pixData = {
                            qr_code: result.point_of_interaction.transaction_data.qr_code,
                            qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64,
                        };
                    }
                } else if (ownerData.paypalClientId && ownerData.paypalClientSecret) {
                    // LÓGICA PAYPAL (INTERNACIONAL)
                    try {
                        const paypalUrl = await generatePaypalOrder(amount, description, external_reference, ownerData.paypalClientId, ownerData.paypalClientSecret);
                        if (paypalUrl) {
                            message += `\n\n💳 *Pay with Credit Card (PayPal):*\n${paypalUrl}`;
                        }
                    } catch (ppErr) {
                        console.error("[CAMPANHA] Erro PayPal:", ppErr.message);
                        pixErrorMsg = "\n\n(Error generating PayPal link)";
                    }
                } else {
                    pixErrorMsg = isPortuguese ? "\n\n(Erro: Configuração de pagamento incompleta.)" : "\n\n(Error: Payment configuration incomplete.)";
                }
                
                // Atualiza lista de pagamentos no front
                const allPayments = readJSON(PAYMENTS_DB_PATH);
                io.to(campaign.owner.toLowerCase()).emit('payments:list', allPayments.filter(p => p.owner === campaign.owner));

            } catch (e) {
                console.error("[CAMPANHA] Erro geral cobrança:", e.message);
                pixErrorMsg = "\n\n(Error generating automatic payment)";
            }
        }

        // Prepara o Payload
        const payload = {
            targetBot: campaign.targetBot,
            clientNumber: formattedNumber,
            clientId: client.id, // ID para atualizar a foto
            owner: campaign.owner, // Dono para atualizar a tela
            message: message + pixErrorMsg,
            pixData: pixData 
        };

        // Sistema de Retry (Tenta até 3 vezes)
        let messageSent = false;
        let attempts = 0;
        const maxAttempts = 3;

        while (!messageSent && attempts < maxAttempts) {
            attempts++;
            console.log(`[CAMPANHA] Enviando para ${formattedNumber} (Tentativa ${attempts}/${maxAttempts})...`);
            
            try {
                const response = await sendMessageWithAck(io, campaign.targetBot, payload);
                if (response.success) {
                    messageSent = true;
                    console.log(`[CAMPANHA] ✅ Sucesso para ${formattedNumber}`);
                } else {
                    console.log(`[CAMPANHA] ⚠️ Falha para ${formattedNumber}: ${response.error}`);
                }
            } catch (e) {
                console.log(`[CAMPANHA] ⚠️ Erro de execução para ${formattedNumber}:`, e.message);
            }

            if (!messageSent && attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 5000)); // Espera 5s antes de tentar de novo
            }
        }

        if (messageSent) {
            successCount++;
        } else {
            failCount++;
        }

        // ANTI-BAN: Aguarda 5 a 8 segundos antes de disparar para o PRÓXIMO cliente
        const randomDelay = Math.floor(Math.random() * 3000) + 5000;
        await new Promise(resolve => setTimeout(resolve, randomDelay));
    }

    // Atualiza o status final da campanha
    if (campaign.scheduleType === 'now' || campaign.scheduleType === 'scheduled') {
        const allCampaigns = readJSON(CAMPAIGNS_DB_PATH);
        const campaignIndex = allCampaigns.findIndex(c => c.id === campaign.id);
        
        if (campaignIndex !== -1) {
            
            if (allCampaigns[campaignIndex].status === 'canceled') {
                // Se foi cancelada, não altera o status para 'sent', apenas avisa o frontend
                io.to(campaign.owner.toLowerCase()).emit('campaign:finished', {
                    campaignName: campaign.name + ' (Cancelada)',
                    successCount,
                    failCount
                });
                io.to(campaign.owner.toLowerCase()).emit('feedback', { success: true, message: `Campanha "${campaign.name}" foi interrompida.` });
            } else {
                // Lógica de finalização normal
                io.to(campaign.owner.toLowerCase()).emit('campaign:finished', {
                    campaignName: campaign.name,
                    successCount,
                    failCount
                });

                if (successCount === 0) {
                    allCampaigns[campaignIndex].status = 'failed';
                    io.to(campaign.owner.toLowerCase()).emit('feedback', { success: false, message: `A campanha "${campaign.name}" falhou. Nenhuma mensagem foi enviada.` });
                } else if (failCount > 0) {
                    allCampaigns[campaignIndex].status = 'sent';
                    io.to(campaign.owner.toLowerCase()).emit('feedback', { success: true, message: `Campanha "${campaign.name}" enviada com ${failCount} falha(s).` });
                } else {
                    allCampaigns[campaignIndex].status = 'sent';
                    io.to(campaign.owner.toLowerCase()).emit('feedback', { success: true, message: `Campanha "${campaign.name}" enviada com sucesso para todos!` });
                }
                
                writeJSON(CAMPAIGNS_DB_PATH, allCampaigns);
            }
            
            const userCampaigns = allCampaigns.filter(c => c.owner === campaign.owner);
            io.to(campaign.owner.toLowerCase()).emit('campaigns:list', userCampaigns);
        }
    }

    // --- LÓGICA DE AUTO-DESLIGAR O BOT ---
    if (wasOffline && botController && botController.activeBots) {
        console.log(`[CAMPANHA] Campanha finalizada. Desligando o bot ${campaign.targetBot} que foi ligado temporariamente.`);
        const activeProcess = botController.activeBots[campaign.targetBot];
        if (activeProcess) {
            activeProcess.intentionalStop = true;
            try { activeProcess.process.kill('SIGINT'); } catch(e){}
            delete botController.activeBots[campaign.targetBot];
        }
        botController.updateBotStatus(campaign.targetBot, 'Offline');
    }
    // -------------------------------------
}

function clientRoutes(io, generatePix, generatePaypalOrder, db, botController) {
    
    // --- AUTO-CURA: Limpa campanhas que ficaram presas se o servidor reiniciou ---
    try {
        let allCamps = readJSON(CAMPAIGNS_DB_PATH);
        let changed = false;
        allCamps.forEach(c => {
            if (c.status === 'processing') {
                c.status = 'failed'; // Marca como falha para o usuário saber que parou
                changed = true;
            }
        });
        if (changed) writeJSON(CAMPAIGNS_DB_PATH, allCamps);
    } catch (e) { console.error("[SISTEMA] Erro ao limpar campanhas presas:", e); }
    // -----------------------------------------------------------------------------

    cron.schedule('* * * * *', async () => {
        try {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const nowTime = Date.now(); // Tempo universal exato
            
            // --- CORREÇÃO DE FUSO HORÁRIO (TIMEZONE) ---
            // Força a leitura do dia, hora e minuto atual no fuso do Brasil (UTC-3)
            const nowBRStr = new Date().toLocaleString("en-US", { timeZone: "America/Sao_Paulo" });
            const nowBR = new Date(nowBRStr);
            const currentDay = nowBR.getDate();
            const currentHour = nowBR.getHours();
            const currentMinute = nowBR.getMinutes();

            const toRun =[];

            // 1. Mensais e Recorrência Diária: Dispara às 09:00 (Horário de Brasília)
            if (currentHour === 9 && currentMinute === 0) {
                const monthlyCampaigns = campaigns.filter(c => {
                    if (c.status !== 'active' || c.scheduleType !== 'monthly') return false;
                    
                    const dueDay = parseInt(c.scheduleDay);
                    
                    // Caso A: Hoje é exatamente o dia do vencimento
                    if (dueDay === currentDay) return true;
                    
                    // Caso B: Cobrança diária antecipada ativada
                    if (c.sendDailyUntilDue) {
                        const daysBefore = parseInt(c.daysBeforeStart) || 0;
                        const startDay = dueDay - daysBefore;
                        
                        // Verifica se hoje está no intervalo [Vencimento - X dias, Vencimento]
                        return currentDay >= startDay && currentDay < dueDay;
                    }
                    
                    return false;
                });
                toRun.push(...monthlyCampaigns);
            }

            // 2. Agendamento Fixo: Garante que a data do HTML seja validada no Fuso do Brasil
            const scheduledCampaigns = campaigns.filter(c => {
                if (c.status !== 'active' || c.scheduleType !== 'scheduled' || !c.scheduleDate) return false;
                
                let dateStr = c.scheduleDate;
                
                // O HTML envia a data no formato "YYYY-MM-DDThh:mm" sem fuso.
                // Aqui nós forçamos o "-03:00" para que a VPS não confunda com o fuso local dela.
                if (dateStr.length === 16) { 
                    dateStr += ':00-03:00'; 
                }
                
                const scheduledTime = new Date(dateStr).getTime();
                
                // Só dispara se o tempo agendado (agora em UTC-3) for igual ou menor que o momento exato agora
                return scheduledTime <= nowTime;
            });
            
            toRun.push(...scheduledCampaigns);

            // Otimização: Lê e escreve no disco apenas UMA vez, em vez de fazer isso dentro do loop
            if (toRun.length > 0) {
                let allCamps = readJSON(CAMPAIGNS_DB_PATH);
                let needsSave = false;

                for (const campaign of toRun) {
                    const idx = allCamps.findIndex(c => c.id === campaign.id);
                    if (idx !== -1 && allCamps[idx].status === 'active') {
                        allCamps[idx].status = 'processing';
                        needsSave = true;
                    }
                }

                if (needsSave) {
                    writeJSON(CAMPAIGNS_DB_PATH, allCamps);
                }

                // Executa as campanhas após salvar o status
                for (const campaign of toRun) {
                    await executeCampaign(io, campaign, generatePix, db, botController, generatePaypalOrder);
                }
            }
        } catch (e) { console.error("[CRON] Erro:", e); }
    });

    io.on('connection', (socket) => {
        const user = socket.request.session.user;
        if (!user) return;

        socket.on('clients:get', () => {
            const allClients = readJSON(CLIENTS_DB_PATH);
            const userClients = allClients.filter(c => c.owner === user.username);
            socket.emit('clients:list', userClients);
        });

        socket.on('clients:add', (data) => {
            if (!data.name || !data.number) return socket.emit('clients:added', { success: false, message: 'Dados incompletos.' });
            const clients = readJSON(CLIENTS_DB_PATH);
            const finalNumber = formatNumber(data.number);
            const newClient = { id: crypto.randomUUID(), owner: user.username, name: data.name, number: finalNumber };
            clients.push(newClient);
            writeJSON(CLIENTS_DB_PATH, clients);
            socket.emit('clients:added', { success: true, message: 'Cliente adicionado!' });
            socket.emit('clients:list', clients.filter(c => c.owner === user.username));
        });

        socket.on('clients:add-bulk', (data) => {
            if (!data || !Array.isArray(data)) return;
            const clients = readJSON(CLIENTS_DB_PATH);
            let addedCount = 0;
            
            data.forEach(c => {
                if (c.number) {
                    const finalNumber = formatNumber(c.number);
                    const exists = clients.some(existing => existing.number === finalNumber && existing.owner === user.username);
                    if (!exists) {
                        clients.push({ 
                            id: crypto.randomUUID(), 
                            owner: user.username, 
                            name: c.name || 'Cliente', 
                            number: finalNumber,
                            profilePicUrl: c.profilePicUrl || null 
                        });
                        addedCount++;
                    }
                }
            });
            
            writeJSON(CLIENTS_DB_PATH, clients);
            socket.emit('clients:added', { success: true, message: `${addedCount} importados.` });
            socket.emit('clients:list', clients.filter(c => c.owner === user.username));
        });

        socket.on('clients:delete', (data) => {
            let clients = readJSON(CLIENTS_DB_PATH);
            const clientIndex = clients.findIndex(c => c.id === data.id);
            if (clientIndex !== -1) {
                const client = clients[clientIndex];
                if (client.owner === user.username || user.isAdmin) {
                    clients.splice(clientIndex, 1); 
                    writeJSON(CLIENTS_DB_PATH, clients); 
                    socket.emit('clients:list', clients.filter(c => c.owner === user.username));
                    socket.emit('feedback', { success: true, message: 'Cliente excluído.' });
                } else {
                    socket.emit('feedback', { success: false, message: 'Sem permissão.' });
                }
            } else {
                socket.emit('feedback', { success: false, message: 'Cliente não encontrado.' });
            }
        });

        socket.on('clients:delete-bulk', (data) => {
            if (!data.ids || !Array.isArray(data.ids)) return;
            let clients = readJSON(CLIENTS_DB_PATH);
            const initialLen = clients.length;
            clients = clients.filter(c => !data.ids.includes(c.id) || (c.owner !== user.username && !user.isAdmin));
            if (clients.length < initialLen) {
                writeJSON(CLIENTS_DB_PATH, clients);
                socket.emit('clients:list', clients.filter(c => c.owner === user.username));
                socket.emit('feedback', { success: true, message: 'Clientes excluídos.' });
            }
        });

        socket.on('campaigns:get', () => {
            const all = readJSON(CAMPAIGNS_DB_PATH);
            socket.emit('campaigns:list', all.filter(c => c.owner === user.username));
        });

        socket.on('campaigns:create', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            
            // Cálculo do Próximo Envio inicial para Campanhas de Grupo
            let nextRun = null;
            if (data.type === 'group_blast') {
                const now = new Date();
                if (data.frequency === 'hourly') {
                    // Primeiro envio agora
                    nextRun = now.toISOString();
                } else if (data.frequency === 'daily' && data.time) {
                    const [hrs, mins] = data.time.split(':');
                    let scheduled = new Date();
                    scheduled.setHours(parseInt(hrs), parseInt(mins), 0, 0);
                    
                    // Se o horário já passou hoje, agenda para amanhã
                    if (scheduled <= now) {
                        scheduled.setDate(scheduled.getDate() + 1);
                    }
                    nextRun = scheduled.toISOString();
                }
            }

            const newCampaign = {
                id: crypto.randomUUID(),
                owner: user.username,
                status: data.scheduleType === 'now' ? 'processing' : 'active',
                createdAt: new Date().toISOString(),
                nextRun: nextRun, // Inicializa o campo para o processador encontrar
                ...data
            };

            campaigns.push(newCampaign);
            writeJSON(CAMPAIGNS_DB_PATH, campaigns);
            socket.emit('campaigns:created', { success: true });
            socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
            
            if (newCampaign.scheduleType === 'now' && newCampaign.type !== 'group_blast') {
                executeCampaign(io, newCampaign, generatePix, db, botController);
            }
        });

        socket.on('campaigns:delete', (data) => {
            let campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const initialLen = campaigns.length;
            campaigns = campaigns.filter(c => c.id !== data.id || (c.owner !== user.username && !user.isAdmin));
            if (campaigns.length < initialLen) {
                writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
                socket.emit('feedback', { success: true, message: 'Campanha excluída.' });
            } else {
                socket.emit('feedback', { success: false, message: 'Erro ao excluir.' });
            }
        });

        socket.on('campaigns:delete-bulk', (data) => {
            if (!data.ids) return;
            let campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const initialLen = campaigns.length;
            campaigns = campaigns.filter(c => !data.ids.includes(c.id) || (c.owner !== user.username && !user.isAdmin));
            if (campaigns.length < initialLen) {
                writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
                socket.emit('feedback', { success: true, message: 'Campanhas excluídas.' });
            }
        });

        // NOVO: Rota para cancelar uma campanha em andamento
        socket.on('campaigns:cancel', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const idx = campaigns.findIndex(c => c.id === data.id);
            if (idx !== -1 && (campaigns[idx].owner === user.username || user.isAdmin)) {
                campaigns[idx].status = 'canceled';
                writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
            }
        });

        socket.on('campaigns:get-single', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const campaign = campaigns.find(c => c.id === data.id);
            if (campaign && (campaign.owner === user.username || user.isAdmin)) {
                socket.emit('campaigns:single-data', campaign);
            }
        });

        socket.on('campaigns:update', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const idx = campaigns.findIndex(c => c.id === data.id);
            if (idx !== -1 && (campaigns[idx].owner === user.username || user.isAdmin)) {
                campaigns[idx] = { ...campaigns[idx], ...data, status: data.scheduleType === 'now' ? 'processing' : 'active' };
                writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
                socket.emit('feedback', { success: true, message: 'Atualizado!' });
                if (campaigns[idx].scheduleType === 'now') {
                    executeCampaign(io, campaigns[idx], generatePix, db, botController);
                }
            }
        });

        socket.on('campaigns:resend', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const idx = campaigns.findIndex(c => c.id === data.id);
            if (idx !== -1 && (campaigns[idx].owner === user.username || user.isAdmin)) {
                if (campaigns[idx].scheduleType === 'now') {
                    campaigns[idx].status = 'processing';
                    writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                    io.to(user.username.toLowerCase()).emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
                    executeCampaign(io, campaigns[idx], generatePix, db, botController);
                    socket.emit('feedback', { success: true, message: 'Reenviando...' });
                } else {
                    socket.emit('feedback', { success: false, message: 'Apenas campanhas "Enviar Agora" podem ser reenviadas.' });
                }
            }
        });

        socket.on('bots:get-for-clients', async () => {
            try {
                const allBots = await db.getAllBots();
                const userBots = Object.values(allBots).filter(b => b.owner === user.username);
                socket.emit('bots:list-for-clients', userBots);
            } catch (e) {
                console.error("Erro ao buscar bots:", e);
                socket.emit('bots:list-for-clients',[]);
            }
        });

        socket.on('payments:get', () => {
            const all = readJSON(PAYMENTS_DB_PATH);
            socket.emit('payments:list', all.filter(p => p.owner === user.username));
        });

        socket.on('payments:clear', () => {
            let all = readJSON(PAYMENTS_DB_PATH);
            all = all.filter(p => p.owner !== user.username);
            writeJSON(PAYMENTS_DB_PATH, all);
            socket.emit('payments:list',[]);
            socket.emit('feedback', { success: true, message: 'Histórico limpo.' });
        });
    });
}

module.exports = clientRoutes;








