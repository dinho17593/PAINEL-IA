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
        return [];
    } catch (e) {
        console.error(`Erro ao ler ${filePath}:`, e);
        return [];
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
if (!fs.existsSync(CLIENTS_DB_PATH)) writeJSON(CLIENTS_DB_PATH, []);
if (!fs.existsSync(CAMPAIGNS_DB_PATH)) writeJSON(CAMPAIGNS_DB_PATH, []);
if (!fs.existsSync(PAYMENTS_DB_PATH)) writeJSON(PAYMENTS_DB_PATH, []);

// Função auxiliar para formatar número (Adiciona 55 se necessário)
function formatNumber(num) {
    let cleanNum = num.replace(/\D/g, '');
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

// Lógica de envio
async function executeCampaign(io, campaign, generatePix, db) {
    const clients = readJSON(CLIENTS_DB_PATH);
    const targetClients = clients.filter(c => campaign.clients.includes(c.id));

    for (const client of targetClients) {
        let message = campaign.message.replace(/{nome}/g, client.name);
        const formattedNumber = formatNumber(client.number);

        if (campaign.type === 'cobranca') {
            const valor = parseFloat(campaign.value).toFixed(2);
            message = message.replace(/{valor}/g, valor);
            message = message.replace(/{link_pagamento}/g, '');
            
            try {
                // Usa o DB injetado para buscar usuários (tokens MP)
                const users = await db.getAllUsers();
                const ownerData = users[campaign.owner];
                const userMpToken = ownerData ? ownerData.mpAccessToken : null;

                if (userMpToken) {
                    const amount = parseFloat(campaign.value);
                    const description = `Pagamento: ${campaign.name}`;
                    const external_reference = `campaign|${campaign.id}|${formattedNumber}`;

                    const reqMock = {
                        headers: { host: 'localhost:3000' },
                        body: { botSessionName: campaign.targetBot },
                        connection: {}
                    };

                    const result = await generatePix(reqMock, amount, description, external_reference, userMpToken);
                    
                    if (result && result.id) {
                        const pendingRecord = savePendingPayment({
                            id: result.id,
                            transaction_amount: amount
                        }, campaign, formattedNumber, client.name);
                        
                        if (pendingRecord) {
                            const allPayments = readJSON(PAYMENTS_DB_PATH);
                            const userPayments = allPayments.filter(p => p.owner === campaign.owner);
                            io.to(campaign.owner.toLowerCase()).emit('payments:list', userPayments);
                        }
                    }

                    const pixData = {
                        qr_code: result.point_of_interaction.transaction_data.qr_code,
                        qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64,
                    };

                    io.emit('bot:send-campaign-with-pix', {
                        targetBot: campaign.targetBot,
                        clientNumber: formattedNumber,
                        message: message,
                        campaignId: campaign.id,
                        pixData: pixData
                    });
                } else {
                    io.emit('bot:send-client-message', {
                        targetBot: campaign.targetBot,
                        clientNumber: formattedNumber,
                        message: message + "\n\n(Erro: Configuração de pagamento incompleta)",
                        campaignId: campaign.id
                    });
                }
            } catch (e) {
                console.error(`[CAMPAIGN] Erro PIX:`, e.message);
                io.emit('bot:send-client-message', {
                    targetBot: campaign.targetBot,
                    clientNumber: formattedNumber,
                    message: message + "\n\n(Erro ao gerar PIX automático)",
                    campaignId: campaign.id
                });
            }

        } else {
            io.emit('bot:send-client-message', {
                targetBot: campaign.targetBot,
                clientNumber: formattedNumber,
                message: message,
                campaignId: campaign.id
            });
        }
    }

    if (campaign.scheduleType === 'now' || campaign.scheduleType === 'scheduled') {
        const allCampaigns = readJSON(CAMPAIGNS_DB_PATH);
        const campaignIndex = allCampaigns.findIndex(c => c.id === campaign.id);
        if (campaignIndex !== -1) {
            allCampaigns[campaignIndex].status = 'sent';
            writeJSON(CAMPAIGNS_DB_PATH, allCampaigns);
            const userCampaigns = allCampaigns.filter(c => c.owner === campaign.owner);
            io.to(campaign.owner.toLowerCase()).emit('campaigns:list', userCampaigns);
        }
    }
}

function clientRoutes(io, generatePix, db) {
    // Cron Job
    cron.schedule('* * * * *', () => {
        try {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const now = new Date();
            const currentDay = now.getDate();
            const currentHour = now.getHours();

            if (currentHour === 9 && now.getMinutes() === 0) {
                const monthlyCampaigns = campaigns.filter(c => 
                    c.status === 'active' && c.scheduleType === 'monthly' && parseInt(c.scheduleDay) === currentDay
                );
                monthlyCampaigns.forEach(campaign => executeCampaign(io, campaign, generatePix, db));
            }

            const scheduledCampaigns = campaigns.filter(c => 
                c.status === 'active' && c.scheduleType === 'scheduled' && c.scheduleDate && new Date(c.scheduleDate) <= now
            );
            scheduledCampaigns.forEach(campaign => executeCampaign(io, campaign, generatePix, db));
        } catch (e) { console.error("[CRON] Erro:", e); }
    });

    io.on('connection', (socket) => {
        const user = socket.request.session.user;
        if (!user) return;

        // --- CLIENTES ---
        socket.on('clients:get', () => {
            const allClients = readJSON(CLIENTS_DB_PATH);
            const userClients = allClients.filter(c => c.owner === user.username);
            socket.emit('clients:list', userClients);
        });

        socket.on('clients:add', (data) => {
            if (!data.name || !data.number) return socket.emit('clients:added', { success: false, message: 'Dados incompletos.' });
            
            const clients = readJSON(CLIENTS_DB_PATH);
            const finalNumber = formatNumber(data.number);

            const newClient = {
                id: crypto.randomUUID(),
                owner: user.username,
                name: data.name,
                number: finalNumber
            };
            
            clients.push(newClient);
            writeJSON(CLIENTS_DB_PATH, clients);
            
            socket.emit('clients:added', { success: true, message: 'Cliente adicionado!' });
            socket.emit('clients:list', clients.filter(c => c.owner === user.username));
        });

        socket.on('clients:add-bulk', (clientsData) => {
            if (!Array.isArray(clientsData)) return;
            const clients = readJSON(CLIENTS_DB_PATH);
            let addedCount = 0;

            clientsData.forEach(c => {
                if (c.number) {
                    const finalNumber = formatNumber(c.number);
                    const exists = clients.some(existing => existing.owner === user.username && existing.number === finalNumber);
                    if (!exists) {
                        clients.push({
                            id: crypto.randomUUID(),
                            owner: user.username,
                            name: c.name || 'Cliente',
                            number: finalNumber
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
                    clients.splice(clientIndex, 1); // Remove do array
                    writeJSON(CLIENTS_DB_PATH, clients); // Salva no arquivo
                    
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

        // --- CAMPANHAS ---
        socket.on('campaigns:get', () => {
            const all = readJSON(CAMPAIGNS_DB_PATH);
            socket.emit('campaigns:list', all.filter(c => c.owner === user.username));
        });

        socket.on('campaigns:create', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const newCampaign = {
                id: crypto.randomUUID(),
                owner: user.username,
                status: 'active',
                createdAt: new Date().toISOString(),
                ...data
            };
            campaigns.push(newCampaign);
            writeJSON(CAMPAIGNS_DB_PATH, campaigns);
            
            socket.emit('campaigns:created', { success: true });
            socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));

            if (newCampaign.scheduleType === 'now') {
                executeCampaign(io, newCampaign, generatePix, db);
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
                campaigns[idx] = { ...campaigns[idx], ...data, status: 'active' };
                writeJSON(CAMPAIGNS_DB_PATH, campaigns);
                
                socket.emit('campaigns:list', campaigns.filter(c => c.owner === user.username));
                socket.emit('feedback', { success: true, message: 'Atualizado!' });
                
                if (campaigns[idx].scheduleType === 'now') {
                    executeCampaign(io, campaigns[idx], generatePix, db);
                }
            }
        });

        socket.on('campaigns:resend', (data) => {
            const campaigns = readJSON(CAMPAIGNS_DB_PATH);
            const campaign = campaigns.find(c => c.id === data.id);
            if (campaign && (campaign.owner === user.username || user.isAdmin)) {
                if (campaign.scheduleType === 'now') {
                    executeCampaign(io, campaign, generatePix, db);
                    socket.emit('feedback', { success: true, message: 'Reenviando...' });
                } else {
                    socket.emit('feedback', { success: false, message: 'Apenas campanhas "Enviar Agora" podem ser reenviadas.' });
                }
            }
        });

        // --- BOTS (Usa o DB injetado para garantir sincronia com server.js) ---
        socket.on('bots:get-for-clients', async () => {
            try {
                const allBots = await db.getAllBots();
                const userBots = Object.values(allBots).filter(b => b.owner === user.username);
                socket.emit('bots:list-for-clients', userBots);
            } catch (e) {
                console.error("Erro ao buscar bots:", e);
                socket.emit('bots:list-for-clients', []);
            }
        });

        // --- PAGAMENTOS ---
        socket.on('payments:get', () => {
            const all = readJSON(PAYMENTS_DB_PATH);
            socket.emit('payments:list', all.filter(p => p.owner === user.username));
        });

        socket.on('payments:clear', () => {
            let all = readJSON(PAYMENTS_DB_PATH);
            all = all.filter(p => p.owner !== user.username);
            writeJSON(PAYMENTS_DB_PATH, all);
            socket.emit('payments:list', []);
            socket.emit('feedback', { success: true, message: 'Histórico limpo.' });
        });
    });
}

module.exports = clientRoutes;
