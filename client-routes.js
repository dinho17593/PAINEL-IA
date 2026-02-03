const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cron = require('node-cron');

const BASE_DIR = __dirname;
const CLIENTS_DB_PATH = path.join(BASE_DIR, 'clients.json');
const CAMPAIGNS_DB_PATH = path.join(BASE_DIR, 'campaigns.json');
const USERS_DB_PATH = path.join(BASE_DIR, 'users.json');
const PAYMENTS_DB_PATH = path.join(BASE_DIR, 'payments.json');

// Funções de Leitura/Escrita do Banco de Dados (JSON)
const readDB = (filePath, defaultValue = []) => {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        }
        return defaultValue;
    } catch (e) {
        console.error(`Erro ao ler o arquivo ${filePath}:`, e);
        return defaultValue;
    }
};

const writeDB = (filePath, data) => {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (e) {
        console.error(`Erro ao escrever no arquivo ${filePath}:`, e);
    }
};

// Inicializa os arquivos de banco de dados se não existirem
if (!fs.existsSync(CLIENTS_DB_PATH)) {
    writeDB(CLIENTS_DB_PATH, []);
}
if (!fs.existsSync(CAMPAIGNS_DB_PATH)) {
    writeDB(CAMPAIGNS_DB_PATH, []);
}
if (!fs.existsSync(PAYMENTS_DB_PATH)) {
    writeDB(PAYMENTS_DB_PATH, []);
}

// Função auxiliar para formatar número (Adiciona 55 se necessário)
function formatNumber(num) {
    let cleanNum = num.replace(/\D/g, '');
    // Se tiver 10 ou 11 dígitos (DDD + Número), adiciona 55
    if (cleanNum.length >= 10 && cleanNum.length <= 11) {
        return '55' + cleanNum;
    }
    return cleanNum;
}

// Função auxiliar para salvar pagamento pendente
function savePendingPayment(paymentData, campaign, clientNumber, clientName) {
    try {
        const payments = readDB(PAYMENTS_DB_PATH);
        
        // Verifica se já existe (evita duplicidade)
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
            status: 'pending' // Status inicial
        };

        payments.push(record);
        writeDB(PAYMENTS_DB_PATH, payments);
        return record;
    } catch (e) {
        console.error("[PAYMENT] Erro ao salvar pagamento pendente:", e);
    }
}

// Lógica de envio
async function executeCampaign(io, campaign, generatePix) {
    const clients = readDB(CLIENTS_DB_PATH);
    const targetClients = clients.filter(c => campaign.clients.includes(c.id));

    for (const client of targetClients) {
        let message = campaign.message.replace(/{nome}/g, client.name);
        
        // Garante que o número tenha o formato correto antes de enviar
        const formattedNumber = formatNumber(client.number);

        if (campaign.type === 'cobranca') {
            const valor = parseFloat(campaign.value).toFixed(2);
            message = message.replace(/{valor}/g, valor);
            message = message.replace(/{link_pagamento}/g, '');
            
            // Geração Automática do PIX
            try {
                const users = readDB(USERS_DB_PATH);
                const ownerData = users[campaign.owner];
                const userMpToken = ownerData ? ownerData.mpAccessToken : null;

                if (userMpToken) {
                    const amount = parseFloat(campaign.value);
                    const description = `Pagamento: ${campaign.name}`;
                    const external_reference = `campaign|${campaign.id}|${formattedNumber}`;

                    // Mock do objeto req para a função generatePix
                    const reqMock = {
                        headers: { host: 'localhost:3000' }, // Fallback se não houver contexto HTTP
                        body: { botSessionName: campaign.targetBot },
                        connection: {}
                    };

                    const result = await generatePix(reqMock, amount, description, external_reference, userMpToken);
                    
                    // SALVA O PAGAMENTO COMO PENDENTE
                    if (result && result.id) {
                        const pendingRecord = savePendingPayment({
                            id: result.id,
                            transaction_amount: amount
                        }, campaign, formattedNumber, client.name);
                        
                        // Notifica o frontend para atualizar a lista de pendentes
                        if (pendingRecord) {
                            const allPayments = readDB(PAYMENTS_DB_PATH);
                            const userPayments = allPayments.filter(p => p.owner === campaign.owner);
                            io.to(campaign.owner.toLowerCase()).emit('payments:list', userPayments);
                        }
                    }

                    const pixData = {
                        qr_code: result.point_of_interaction.transaction_data.qr_code,
                        qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64,
                    };

                    // Emite evento para enviar Mensagem + PIX diretamente
                    io.emit('bot:send-campaign-with-pix', {
                        targetBot: campaign.targetBot,
                        clientNumber: formattedNumber,
                        message: message,
                        campaignId: campaign.id,
                        pixData: pixData
                    });
                } else {
                    console.error(`[CAMPAIGN] Token MP não encontrado para usuário ${campaign.owner}`);
                    // Fallback: envia apenas mensagem de erro ou aviso
                    io.emit('bot:send-client-message', {
                        targetBot: campaign.targetBot,
                        clientNumber: formattedNumber,
                        message: message + "\n\n(Erro: Configuração de pagamento incompleta pelo administrador)",
                        campaignId: campaign.id
                    });
                }
            } catch (e) {
                console.error(`[CAMPAIGN] Erro ao gerar PIX automático para ${client.name}:`, e.message);
                io.emit('bot:send-client-message', {
                    targetBot: campaign.targetBot,
                    clientNumber: formattedNumber,
                    message: message + "\n\n(Erro ao gerar PIX automático. Entre em contato.)",
                    campaignId: campaign.id
                });
            }

        } else {
            // Envio normal (Aviso)
            io.emit('bot:send-client-message', {
                targetBot: campaign.targetBot,
                clientNumber: formattedNumber,
                message: message,
                campaignId: campaign.id
            });
        }
    }

    // Atualiza status para 'sent' se for envio imediato OU agendado
    if (campaign.scheduleType === 'now' || campaign.scheduleType === 'scheduled') {
        const campaigns = readDB(CAMPAIGNS_DB_PATH);
        const campaignIndex = campaigns.findIndex(c => c.id === campaign.id);
        if (campaignIndex !== -1) {
            campaigns[campaignIndex].status = 'sent';
            writeDB(CAMPAIGNS_DB_PATH, campaigns);
            // Notifica o dono da campanha sobre a atualização da lista
            io.to(campaign.owner.toLowerCase()).emit('campaigns:list', campaigns.filter(c => c.owner === campaign.owner));
        }
    }
}

function clientRoutes(io, generatePix) {
    // Agendador Cron - Executa a cada minuto para verificar agendamentos precisos
    cron.schedule('* * * * *', () => {
        const campaigns = readDB(CAMPAIGNS_DB_PATH);
        const now = new Date();
        const currentDay = now.getDate();
        const currentHour = now.getHours();

        // 1. Verifica Campanhas Mensais (apenas às 9h)
        if (currentHour === 9 && now.getMinutes() === 0) {
            const monthlyCampaigns = campaigns.filter(c => 
                c.status === 'active' && 
                c.scheduleType === 'monthly' &&
                parseInt(c.scheduleDay) === currentDay
            );

            if (monthlyCampaigns.length > 0) {
                console.log(`[CRON] Encontradas ${monthlyCampaigns.length} campanhas mensais para hoje. Enviando...`);
                monthlyCampaigns.forEach(campaign => executeCampaign(io, campaign, generatePix));
            }
        }

        // 2. Verifica Campanhas Agendadas (Data/Hora Específica)
        const scheduledCampaigns = campaigns.filter(c => 
            c.status === 'active' && 
            c.scheduleType === 'scheduled' &&
            c.scheduleDate && 
            new Date(c.scheduleDate) <= now
        );

        if (scheduledCampaigns.length > 0) {
            console.log(`[CRON] Encontradas ${scheduledCampaigns.length} campanhas agendadas para agora. Enviando...`);
            scheduledCampaigns.forEach(campaign => executeCampaign(io, campaign, generatePix));
        }
    });

    io.on('connection', (socket) => {
        const user = socket.request.session.user;
        if (!user) return;

        // --- Gerenciamento de Clientes ---
        socket.on('clients:get', () => {
            const allClients = readDB(CLIENTS_DB_PATH);
            const userClients = allClients.filter(c => c.owner === user.username);
            socket.emit('clients:list', userClients);
        });

        socket.on('clients:add', (data) => {
            if (!data.name || !data.number) {
                return socket.emit('clients:added', { success: false, message: 'Nome e número são obrigatórios.' });
            }
            const clients = readDB(CLIENTS_DB_PATH);
            
            // Formata o número antes de salvar
            const finalNumber = formatNumber(data.number);

            const newClient = {
                id: crypto.randomUUID(),
                owner: user.username,
                name: data.name,
                number: finalNumber
            };
            clients.push(newClient);
            writeDB(CLIENTS_DB_PATH, clients);
            socket.emit('clients:added', { success: true, message: 'Cliente adicionado!' });
            const userClients = clients.filter(c => c.owner === user.username);
            socket.emit('clients:list', userClients);
        });

        // NOVO: Adicionar em Massa (Importação)
        socket.on('clients:add-bulk', (clientsData) => {
            if (!Array.isArray(clientsData) || clientsData.length === 0) {
                return socket.emit('clients:added', { success: false, message: 'Lista vazia.' });
            }

            const clients = readDB(CLIENTS_DB_PATH);
            let addedCount = 0;

            clientsData.forEach(c => {
                if (c.number) {
                    const finalNumber = formatNumber(c.number);
                    
                    // Verifica duplicidade simples (opcional, mas recomendado)
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

            writeDB(CLIENTS_DB_PATH, clients);
            socket.emit('clients:added', { success: true, message: `${addedCount} clientes importados com sucesso!` });
            
            const userClients = clients.filter(c => c.owner === user.username);
            socket.emit('clients:list', userClients);
        });

        socket.on('clients:delete', (data) => {
            let clients = readDB(CLIENTS_DB_PATH);
            const clientToDelete = clients.find(c => c.id === data.id);

            if (clientToDelete && (clientToDelete.owner === user.username || user.isAdmin)) {
                clients = clients.filter(c => c.id !== data.id);
                writeDB(CLIENTS_DB_PATH, clients);
                const userClients = clients.filter(c => c.owner === user.username);
                socket.emit('clients:list', userClients);
                socket.emit('feedback', { success: true, message: 'Cliente excluído.' });
            } else {
                socket.emit('feedback', { success: false, message: 'Não foi possível excluir o cliente.' });
            }
        });

        // NOVO: Exclusão em Massa de Clientes
        socket.on('clients:delete-bulk', (data) => {
            if (!data.ids || !Array.isArray(data.ids)) return;
            
            let clients = readDB(CLIENTS_DB_PATH);
            const initialLength = clients.length;
            
            // Filtra mantendo apenas os que NÃO estão na lista de exclusão OU que não pertencem ao usuário
            clients = clients.filter(c => !data.ids.includes(c.id) || (c.owner !== user.username && !user.isAdmin));
            
            if (clients.length < initialLength) {
                writeDB(CLIENTS_DB_PATH, clients);
                const userClients = clients.filter(c => c.owner === user.username);
                socket.emit('clients:list', userClients);
                socket.emit('feedback', { success: true, message: 'Clientes excluídos.' });
            }
        });

        // --- Gerenciamento de Campanhas ---
        socket.on('campaigns:get', () => {
            const allCampaigns = readDB(CAMPAIGNS_DB_PATH);
            const userCampaigns = allCampaigns.filter(c => c.owner === user.username);
            socket.emit('campaigns:list', userCampaigns);
        });

        socket.on('campaigns:create', (data) => {
            const campaigns = readDB(CAMPAIGNS_DB_PATH);
            const newCampaign = {
                id: crypto.randomUUID(),
                owner: user.username,
                status: 'active',
                createdAt: new Date().toISOString(),
                ...data
            };
            campaigns.push(newCampaign);
            writeDB(CAMPAIGNS_DB_PATH, campaigns);
            socket.emit('campaigns:created', { success: true });
            
            const userCampaigns = campaigns.filter(c => c.owner === user.username);
            socket.emit('campaigns:list', userCampaigns);

            if (newCampaign.scheduleType === 'now') {
                executeCampaign(io, newCampaign, generatePix);
            }
        });

        socket.on('campaigns:delete', (data) => {
            let campaigns = readDB(CAMPAIGNS_DB_PATH);
            const campaignToDelete = campaigns.find(c => c.id === data.id);

            if (campaignToDelete && (campaignToDelete.owner === user.username || user.isAdmin)) {
                campaigns = campaigns.filter(c => c.id !== data.id);
                writeDB(CAMPAIGNS_DB_PATH, campaigns);
                const userCampaigns = campaigns.filter(c => c.owner === user.username);
                socket.emit('campaigns:list', userCampaigns);
                socket.emit('feedback', { success: true, message: 'Campanha excluída.' });
            } else {
                socket.emit('feedback', { success: false, message: 'Não foi possível excluir a campanha.' });
            }
        });

        // NOVO: Exclusão em Massa de Campanhas
        socket.on('campaigns:delete-bulk', (data) => {
            if (!data.ids || !Array.isArray(data.ids)) return;

            let campaigns = readDB(CAMPAIGNS_DB_PATH);
            const initialLength = campaigns.length;

            campaigns = campaigns.filter(c => !data.ids.includes(c.id) || (c.owner !== user.username && !user.isAdmin));

            if (campaigns.length < initialLength) {
                writeDB(CAMPAIGNS_DB_PATH, campaigns);
                const userCampaigns = campaigns.filter(c => c.owner === user.username);
                socket.emit('campaigns:list', userCampaigns);
                socket.emit('feedback', { success: true, message: 'Campanhas excluídas.' });
            }
        });

        // NOVO: Buscar dados de uma campanha para edição
        socket.on('campaigns:get-single', (data) => {
            const campaigns = readDB(CAMPAIGNS_DB_PATH);
            const campaign = campaigns.find(c => c.id === data.id);
            if (campaign && (campaign.owner === user.username || user.isAdmin)) {
                socket.emit('campaigns:single-data', campaign);
            }
        });

        // NOVO: Atualizar uma campanha existente
        socket.on('campaigns:update', (data) => {
            const campaigns = readDB(CAMPAIGNS_DB_PATH);
            const campaignIndex = campaigns.findIndex(c => c.id === data.id);

            if (campaignIndex !== -1 && (campaigns[campaignIndex].owner === user.username || user.isAdmin)) {
                // Mantém os dados originais que não são editáveis
                const originalCampaign = campaigns[campaignIndex];
                campaigns[campaignIndex] = {
                    ...originalCampaign,
                    ...data,
                    status: 'active' // Reativa a campanha ao editar
                };
                writeDB(CAMPAIGNS_DB_PATH, campaigns);
                
                const userCampaigns = campaigns.filter(c => c.owner === user.username);
                socket.emit('campaigns:list', userCampaigns);
                socket.emit('feedback', { success: true, message: 'Campanha atualizada com sucesso!' });

                // Se a campanha atualizada for para "Enviar Agora", executa imediatamente
                if (campaigns[campaignIndex].scheduleType === 'now') {
                    executeCampaign(io, campaigns[campaignIndex], generatePix);
                }
            } else {
                socket.emit('feedback', { success: false, message: 'Falha ao atualizar a campanha.' });
            }
        });

        // NOVO: Reenviar uma campanha
        socket.on('campaigns:resend', (data) => {
            const campaigns = readDB(CAMPAIGNS_DB_PATH);
            const campaign = campaigns.find(c => c.id === data.id);

            if (campaign && (campaign.owner === user.username || user.isAdmin)) {
                if (campaign.scheduleType === 'now') {
                    executeCampaign(io, campaign, generatePix);
                    socket.emit('feedback', { success: true, message: 'Campanha reenviada!' });
                } else {
                    socket.emit('feedback', { success: false, message: 'Apenas campanhas do tipo "Enviar Agora" podem ser reenviadas.' });
                }
            }
        });

        // --- Obter Bots para o seletor ---
        socket.on('bots:get-for-clients', () => {
            const BOTS_DB_PATH = path.join(BASE_DIR, 'bots.json');
            const allBots = readDB(BOTS_DB_PATH, {});
            const userBots = Object.values(allBots).filter(b => b.owner === user.username);
            socket.emit('bots:list-for-clients', userBots);
        });

        // --- Obter Histórico de Pagamentos ---
        socket.on('payments:get', () => {
            const allPayments = readDB(PAYMENTS_DB_PATH);
            const userPayments = allPayments.filter(p => p.owner === user.username);
            socket.emit('payments:list', userPayments);
        });

        // --- Limpar Histórico ---
        socket.on('payments:clear', () => {
            let allPayments = readDB(PAYMENTS_DB_PATH);
            // Remove apenas os pagamentos do usuário atual
            const filteredPayments = allPayments.filter(p => p.owner !== user.username);
            writeDB(PAYMENTS_DB_PATH, filteredPayments);
            socket.emit('payments:list', []);
            socket.emit('feedback', { success: true, message: 'Histórico limpo com sucesso.' });
        });
    });
}

module.exports = clientRoutes;
