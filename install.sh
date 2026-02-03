#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO E ATUALIZAÇÃO (ZAPPBOT COMPLETO) ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ZAPPBOT ---${NC}"

# Garante que pacotes essenciais estejam instalados
sudo apt-get update -qq
sudo apt-get install -y nano curl -qq

# Cria o diretório se não existir (caso esteja rodando sem git clone antes)
if [ ! -d "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
fi

cd "$TARGET_DIR" || exit 1

# ===================================================
# 1. COLETA DE DADOS DO SERVIDOR
# ===================================================
echo -e "${BLUE}---------------------------------------------------${NC}"
echo -e "${BLUE}           DADOS DO SERVIDOR E SSL               ${NC}"
echo -e "${BLUE}---------------------------------------------------${NC}"

read -p "1. Digite seu Domínio (ex: painel.site.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: O domínio é um campo obrigatório!${NC}"
    exit 1
fi

read -p "2. Digite seu E-mail (usado para o certificado SSL): " EMAIL_SSL

# ===================================================
# 2. CONFIGURAÇÃO DO ARQUIVO .ENV
# ===================================================

edit_env_file() {
    echo ""
    echo -e "${BLUE}O editor NANO será aberto. Cole suas API KEYS e configurações.${NC}"
    echo -e "Certifique-se de definir: API_KEYS_GEMINI, SESSION_SECRET, etc."
    echo -e "Pressione ${YELLOW}CTRL+O${NC} + ${YELLOW}ENTER${NC} para SALVAR e ${YELLOW}CTRL+X${NC} para SAIR."
    echo -e "${GREEN}Pressione ENTER para abrir o editor...${NC}"
    read -r
    
    nano .env

    if [ ! -s .env ]; then
        echo -e "${RED}ERRO: O arquivo .env está vazio! A instalação não pode continuar.${NC}"
        exit 1
    fi
}

if [ ! -f ".env" ]; then
    echo ""
    echo -e "${YELLOW}--- ARQUIVO .ENV (CRIANDO NOVO) ---${NC}"
    touch .env
    # Adiciona um template básico se estiver vazio
    echo "PORT=3000" >> .env
    echo "SESSION_SECRET=sua_chave_secreta_aqui" >> .env
    echo "API_KEYS_GEMINI=sua_api_key_gemini_aqui" >> .env
    edit_env_file
else
    echo ""
    echo -e "${YELLOW}--- ARQUIVO .ENV ENCONTRADO ---${NC}"
    read -p "Deseja editar o arquivo .env existente? (s/N): " EDIT_ENV
    if [[ "${EDIT_ENV,,}" == "s" ]]; then
        edit_env_file
    fi
fi

# ===================================================
# 3. INSTALAÇÃO DE DEPENDÊNCIAS DO SISTEMA
# ===================================================
echo -e "${YELLOW}Instalando/Atualizando dependências do sistema...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx -qq

# ===================================================
# 4. INSTALAÇÃO DOS MÓDULOS NODE.JS (ATUALIZADO)
# ===================================================
echo -e "${YELLOW}Instalando módulos do Node.js (Isso pode levar alguns instantes)...${NC}"
rm -rf node_modules package-lock.json

# Instalação explícita para garantir que todos os novos módulos estejam presentes
npm install express socket.io @whiskeysockets/baileys pino pino-pretty \
    qrcode @google/generative-ai telegraf node-cron mercadopago multer \
    adm-zip archiver bcrypt passport passport-google-oauth20 express-session \
    session-file-store cookie-parser axios socket.io-client dotenv --silent

# ===================================================
# 5. ESTRUTURA E PERMISSÕES (ATUALIZADO)
# ===================================================
echo -e "${YELLOW}Verificando estrutura de arquivos e permissões...${NC}"

# Cria pastas necessárias
mkdir -p uploads sessions auth_sessions

# Cria arquivos JSON de banco de dados se não existirem
for db in users.json bots.json groups.json settings.json clients.json campaigns.json payments.json; do
    if [ ! -f "$db" ]; then 
        if [ "$db" == "payments.json" ] || [ "$db" == "clients.json" ] || [ "$db" == "campaigns.json" ]; then
             echo "[]" > "$db" # Cria como array vazio
        else
             echo "{}" > "$db" # Cria como objeto vazio
        fi
    fi
done

# Ajusta permissões
chmod -R 777 uploads sessions auth_sessions *.json

# Renomeia app.js para server.js se necessário (compatibilidade antiga)
if [ -f "app.js" ] && [ ! -f "server.js" ]; then mv app.js server.js; fi

# ===================================================
# 6. INICIALIZAÇÃO (PM2)
# ===================================================
echo -e "${YELLOW}Reiniciando a aplicação com PM2...${NC}"
npm install pm2 -g --silent
pm2 start server.js --name "painel" --update-env || pm2 restart painel
pm2 save
pm2 startup

# ===================================================
# 7. NGINX E SSL
# ===================================================
read -p "Deseja configurar/reconfigurar o Nginx e o certificado SSL para ${DOMAIN}? (s/N): " CONFIGURE_SSL

if [[ "${CONFIGURE_SSL,,}" == "s" ]]; then
    echo -e "${YELLOW}Configurando Proxy Reverso com Nginx...${NC}"
    NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

    cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN};
    root ${TARGET_DIR};
    client_max_body_size 50M; # Aumentado para uploads de backup/imagens
    
    location ~ /.well-known/acme-challenge { allow all; }
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl restart nginx

    if [ ! -z "$EMAIL_SSL" ]; then
        echo -e "${YELLOW}Gerando certificado SSL com Certbot...${NC}"
        sudo ufw allow 'Nginx Full'
        sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
    else
        echo -e "${RED}E-mail não informado. Geração de SSL ignorada.${NC}"
    fi
else
    echo -e "${YELLOW}Configuração de Nginx e SSL ignorada.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo "---------------------------------------------------"
echo "Painel acessível em: https://$DOMAIN"
echo "Verifique a aba 'Clientes' para testar as novas funções."
echo "---------------------------------------------------"
