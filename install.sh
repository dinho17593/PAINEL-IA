#!/bin/bash

# --- SCRIPT DE INSTALAÇÃO COMPLETA (V2) ---

TARGET_DIR="/var/www/bot-whatsapp"
REPO_ZIP_URL="https://github.com/dinho17593/PAINEL-IA/archive/refs/tags/V2.zip"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- INICIANDO INSTALAÇÃO ZAPPBOT V2 ---${NC}"

# 1. Atualiza e Instala utilitários básicos
sudo apt-get update -qq
sudo apt-get install -y nano curl unzip wget git build-essential -qq

# 2. Prepara o diretório
echo -e "${YELLOW}Baixando código fonte...${NC}"
mkdir -p "$TARGET_DIR"
cd /tmp || exit
wget "$REPO_ZIP_URL" -O painel.zip
unzip -o painel.zip

# Identifica a pasta extraída (geralmente PAINEL-IA-V2)
EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "PAINEL-IA*" | head -n 1)

if [ -d "$EXTRACTED_DIR" ]; then
    echo -e "${GREEN}Código extraído. Movendo para $TARGET_DIR...${NC}"
    # Move o conteúdo para o destino, sobrescrevendo se necessário
    cp -rf "$EXTRACTED_DIR/"* "$TARGET_DIR/"
    rm -rf painel.zip "$EXTRACTED_DIR"
else
    echo -e "${RED}Erro ao baixar ou extrair o código. Verifique a URL do repositório.${NC}"
    exit 1
fi

cd "$TARGET_DIR" || exit 1

# ===================================================
# 3. COLETA DE DADOS
# ===================================================
echo -e "${BLUE}---------------------------------------------------${NC}"
echo -e "${BLUE}           CONFIGURAÇÃO DO SERVIDOR              ${NC}"
echo -e "${BLUE}---------------------------------------------------${NC}"

read -p "1. Digite seu Domínio (ex: painel.site.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: O domínio é obrigatório!${NC}"
    exit 1
fi

read -p "2. Digite seu E-mail (para SSL): " EMAIL_SSL

# ===================================================
# 4. CONFIGURAÇÃO .ENV
# ===================================================
edit_env_file() {
    echo ""
    echo -e "${BLUE}O editor NANO será aberto.${NC}"
    echo -e "Defina suas chaves (API_KEYS_GEMINI, SESSION_SECRET, etc)."
    echo -e "Salve com ${YELLOW}CTRL+O${NC} e saia com ${YELLOW}CTRL+X${NC}."
    read -p "Pressione ENTER para continuar..."
    nano .env
    if [ ! -s .env ]; then
        echo -e "${RED}ERRO: .env vazio!${NC}"
        exit 1
    fi
}

if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Criando arquivo .env...${NC}"
    touch .env
    echo "PORT=3000" >> .env
    echo "SESSION_SECRET=mude_isso_para_algo_seguro" >> .env
    echo "API_KEYS_GEMINI=" >> .env
    edit_env_file
else
    read -p "Arquivo .env já existe. Deseja editar? (s/N): " EDIT_ENV
    if [[ "${EDIT_ENV,,}" == "s" ]]; then
        edit_env_file
    fi
fi

# ===================================================
# 5. INSTALAÇÃO DE DEPENDÊNCIAS (SISTEMA & NODE)
# ===================================================
echo -e "${YELLOW}Instalando Node.js e dependências...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs nginx python3 ffmpeg certbot python3-certbot-nginx -qq

echo -e "${YELLOW}Instalando módulos do Painel...${NC}"
# Remove node_modules antigo para garantir instalação limpa
rm -rf node_modules package-lock.json

# Instala todos os módulos necessários para a nova versão
npm install express socket.io @whiskeysockets/baileys pino pino-pretty \
    qrcode @google/generative-ai telegraf node-cron mercadopago multer \
    adm-zip archiver bcrypt passport passport-google-oauth20 express-session \
    session-file-store cookie-parser axios socket.io-client dotenv --silent

# ===================================================
# 6. ESTRUTURA E PERMISSÕES
# ===================================================
echo -e "${YELLOW}Configurando permissões...${NC}"
mkdir -p uploads sessions auth_sessions

# Cria arquivos JSON necessários
for db in users.json bots.json groups.json settings.json clients.json campaigns.json payments.json; do
    if [ ! -f "$db" ]; then
        if [[ "$db" == "payments.json" || "$db" == "clients.json" || "$db" == "campaigns.json" ]]; then
             echo "[]" > "$db"
        else
             echo "{}" > "$db"
        fi
    fi
done

chmod -R 777 uploads sessions auth_sessions *.json

# Garante que o arquivo principal seja server.js
if [ -f "app.js" ] && [ ! -f "server.js" ]; then mv app.js server.js; fi

# ===================================================
# 7. INICIALIZAÇÃO (PM2)
# ===================================================
echo -e "${YELLOW}Iniciando aplicação...${NC}"
npm install pm2 -g --silent
pm2 start server.js --name "painel" --update-env || pm2 restart painel
pm2 save
pm2 startup

# ===================================================
# 8. NGINX E SSL
# ===================================================
read -p "Configurar Nginx e SSL para $DOMAIN? (s/N): " CONF_SSL
if [[ "${CONF_SSL,,}" == "s" ]]; then
    NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"
    cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN};
    root ${TARGET_DIR};
    client_max_body_size 50M;
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
        sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
    fi
fi

echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA! Acesse: https://$DOMAIN${NC}"
