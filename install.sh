#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO E ATUALIZAÇÃO ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ---${NC}"

# Garante que pacotes essenciais estejam instalados
sudo apt-get update -qq
sudo apt-get install -y nano curl -qq

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
# 2. CONFIGURAÇÃO DO ARQUIVO .ENV (LÓGICA MELHORADA)
# ===================================================

# Função para encapsular o processo de edição
edit_env_file() {
    echo ""
    echo -e "${BLUE}O editor de texto NANO será aberto para você colar/editar o conteúdo.${NC}"
    echo "1. Cole ou edite as variáveis de ambiente."
    echo -e "2. Pressione ${YELLOW}CTRL+O${NC} e depois ${YELLOW}ENTER${NC} para SALVAR."
    echo -e "3. Pressione ${YELLOW}CTRL+X${NC} para SAIR."
    echo -e "${GREEN}Pressione ENTER para abrir o editor agora...${NC}"
    read -r
    
    nano .env

    # Validação para garantir que o arquivo não ficou vazio
    if [ ! -s .env ]; then
        echo -e "${RED}ERRO: O arquivo .env está vazio! A instalação não pode continuar.${NC}"
        echo "Abortando..."
        exit 1
    fi
    echo -e "${GREEN}Arquivo .env salvo com sucesso!${NC}"
}

# Verifica se o arquivo .env existe para decidir a ação
if [ ! -f ".env" ]; then
    # Se NÃO existe, a criação é OBRIGATÓRIA.
    echo ""
    echo -e "${YELLOW}--- ARQUIVO .ENV (PRIMEIRA INSTALAÇÃO) ---${NC}"
    echo "Nenhum arquivo de configuração (.env) foi encontrado. É necessário criá-lo agora."
    touch .env # Cria o arquivo para o nano não dar erro
    edit_env_file
else
    # Se JÁ existe, o usuário pode escolher se quer editar.
    echo ""
    echo -e "${YELLOW}--- ARQUIVO .ENV ENCONTRADO ---${NC}"
    read -p "Um arquivo .env já existe. Deseja editá-lo agora? (s/N): " EDIT_ENV
    if [[ "${EDIT_ENV,,}" == "s" ]]; then
        edit_env_file
    else
        echo "Ok, mantendo o arquivo .env existente."
    fi
fi

# ===================================================
# 3. INSTALAÇÃO DE DEPENDÊNCIAS
# ===================================================
echo -e "${YELLOW}Instalando/Atualizando dependências do sistema...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx -qq

# ===================================================
# 4. INSTALAÇÃO DO NODE.JS
# ===================================================
echo -e "${YELLOW}Instalando/Atualizando módulos do Node.js...${NC}"
rm -rf node_modules package-lock.json
npm install --silent

# ===================================================
# 5. ESTRUTURA E PERMISSÕES
# ===================================================
echo -e "${YELLOW}Verificando estrutura de arquivos e permissões...${NC}"
mkdir -p uploads sessions auth_sessions
for db in users.json bots.json groups.json settings.json; do
    if [ ! -f "$db" ]; then echo "{}" > "$db"; fi
done
chmod -R 777 uploads sessions auth_sessions *.json
if [ -f "app.js" ]; then mv app.js server.js; fi

# ===================================================
# 6. INICIALIZAÇÃO (PM2)
# ===================================================
echo -e "${YELLOW}Reiniciando a aplicação com PM2...${NC}"
npm install pm2 -g --silent
pm2 start server.js --name "painel" --update-env || pm2 restart painel
pm2 save
pm2 startup

# ===================================================
# 7. NGINX E SSL (CONDICIONAL)
# ===================================================
read -p "Deseja configurar/reconfigurar o Nginx e o certificado SSL para o domínio ${DOMAIN}? (s/N): " CONFIGURE_SSL

if [[ "${CONFIGURE_SSL,,}" == "s" ]]; then
    echo -e "${YELLOW}Configurando Proxy Reverso com Nginx...${NC}"
    NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

    cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN};
    root ${TARGET_DIR};
    
    location ~ /.well-known/acme-challenge { allow all; }
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
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
    echo -e "${YELLOW}Configuração de Nginx e SSL ignorada, conforme solicitado.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ PROCESSO CONCLUÍDO!${NC}"
echo "---------------------------------------------------"
echo "Seu painel deve estar acessível em: https://$DOMAIN"
echo "(Verifique se o DNS do seu domínio está apontando corretamente para o IP deste servidor)."
echo "---------------------------------------------------"
