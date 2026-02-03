#!/bin/bash

# --- SCRIPT DE DOWNLOAD E ATUALIZAÇÃO ---

# Configurações
PROJECT_ZIP_URL="https://github.com/dinho17593/PAINEL-IA/archive/refs/tags/V2.zip"
TARGET_DIR="/var/www/bot-whatsapp"
ZIP_FILE="project.zip"
TEMP_EXTRACT_FOLDER="zappbot-painel-main"
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}--- INICIANDO PROCESSO DE INSTALAÇÃO/ATUALIZAÇÃO ---${NC}"

# Garante que os pacotes necessários estejam instalados
sudo apt-get update -qq
sudo apt-get install -y wget unzip git rsync -qq

# --- LÓGICA DE BACKUP E ATUALIZAÇÃO ---
if [ -d "$TARGET_DIR" ]; then
    echo -e "${YELLOW}Detectamos uma instalação existente. Preparando para atualização...${NC}"
    
    # Cria um diretório de backup com data e hora para segurança
    BKP_DIR="/root/bkp_bot_$(date +%F_%H-%M-%S)"
    mkdir -p "$BKP_DIR"
    echo "Criando backup dos dados importantes em: $BKP_DIR"
    
    # Copia os arquivos e pastas essenciais para o backup
    cp "$TARGET_DIR/.env" "$BKP_DIR/" 2>/dev/null
    cp "$TARGET_DIR"/*.json "$BKP_DIR/" 2>/dev/null
    cp -r "$TARGET_DIR/sessions" "$BKP_DIR/" 2>/dev/null
    cp -r "$TARGET_DIR/uploads" "$BKP_DIR/" 2>/dev/null
    cp -r "$TARGET_DIR/auth_sessions" "$BKP_DIR/" 2>/dev/null
    
    echo "Backup concluído."
fi

# Prepara o diretório de destino
mkdir -p "$TARGET_DIR"
cd /tmp

echo "Baixando a versão mais recente do código fonte..."
wget -q "$PROJECT_ZIP_URL" -O $ZIP_FILE
unzip -o -q $ZIP_FILE

echo "Sincronizando os novos arquivos com o diretório de destino..."
# Usamos rsync para copiar os novos arquivos, sobrescrevendo os antigos
rsync -a --delete "$TEMP_EXTRACT_FOLDER/" "$TARGET_DIR/"

# --- RESTAURAÇÃO DO BACKUP (SE APLICÁVEL) ---
if [ -d "$BKP_DIR" ]; then
    echo "Restaurando seus dados a partir do backup..."
    # Copia os dados de volta, garantindo que suas configurações e sessões sejam mantidas
    cp "$BKP_DIR/.env" "$TARGET_DIR/" 2>/dev/null
    cp "$BKP_DIR"/*.json "$TARGET_DIR/" 2>/dev/null
    cp -r "$BKP_DIR/sessions" "$TARGET_DIR/" 2>/dev/null
    cp -r "$BKP_DIR/uploads" "$TARGET_DIR/" 2>/dev/null
    cp -r "$BKP_DIR/auth_sessions" "$TARGET_DIR/" 2>/dev/null
    echo "Restauração concluída."
fi

# Copia o novo script de instalação para o diretório
echo "Atualizando o script de configuração..."
if [ -f "$OLDPWD/install.sh" ]; then
    cp "$OLDPWD/install.sh" "$TARGET_DIR/install.sh"
else
    echo "AVISO: install.sh não encontrado na pasta original."
fi

# Limpeza dos arquivos temporários
rm $ZIP_FILE
rm -rf $TEMP_EXTRACT_FOLDER
chmod -R 777 "$TARGET_DIR"

echo -e "${CYAN}--- DOWNLOAD E PREPARAÇÃO CONCLUÍDOS ---${NC}"
cd "$TARGET_DIR"

# Executa o script de configuração
if [ -f "install.sh" ]; then
    chmod +x install.sh
    sed -i 's/\r$//' install.sh
    ./install.sh
else
    echo "ERRO CRÍTICO: O script install.sh não foi encontrado."
fi
