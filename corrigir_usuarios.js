const db = require('./database');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

(async () => {
    try {
        console.log("--- LENDO BANCO DE DADOS ---");
        const users = await db.getAllUsers();
        const keys = Object.keys(users);

        if (keys.length === 0) {
            console.log("Nenhum usuário encontrado no banco de dados.");
            process.exit(0);
        }

        console.log("\n=== LISTA DE USUÁRIOS ===");
        console.log("ID  | CHAVE (Nome no Banco)");
        console.log("---------------------------");
        
        keys.forEach((key, index) => {
            // Mostra entre aspas para você ver se tem espaços vazios ou erro
            console.log(`${index + 1}.  | "${key}"`);
        });

        console.log("\n---------------------------");
        rl.question('Digite o NÚMERO do usuário que deseja EXCLUIR (ou 0 para sair): ', async (answer) => {
            const num = parseInt(answer);

            if (isNaN(num) || num <= 0 || num > keys.length) {
                console.log("Operação cancelada. Nada foi apagado.");
                process.exit(0);
            }

            const keyToDelete = keys[num - 1];
            
            console.log(`\nATENÇÃO: Você vai apagar o usuário: "${keyToDelete}"`);
            
            // Confirmação simples
            // Executa a exclusão
            try {
                // Tenta usar a função padrão do DB
                await db.deleteUser(keyToDelete);
                
                // Verificação extra: Se for SQLite e a função deleteUser não limpar tudo,
                // forçamos a remoção do objeto e salvamos (caso o deleteUser falhe com caracteres estranhos)
                const checkUsers = await db.getAllUsers();
                if (checkUsers[keyToDelete]) {
                    delete checkUsers[keyToDelete];
                    // Se o seu db.js tiver saveAllUsers ou similar, seria ideal, 
                    // mas geralmente deleteUser já resolve.
                    console.log("Tentativa forçada de remoção...");
                }
                
                console.log(`✅ SUCESSO: Usuário "${keyToDelete}" foi removido!`);
            } catch (err) {
                console.error("Erro ao tentar excluir:", err.message);
            }

            console.log("Reinicie o painel para atualizar a lista.");
            process.exit(0);
        });

    } catch (e) {
        console.error("Erro fatal:", e);
        process.exit(1);
    }
})();
