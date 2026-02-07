const db = require('./database');
(async () => {
    try {
        const s = await db.getSettings();
        s.allowRegistrations = true;
        await db.saveSettings(s);
        console.log('✅ SUCESSO: Novos registros foram ATIVADOS.');
        process.exit(0);
    } catch (e) { console.error(e); }
})();
