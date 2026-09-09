require('dotenv').config();
const { initDb, getAccounts, getProxiesForAccount, getConfig, logger } = require('./database');

const { captchaManager } = require('./captcha');
const { BotWorker } = require('./botWorker');

async function main() {
    logger.info('==================================');
    logger.info('   IVAC Automation System Node    ');
    logger.info('==================================');

    // 1. Initialize Database
    await initDb();

    // 3. Load Config
    const config = await getConfig();

    // 4. Load Accounts
    const accounts = await getAccounts();
    // Same filter the dashboard's bot/start uses — a deactivated account must not run here either
    const activeAccounts = accounts.filter(acc => acc.status !== 'COMPLETED' && acc.is_active === 1);

    if (activeAccounts.length === 0) {
        logger.info('No active accounts found in the database. Please add accounts to the `accounts` table.');
        process.exit(0);
    }

    logger.info(`Loaded ${activeAccounts.length} active accounts to process.`);

    // 5. Spawn Workers
    logger.info('Starting Captcha Pool generation...');
    const workers = [];
    for (const account of activeAccounts) {
        const proxies = await getProxiesForAccount(account.id);
        const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
        // Pre-fill one pool per account/endpoint — solvers are keyed by account + siteKey
        ['ep_signin', 'ep_reserve', 'ep_payment'].forEach(k => {
            if (!config[`${k}_siteKey`]) return; // payment captcha optional — skip when unconfigured
            captchaManager.getSolver(account.id, proxyUrl, config[`${k}_captchaType`], config[`${k}_siteKey`]).fillCaptchaPool();
        });
        const worker = new BotWorker(account, proxies, config);
        workers.push(worker);
    }

    logger.info(`Starting ${workers.length} concurrent workers...`);
    const workerPromises = workers.map(worker => worker.run());

    // Wait for all to finish
    await Promise.allSettled(workerPromises);

    logger.info('All automation routines have completed.');
    process.exit(0);
}

main().catch(err => {
    logger.error(`Fatal error in main process: ${err.message}`);
    process.exit(1);
});
