require('dotenv').config();
const mysql = require('mysql2/promise');
const winston = require('winston');

const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console()
    ]
});

// Create connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'visa_automation',
    waitForConnections: true,
    connectionLimit: 100,
    queueLimit: 0
});

async function initDb() {
    try {
        const initPool = mysql.createPool({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            waitForConnections: true,
            connectionLimit: 1,
            queueLimit: 0
        });

        await initPool.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME || 'visa_automation'}\``);
        await initPool.end();

        await pool.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                phone VARCHAR(20) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) NULL,
                email VARCHAR(255) NULL,
                status VARCHAR(50) DEFAULT 'IDLE',
                access_token TEXT NULL,
                token_expires_at DATETIME NULL,
                last_run DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Add token columns if they don't exist (INFORMATION_SCHEMA check for MySQL 5.7 compatibility)
        const dbName = pool.pool.config.connectionConfig.database;
        const [cols] = await pool.query(
            `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'accounts'`,
            [dbName]
        );
        const existingCols = cols.map(c => c.COLUMN_NAME);
        if (!existingCols.includes('assigned_ip')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN assigned_ip VARCHAR(50) NULL`);
            logger.info('[DB] Added column: accounts.assigned_ip');
        }
        if (!existingCols.includes('is_active')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN is_active BOOLEAN DEFAULT TRUE`);
            logger.info('[DB] Added column: accounts.is_active');
        }
        if (!existingCols.includes('access_token')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN access_token TEXT NULL`);
            logger.info('[DB] Added column: accounts.access_token');
        }
        if (!existingCols.includes('token_expires_at')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN token_expires_at DATETIME NULL`);
            logger.info('[DB] Added column: accounts.token_expires_at');
        }
        if (!existingCols.includes('name')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN name VARCHAR(255) NULL`);
            logger.info('[DB] Added column: accounts.name');
        }
        if (!existingCols.includes('email')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN email VARCHAR(255) NULL`);
            logger.info('[DB] Added column: accounts.email');
        }
        if (existingCols.includes('adv_otp_enabled')) {
            await pool.query(`ALTER TABLE accounts DROP COLUMN adv_otp_enabled`);
            logger.info('[DB] Dropped obsolete column: accounts.adv_otp_enabled');
        }
        if (!existingCols.includes('appointment_id')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN appointment_id VARCHAR(255) NULL`);
            logger.info('[DB] Added column: accounts.appointment_id');
        }
        if (!existingCols.includes('appointment_date')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN appointment_date DATE NULL`);
            logger.info('[DB] Added column: accounts.appointment_date');
        }
        // Marks the day the account's mission/center confirmation (appointment-booking-config)
        // last succeeded. Files only need uploading once per day, so a run on the same date skips
        // the whole file-upload phase. See botWorker.fileUploadStep / isFileConfirmedToday.
        if (!existingCols.includes('file_confirmed_date')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN file_confirmed_date DATE NULL`);
            logger.info('[DB] Added column: accounts.file_confirmed_date');
        }
        if (!existingCols.includes('request_id')) {
            await pool.query(`ALTER TABLE accounts ADD COLUMN request_id VARCHAR(255) NULL`);
            logger.info('[DB] Added column: accounts.request_id');
        }

        await pool.query(`
            CREATE TABLE IF NOT EXISTS proxies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_id INT NOT NULL,
                proxy_url VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS config (
                \`key\` VARCHAR(100) PRIMARY KEY,
                value TEXT NOT NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                phone VARCHAR(20) NOT NULL,
                level VARCHAR(10) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_phone (phone),
                INDEX idx_created (created_at)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS api_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(50) NOT NULL UNIQUE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS otp_servers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(255) NOT NULL UNIQUE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Seed the default OTP server so behavior is unchanged out of the box
        await pool.query('INSERT IGNORE INTO otp_servers (url) VALUES (?)', [process.env.SOCKET_URL || 'otps.top']);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS callback_tasks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                uri TEXT NOT NULL,
                interval_ms INT DEFAULT 1000,
                workers INT DEFAULT 1,
                is_active BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Per-account PDF documents uploaded from the dashboard, used by the file-upload step.
        // Files are stored on disk (storage_path); this table holds only metadata + ordering.
        await pool.query(`
            CREATE TABLE IF NOT EXISTS account_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                account_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                mime VARCHAR(100) NULL,
                byte_size INT NULL,
                applicant_index INT DEFAULT 0,
                is_primary BOOLEAN DEFAULT FALSE,
                web_file_number VARCHAR(100) NULL,
                storage_path VARCHAR(500) NOT NULL,
                uploaded_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_account (account_id),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
        `);

        // Add uploaded_at to account_files if an earlier build created the table without it.
        const [afCols] = await pool.query(
            `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'account_files'`,
            [dbName]
        );
        if (!afCols.map(c => c.COLUMN_NAME).includes('uploaded_at')) {
            await pool.query(`ALTER TABLE account_files ADD COLUMN uploaded_at DATETIME NULL`);
            logger.info('[DB] Added column: account_files.uploaded_at');
        }

        // ─── Signups (auto sign-up queue) ─────────────────────────────────────────────
        // Accounts to be auto-registered on the live IVAC site. The signup worker walks each
        // row through: phone-OTP verify → email-OTP verify → /auth/signup. A finished row can be
        // "converted" into a real accounts row (see convertSignupToAccount). Kept separate from
        // `accounts` so an in-progress/failed signup never pollutes the booking pipeline.
        await pool.query(`
            CREATE TABLE IF NOT EXISTS signups (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                given_name VARCHAR(255) NULL,
                surname VARCHAR(255) NULL,
                dob VARCHAR(20) NULL,
                nid VARCHAR(100) NULL,
                passport VARCHAR(100) NULL,
                phone VARCHAR(30) NOT NULL,
                password VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'PENDING',
                step INT DEFAULT 0,
                progress TEXT NULL,
                request_id VARCHAR(255) NULL,
                account_id INT NULL,
                last_log TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_signup_phone (phone)
            )
        `);

        // Resumable-progress columns for installs whose signups table predates them.
        // step = number of COMPLETED steps in the 5-step flow: 0=nothing, 1=phone OTP sent,
        // 2=phone verified, 3=email OTP sent, 4=email verified, 5=account created. progress: JSON of
        // the OTPs / turnstile tokens / requestIds captured per channel, so a resumed submit can
        // echo them back the way the site does (see signupWorker).
        const [suCols] = await pool.query(
            `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'signups'`,
            [dbName]
        );
        const suColNames = suCols.map(c => c.COLUMN_NAME);
        if (!suColNames.includes('step')) {
            await pool.query(`ALTER TABLE signups ADD COLUMN step INT DEFAULT 0`);
            logger.info('[DB] Added column: signups.step');
        }
        if (!suColNames.includes('progress')) {
            await pool.query(`ALTER TABLE signups ADD COLUMN progress TEXT NULL`);
            logger.info('[DB] Added column: signups.progress');
        }

        // Reset any previously active callback tasks on boot so they don't auto-start unhandled
        await pool.query('UPDATE callback_tasks SET is_active = FALSE');

        // A signup left RUNNING when the server stopped isn't actually running. Roll its status back
        // to the resumable label for its step (keeping step/progress) so it can be continued, not
        // restarted. Terminal DONE/CONVERTED and FAILED/STOPPED states are left untouched.
        await pool.query(`
            UPDATE signups
               SET status = CASE step WHEN 1 THEN 'PHONE_VERIFIED' WHEN 2 THEN 'EMAIL_VERIFIED' ELSE 'PENDING' END
             WHERE status IN ('RUNNING','QUEUED')
        `);

        // Insert default config values if not present
        const defaults = [
            ['retryDelay', '5'],
            ['successDelay', '0'],
            ['paymentInitDelay', '0'],
            ['failDelay', '5'],
            ['maxRetry', '10'],
            ['maxReserveRetry', '100'],
            ['multiReserve', '0'],
            ['autoReserveSlot', '1'],
            ['ep_signin_url', 'https://api.ivacbd.com/iams/api/'],
            ['ep_signin_captchaType', 'TurnstileTask'],
            ['ep_signin_siteKey', '0x4AAAAAACghKkJHL1t7UkuZ'],
            ['ep_signin_encode', '0'],
            ['ep_signin_ip_count', '1'],
            ['ep_reserve_url', 'https://api.ivacbd.com/iams/api/'],
            // Reserve endpoint is now v1/slots/<slotId>/reserve-slot; slotId is baked into the site
            // bundle. Stored here so it can be updated from config if the site rotates it.
            ['ep_reserve_slot_id', 'ccd3dd63-e781-48ba-a48d-c65eaa4fc663'],
            ['ep_reserve_captchaType', 'RecaptchaV2Task'],
            ['ep_reserve_siteKey', '6LdyiGMsAAAAAJefesdWMjxy8pu3A3DmbeJkkdUl'],
            ['ep_reserve_encode', '0'],
            ['ep_reserve_ip_count', '1'],
            ['ep_verifyotp_url', 'https://api.ivacbd.com/iams/api/'],
            ['ep_verifyotp_ip_count', '1'],
            ['ep_payment_url', 'https://api.ivacbd.com/iams/api/'],
            ['ep_payment_captchaType', 'RecaptchaV2Task'],
            ['ep_payment_siteKey', ''],
            ['ep_payment_ip_count', '1'],
            // File-upload step (runs after OTP verify, before Reserve). x-token is a Cloudflare
            // Turnstile token, so this reuses the same solver mechanism as sign-in.
            ['autoFileUpload', '1'],
            ['ep_fileupload_url', 'https://api.ivacbd.com/iams/api/'],
            ['ep_fileupload_captchaType', 'TurnstileTask'],
            ['ep_fileupload_siteKey', '0x4AAAAAACghKkJHL1t7UkuZ'],
            ['ep_fileupload_ip_count', '1'],
            // Signup step (auto sign-up). Both OTP sends carry a Cloudflare Turnstile token in the
            // x-token header, so this reuses the same solver mechanism as sign-in / file-upload.
            // ep_signup_url is the API base; the worker hits v1/otp/signupOtp, v1/otp/verifyOtp and
            // v1/auth/signup under it. Channels are "PHONE" and "EMAIL" (verified in the site bundle).
            ['ep_signup_url', 'https://api.ivacbd.com/iams/api/'],
            ['ep_signup_captchaType', 'TurnstileTask'],
            ['ep_signup_siteKey', '0x4AAAAAACghKkJHL1t7UkuZ'],
            ['ep_signup_ip_count', '1'],
            ['api_timeout', '30']
        ];
        for (const [key, value] of defaults) {
            await pool.query('INSERT IGNORE INTO config (`key`, value) VALUES (?, ?)', [key, value]);
        }

        // ─── Migration: dead API host iodp.ivacbd.com → api.ivacbd.com ────────────────
        // The endpoint base URLs were previously pointed at iodp.ivacbd.com, a backend that
        // Cloudflare now answers with a 403 challenge page (blocked). The live IVAC API is
        // https://api.ivacbd.com/iams/api/ (verified: api.* returns real 401/400 JSON while
        // iodp.* returns a CF block page). INSERT IGNORE above never overwrites existing rows,
        // so rewrite any stored config value still on the dead host. Idempotent.
        const [mig] = await pool.query(
            "UPDATE config SET value = REPLACE(value, 'iodp.ivacbd.com', 'api.ivacbd.com') WHERE value LIKE '%iodp.ivacbd.com%'"
        );
        if (mig && mig.affectedRows) {
            logger.info(`[Migration] Rewrote ${mig.affectedRows} config URL(s) from dead host iodp.ivacbd.com → api.ivacbd.com`);
        }

        logger.info('Database initialized successfully.');
    } catch (error) {
        logger.error('Database initialization failed:', error);
        process.exit(1);
    }
}

// ─── Accounts ─────────────────────────────────────────────────────────────────
async function getAccounts() {
    // files_uploaded counts TODAY's uploads only — files re-upload each day, so the same CURDATE()
    // rule getAccountFiles/fileUploadStep use (uploaded_today) is what makes the dashboard count
    // match what the worker will actually do on a run today.
    const [rows] = await pool.query(`
        SELECT a.id, a.phone, a.password, a.name, a.email, a.status, a.last_run, a.created_at,
               a.is_active, a.token_expires_at, a.assigned_ip, a.request_id, a.appointment_id,
               DATE_FORMAT(a.appointment_date, '%Y-%m-%d') AS appointment_date,
               (SELECT COUNT(*) FROM account_files f WHERE f.account_id = a.id) AS files_total,
               (SELECT COUNT(*) FROM account_files f
                 WHERE f.account_id = a.id AND DATE(f.uploaded_at) = CURDATE()) AS files_uploaded
        FROM accounts a
        ORDER BY a.created_at DESC
    `);
    return rows;
}

async function getAccount(id) {
    const [rows] = await pool.query('SELECT * FROM accounts WHERE id = ?', [id]);
    return rows[0];
}

async function createAccount(phone, password, name = null, email = null, assigned_ip = null) {
    const [result] = await pool.query(
        'INSERT INTO accounts (phone, password, name, email, assigned_ip) VALUES (?, ?, ?, ?, ?)',
        [phone, password, name, email, assigned_ip]
    );
    return result.insertId;
}

async function updateAccount(id, phone, password, name = null, email = null, assigned_ip = null) {
    await pool.query(
        'UPDATE accounts SET phone = ?, password = ?, name = ?, email = ?, assigned_ip = ? WHERE id = ?',
        [phone, password, name, email, assigned_ip, id]
    );
}

async function deleteAccount(id) {
    await pool.query('DELETE FROM accounts WHERE id = ?', [id]);
}

async function resetAccountStatus(id) {
    await pool.query('UPDATE accounts SET status = ? WHERE id = ?', ['IDLE', id]);
}

async function toggleAccountActivity(id, isActive) {
    await pool.query('UPDATE accounts SET is_active = ? WHERE id = ?', [isActive, id]);
}

// ─── Signups (auto sign-up queue) ──────────────────────────────────────────────
async function getSignups() {
    const [rows] = await pool.query(
        'SELECT id, email, given_name, surname, dob, nid, passport, phone, password, status, step, request_id, account_id, last_log, created_at FROM signups ORDER BY created_at DESC'
    );
    return rows;
}

async function getSignup(id) {
    const [rows] = await pool.query('SELECT * FROM signups WHERE id = ?', [id]);
    return rows[0];
}

async function createSignup(s) {
    const [result] = await pool.query(
        `INSERT INTO signups (email, given_name, surname, dob, nid, passport, phone, password, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
        [s.email, s.given_name || null, s.surname || null, s.dob || null, s.nid || null, s.passport || null, s.phone, s.password]
    );
    return result.insertId;
}

async function updateSignup(id, s) {
    // Changing the phone or email invalidates any prior OTP verification, so reset progress in that
    // case. Editing other fields (name/dob/nid/passport/password) keeps the verified steps intact.
    const prev = await getSignup(id);
    const identityChanged = prev && (String(prev.phone) !== String(s.phone) || String(prev.email) !== String(s.email));
    if (identityChanged) {
        await pool.query(
            `UPDATE signups SET email = ?, given_name = ?, surname = ?, dob = ?, nid = ?, passport = ?, phone = ?, password = ?,
                    step = 0, progress = NULL, request_id = NULL, status = 'PENDING' WHERE id = ?`,
            [s.email, s.given_name || null, s.surname || null, s.dob || null, s.nid || null, s.passport || null, s.phone, s.password, id]
        );
    } else {
        await pool.query(
            `UPDATE signups SET email = ?, given_name = ?, surname = ?, dob = ?, nid = ?, passport = ?, phone = ?, password = ? WHERE id = ?`,
            [s.email, s.given_name || null, s.surname || null, s.dob || null, s.nid || null, s.passport || null, s.phone, s.password, id]
        );
    }
}

async function deleteSignup(id) {
    await pool.query('DELETE FROM signups WHERE id = ?', [id]);
}

async function updateSignupStatus(id, status, lastLog = null) {
    if (lastLog !== null) {
        await pool.query('UPDATE signups SET status = ?, last_log = ? WHERE id = ?', [status, lastLog, id]);
    } else {
        await pool.query('UPDATE signups SET status = ? WHERE id = ?', [status, id]);
    }
}

async function saveSignupRequestId(id, requestId) {
    await pool.query('UPDATE signups SET request_id = ? WHERE id = ?', [requestId, id]);
}

// Persist how far a signup has progressed so it can be resumed/retried from that point.
// step: 0=nothing, 1=phone verified, 2=email verified, 3=done. progress: object of captured
// OTPs/tokens (stored as JSON) or null to leave it unchanged.
async function saveSignupProgress(id, step, status = null, progress = undefined) {
    const sets = ['step = ?'];
    const params = [step];
    if (status !== null) { sets.push('status = ?'); params.push(status); }
    if (progress !== undefined) { sets.push('progress = ?'); params.push(progress === null ? null : JSON.stringify(progress)); }
    params.push(id);
    await pool.query(`UPDATE signups SET ${sets.join(', ')} WHERE id = ?`, params);
}

// Promote a completed signup into a real accounts row (idempotent per signup). Links the two via
// signups.account_id so the same signup can't create duplicate accounts. Returns the account id.
async function convertSignupToAccount(id) {
    const s = await getSignup(id);
    if (!s) throw new Error('Signup not found');
    if (s.account_id) return s.account_id; // already converted
    const name = [s.given_name, s.surname].filter(Boolean).join(' ') || null;
    let accountId;
    // Reuse an existing account with the same phone if one already exists, else create it.
    const [existing] = await pool.query('SELECT id FROM accounts WHERE phone = ?', [s.phone]);
    if (existing.length) {
        accountId = existing[0].id;
        await pool.query('UPDATE accounts SET password = ?, name = ?, email = ? WHERE id = ?', [s.password, name, s.email, accountId]);
    } else {
        const [result] = await pool.query(
            'INSERT INTO accounts (phone, password, name, email) VALUES (?, ?, ?, ?)',
            [s.phone, s.password, name, s.email]
        );
        accountId = result.insertId;
    }
    await pool.query('UPDATE signups SET account_id = ?, status = ? WHERE id = ?', [accountId, 'CONVERTED', id]);
    return accountId;
}

// ─── Account files (PDF documents for the file-upload step) ────────────────────
async function addAccountFile(accountId, { filename, mime, byteSize, applicantIndex = 0, isPrimary = false, webFileNumber = null, storagePath }) {
    const [result] = await pool.query(
        `INSERT INTO account_files (account_id, filename, mime, byte_size, applicant_index, is_primary, web_file_number, storage_path)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [accountId, filename, mime || null, byteSize || null, applicantIndex, isPrimary ? 1 : 0, webFileNumber || null, storagePath]
    );
    return result.insertId;
}

// Ordered by applicant_index then id so files map to overview applicants deterministically.
// `uploaded_today` (1/0) reflects whether uploaded_at is TODAY — files must be re-uploaded each
// day, so the resume-skip must only apply to files already uploaded on the current date, not a
// previous day's leftover uploaded_at.
async function getAccountFiles(accountId) {
    const [rows] = await pool.query(
        'SELECT *, (DATE(uploaded_at) = CURDATE()) AS uploaded_today FROM account_files WHERE account_id = ? ORDER BY applicant_index ASC, id ASC',
        [accountId]
    );
    return rows;
}

async function getAccountFile(fileId) {
    const [rows] = await pool.query('SELECT * FROM account_files WHERE id = ?', [fileId]);
    return rows[0];
}

async function deleteAccountFile(fileId) {
    await pool.query('DELETE FROM account_files WHERE id = ?', [fileId]);
}

// Mark one file as uploaded so a retry/restart of the file-upload step resumes from the next file.
async function markAccountFileUploaded(fileId) {
    await pool.query('UPDATE account_files SET uploaded_at = NOW() WHERE id = ?', [fileId]);
}

// Clear the uploaded flag on all of an account's files so the next run re-uploads them.
// Also clear the account's file_confirmed_date so the file-upload phase runs again
// instead of being skipped by isFileConfirmedToday.
async function resetAccountFilesUploaded(accountId) {
    await pool.query('UPDATE account_files SET uploaded_at = NULL WHERE account_id = ?', [accountId]);
    await pool.query('UPDATE accounts SET file_confirmed_date = NULL WHERE id = ?', [accountId]);
}

async function getProxiesForAccount(accountId) {
    const [rows] = await pool.query('SELECT * FROM proxies WHERE account_id = ? AND is_active = TRUE', [accountId]);
    return rows;
}

async function getAllProxiesForAccount(accountId) {
    const [rows] = await pool.query('SELECT * FROM proxies WHERE account_id = ?', [accountId]);
    return rows;
}

async function addProxy(accountId, proxyUrl) {
    const [result] = await pool.query('INSERT INTO proxies (account_id, proxy_url) VALUES (?, ?)', [accountId, proxyUrl]);
    return result.insertId;
}

async function deleteProxy(proxyId) {
    await pool.query('DELETE FROM proxies WHERE id = ?', [proxyId]);
}

// Global list of every proxy across all accounts, with the owning account's phone/name.
// Ordered by account creation (newest first) to match the dashboard's account list order,
// then by proxy id so each account's proxies stay grouped and in insertion order.
async function getAllProxies() {
    const [rows] = await pool.query(
        `SELECT p.id, p.account_id, p.proxy_url, p.is_active, p.created_at, a.phone, a.name
         FROM proxies p JOIN accounts a ON p.account_id = a.id
         ORDER BY a.created_at DESC, p.id ASC`
    );
    return rows;
}

async function toggleProxy(id, isActive) {
    await pool.query('UPDATE proxies SET is_active = ? WHERE id = ?', [isActive, id]);
}

// Move a proxy to a different account.
async function reassignProxy(proxyId, newAccountId) {
    await pool.query('UPDATE proxies SET account_id = ? WHERE id = ?', [newAccountId, proxyId]);
}

async function bulkDeleteProxies(ids) {
    if (!ids || ids.length === 0) return;
    const placeholders = ids.map(() => '?').join(',');
    await pool.query(`DELETE FROM proxies WHERE id IN (${placeholders})`, ids);
}

async function updateAccountStatus(accountId, status) {
    await pool.query('UPDATE accounts SET status = ?, last_run = NOW() WHERE id = ?', [status, accountId]);
}

async function getConfig() {
    const [rows] = await pool.query('SELECT `key`, value FROM config');
    const config = {};
    for (const row of rows) config[row.key] = row.value;
    return config;
}

async function setConfig(key, value) {
    await pool.query('INSERT INTO config (`key`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?', [key, value, value]);
}

// ─── API IPs (Origin Bypass) ────────────────────────────────────────────────
async function getActiveApiIps() {
    const [rows] = await pool.query('SELECT ip FROM api_ips WHERE is_active = TRUE');
    return rows.map(r => r.ip);
}

async function getApiIps() {
    const [rows] = await pool.query('SELECT * FROM api_ips ORDER BY created_at DESC');
    return rows;
}

async function addApiIp(ip) {
    const [result] = await pool.query('INSERT IGNORE INTO api_ips (ip) VALUES (?)', [ip]);
    return result.insertId;
}

async function deleteApiIp(id) {
    await pool.query('DELETE FROM api_ips WHERE id = ?', [id]);
}

async function bulkDeleteApiIps(ids) {
    if (!ids || ids.length === 0) return;
    const placeholders = ids.map(() => '?').join(',');
    await pool.query(`DELETE FROM api_ips WHERE id IN (${placeholders})`, ids);
}

async function toggleApiIp(id, isActive) {
    await pool.query('UPDATE api_ips SET is_active = ? WHERE id = ?', [isActive, id]);
}

// ─── OTP Servers ──────────────────────────────────────────────────────────────
async function getActiveOtpServers() {
    const [rows] = await pool.query('SELECT url FROM otp_servers WHERE is_active = TRUE');
    return rows.map(r => r.url);
}

async function getOtpServers() {
    const [rows] = await pool.query('SELECT * FROM otp_servers ORDER BY created_at DESC');
    return rows;
}

async function addOtpServer(url) {
    const [result] = await pool.query('INSERT IGNORE INTO otp_servers (url) VALUES (?)', [url]);
    return result.insertId;
}

async function deleteOtpServer(id) {
    await pool.query('DELETE FROM otp_servers WHERE id = ?', [id]);
}

async function toggleOtpServer(id, isActive) {
    await pool.query('UPDATE otp_servers SET is_active = ? WHERE id = ?', [isActive, id]);
}


// ─── Token Persistence ────────────────────────────────────────────────────────
async function saveToken(accountId, accessToken) {
    // Token lifespan is 15 minutes; store with exact expiry
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await pool.query(
        'UPDATE accounts SET access_token = ?, token_expires_at = ? WHERE id = ?',
        [accessToken, expiresAt, accountId]
    );
}

async function getStoredToken(accountId) {
    const [rows] = await pool.query(
        'SELECT access_token, token_expires_at FROM accounts WHERE id = ? AND token_expires_at > NOW()',
        [accountId]
    );
    if (rows.length && rows[0].access_token) {
        return rows[0].access_token;
    }
    return null; // no valid token
}

// ─── Appointment Persistence ──────────────────────────────────────────────────
async function saveAppointmentId(accountId, appointmentId) {
    await pool.query(
        'UPDATE accounts SET appointment_id = ?, appointment_date = CURDATE() WHERE id = ?',
        [appointmentId, accountId]
    );
}

async function getSavedAppointmentId(accountId) {
    const [rows] = await pool.query(
        'SELECT appointment_id FROM accounts WHERE id = ? AND appointment_date = CURDATE()',
        [accountId]
    );
    if (rows.length && rows[0].appointment_id) {
        return rows[0].appointment_id;
    }
    return null;
}

// Record that this account's mission/center confirmation succeeded today, so subsequent runs on
// the same date skip the (once-per-day) file-upload phase.
async function markFileConfirmedToday(accountId) {
    await pool.query('UPDATE accounts SET file_confirmed_date = CURDATE() WHERE id = ?', [accountId]);
}

// True when the file-upload phase already completed (mission/center confirmed) for this account
// today — i.e. the whole phase can be skipped.
async function isFileConfirmedToday(accountId) {
    const [rows] = await pool.query(
        'SELECT 1 AS ok FROM accounts WHERE id = ? AND file_confirmed_date = CURDATE()',
        [accountId]
    );
    return rows.length > 0;
}

async function saveRequestId(accountId, requestId) {
    await pool.query(
        'UPDATE accounts SET request_id = ? WHERE id = ?',
        [requestId, accountId]
    );
}

async function getSavedRequestId(accountId) {
    const [rows] = await pool.query(
        'SELECT request_id FROM accounts WHERE id = ?',
        [accountId]
    );
    if (rows.length && rows[0].request_id) {
        return rows[0].request_id;
    }
    return null;
}

// ─── Log Persistence ──────────────────────────────────────────────────────────
async function insertLog(phone, level, message) {
    try {
        await pool.query('INSERT INTO logs (phone, level, message) VALUES (?, ?, ?)', [phone, level, message]);
    } catch (e) {
        // Never crash the bot due to logging failure
    }
}

async function getRecentLogs(phone, limit = 200) {
    const [rows] = await pool.query(
        'SELECT level, message, created_at FROM logs WHERE phone = ? ORDER BY created_at DESC LIMIT ?',
        [phone, limit]
    );
    return rows.reverse(); // oldest first
}

async function clearLogsForAccount(phone) {
    await pool.query('DELETE FROM logs WHERE phone = ?', [phone]);
}

async function cleanOldLogs() {
    const [result] = await pool.query('DELETE FROM logs WHERE created_at < NOW() - INTERVAL 1 DAY');
    if (result.affectedRows > 0) {
        logger.info(`[Cleanup] Deleted ${result.affectedRows} old log entries.`);
    }
}

// ─── Callback Tasks ───────────────────────────────────────────────────────────
async function getCallbackTasks() {
    const [rows] = await pool.query('SELECT * FROM callback_tasks ORDER BY created_at DESC');
    return rows;
}

async function addCallbackTask(uri, interval_ms, workers) {
    const [result] = await pool.query(
        'INSERT INTO callback_tasks (uri, interval_ms, workers) VALUES (?, ?, ?)',
        [uri, interval_ms, workers]
    );
    return result.insertId;
}

async function deleteCallbackTask(id) {
    await pool.query('DELETE FROM callback_tasks WHERE id = ?', [id]);
}

async function toggleCallbackTask(id, isActive) {
    await pool.query('UPDATE callback_tasks SET is_active = ? WHERE id = ?', [isActive, id]);
}

module.exports = {
    pool,
    initDb,
    getAccounts,
    getAccount,
    createAccount,
    updateAccount,
    deleteAccount,
    resetAccountStatus,
    toggleAccountActivity,
    getSignups,
    getSignup,
    createSignup,
    updateSignup,
    deleteSignup,
    updateSignupStatus,
    saveSignupRequestId,
    saveSignupProgress,
    convertSignupToAccount,
    addAccountFile,
    getAccountFiles,
    getAccountFile,
    deleteAccountFile,
    markAccountFileUploaded,
    resetAccountFilesUploaded,
    getProxiesForAccount,
    getAllProxiesForAccount,
    addProxy,
    deleteProxy,
    getAllProxies,
    toggleProxy,
    bulkDeleteProxies,
    reassignProxy,
    updateAccountStatus,
    getConfig,
    setConfig,
    saveToken,
    getStoredToken,
    insertLog,
    getRecentLogs,
    clearLogsForAccount,
    cleanOldLogs,
    logger,
    getActiveApiIps,
    getApiIps,
    addApiIp,
    deleteApiIp,
    bulkDeleteApiIps,
    toggleApiIp,
    getActiveOtpServers,
    getOtpServers,
    addOtpServer,
    deleteOtpServer,
    toggleOtpServer,
    getCallbackTasks,
    addCallbackTask,
    deleteCallbackTask,
    toggleCallbackTask,
    saveAppointmentId,
    getSavedAppointmentId,
    markFileConfirmedToday,
    isFileConfirmedToday,
    saveRequestId,
    getSavedRequestId
};
