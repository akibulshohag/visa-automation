const { app, BrowserWindow, session, Menu, MenuItem, clipboard, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');

const proxyUrlRaw = process.argv[process.argv.length - 1];
let proxyUrl, windowTitle, targetUrl, winWidth, winHeight, winX, winY, accountPhone;
try {
    const decoded = JSON.parse(Buffer.from(proxyUrlRaw, 'base64').toString('utf8'));
    proxyUrl = decoded.proxy;
    windowTitle = decoded.title;
    targetUrl = decoded.url;
    winWidth = decoded.width || 1024;
    winHeight = decoded.height || 768;
    winX = decoded.x;
    winY = decoded.y;
    accountPhone = decoded.phone;
} catch (e) {
    proxyUrl = process.argv[2];
    windowTitle = process.argv[3];
    targetUrl = process.argv[4];
    winWidth = 1024;
    winHeight = 768;
}

// Ignore certificate errors often caused by proxies
app.commandLine.appendSwitch('ignore-certificate-errors');

// Per-account persistent profile: keeps localStorage (payment selection) per account
// across opens, and stops concurrent instances from fighting over one profile lock.
const profileId = (accountPhone || 'default').replace(/[^0-9a-zA-Z]/g, '') || 'default';
app.setPath('userData', path.join(app.getPath('appData'), 'ivac-payment-profiles', profileId));

app.on('ready', async () => {
    let proxyHost = '', proxyPort = '', proxyUser = '', proxyPass = '';

    if (proxyUrl && proxyUrl !== 'null') {
        const parts = proxyUrl.split(':');
        if (parts.length === 4) {
            proxyHost = parts[0];
            proxyPort = parts[1];
            proxyUser = parts[2];
            proxyPass = parts[3];
        } else if (parts.length === 2) {
            proxyHost = parts[0];
            proxyPort = parts[1];
        }

        if (proxyHost && proxyPort) {
            const proxyRules = `http://${proxyHost}:${proxyPort}`;
            await session.defaultSession.setProxy({ proxyRules });
            console.log(`[Electron] Proxied via ${proxyRules}`);
        }
    } else {
        console.log('[Electron] No proxy provided, routing direct.');
    }

    app.on('login', (event, webContents, request, authInfo, callback) => {
        if (proxyUser && proxyPass) {
            event.preventDefault();
            callback(proxyUser, proxyPass);
        }
    });

    const winOpts = {
        width: winWidth,
        height: winHeight,
        title: windowTitle || 'IVAC Payment',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: false,
            webSecurity: false,
            preload: path.join(__dirname, 'preload.js')
        }
    };
    if (winX !== undefined) winOpts.x = winX;
    if (winY !== undefined) winOpts.y = winY;

    const win = new BrowserWindow(winOpts);

    // Handle reload request from renderer — preserves POST method unlike window.location.reload()
    ipcMain.on('reload-window', () => {
        win.webContents.reload();
    });

    win.on('page-title-updated', (event) => {
        event.preventDefault();
    });

    // White-page recovery: retry failed loads (dead proxy, network blip) and
    // reload if the renderer process dies.
    let loadRetries = 0;
    win.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
        if (!isMainFrame || errorCode === -3) return; // -3 = ERR_ABORTED (manual reload/navigation)
        if (loadRetries >= 5 || !targetUrl) return;
        loadRetries++;
        console.error(`[Electron] Load failed (${errorCode} ${errorDescription}), retry ${loadRetries}/5 in 3s...`);
        setTimeout(() => {
            if (!win.isDestroyed()) win.loadURL(targetUrl);
        }, 3000);
    });
    win.webContents.on('did-finish-load', () => {
        loadRetries = 0;
    });
    win.webContents.on('render-process-gone', (event, details) => {
        console.error(`[Electron] Renderer gone (${details.reason}), reloading...`);
        if (!win.isDestroyed()) win.webContents.reload();
    });

    win.setMenuBarVisibility(false);
    win.setAutoHideMenuBar(true);

    win.webContents.on('context-menu', (event, params) => {
        const menu = new Menu();
        
        if (params.isEditable) {
            menu.append(new MenuItem({ label: 'Cut', role: 'cut' }));
            menu.append(new MenuItem({ label: 'Copy', role: 'copy' }));
            menu.append(new MenuItem({ label: 'Paste', role: 'paste' }));
            menu.append(new MenuItem({ type: 'separator' }));
        } else if (params.selectionText && params.selectionText.trim().length > 0) {
            menu.append(new MenuItem({ label: 'Copy', role: 'copy' }));
            menu.append(new MenuItem({ type: 'separator' }));
        }

        if (params.linkURL) {
            menu.append(new MenuItem({ 
                label: 'Copy Link Address', 
                click: () => clipboard.writeText(params.linkURL) 
            }));
        }

        menu.append(new MenuItem({ type: 'separator' }));
        menu.append(new MenuItem({ label: 'Reload Page', role: 'reload' }));
        menu.append(new MenuItem({ label: 'Go Back', click: () => { if(win.webContents.canGoBack()) win.webContents.goBack(); } }));

        if (menu.items.length > 0) {
            menu.popup(win);
        }
    });

    // Some sites block electron user agents, cleanly strips it
    win.webContents.setUserAgent(win.webContents.getUserAgent().replace(/Electron\/\S*\s/, ''));

    win.webContents.on('did-finish-load', () => {
        try {
            // Tampermonkey API Polyfills for the specific ones used locally
            const polyfill = `
                window.__ACCOUNT_PHONE__ = "${accountPhone || ''}";
                window.GM_setValue = function(k, v) { 
                    localStorage.setItem(k, v); 
                    if (k === 'qp_selected_payment' && window.__ACCOUNT_PHONE__) {
                        fetch('http://localhost:3000/api/bot/payment-log', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ phone: window.__ACCOUNT_PHONE__, data: v })
                        }).catch(e => console.error('Log sync error:', e));
                    }
                };
                window.GM_getValue = function(k, d) { return localStorage.getItem(k) || d; };
                window.GM_deleteValue = function(k) { localStorage.removeItem(k); };
                window.GM_addStyle = function(css) { const style = document.createElement('style'); style.textContent = css; document.head.appendChild(style); };
                window.GM_openInTab = function(url) { window.open(url, '_blank'); };
                if (typeof window.unsafeWindow === 'undefined') { window.unsafeWindow = window; }
                
                // Force allow copy/paste/select operations
                const allowCopyAndPaste = function(e) {
                    e.stopImmediatePropagation();
                    return true;
                };
                ['copy', 'paste', 'cut', 'contextmenu', 'selectstart', 'drag', 'drop'].forEach(evt => 
                    document.addEventListener(evt, allowCopyAndPaste, true)
                );
                
                const styleOverride = document.createElement('style');
                styleOverride.innerHTML = '*, *::before, *::after { -webkit-user-select: auto !important; user-select: auto !important; }';
                if (document.head) document.head.appendChild(styleOverride);

                if (!document.getElementById('ivac-custom-url-bar')) {
                    const bar = document.createElement('div');
                    bar.id = 'ivac-custom-url-bar';
                    bar.innerHTML = \`<div style="display:flex; padding:5px; background:#f0f0f0; border-bottom:1px solid #ccc; z-index:99999999; position:fixed; top:0; left:0; width:100%; box-sizing:border-box; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <input type="text" id="ivac-url-input" value="\${window.location.href}" style="flex:1; padding:4px 8px; border:1px solid #ccc; border-radius:3px; outline:none; font-family:monospace; font-size:12px;" readonly>
                        <button onclick="window.location.reload()" style="margin-left:8px; padding:4px 12px; cursor:pointer; background:#fff; border:1px solid #aaa; border-radius:3px; font-weight:bold;">Reload</button>
                        <button id="ivac-stop-btn" style="margin-left:8px; padding:4px 12px; cursor:pointer; background:#fee; border:1px solid #f99; border-radius:3px; font-weight:bold; color:#d00;">Stop Auto-Reload</button>
                    </div>\`;
                    
                    if (document.body) {
                        document.body.prepend(bar);
                        document.body.style.paddingTop = '40px';
                    } else if (document.documentElement) {
                        document.documentElement.appendChild(bar);
                    }
                    
                    let stopReload = sessionStorage.getItem('__STOP_RELOAD__') === 'true';
                    const stopBtn = document.getElementById('ivac-stop-btn');
                    
                    const updateBtnState = () => {
                        if (!stopBtn) return;
                        if (stopReload) {
                            stopBtn.innerHTML = "Auto-Reload: OFF";
                            stopBtn.style.background = "#ddd";
                            stopBtn.style.border = "1px solid #999";
                            stopBtn.style.color = "#333";
                        } else {
                            stopBtn.innerHTML = "Stop Auto-Reload";
                            stopBtn.style.background = "#fee";
                            stopBtn.style.border = "1px solid #f99";
                            stopBtn.style.color = "#d00";
                        }
                    };
                    updateBtnState();

                    if (stopBtn) {
                        stopBtn.addEventListener('click', function() {
                            stopReload = !stopReload;
                            sessionStorage.setItem('__STOP_RELOAD__', stopReload);
                            updateBtnState();
                        });
                    }

                    setTimeout(() => {
                        const text = document.body ? (document.body.innerText || '') : '';
                        const title = document.title || '';
                        
                        const isError = title.includes('502') || title.includes('504') || 
                                        text.includes('502 Bad Gateway') || text.includes('504 Gateway Time-out') ||
                                        text.includes('504 Gateway Timeout') || text.includes('502') || text.includes('504');
                        
                        if (isError && !stopReload) {
                            console.log('502/504 detected, reloading...');
                            setTimeout(() => {
                                if (sessionStorage.getItem('__STOP_RELOAD__') !== 'true') {
                                    // Use Electron IPC reload to preserve POST request method
                                    if (typeof window.__electronReload__ === 'function') {
                                        window.__electronReload__();
                                    } else {
                                        window.location.reload();
                                    }
                                }
                            }, 2000);
                        }
                    }, 1500);

                    setInterval(() => {
                        const el = document.getElementById('ivac-url-input');
                        if(el && el.value !== window.location.href) el.value = window.location.href;
                    }, 500);
                }
            `;
            let combinedScript = polyfill + '\n\n';

            const scriptsToInject = ['paymentConfig.js'];
            scriptsToInject.forEach(file => {
                const scriptPath = path.join(__dirname, file);
                if (fs.existsSync(scriptPath)) {
                    combinedScript += fs.readFileSync(scriptPath, 'utf8') + '\n\n';
                } else {
                    console.warn(file + ' not found at', scriptPath);
                }
            });

            win.webContents.executeJavaScript(combinedScript)
                .then(() => console.log('Scripts injected successfully.'))
                .catch(err => console.error('Script injection error:', err));
        } catch (e) {
            console.error('Failed to inject scripts:', e);
        }
    });

    if (targetUrl) {
        win.loadURL(targetUrl);
    } else {
        console.error('No target URL provided.');
    }
});

app.on('window-all-closed', () => {
    app.quit();
});
