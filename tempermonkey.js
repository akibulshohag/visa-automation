// ==UserScript==
// @name         IVAC — All In One System
// @namespace    http://tampermonkey.net/
// @version      V10.0.0.6
// @description  Advanced IVAC automation system
// @author       System Administrator
// @match        https://appointment.ivacbd.com/*
// @run-at       document-end
// @grant        GM_addStyle
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_openInTab
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      api.ivacbd.com
// @noframes
// ==/UserScript==

(function () {
    const fileName = 'Visa Automation v5.js';
    const baseUrl = 'https://appointment.ivacbd.com/';
    const apiUrl = 'https://api.ivacbd.com/iams/api/';
    const googleRecaptchaSiteKey = '0x4AAAAAACghKkJHL1t7UkuZ';
    const captchaSolverBaseApi = 'https://api.capmonster.cloud/';
    const captchaSolverToken = '0a9cbadf78a85acbe1167d88b8854933';
    let socket;
    const socketUrl = 'https://otps.top/';
    let card, headerEl, minBtn, closeBtn, bodyEl, host;
    const storageKey = '__tm_floating_card_pos_v1';
    const stateKey = '__tm_floating_card_state_v1';
    let state = { x: 0, y: 0, minimized: false, opacityLow: false };
    window.intervals = window.intervals || {};
    let EXECUTION_TOKEN = 0;
    const autoStartTime = '13:31:00';
    const reserveSlotTargetTime = '13:32:00';
    let isReservedSlotRunning = false;
    let autoStartTimer = null;
    let shadow, isRunning = false;
    const DB_NAME = 'automotion', STORE_NAME = 'user';
    let db, currentIndex;
    let retryConfig = {
        retryDelay: 5,
        maxRetry: 100,
        successDelay: 0,
    }
    const blockedCode = [429, 401, 419];
    const ignoredCode = [502, 504];

    const steps = [
        { name: 'Sign In', run: async () => await loginFn() },
        { name: 'Verify Otp', input: true, run: async () => await verifyOtpFn() },
        { name: 'Reserve Slot', run: async () => await reserveSlotFn() },
        { name: 'Payment Init', run: async () => await initiateFn() },
    ];
    let pendingReserveRequests = [];
    let reserveSuccess = false;
    let reserverSlotTimeout = null;
    async function runStep() {
        if (isRunning) {
            logConsole(`🛑 Process is already running. Please stop it before starting again.`, false);
            return;
        }
        const token = Date.now();
        EXECUTION_TOKEN = token;
        isRunning = true;
        currentIndex = parseInt(localStorage.getItem('auto_lastStep') || '0', 10);
        await updateCurrentStepUI(currentIndex);
        while (isRunning && EXECUTION_TOKEN === token && currentIndex < steps.length) {
            const step = steps[currentIndex];
            logConsole(`🔁 Starting step ${step.name}...`, true);
            if (step.delay) {
                const countdownOk = await startCountdown(step.delay);
                if (!countdownOk || !isRunning || EXECUTION_TOKEN !== token) {
                    logConsole(`🛑 Countdown interrupted. Stopping current run.`, false);
                    isRunning = false;
                    return;
                }
            }
            let successDelayInput = shadow.getElementById('auto-delay')?.value.trim();
            successDelayInput = parseInt(successDelayInput, 10) || 0;
            let success = false;
            let retryCount = 0;
            while (!success && isRunning && EXECUTION_TOKEN === token) {
                let retryDelayInput = shadow.getElementById('retry-delay')?.value.trim();
                retryDelayInput = parseInt(retryDelayInput, 10) || 0;
                let maxRetryInput = shadow.getElementById('max-retry')?.value.trim();
                maxRetryInput = parseInt(maxRetryInput, 10) || 0;
                try {
                    success = await step.run();
                    if (!isRunning || EXECUTION_TOKEN !== token) {
                        return;
                    }
                    if (success) {
                        logConsole(`✅ ${step.name} done.`, true);
                        currentIndex++;
                        break;
                    } else {
                        retryCount++;
                        if (retryCount >= maxRetryInput) {
                            logConsole(`⛔ ${step.name} failed ${maxRetryInput} times. Cancelling all steps.`, false);
                            isRunning = false;
                            break;
                        }
                        logConsole(`❌ ${step.name} failed (attempt ${retryCount}/${maxRetryInput}), retrying in ${retryDelayInput}s...`, false);
                        const slept = await sleepWithToken(retryDelayInput * 1000, token);
                        if (!slept) {
                            isRunning = false;
                            return;
                        }
                    }
                } catch (e) {
                    retryCount++;
                    if (retryCount >= maxRetryInput) {
                        logConsole(`⚠ Error in "${step.name}" exceeded ${maxRetryInput} attempts: ${e}`, false);
                        isRunning = false;
                        break;
                    }
                    logConsole(`⚠ Error in "${step.name}" (attempt ${retryCount}/${maxRetryInput}): ${e}`, false);
                    const slept = await sleepWithToken(retryDelayInput * 1000, token);
                    if (!slept) {
                        isRunning = false;
                        return;
                    }
                }
            }
            if (!isRunning || !success || EXECUTION_TOKEN !== token) {
                logConsole(`🛑 Process stopped. Please call Start again to restart.`, false);
                return;
            }
        }
        if (isRunning && EXECUTION_TOKEN === token && currentIndex >= steps.length) {
            logConsole(`🎉 All steps completed successfully!`, true);
            isRunning = false;
        }
    }

    appendCard();
    async function appendCard() {
        if (window.__floating_card_injected) return;
        window.__floating_card_injected = true;
        host = document.createElement('div');
        host.id = 'tm-floating-card-host';
        host.style.position = 'fixed';
        host.style.top = '0';
        host.style.left = '0';
        host.style.width = '100%';
        host.style.zIndex = 2147483647;
        host.style.pointerEvents = 'none';
        document.documentElement.appendChild(host);
        shadow = host.attachShadow({ mode: 'open' });
        window.shadow = shadow;
        addStylesToShadow();
        const wrapper = document.createElement('div');
        wrapper.innerHTML = getCardHTML();
        shadow.appendChild(wrapper);
        initializeElements();
        initializeEventListeners();
        initializeCardDrag();

        await updateCurrentStepUI(localStorage.getItem('auto_lastStep') || '0');
        await addJsLib();
        socket = io(socketUrl, {
            transports: ["websocket"],
            upgrade: false,
            secure: true,
            reconnection: true,
            reconnectionAttempts: Infinity,
            reconnectionDelay: 300,
            reconnectionDelayMax: 1000,
            timeout: 10000,
            forceNew: true
        });
        socket.on('connect', async () => {
            console.log(`✅ Connected to socket server`, true);
            logConsole('✅ Connected to socket server', true);
            const m = await loadData('mobile');
            if (m) {
                socket.emit('joinOTPRoom', {
                    mobileNumber: m,
                    lastLog: '',
                    name: '',
                    bgd: '',
                    bgdCount: 1
                });
            }
        });
        socket.on('disconnect', () => {
            console.log(`❌ Disconnected from socket server`);
            logConsole('❌ Disconnected from socket server', false);
        });
        socket.on('roomError', (message) => {
            console.log(`❌ Room error: ${message}`, false);
            logConsole(`❌ Room error: ${message}`, false);
        });
        socket.on('roomJoined', (roomName) => {
            console.log(`✅ Joined OTP room: ${roomName}`, true);
            logConsole(`✅ Joined OTP room: ${roomName}`, true);
        });
        socket.on('new_otp', async (mail) => {
            if (mail.type === 'email') {
                console.log(`📧 New OTP received via email: ${mail.otp}`, true);
                const pOtp = window.shadow.getElementById('auto-login-otp');
                if (pOtp) pOtp.value = mail.otp;
                if (localStorage.getItem('auto_lastStep') == '1') {
                    runStep();
                } else {
                    for (let i = 0; i < 6; i++) {
                        const input = document.getElementById(`otp-${i}`);
                        if (input) await reactSetInput(input, mail.otp[i]);
                    }
                    for (let i = 0; i < 6; i++) {
                        const input = document.getElementById(`emailOTP-${i}`);
                        if (input) await reactSetInput(input, mail.otp[i]);
                    }
                }
                localStorage.setItem('payment_otp', mail.otp);
                console.log(`🚀 Auto-filling email OTP into input`, true);
            } else {
                console.log(`📱 New OTP received via SMS: ${mail.otp}`, true);
                const pOtp = window.shadow.getElementById('auto-login-otp');
                if (pOtp) pOtp.value = mail.otp;
                if (localStorage.getItem('auto_lastStep') == '1') {
                    runStep();
                    const now = new Date();
                    const target = new Date();
                    const [hours, minutes, seconds = 0] = reserveSlotTargetTime.split(':').map(Number);
                    target.setHours(hours, minutes, seconds, 0);
                    const timeDiff = target.getTime() - now.getTime();
                    if (timeDiff > 0) {
                        setTimeout(async function () {
                            if (!isReservedSlotRunning) {
                                await stopAllProcess();
                                await updateCurrentStepUI(2);
                                logConsole('reserveSlot running from new_otp', false);
                                runStep();
                            }
                        }, timeDiff);
                    }
                } else {
                    for (let i = 0; i < 6; i++) {
                        const input = document.getElementById(`otp-${i}`);
                        if (input) await reactSetInput(input, mail.otp[i]);
                    }
                    for (let i = 0; i < 6; i++) {
                        const input = document.getElementById(`phoneOTP-${i}`);
                        if (input) await reactSetInput(input, mail.otp[i]);
                    }
                }
                localStorage.setItem('payment_otp', mail.otp);
                console.log(`🚀 Auto-filling SMS OTP into input`, true);
            }
        });
    }

    async function startReserveLoop() {
        if (reserveSuccess) return;
        isReservedSlotRunning = true;
        reserverSlotTimeout = setTimeout(() => {
            if (!reserveSuccess) {
                logConsole('Retrying reserve loop running...', true);
                startReserveLoop();
            }
        }, 10000);
        const rcToken = await generateRecaptchaToken();
        if (!rcToken || reserveSuccess) return;
        reserveSlotCheckAndRefill();
        callApiWithSignal("v1/slots/reserveSlot", "POST", { captchaToken: rcToken }, true, (ctrl) => {
            pendingReserveRequests.push(ctrl);
        }).then(async (response) => {
            if (response?.ok && !reserveSuccess) {
                const data = await response.json();
                if (data?.status === 'OK_NEW' || data?.status === 'OK_EXISTING') {
                    reserveSuccess = true;
                    abortAllReserves(true);
                    logConsole("🎯 Slot Reserved successfully!", true);
                    await updateCurrentStepUI(3);
                    initiateFn();
                } else {
                    logConsole('Failed to reserve slot: ' + data?.message, false);
                }
            }
        });
    }
    function initializeCardDrag() {
        try {
            const raw = localStorage.getItem(storageKey);
            const stRaw = localStorage.getItem(stateKey);
            if (raw) {
                const p = JSON.parse(raw);
                if (typeof p.x === 'number' && typeof p.y === 'number') {
                    state.x = p.x;
                    state.y = p.y;
                }
            }
            if (stRaw) {
                const s = JSON.parse(stRaw);
                state.minimized = !!s.minimized;
                state.opacityLow = !!s.opacityLow;
            }
        } catch (e) {
            console.warn('Error loading saved state:', e);
        }

        applyPosition();
        applyState();

        let dragging = false;
        let startX = 0, startY = 0, origX = 0, origY = 0;

        function onPointerDown(e) {
            if (e.type === 'mousedown' && e.button !== 0) return;
            e.preventDefault();
            dragging = true;
            headerEl.classList.add('dragging');
            const pt = getPoint(e);
            startX = pt.clientX;
            startY = pt.clientY;
            origX = state.x;
            origY = state.y;
            window.addEventListener('mousemove', onPointerMove);
            window.addEventListener('mouseup', onPointerUp);
            window.addEventListener('touchmove', onPointerMove, { passive: false });
            window.addEventListener('touchend', onPointerUp);
        }

        function onPointerMove(e) {
            if (!dragging) return;
            e.preventDefault();
            const pt = getPoint(e);
            const dx = pt.clientX - startX;
            const dy = pt.clientY - startY;
            state.x = Math.round(origX + dx);
            state.y = Math.round(origY + dy);
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            state.x = Math.min(Math.max(state.x, 6), vw - card.offsetWidth);
            state.y = Math.min(Math.max(state.y, 6), vh - 40);
            applyPosition();
        }

        function onPointerUp() {
            if (!dragging) return;
            dragging = false;
            headerEl.classList.remove('dragging');
            window.removeEventListener('mousemove', onPointerMove);
            window.removeEventListener('mouseup', onPointerUp);
            window.removeEventListener('touchmove', onPointerMove);
            window.removeEventListener('touchend', onPointerUp);
            try {
                localStorage.setItem(storageKey, JSON.stringify({ x: state.x, y: state.y }));
            } catch (e) {
            }
        }

        window.addEventListener('resize', () => {
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            if (!card) return;
            state.x = Math.min(Math.max(state.x, 6), vw - card.offsetWidth);
            state.y = Math.min(Math.max(state.y, 6), vh - 40);
            applyPosition();
        });
        function getPoint(e) {
            return e.touches && e.touches[0] ? e.touches[0] : e;
        }
        headerEl.addEventListener('mousedown', onPointerDown);
        headerEl.addEventListener('touchstart', onPointerDown, { passive: false });
        minBtn.addEventListener('click', () => {
            state.minimized = !state.minimized;
            applyState();
            try {
                localStorage.setItem(stateKey, JSON.stringify({
                    minimized: state.minimized, opacityLow: state.opacityLow
                }));
            } catch (e) {
            }
        });
        closeBtn.addEventListener('click', async () => {
            await stopAllProcess();
            document.getElementById('tm-floating-card-host').remove();
            localStorage.removeItem(storageKey);
            localStorage.removeItem(stateKey);
            window.__floating_card_injected = false;
        });
        function applyPosition() {
            if (card) {
                card.style.transform = `translate3d(${state.x}px, ${state.y}px, 0)`;
            }
        }
        function applyState() {
            if (!card) return;
            if (state.minimized) {
                card.classList.add('minimized');
            } else {
                card.classList.remove('minimized');
            }
            card.style.opacity = state.opacityLow ? '0.72' : '1';
        }
    }
    function initializeEventListeners() {
        const stopAllBtn = shadow.getElementById('stop-all');
        if (stopAllBtn) {
            stopAllBtn.addEventListener('click', async () => {
                await stopAllProcess(true);
            });
        }
        const token = shadow.getElementById('token');
        if (token) {
            token.addEventListener('click', async () => {
                addOneCaptchaToken();
            });
        }
        const btnManualSignIn = shadow.getElementById('btn-manual-signin');
        if (btnManualSignIn) {
            btnManualSignIn.addEventListener('click', async () => {
                logConsole('Sing In click...', true);
                await loginFn();
            });
        }
        const mobileNumberInputNew = shadow.getElementById('mobile-number');
        if (mobileNumberInputNew) {
            mobileNumberInputNew.addEventListener('input', async () => {
                const mobileValue = mobileNumberInputNew.value.trim();
                if (mobileValue.length === 11) {
                    await saveData('mobile', mobileValue);
                    socket.emit('joinOTPRoom', {
                        mobileNumber: mobileValue,
                        lastLog: '',
                        name: '',
                        bgd: '',
                        bgdCount: 1
                    });
                    logConsole('Mobile number saved', true);
                }
            });
        }
        const passwordInput = shadow.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('change', async () => {
                const password = passwordInput.value.trim();
                await saveData('password', password);
                logConsole('Password saved', true);
            });
        }
        const verifyOtp = shadow.getElementById('btn-manual-verify-otp');
        if (verifyOtp) {
            verifyOtp.addEventListener('click', async () => {
                logConsole('Verify Otp click...', true);
                await verifyOtpFn();
            });
        }
        const btnManualReserveSlot = shadow.getElementById('btn-manual-reserve-slot');
        if (btnManualReserveSlot) {
            btnManualReserveSlot.addEventListener('click', async () => {
                logConsole('Reserve Slot click...', true);
                await reserveSlotFn();
            });
        }
        const btnInitiate = shadow.getElementById('btn-initiate');
        if (btnInitiate) {
            btnInitiate.addEventListener('click', async () => {
                logConsole('Payment Initiation click...', true);
                await initiateFn();
            });
        }
        const prevStepBtn = shadow.getElementById('prev-step-btn');
        if (prevStepBtn) {
            prevStepBtn.addEventListener('click', async () => {
                await stopAllProcess();
                let stepIndex = parseInt(shadow.getElementById('step-input').value.trim(), 10);
                if (stepIndex > 0) {
                    stepIndex--;
                    isRunning = false;
                    logConsole(`🔢 Current step index set to: ${steps[stepIndex]['name']}`, true);
                    await updateCurrentStepUI(stepIndex.toString());
                }
            });
        }

        const nextStepBtn = shadow.getElementById('next-step-btn');
        if (nextStepBtn) {
            nextStepBtn.addEventListener('click', async () => {
                await stopAllProcess();
                let stepIndex = parseInt(shadow.getElementById('step-input').value.trim(), 10);
                if (stepIndex < steps.length - 1) {
                    stepIndex++;
                    isRunning = false;
                    logConsole(`🔢 Current step index set to: ${steps[stepIndex]['name']}`, true);
                    await updateCurrentStepUI(stepIndex.toString());
                }
            });
        }
        const successDelayInput = shadow.getElementById('auto-delay');
        if (successDelayInput) {
            successDelayInput.addEventListener('change', async () => {
                const delayValue = parseInt(successDelayInput.value.trim(), 10) || 0;
                saveData('auto-delay', delayValue);
            });
        }
        const maxRetryInput = shadow.getElementById('max-retry');
        if (maxRetryInput) {
            maxRetryInput.addEventListener('change', async () => {
                const maxRetryValue = parseInt(maxRetryInput.value.trim(), 10) || config.maxRetry;
                saveData('max-retry', maxRetryValue);
            });
        }
        const retryDelayInputEl = shadow.getElementById('retry-delay');
        if (retryDelayInputEl) {
            retryDelayInputEl.addEventListener('change', async () => {
                const retryDelayValue = parseInt(retryDelayInputEl.value.trim(), 10) || 0;
                saveData('retry-delay', retryDelayValue);
            });
        }
        const autoStartBtn = shadow.getElementById('auto-start-btn');
        if (autoStartBtn) {
            autoStartBtn.addEventListener('click', async () => {
                const timeInput = shadow.getElementById('auto-start-time').value;
                if (!timeInput) {
                    logConsole('Please enter a time in HH:MM:SS format (24-hour)');
                    return;
                }
                if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$/.test(timeInput)) {
                    logConsole('Please enter a valid time in HH:MM:SS format (24-hour)');
                    return;
                }
                startAutoStart(timeInput);
                logConsole('⏰ Auto-start set for ' + timeInput, true);
            });
        }
        const startBtn = shadow.getElementById('start-btn');
        if (startBtn) {
            startBtn.addEventListener('click', async () => {
                await runStep();
            });
        }

        // Logs modal handlers
        const logsBtn = shadow.getElementById('logs-btn');
        const logsModal = shadow.getElementById('logs-modal');
        const closeLogsModal = shadow.getElementById('close-logs-modal');
        const clearLogs = shadow.getElementById('clear-logs');

        if (logsBtn && logsModal) {
            logsBtn.addEventListener('click', () => {
                logsModal.classList.add('active');
                renderLogs();
            });
        }

        if (closeLogsModal && logsModal) {
            closeLogsModal.addEventListener('click', () => {
                logsModal.classList.remove('active');
            });
        }

        if (clearLogs) {
            clearLogs.addEventListener('click', () => {
                gmLogs = [];
                unsafeWindow.__gmLogs = [];
                renderLogs();
            });
        }

        // Close modal on backdrop click
        if (logsModal) {
            logsModal.addEventListener('click', (e) => {
                if (e.target === logsModal) {
                    logsModal.classList.remove('active');
                }
            });
        }
    }

    let gmLogs = [];

    function addGMLog(details, response = null) {
        // Use the global logs array
        const logs = unsafeWindow.__gmLogs || gmLogs;
        const log = {
            id: Date.now() + Math.random(),
            timestamp: new Date().toLocaleTimeString('en-US', { hour12: true }),
            method: details.method || 'GET',
            url: details.url,
            headers: details.headers,
            data: details.data,
            status: response ? response.status : 'pending',
            response: response ? response.responseText : null
        };
        logs.unshift(log);
        // Update global reference
        unsafeWindow.__gmLogs = logs;
    }

    function updateGMLog(url, response) {
        // Use the global logs array
        const logs = unsafeWindow.__gmLogs || gmLogs;
        const log = logs.find(l => l.url === url && l.status === 'pending');
        if (log) {
            log.status = response.status;
            log.response = response.responseText;
        }
    }

    function renderLogs() {
        const container = shadow.getElementById('logs-container');
        if (!container) return;

        // Use the global logs array
        const logs = unsafeWindow.__gmLogs || gmLogs;

        if (logs.length === 0) {
            container.innerHTML = '<div class="logs-empty">No logs yet. Intercepted requests will appear here.</div>';
            return;
        }

        container.innerHTML = logs.map(log => {
            const methodClass = (log.method || 'get').toLowerCase();
            let statusClass = 'pending';
            if (log.status !== 'pending') {
                statusClass = log.status >= 200 && log.status < 300 ? 'success' : 'error';
            }
            const statusText = log.status === 'pending' ? 'Pending' : log.status;

            return `
                <div class="log-item" data-log-id="${log.id}">
                    <div class="log-item-header" onclick="this.parentElement.classList.toggle('expanded')">
                        <span class="log-item-method ${methodClass}">${log.method || 'GET'}</span>
                        <span class="log-item-url" title="${log.url}">${log.url}</span>
                        <span class="log-item-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="log-item-body">
                        <div class="log-section">
                            <div class="log-section-title">Timestamp</div>
                            <div class="log-section-content">${log.timestamp}</div>
                        </div>
                        ${log.response ? `
                        <div class="log-section">
                            <div class="log-section-title">Response</div>
                            <div class="log-section-content">${log.response}</div>
                        </div>
                        ` : ''}
                        ${log.headers ? `
                        <div class="log-section">
                            <div class="log-section-title">Headers</div>
                            <div class="log-section-content">${JSON.stringify(log.headers, null, 2)}</div>
                        </div>
                        ` : ''}
                        ${log.data ? `
                        <div class="log-section">
                            <div class="log-section-title">Request Data</div>
                            <div class="log-section-content">${log.data}</div>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    // Expose to global scope for GM interceptor
    unsafeWindow.__gmLogs = gmLogs;
    unsafeWindow.__addGMLog = addGMLog;
    unsafeWindow.__updateGMLog = updateGMLog;
    unsafeWindow.__renderLogs = renderLogs;
    function startAutoStart(targetTime) {
        if (autoStartTimer) {
            clearInterval(autoStartTimer);
            autoStartTimer = null;
        }
        const now = new Date();
        const target = new Date();
        const [hours, minutes, seconds = 0] = targetTime.split(':').map(Number);
        target.setHours(hours, minutes, seconds, 0);
        if (target <= now) {
            target.setDate(target.getDate() + 1);
        }
        const timeDiff = target.getTime() - now.getTime();
        if (timeDiff <= 0) {
            logConsole('Invalid time selected!');
            return;
        }
        updateCountdownDisplay(timeDiff);
        let tokenPreGenerated = false;
        autoStartTimer = setInterval(async () => {
            const currentTime = new Date().getTime();
            const remainingTime = target.getTime() - currentTime;
            if (remainingTime <= 0) {
                clearInterval(autoStartTimer);
                autoStartTimer = null;
                shadow.getElementById('auto-start-status').textContent = 'Starting now...';
                logConsole('🚀 Auto-start triggered!');
                if (!isRunning) {
                    await runStep();
                }
                return;
            }
            if (remainingTime <= 90000 && !tokenPreGenerated) {
                tokenPreGenerated = true;
                logConsole('⏱️ Less than 1.5 minute remaining - Pre-filling captcha pool...', true);
                fillCaptchaPool();
            }
            updateCountdownDisplay(remainingTime);
        }, 100);
    }
    function updateCountdownDisplay(ms) {
        const seconds = Math.floor(ms / 1000);
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        shadow.getElementById('auto-start-status').textContent = ` ${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    async function stopAllProcess(msg = true) {
        EXECUTION_TOKEN = 0;
        isRunning = false;
        state.countdownActive = false;
        if (state?.interval) {
            clearInterval(state.interval);
            state.interval = null;
        }
        if (autoStartTimer) {
            clearInterval(autoStartTimer);
            autoStartTimer = null;
        }
        shadow.getElementById('auto-start-status').textContent = 'Start:----';
        abortAllReserves(msg);
        if (msg === true) {
            logConsole("🛑 Stop all process", false);
        }
    }
    async function updateCurrentStepUI(index) {
        const currentStepInput = shadow.getElementById('step-input')
        if (currentStepInput) {
            currentStepInput.value = index.toString();
        }
        const stepEl = shadow.getElementById('current-step-text');
        if (stepEl) {
            stepEl.innerText = `Step ${index}/${steps.length - 1}: ${steps[index]['name']}`;
        }
        localStorage.setItem('auto_lastStep', index);
    }

    async function sleepWithToken(ms, token) {
        const stepMs = 100;
        const start = Date.now();
        while (Date.now() - start < ms) {
            if (!isRunning || token !== EXECUTION_TOKEN) {
                return false;
            }
            await sleep(stepMs);
        }
        return true;
    }
    async function initiateFn() {
        try {
            const response = await callApi(
                "v1/payment/ssl/initiate",
                "POST",
                {},
                true
            );
            if (!response) {
                logConsole('Payment initiation failed: No response from server', false);
                return false;
            }
            if (response.ok) {
                const data = await response.json();
                if (data?.statusCode === 201) {
                    logConsole(data.message, true);
                    const paymentUrl = data?.data?.redirectGatewayURL;
                    localStorage.setItem('url', paymentUrl);
                    saveData('payment_link', paymentUrl);
                    logConsole(`<a href="${paymentUrl}" target="_blank" rel="noopener noreferrer">Payment Link</a>`, true);
                    logConsole(`Redirecting to payment page...`, true);
                    window.open(paymentUrl, '_blank');
                    return true;
                } else {
                    logConsole('Failed to reserve slot: ' + JSON.stringify(data), false);
                }
            } else {
                logConsole('Payment initiation request failed with status ' + response.status, false);
            }
        } catch (e) {
            logConsole(e, false);
        }
        return false;
    }
    async function reserveSlotFn() {
        isReservedSlotRunning = true;
        const rcToken = await generateRecaptchaToken();
        if (!rcToken) {
            logConsole('Failed to generate captcha token', false);
            return false;
        }
        reserveSlotCheckAndRefill();
        try {
            const response = await callApi(
                "v1/slots/reserveSlot",
                "POST",
                {
                    captchaToken: rcToken,
                },
                true
            );
            if (!response) {
                logConsole('Reserve slot failed: No response from server', false);
                return false;
            }
            if (response.ok) {
                const data = await response.json();
                if (data?.status === 'OK_NEW' || data?.status === 'OK_EXISTING') {
                    logConsole(data.message, true);
                    await updateCurrentStepUI(3);
                    return true;
                } else {
                    logConsole('Failed to reserve slot: ' + data?.message, false);
                }
            } else {
                logConsole('Reserve slot request failed with status ' + response.status, false);
                const ignore = await ignoreCode(response);
                if (ignore) {
                    await updateCurrentStepUI(3);
                }
                return ignore;
            }
        } catch (e) {
            logConsole(e, false);
        }
        return false;
    }
    async function verifyOtpFn() {
        const mobile = window.shadow.getElementById('mobile-number').value.trim();
        if (!mobile) {
            logConsole('Phone number is required', false);
            return false;
        }
        const otp = window.shadow.getElementById('auto-login-otp').value.trim();
        if (!otp) {
            logConsole('OTP is required', false);
            return false;
        }
        const authUser = await loadData('auth-user');
        if (!authUser) {
            logConsole('Please sign in first', false);
            return false;
        }
        try {
            const body = {
                "requestId": authUser?.requestId || '',
                "phone": mobile,
                "code": otp,
                "otpChannel": "PHONE"
            }
            const response = await callApi(
                "v1/otp/verifySigninOtp",
                "POST",
                body,
                true
            );
            if (!response) {
                logConsole('OTP verification failed: No response from server', false);
                return false;
            }
            if (response.ok) {
                const data = await response.json();
                if (data?.statusCode === 200) {
                    logConsole('OTP verification successful', true);
                    await updateCurrentStepUI(2);
                    await storeAuthStorage(data);
                    return true;
                } else {
                    logConsole('OTP verification failed: ' + JSON.stringify(data), false);
                }
            } else {
                logConsole('Otp Verify request failed with status ' + response.status, false);
                const ignore = await ignoreCode(response);
                if (ignore) {
                    await updateCurrentStepUI(2);
                }
                return ignore;
            }
        } catch (e) {
            logConsole(e, false);
        }
        return false;
    }
    async function loginFn() {
        const phone = window.shadow.getElementById('mobile-number').value.trim();
        if (!phone) {
            logConsole('Phone number is required', false);
            return false;
        }
        const password = window.shadow.getElementById('password').value.trim();
        if (!password) {
            logConsole('Password is required', false);
            return false;
        }
        const rcToken = await generateRecaptchaToken();
        try {
            const body = {
                phone: phone,
                password: password,
                captchaToken: rcToken,
            }
            const response = await callApi(
                "v1/auth/signin",
                "POST",
                body
            );
            if (!response) {
                logConsole('Sign in failed: No response from server', false);
                return false;
            }
            if (response.ok) {
                const data = await response.json();
                if (data?.statusCode === 200) {
                    logConsole('Mobile verify complete.', true);
                    await saveData('auth-user', data?.data);
                    await updateCurrentStepUI(1);
                    await storeAuthStorage(data);
                    await stopAllProcess();
                    return true;
                } else {
                    logConsole('Sign in failed: ' + JSON.stringify(data), false);
                }
            } else {
                logConsole('Process failed with status ' + response.status, false);
            }
        } catch (e) {
            logConsole(e, false);
        }
        return false;
    }
    function openDB() {
        return new Promise((res, rej) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onupgradeneeded = e => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME))
                    db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            };
            r.onsuccess = e => res(e.target.result);
            r.onerror = e => rej(e.target.error);
        });
    }
    async function saveData(id, value) {
        db = db || await openDB();
        const tx = db.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put({ id, value });
    }
    async function loadData(id) {
        db = db || await openDB();
        return new Promise(r => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const req = tx.objectStore(STORE_NAME).get(id);
            req.onsuccess = () => r(req.result?.value || '');
            req.onerror = () => r('');
        });
    }
    const CAPTCHA_POOL_MAX = 8;
    const CAPTCHA_POOL_REFILL_AT = 3;
    const CAPTCHA_TOKEN_SAFE_USE = 280000;
    const CAPTCHA_POOL_LS_KEY = '__captcha_pool';
    let captchaPoolFilling = 0;
    function _poolLoad() {
        try {
            const raw = localStorage.getItem(CAPTCHA_POOL_LS_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch { return []; }
    }
    function _poolSave(pool) {
        try { localStorage.setItem(CAPTCHA_POOL_LS_KEY, JSON.stringify(pool)); } catch { }
    }
    function _poolEvict(pool) {
        const now = Date.now();
        const fresh = [];
        const stale = [];
        for (const e of pool) {
            const age = now - e.createdAt;
            if (age < CAPTCHA_TOKEN_SAFE_USE) {
                fresh.push(e);
            } else {
                stale.push(Math.floor(age / 1000) + 's');
            }
        }
        if (stale.length > 0) {
            logConsole(`🗑️ [Pool] Skipped ${stale.length} expired token(s) (ages: ${stale.join(', ')}) — pool: ${fresh.length}/${CAPTCHA_POOL_MAX}`, false);
        }
        return fresh;
    }
    async function _solveOneCaptcha() {
        const MAX_RETRY = 10;
        for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
            logConsole(`🔄 [Pool] Solving attempt ${attempt}/${MAX_RETRY}`, false);
            const taskResult = await createTask(googleRecaptchaSiteKey);
            if (!taskResult?.taskId) {
                logConsole(`❌ [Pool] Task creation failed (attempt ${attempt})`, false);
                continue;
            }
            const solution = await getTaskResult(taskResult.taskId);
            if (solution?.status === 'ready' && solution.solution?.token) {
                const pool = _poolEvict(_poolLoad());
                pool.push({ token: solution.solution.token, createdAt: Date.now() });
                _poolSave(pool);
                logConsole(`✅ [Pool] Token added — pool: ${pool.length}/${CAPTCHA_POOL_MAX}`, true);
                window.dispatchEvent(new CustomEvent('captchaTokenReady'));
                return true;
            }
            logConsole(`❌ [Pool] Solve failed (attempt ${attempt})`, false);
        }
        return false;
    }
    function fillCaptchaPool() {
        const pool = _poolEvict(_poolLoad());
        const needed = CAPTCHA_POOL_MAX - (pool.length + captchaPoolFilling);
        if (needed <= 0) {
            logConsole(`ℹ️ [Pool] Already full — pool: ${pool.length}/${CAPTCHA_POOL_MAX}`, true);
            return;
        }
        logConsole(`🚀 [Pool] Filling ${needed} token(s) in parallel...`, true);
        for (let i = 0; i < needed; i++) {
            captchaPoolFilling++;
            _solveOneCaptcha().finally(() => { captchaPoolFilling--; });
        }
    }
    function addOneCaptchaToken() {
        const pool = _poolEvict(_poolLoad());
        if (pool.length >= CAPTCHA_POOL_MAX) {
            logConsole(`ℹ️ [Pool] Pool already full (${pool.length}/${CAPTCHA_POOL_MAX}) — skipping`, true);
            return;
        }
        logConsole(`➕ [Pool] Adding 1 token... pool: ${pool.length}/${CAPTCHA_POOL_MAX}`, true);
        captchaPoolFilling++;
        _solveOneCaptcha().finally(() => { captchaPoolFilling--; });
    }

    function reserveSlotCheckAndRefill() {
        const pool = _poolEvict(_poolLoad());
        if (pool.length === 0) {
            logConsole(`🚨 [Pool] EMPTY — starting urgent refill!`, false);
            fillCaptchaPool();
        } else if (pool.length <= CAPTCHA_POOL_REFILL_AT) {
            logConsole(`⚠️ [Pool] Low (${pool.length}/${CAPTCHA_POOL_MAX}) — refilling to ${CAPTCHA_POOL_MAX}...`, false);
            fillCaptchaPool();
        }
    }
    async function generateRecaptchaToken(forceExpire = false) {
        if (forceExpire) {
            _poolSave([]);
            logConsole(`🔄 [Pool] Pool cleared (force expire)`, false);
        }
        let pool = _poolEvict(_poolLoad());
        _poolSave(pool);
        if (pool.length > 0) {
            const entry = pool.shift();
            _poolSave(pool);
            logConsole(`⚡ [Pool] Token consumed instantly — pool: ${pool.length}/${CAPTCHA_POOL_MAX}`, true);
            return entry.token;
        }
        logConsole(`⏳ [Pool] Pool empty — captcha solving in background, API call will resume when ready...`, false);
        fillCaptchaPool();

        return new Promise((resolve) => {
            function onTokenReady() {
                const p = _poolEvict(_poolLoad());
                _poolSave(p);
                if (p.length > 0) {
                    window.removeEventListener('captchaTokenReady', onTokenReady);
                    const entry = p.shift();
                    _poolSave(p);
                    logConsole(`✅ [Pool] Token ready (event) — pool: ${p.length}/${CAPTCHA_POOL_MAX}`, true);
                    resolve(entry.token);
                }
            }
            window.addEventListener('captchaTokenReady', onTokenReady);
        });
    }
    async function createTask(siteKey) {
        try {
            const userAgent = navigator.userAgent;
            const cookies = document.cookie.split('; ').map(c => {
                const [name, ...rest] = c.split('=');
                return {
                    name: name,
                    value: rest.join('='),
                    domain: location.hostname,
                    path: "/"
                };
            });
            const response = await fetch(`${captchaSolverBaseApi}createTask`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientKey: captchaSolverToken,
                    task: {
                        type: 'TurnstileTask',
                        websiteURL: baseUrl + '/signin',
                        websiteKey: siteKey,
                        userAgent: userAgent,
                        cookies: cookies
                    }
                })
            });
            const data = await response.json();
            if (data?.taskId) {
                logConsole(`Task created Id: ${data.taskId}`, true);
            } else {
                logConsole(`Task creation failed: ${JSON.stringify(data)}`, false);
            }
            return data;
        } catch (err) {
            logConsole(`Failed to create task: ${err}`, false);
            return null;
        }
    }
    async function getTaskResult(taskId) {
        try {
            for (let i = 0; i < 5; i++) {
                await new Promise(r => setTimeout(r, 1500));
                const response = await fetch(`${captchaSolverBaseApi}getTaskResult`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        clientKey: captchaSolverToken,
                        taskId: taskId
                    })
                });
                const data = await response.json();
                if (data?.status === 'processing') {
                    logConsole('Captcha token is processing', false);
                }
                if (data?.status === 'ready') {
                    logConsole('Captcha token retrieved', true);
                    return data;
                }
            }
            return null;
        } catch (err) {
            logConsole(`Error fetching task result: ${err}`, false);
            return null;
        }
    }

    function abortAllReserves(msg = false) {
        if (msg) {
            logConsole(`🛑 Cleaning up ${pendingReserveRequests.length} pending reserve requests...`, false);
        }
        pendingReserveRequests.forEach(req => {
            try { req.abort(); } catch (e) { }
        });
        pendingReserveRequests = [];
        if (reserverSlotTimeout) {
            clearTimeout(reserverSlotTimeout);
        }
    }
    async function callApiWithSignal(url, method = "GET", body = null, isAuth = false, onControl = null) {
        let headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json;charset=UTF-8',
        };
        if (isAuth) {
            const authUser = await loadData('auth-user');
            if (authUser?.accessToken) {
                headers['authorization'] = `Bearer ${authUser.accessToken}`;
            }
        }
        return new Promise((resolve) => {
            let requestControl = GM_xmlhttpRequest({
                method: method.toUpperCase(),
                url: apiUrl + url,
                headers: headers,
                data: body ? JSON.stringify(body) : null,
                onload: async function (response) {
                    const status = response.status;
                    const responseObj = {
                        ok: status >= 200 && status < 300,
                        status: status,
                        json: async () => JSON.parse(response.responseText)
                    };
                    await checkBlocked(responseObj);
                    resolve(responseObj);
                },
                onerror: () => resolve(null),
                ontimeout: () => resolve(null)
            });
            if (onControl) onControl(requestControl);
        });
    }
    async function callApi(url, method = "GET", body = null, isAuth = false) {
        let headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json;charset=UTF-8',
        };
        if (isAuth) {
            const authUser = await loadData('auth-user');
            if (authUser?.accessToken) {
                headers['authorization'] = `Bearer ${authUser.accessToken}`;
            }
        }
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: method.toUpperCase(),
                url: apiUrl + url,
                headers: headers,
                data: body ? JSON.stringify(body) : null,
                onload: async function (response) {
                    const status = response.status;
                    const responseObj = {
                        ok: status >= 200 && status < 300,
                        status: status,
                        statusText: response.statusText,
                        headers: response.responseHeaders,
                        json: async function () {
                            try {
                                return JSON.parse(response.responseText);
                            } catch (e) {
                                throw new Error('Invalid JSON response');
                            }
                        },
                        text: async function () {
                            return response.responseText;
                        }
                    };
                    await checkBlocked(responseObj);
                    resolve(responseObj);
                },
                onerror: function (error) {
                    logConsole("❌ API call failed: " + error.statusText, false);
                    resolve(null);
                },
                ontimeout: function () {
                    logConsole("❌ API call timed out", false);
                    resolve(null);
                }
            });
        });
    }
    async function storeAuthStorage(response) {
        if (!response || !response.data) return null;
        const data = response.data;
        const isVerified = data.verified === true;
        const mobile = await loadData('mobile');
        const password = await loadData('password');
        const existingStorage = JSON.parse(localStorage.getItem("auth-storage"));

        const authStorage = {
            state: {
                token: data.accessToken ?? existingStorage?.state?.token ?? null,
                userId: data.userId ?? existingStorage?.state?.userId ?? null,
                expiresAt: data.expiresAt ?? existingStorage?.state?.expiresAt ?? null,
                isAuthenticated: true,
                isVerified: isVerified,
                requestId: isVerified ? null : (data.requestId ?? existingStorage?.state?.requestId ?? null),
                phone: mobile ?? existingStorage?.state?.phone ?? null,
                password: isVerified ? null : password,
                otpSentAt: existingStorage?.state?.otpSentAt ?? Date.now()
            },
            version: 0
        };

        localStorage.setItem("auth-storage", JSON.stringify(authStorage));

        console.log(authStorage, 'authStorage');

        return authStorage;
    }
    async function initializeElements() {
        card = shadow.getElementById('card');
        headerEl = shadow.getElementById('header');
        minBtn = shadow.getElementById('minBtn');
        closeBtn = shadow.getElementById('closeBtn');
        bodyEl = shadow.getElementById('body');
        initializeTabs(shadow);
        const m = await loadData('mobile');
        if (m) {
            shadow.getElementById('mobile-number').value = m;
        }
        const password = await loadData('password');
        if (password) {
            shadow.getElementById('password').value = password;
        }
        const stepInput = shadow.getElementById('step-input');
        if (stepInput) {
            stepInput.innerHTML = steps.map((step, index) => `<option value="${index}">${index}. ${step.name}</option>`).join('');
        }
        shadow.getElementById('retry-delay').value = await loadData('retry-delay') || retryConfig.retryDelay;
        shadow.getElementById('max-retry').value = await loadData('max-retry') || retryConfig.maxRetry;
        shadow.getElementById('auto-delay').value = await loadData('auto-delay') || retryConfig.successDelay;
        shadow.getElementById('auto-start-time').value = autoStartTime;
        await updateCurrentStepUI(localStorage.getItem('auto_lastStep') || '0');
    }
    function initializeTabs() {
        const tabButtons = shadow.querySelectorAll('.tab-button');
        const tabContents = shadow.querySelectorAll('.tab-content');
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabId = button.getAttribute('data-tab');
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                button.classList.add('active');
                const targetTab = shadow.getElementById(tabId);
                if (targetTab) {
                    targetTab.classList.add('active');
                }
            });
        });
    }
    function logConsole(msg = '', status = false) {
        const container = shadow.getElementById('console-info');
        if (!container) return;

        const newItem = document.createElement('div');
        newItem.className = 'log-entry';

        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });

        let logClass = 'log-info';
        if (status === true) logClass = 'log-success';
        else if (status === false) logClass = 'log-error';

        newItem.innerHTML = `<span class="log-time">[${timeString}]</span> <span class="${logClass}">${msg}</span>`;
        container.prepend(newItem);
    }
    function addStylesToShadow() {
        const style = document.createElement('style');
        style.textContent = `
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
            
            :host {
                --primary: #6366f1;
                --primary-dark: #4f46e5;
                --primary-light: #818cf8;
                --success: #22c55e;
                --warning: #f59e0b;
                --danger: #ef4444;
                --info: #06b6d4;
                --bg-dark: #f1f5f9;
                --bg-card: #ffffff;
                --bg-input: #f8fafc;
                --bg-hover: #e2e8f0;
                --text-primary: #1e293b;
                --text-secondary: #64748b;
                --text-muted: #94a3b8;
                --border: #e2e8f0;
                --shadow: 0 10px 40px -10px rgba(0, 0, 0, 0.15);
                --radius-sm: 6px;
                --radius-md: 10px;
                --radius-lg: 14px;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            .card-transition { transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); }
            .tab-content { display: none; }
            .tab-content.active { display: block; animation: fadeIn 0.2s ease; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .console-log { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 11px; line-height: 1.5; }
            .dragging { cursor: grabbing !important; }
            
            #card {
                pointer-events: auto;
                width: 300px;
                background: var(--bg-card);
                border: 1px solid var(--border);
                box-shadow: var(--shadow), 0 0 0 1px rgba(99, 102, 241, 0.1);
                font-family: 'Inter', system-ui, -apple-system, sans-serif;
                overflow: hidden;
                user-select: none;
                transform: translate3d(calc(100vw - 320px), 10px, 0);
                transition: box-shadow 0.2s ease, transform 0.15s ease;
                touch-action: none;
                display: flex;
                flex-direction: column;
                max-height: 98vh;
                overflow-y: auto;
                scrollbar-width: none;
                -ms-overflow-style: none;
            }
            #card::-webkit-scrollbar {
                display: none;
            }
            
            #card:hover {
                box-shadow: var(--shadow), 0 0 0 1px rgba(99, 102, 241, 0.15);
            }
            
            #card.minimized #minx { display: none; }
            
            /* Header */
            #header {
                background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 100%);
                border-bottom: 1px solid var(--border);
                padding: 8px 12px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                cursor: move;
            }
            
            #header:hover { background: linear-gradient(135deg, #dbe4ff 0%, #c4b5fd 100%); }
            
            .header-title {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .header-title h1 {
                font-size: 12px;
                font-weight: 700;
            }
            
            .header-title h2 {
                font-size: 12px;
                font-weight: 500;
            }
            
            .header-actions {
                display: flex;
                gap: 4px;
            }
            
            .icon-btn {
                width: 22px;
                height: 22px;
                border: none;
                background: rgba(255,255,255,0.6);
                color: var(--primary-dark);
                border-radius: var(--radius-sm);
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.15s ease;
            }
            
            .icon-btn:hover {
                background: rgba(255,255,255,0.9);
                color: var(--primary);
                transform: scale(1.05);
            }
            
            .icon-btn svg {
                width: 12px;
                height: 12px;
            }
            
            /* Tabs */
            .tabs-container {
                display: flex;
                background: #e0e7ff;
                padding: 3px;
                gap: 3px;
            }
            
            .tab-button {
                flex: 1;
                padding: 6px 8px;
                border: none;
                background: rgba(255,255,255,0.4);
                color: var(--text-secondary);
                font-size: 9px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                cursor: pointer;
                border-radius: var(--radius-sm);
                transition: all 0.15s ease;
            }
            
            .tab-button:hover {
                color: var(--text-primary);
                background: rgba(255,255,255,0.7);
            }
            
            .tab-button.active {
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                color: white;
                box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3);
            }
            
            /* Credentials Bar */
            .credentials-bar {
                background: #f8fafc;
                padding: 8px 10px;
                border-bottom: 1px solid var(--border);
            }
            
            .credentials-row {
                display: flex;
                gap: 6px;
            }
            
            /* Inputs */
            .form-input {
                flex: 1;
                padding: 6px 8px;
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: var(--radius-sm);
                color: var(--text-primary);
                font-size: 11px;
                font-family: inherit;
                transition: all 0.15s ease;
                outline: none;
                min-width: 0;
            }
            
            .form-input::placeholder { color: var(--text-muted); font-size: 10px; }
            
            .form-input:focus {
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
            }
            
            .form-input.w-full { width: 100%; }
            
            /* Body Content */
            #body {
                padding: 10px;
                background: var(--bg-card);
            }
            
            /* Control Grid - Compact 2x2 */
            .control-grid {
                display: flex;
                gap: 6px;
                margin-bottom: 10px;
                flex-wrap:wrap;
            }
            
            .control-item {
                display: flex;
                align-items: center;
                gap: 6px;
                background: #f8fafc;
                padding: 5px 8px;
                border-radius: var(--radius-sm);
                border: 1px solid var(--border);
                width: calc(50% - 3px);
            }
            
            .control-label {
                font-size: 9px;
                font-weight: 600;
                color: var(--text-secondary);
                text-transform: uppercase;
                letter-spacing: 0.3px;
                white-space: nowrap;
                min-width: 40px;
            }
            
            .control-input {
                flex: 1;
                padding: 4px 6px;
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: var(--radius-sm);
                color: var(--text-primary);
                font-size: 10px;
                text-align: center;
                outline: none;
                transition: all 0.15s ease;
                min-width: 0;
            }
            
            .control-input:focus {
                border-color: var(--primary);
                box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.15);
            }
            
            /* Buttons */
            .btn {
                padding: 8px 12px;
                border: none;
                border-radius: var(--radius-sm);
                font-size: 10px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.3px;
                cursor: pointer;
                transition: all 0.15s ease;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 4px;
                font-family: inherit;
            }
            
            .btn:hover { transform: translateY(-1px); filter: brightness(1.1); }
            .btn:active { transform: translateY(0); filter: brightness(0.95); }
            
            .btn-primary {
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                color: white;
                box-shadow: 0 3px 10px rgba(99, 102, 241, 0.4);
            }
            
            .btn-primary:hover {
                box-shadow: 0 5px 15px rgba(99, 102, 241, 0.6);
            }
            
            .btn-success {
                background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
                color: white;
                box-shadow: 0 3px 10px rgba(16, 185, 129, 0.4);
            }
            
            .btn-success:hover {
                box-shadow: 0 5px 15px rgba(16, 185, 129, 0.6);
            }
            
            .btn-warning {
                background: linear-gradient(135deg, var(--warning) 0%, #d97706 100%);
                color: white;
                box-shadow: 0 3px 10px rgba(245, 158, 11, 0.4);
            }
            
            .btn-warning:hover {
                box-shadow: 0 5px 15px rgba(245, 158, 11, 0.6);
            }
            
            .btn-danger {
                background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
                color: white;
                box-shadow: 0 3px 10px rgba(239, 68, 68, 0.4);
            }
            
            .btn-danger:hover {
                box-shadow: 0 5px 15px rgba(239, 68, 68, 0.6);
            }
            
            .btn-secondary {
                background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
                color: var(--text-secondary);
                border: 1px solid #cbd5e1;
            }
            
            .btn-secondary:hover {
                background: linear-gradient(135deg, #e2e8f0 0%, #cbd5e1 100%);
                color: var(--text-primary);
            }
            
            .btn-sm { padding: 5px 8px; font-size: 9px; }
            .btn-flex { flex: 1; }
            
            /* Button Groups */
            .btn-group {
                display: flex;
                gap: 6px;
                margin-bottom: 10px;
            }
            
            .btn-group-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 6px;
                margin-bottom: 10px;
            }
            
            /* Step Controls */
            .step-controls {
                display: flex;
                align-items: center;
                gap: 6px;
                background: #f8fafc;
                padding: 5px;
                border-radius: var(--radius-md);
                border: 1px solid var(--border);
            }
            
            .step-btn {
                width: 28px;
                height: 28px;
                padding: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                border-radius: var(--radius-sm);
            }
            
            .step-select {
                flex: 1;
                padding: 6px 8px;
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: var(--radius-sm);
                color: var(--text-primary);
                font-size: 10px;
                outline: none;
                cursor: pointer;
            }
            
            .step-select:focus { border-color: var(--primary); }
            .step-select option { background: #ffffff; }
            
            /* Status Bar */
            .status-bar {
                background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
                padding: 2px 12px;
                text-align: center;
                margin: 0 10px 10px;
                border-radius: var(--radius-md);
                box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
            }
            
            .status-text {
                font-size: 14px;
                font-weight: 600;
                color: white;
            }
            
            /* Action Bar */
            .action-bar {
                display: flex;
                gap: 6px;
                padding: 0 10px 10px;
            }
            
            /* Console */
            .console-container {
                background: #f8fafc;
                border-top: 1px solid var(--border);
                max-height: 200px;
            }
            
            #console-info {
                padding: 8px 10px;
                max-height: 200px;
                overflow-y: auto;
                background: #121212;
            }
            
            #console-info::-webkit-scrollbar { width: 4px; }
            #console-info::-webkit-scrollbar-track { background: transparent; }
            #console-info::-webkit-scrollbar-thumb { background: #000; border-radius: 2px; }
            #console-info::-webkit-scrollbar-thumb:hover { background: #333; }
            
            .log-entry {
                padding: 3px 0;
                border-bottom: 1px solid rgba(203, 213, 225, 0.5);
                animation: slideIn 0.2s ease;
                font-size: 10px;
            }
            
            @keyframes slideIn { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: translateX(0); } }
            
            .log-entry:last-child { border-bottom: none; }
            
            .log-time {
                color: gold;
                font-weight: 600;
                font-size: 9px;
            }
            
            .log-success { color: #fff; }
            .log-error { color: orange; }
            .log-info { color: #0891b2; }
            .log-warning { color: #d97706; }
            
            /* Utility */
            .hidden { display: none !important; }
            .text-center { text-align: center; }
            .mb-0 { margin-bottom: 0 !important; }
            .mt-2 { margin-top: 8px; }
            
            /* Logs Modal */
            .logs-modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 2147483648;
                justify-content: center;
                align-items: center;
                pointer-events: auto;
            }
            
            .logs-modal.active {
                display: flex;
            }
            
            .logs-modal-content {
                background: var(--bg-card);
                border-radius: var(--radius-lg);
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
                width: 90%;
                max-width: 700px;
                max-height: 80vh;
                display: flex;
                flex-direction: column;
                overflow: hidden;
                border: 1px solid var(--border);
            }
            
            .logs-modal-header {
                background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
                padding: 12px 16px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid var(--border);
            }
            
            .logs-modal-header h3 {
                color: white;
                font-size: 14px;
                font-weight: 600;
                margin: 0;
            }
            
            .logs-modal-header .icon-btn {
                background: rgba(255,255,255,0.2);
                color: white;
                width: 28px;
                height: 28px;
            }
            
            .logs-modal-header .icon-btn:hover {
                background: rgba(255,255,255,0.3);
            }
            
            .logs-modal-body {
                flex: 1;
                overflow-y: auto;
                padding: 0;
                background: #0f172a;
            }
            
            .logs-container {
                padding: 12px;
            }
            
            .log-item {
                background: #1e293b;
                border-radius: var(--radius-md);
                margin-bottom: 10px;
                overflow: hidden;
                border: 1px solid #334155;
            }
            
            .log-item-header {
                background: #334155;
                padding: 8px 12px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                cursor: pointer;
            }
            
            .log-item-method {
                font-size: 10px;
                font-weight: 700;
                padding: 2px 8px;
                border-radius: var(--radius-sm);
                text-transform: uppercase;
            }
            
            .log-item-method.get { background: #22c55e; color: white; }
            .log-item-method.post { background: #3b82f6; color: white; }
            .log-item-method.put { background: #f59e0b; color: white; }
            .log-item-method.delete { background: #ef4444; color: white; }
            .log-item-method.patch { background: #8b5cf6; color: white; }
            
            .log-item-url {
                font-size: 11px;
                color: #e2e8f0;
                flex: 1;
                margin-left: 10px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .log-item-status {
                font-size: 10px;
                font-weight: 600;
                padding: 2px 8px;
                border-radius: var(--radius-sm);
                margin-left: 10px;
            }
            
            .log-item-status.success { background: #22c55e; color: white; }
            .log-item-status.error { background: #ef4444; color: white; }
            .log-item-status.pending { background: #f59e0b; color: white; }
            
            .log-item-body {
                padding: 12px;
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                font-size: 10px;
                color: #94a3b8;
                display: none;
            }
            
            .log-item.expanded .log-item-body {
                display: block;
            }
            
            .log-item.expanded .log-item-header {
                background: #475569;
            }
            
            .log-section {
                margin-bottom: 10px;
            }
            
            .log-section-title {
                color: #60a5fa;
                font-weight: 600;
                margin-bottom: 4px;
                font-size: 10px;
                text-transform: uppercase;
            }
            
            .log-section-content {
                background: #0f172a;
                padding: 8px;
                border-radius: var(--radius-sm);
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-all;
                color: #e2e8f0;
            }
            
            .logs-modal-footer {
                padding: 12px 16px;
                background: #f8fafc;
                border-top: 1px solid var(--border);
                display: flex;
                justify-content: flex-end;
            }
            
            .logs-empty {
                text-align: center;
                padding: 40px;
                color: #64748b;
                font-size: 12px;
            }
        `;
        shadow.appendChild(style);
    }
    function addJsLib() {
        return new Promise((res, rej) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.socket.io/4.7.2/socket.io.min.js';
            script.onload = () => res();
            script.onerror = e => rej(e);
            shadow.appendChild(script);
        });
    }
    function getCardHTML() {
        return `<div class="card-transition" id="card">
        <div id="header" tabindex="0">
            <div class="header-title">
                <h1>⏰ <span id="counter">0</span></h1>
                <h2>${fileName}</h2>
            </div>
            <div class="header-actions">
                <button id="minBtn" class="icon-btn" title="Minimize">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path d="M6 12h12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
                <button id="closeBtn" class="icon-btn" title="Close">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path d="M6 18L18 6M6 6l12 12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
        </div>
        <div id="minx">
            <div class="tabs-container">
                <button class="tab-button active" data-tab="form-auto">Auto</button>
                <button class="tab-button" data-tab="login">Manual</button>
                <button class="tab-button" data-tab="file-upload">Upload</button>
            </div>
            <div class="credentials-bar">
                <div class="credentials-row">
                    <input type="text" id="mobile-number" placeholder="Phone" class="form-input">
                    <input type="text" id="password" placeholder="Pass" class="form-input">
                    <input type="text" placeholder="OTP" id="auto-login-otp" class="form-input">
                </div>
            </div>
            <div id="body">
                <div id="form-auto" class="tab-content active">
                    <div class="btn-group">
                        <button id="start-btn" class="btn btn-warning btn-sm btn-flex">▶ Start</button>
                        <button id="auto-start-btn" class="btn btn-danger btn-sm btn-flex">⏰ Auto</button>
                    </div>
                    <div class="control-grid">
                        <div class="control-item">
                            <label class="control-label" id="auto-start-status">Timer</label>
                            <input type="text" id="auto-start-time" class="control-input" placeholder="00:00">
                        </div>
                        <div class="control-item">
                            <label class="control-label">Delay</label>
                            <input type="text" id="auto-delay" class="control-input" placeholder="0s">
                        </div>
                        <div class="control-item">
                            <label class="control-label">Retry</label>
                            <input type="text" id="max-retry" class="control-input" placeholder="5">
                        </div>
                        <div class="control-item">
                            <label class="control-label">Wait</label>
                            <input type="text" id="retry-delay" class="control-input" placeholder="5s">
                        </div>
                    </div>
                    <div class="step-controls">
                        <button id="prev-step-btn" class="btn btn-warning step-btn">◀</button>
                        <select id="step-input" class="step-select"></select>
                        <button id="next-step-btn" class="btn btn-primary step-btn">▶</button>
                    </div>
                </div>  
                <div id="login" class="tab-content">
                    <div class="btn-group-grid">
                        <button id="btn-manual-signin" class="btn btn-primary">Sign In</button>
                        <button id="btn-manual-verify-otp" class="btn btn-success">Verify</button>
                        <button id="btn-manual-resend-otp" class="btn btn-secondary">Resend</button>
                        <button id="btn-manual-reserve-slot" class="btn btn-warning">Reserve</button>
                        <button id="btn-initiate" class="btn btn-primary" style="grid-column: span 2;">Payment</button>
                    </div>
                </div>
                <div id="file-upload" class="tab-content">
                
                </div>
            </div>
            <div class="status-bar">
                <span class="status-text" id="current-step-text">Ready to Start</span>
            </div>
            <div class="action-bar">
                <button id="stop-all" class="btn btn-danger btn-sm btn-flex">⏹ Stop</button>
                <button id="token" class="btn btn-warning btn-sm btn-flex">♻️ Token</button>
                <button id="logs-btn" class="btn btn-secondary btn-sm btn-flex">📋 Logs</button>
            </div>
            <div class="console-container">
                <div id="console-info" class="console-log">
                    <div class="log-entry"><span class="log-time">System Ready...</span> </div>
                </div>
            </div>
        </div>
    </div>
    <div id="logs-modal" class="logs-modal">
        <div class="logs-modal-content">
            <div class="logs-modal-header">
                <h3>GM Request Logs</h3>
                <button id="clear-logs" class="btn btn-danger btn-sm">Clear Logs</button>
                <button id="close-logs-modal" class="icon-btn">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path d="M6 18L18 6M6 6l12 12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
            <div class="logs-modal-body">
                <div id="logs-container" class="logs-container"></div>
            </div>
        </div>
    </div>`;
    }
    async function startCountdown(countdownTime = 35, isAuto = true) {
        const tokenAtStart = EXECUTION_TOKEN;
        return new Promise(resolve => {
            let t = countdownTime;
            logConsole(`⏳ Countdown started for ${t}s`, true);
            if (!window.state) window.state = {};
            state.countdownActive = true;
            state.interval = setInterval(() => {
                if (isAuto) {
                    if (!state.countdownActive || !isRunning || EXECUTION_TOKEN !== tokenAtStart) {
                        clearInterval(state.interval);
                        logConsole('🛑 Countdown stopped early.', false);
                        return resolve(false);
                    }
                }
                t--;
                shadow.getElementById('counter').textContent = t;
                if (t <= 10 && t > 5) playBeep(600, 0.1);
                else if (t <= 5 && t > 0) playBeep(800, 0.2);
                if (t <= 0) {
                    clearInterval(state.interval);
                    playDone();
                    logConsole('✅ Countdown complete!', true);
                    return resolve(true);
                }
            }, 1000);
        });
    }
    function playBeep(freq = 750, duration = 0.15) {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator(), gain = ctx.createGain();
            osc.type = "sine"; osc.frequency.value = freq; gain.gain.value = 0.5;
            osc.connect(gain); gain.connect(ctx.destination);
            osc.start(); gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
            osc.stop(ctx.currentTime + duration);
        } catch (e) { }
    }
    function playDone() {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator(), gain = ctx.createGain();
            gain.gain.value = 0.5; osc.connect(gain); gain.connect(ctx.destination);
            osc.frequency.setValueAtTime(523, ctx.currentTime);
            osc.frequency.setValueAtTime(659, ctx.currentTime + 0.2);
            osc.frequency.setValueAtTime(784, ctx.currentTime + 0.4);
            osc.frequency.setValueAtTime(1046, ctx.currentTime + 0.6);
            osc.start(); gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 1);
            osc.stop(ctx.currentTime + 1);
        } catch (e) { }
    }
    async function checkBlocked(response) {
        if (blockedCode.includes(response?.status)) {
            logConsole('⚠️ Request blocked with status ' + response.status, false);
            await stopAllProcess();
        }
    }
    async function ignoreCode(response) {
        if (ignoredCode.includes(response?.status)) {
            logConsole('⚠️ Ignored response with status ' + response.status, true);
            return true;
        }
        return false;
    }
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    async function reactSetInput(el, value) {
        if (!el) return false;
        const nativeSetter = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value')?.set;
        if (!nativeSetter) return false;
        nativeSetter.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        el.focus?.();
        el.blur?.();
        return true;
    }
})();
(function () {
    'use strict';

    function insertTextIntoElement(el, text) {
        try {
            if (!el || !text) return;
            const targetEl = el.shadowRoot ? el.shadowRoot.activeElement : el;
            if (!targetEl) return;

            if (targetEl.isContentEditable) {
                const sel = targetEl.getRootNode().getSelection ? targetEl.getRootNode().getSelection() : window.getSelection();
                if (!sel || sel.rangeCount === 0) {
                    targetEl.textContent = text;
                    targetEl.dispatchEvent(new InputEvent('input', { bubbles: true }));
                    return;
                }
                const range = sel.getRangeAt(0);
                range.deleteContents();
                range.insertNode(document.createTextNode(text));
                range.collapse(false);
                sel.removeAllRanges();
                sel.addRange(range);
                targetEl.dispatchEvent(new InputEvent('input', { bubbles: true }));
                return;
            }

            const tag = (targetEl.tagName || '').toUpperCase();
            if (tag === 'INPUT' || tag === 'TEXTAREA') {
                const start = typeof targetEl.selectionStart === 'number' ? targetEl.selectionStart : targetEl.value.length;
                const end = typeof targetEl.selectionEnd === 'number' ? targetEl.selectionEnd : start;
                const val = targetEl.value || '';
                const newVal = val.slice(0, start) + text + val.slice(end);

                // Use native setter for React/Vue compatibility
                const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set
                    || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set;

                if (nativeSetter) {
                    nativeSetter.call(targetEl, newVal);
                } else {
                    targetEl.value = newVal;
                }

                const pos = start + text.length;
                try { targetEl.setSelectionRange(pos, pos); } catch (e) { }

                // Trigger multiple events for better compatibility
                targetEl.dispatchEvent(new Event('input', { bubbles: true }));
                targetEl.dispatchEvent(new Event('change', { bubbles: true }));
                targetEl.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
            }
        } catch (e) {
            console.warn('insertTextIntoElement error', e);
        }
    }

    window.__ivac_insertTextIntoElement = insertTextIntoElement;

    // Remove restrictive event handlers
    function removeRestrictiveHandlers() {
        try {
            const allElements = document.querySelectorAll('input,textarea,[contenteditable]');
            allElements.forEach(el => {
                try {
                    el.onpaste = null;
                    el.oncopy = null;
                    el.oncut = null;
                } catch (e) { }
            });

            // Also check shadow DOM
            const hosts = document.querySelectorAll('*');
            hosts.forEach(el => {
                if (el.shadowRoot) {
                    const shadowInputs = el.shadowRoot.querySelectorAll('input,textarea,[contenteditable]');
                    shadowInputs.forEach(sel => {
                        try {
                            sel.onpaste = null;
                            sel.oncopy = null;
                            sel.oncut = null;
                        } catch (e) { }
                    });
                }
            });
        } catch (e) { }
    }

    // Run initially and periodically
    removeRestrictiveHandlers();
    setInterval(removeRestrictiveHandlers, 2000);

    // Paste event handler with capture phase
    document.addEventListener('paste', function (e) {
        try {
            // Get clipboard data first
            let text = '';
            if (e.clipboardData && e.clipboardData.getData) {
                text = e.clipboardData.getData('text/plain') || '';
            }

            if (!text) return;

            // Prevent default and stop propagation
            e.stopImmediatePropagation();
            e.preventDefault();

            // Get active element (works with shadow DOM)
            let active = document.activeElement;

            // If active element is shadow host, get the active element inside shadow root
            if (active && active.shadowRoot && active.shadowRoot.activeElement) {
                active = active.shadowRoot.activeElement;
            }

            // Try to find focused element in shadow roots
            if (!active || (active.tagName !== 'INPUT' && active.tagName !== 'TEXTAREA' && !active.isContentEditable)) {
                const shadows = document.querySelectorAll('*');
                for (const el of shadows) {
                    if (el.shadowRoot) {
                        const focused = el.shadowRoot.querySelector('input:focus, textarea:focus, [contenteditable]:focus');
                        if (focused) {
                            active = focused;
                            break;
                        }
                    }
                }
            }

            if (active) {
                insertTextIntoElement(active, text);
            }
        } catch (er) {
            console.warn('Paste handler error:', er);
        }
    }, true);

    // Keyboard shortcut handler (Ctrl/Cmd + V)
    document.addEventListener('keydown', function (e) {
        try {
            const isPaste = (e.key === 'v' || e.key === 'V') && (e.ctrlKey || e.metaKey);
            if (!isPaste) return;

            e.stopImmediatePropagation();
            e.preventDefault();

            // Try to read clipboard
            if (navigator.clipboard && navigator.clipboard.readText) {
                navigator.clipboard.readText().then(text => {
                    if (!text) return;

                    let active = document.activeElement;

                    // Handle shadow DOM
                    if (active && active.shadowRoot && active.shadowRoot.activeElement) {
                        active = active.shadowRoot.activeElement;
                    }

                    // Search in shadow roots
                    if (!active || (active.tagName !== 'INPUT' && active.tagName !== 'TEXTAREA' && !active.isContentEditable)) {
                        const shadows = document.querySelectorAll('*');
                        for (const el of shadows) {
                            if (el.shadowRoot) {
                                const focused = el.shadowRoot.querySelector('input:focus, textarea:focus, [contenteditable]:focus');
                                if (focused) {
                                    active = focused;
                                    break;
                                }
                            }
                        }
                    }

                    if (active) {
                        insertTextIntoElement(active, text);
                    }
                }).catch(err => {
                    console.warn('Clipboard read failed:', err);
                });
            }
        } catch (er) {
            console.warn('Keyboard paste handler error:', er);
        }
    }, true);

    // Also handle copy
    document.addEventListener('copy', function (e) {
        try {
            let active = document.activeElement;
            if (active && active.shadowRoot && active.shadowRoot.activeElement) {
                active = active.shadowRoot.activeElement;
            }

            if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) {
                const selectedText = active.value.substring(active.selectionStart, active.selectionEnd);
                if (selectedText && e.clipboardData) {
                    e.clipboardData.setData('text/plain', selectedText);
                    e.stopImmediatePropagation();
                    e.preventDefault();
                }
            }
        } catch (er) {
            console.warn('Copy handler error:', er);
        }
    }, true);
})();
(function () {
    'use strict';
    console.log("🔥 GM Global Monitor Loaded");
    if (typeof GM_xmlhttpRequest === "undefined") {
        console.log("❌ GM_xmlhttpRequest not found");
        return;
    }
    const originalGM = GM_xmlhttpRequest;
    unsafeWindow.GM_xmlhttpRequest = GM_xmlhttpRequest = function (details) {
        // Add log to the modal using global exposed function
        if (typeof unsafeWindow.__addGMLog !== 'undefined') {
            unsafeWindow.__addGMLog(details);
        }

        console.group("🟢 INTERCEPTED GM REQUEST");
        console.log("URL:", details.url);
        console.log("Method:", details.method);
        console.log("Headers:", details.headers);
        console.log("Data:", details.data);
        console.groupEnd();

        const originalOnload = details.onload;
        details.onload = function (response) {
            console.group("🟢 GM RESPONSE");
            console.log("Status:", response.status);
            console.log("Response:", response.responseText);
            console.groupEnd();

            // Update log with response using global exposed functions
            if (typeof unsafeWindow.__updateGMLog !== 'undefined' && typeof unsafeWindow.__renderLogs !== 'undefined') {
                unsafeWindow.__updateGMLog(details.url, response);
                // Re-render if modal is open
                const host = document.getElementById('tm-floating-card-host');
                const logsModal = host && host.shadowRoot ? host.shadowRoot.getElementById('logs-modal') : null;
                if (logsModal && logsModal.classList.contains('active')) {
                    unsafeWindow.__renderLogs();
                }
            }

            if (originalOnload) {
                originalOnload(response);
            }
        };
        return originalGM(details);
    };

})();