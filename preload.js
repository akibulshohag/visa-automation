const { ipcRenderer } = require('electron');

// Expose a safe reload trigger to the renderer world
window.__electronReload__ = () => ipcRenderer.send('reload-window');
