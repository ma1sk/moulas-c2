// Initialize Socket.IO
const socket = io();

// State management
let state = {
    currentSession: null,
    fileTransferProgress: 0,
    isUploading: false,
    isDownloading: false
};

// DOM Elements
const elements = {
    sessionsList: document.getElementById('sessions-list'),
    systemInfo: document.getElementById('system-info'),
    fileList: document.getElementById('file-list'),
    terminalOutput: document.getElementById('terminal-output'),
    terminalInput: document.getElementById('terminal-input'),
    currentPath: document.getElementById('current-path'),
    sessionCount: document.getElementById('session-count'),
    uploadBtn: document.getElementById('upload-btn'),
    downloadBtn: document.getElementById('download-btn'),
    refreshBtn: document.getElementById('refresh-btn'),
    progressBar: document.getElementById('progress-bar')
};

// Socket.IO Event Handlers
socket.on('connect', () => {
    appendToTerminal('Connected to server');
    updateStatusIndicator(true);
});

socket.on('disconnect', () => {
    appendToTerminal('Disconnected from server');
    updateStatusIndicator(false);
});

socket.on('session_created', (data) => {
    updateSessionsList();
    appendToTerminal(`New session connected: ${data.session_id}`);
});

socket.on('session_removed', (data) => {
    updateSessionsList();
    appendToTerminal(`Session disconnected: ${data.session_id}`);
    if (state.currentSession === data.session_id) {
        state.currentSession = null;
        clearSystemInfo();
        clearFileList();
    }
});

socket.on('system_info_update', (data) => {
    if (state.currentSession === data.session_id) {
        updateSystemInfo(data.info);
    }
});

socket.on('file_list_update', (data) => {
    if (state.currentSession === data.session_id) {
        updateFileList(data.files);
        elements.currentPath.value = data.current_path;
    }
});

socket.on('command_output', (data) => {
    if (state.currentSession === data.session_id) {
        appendToTerminal(data.output);
    }
});

socket.on('transfer_progress', (data) => {
    if (state.currentSession === data.session_id) {
        updateTransferProgress(data.progress);
    }
});

socket.on('transfer_complete', (data) => {
    if (state.currentSession === data.session_id) {
        handleTransferComplete(data);
    }
});

socket.on('transfer_error', (data) => {
    if (state.currentSession === data.session_id) {
        handleTransferError(data);
    }
});

// UI Update Functions
function updateSessionsList() {
    fetch('/api/sessions')
        .then(response => response.json())
        .then(sessions => {
            elements.sessionsList.innerHTML = sessions.map(session => `
                <div class="p-2 hover:bg-gray-800 rounded cursor-pointer ${state.currentSession === session.id ? 'selected' : ''}" 
                     onclick="selectSession('${session.id}')">
                    <div class="flex items-center">
                        <i class="fas fa-circle text-green-400 mr-2"></i>
                        <div>
                            <div class="font-bold">${session.ip}</div>
                            <div class="text-sm text-gray-400">${session.os} - ${session.username}</div>
                        </div>
                    </div>
                </div>
            `).join('');
            elements.sessionCount.textContent = `Active Sessions: ${sessions.length}`;
        });
}

function updateSystemInfo(info) {
    elements.systemInfo.innerHTML = `
        <div>
            <div class="text-sm text-gray-400">CPU Usage</div>
            <div class="text-lg">${info.cpu_percent || 0}%</div>
        </div>
        <div>
            <div class="text-sm text-gray-400">Memory Usage</div>
            <div class="text-lg">${info.memory_percent || 0}%</div>
        </div>
        <div>
            <div class="text-sm text-gray-400">Hostname</div>
            <div class="text-lg">${info.hostname || 'Unknown'}</div>
        </div>
        <div>
            <div class="text-sm text-gray-400">Username</div>
            <div class="text-lg">${info.username || 'Unknown'}</div>
        </div>
    `;
}

function updateFileList(files) {
    elements.fileList.innerHTML = files.map(file => `
        <div class="file-item p-2 flex items-center cursor-pointer" onclick="handleFileClick('${file.name}')">
            <i class="fas ${file.type === 'directory' ? 'fa-folder' : 'fa-file'} text-green-400 mr-2"></i>
            <div>
                <div class="font-bold">${file.name}</div>
                <div class="text-sm text-gray-400">
                    ${file.type === 'file' ? formatFileSize(file.size) : ''} - ${file.modified}
                </div>
            </div>
        </div>
    `).join('');
}

function appendToTerminal(text) {
    const line = document.createElement('div');
    line.textContent = text;
    elements.terminalOutput.appendChild(line);
    elements.terminalOutput.scrollTop = elements.terminalOutput.scrollHeight;
}

function updateStatusIndicator(isOnline) {
    const indicator = document.querySelector('.status-indicator');
    indicator.className = `status-indicator ${isOnline ? 'online' : 'offline'}`;
    indicator.innerHTML = `<i class="fas fa-circle"></i> Server ${isOnline ? 'Online' : 'Offline'}`;
}

function updateTransferProgress(progress) {
    state.fileTransferProgress = progress;
    elements.progressBar.style.display = 'block';
    elements.progressBar.querySelector('.progress-bar-fill').style.width = `${progress}%`;
}

// Event Handlers
function selectSession(sessionId) {
    state.currentSession = sessionId;
    updateSessionsList();
    socket.emit('select_session', { session_id: sessionId });
}

function handleFileClick(fileName) {
    if (state.currentSession) {
        socket.emit('file_action', {
            session_id: state.currentSession,
            action: 'navigate',
            path: fileName
        });
    }
}

function handleUpload() {
    if (!state.currentSession) {
        showError('No session selected');
        return;
    }

    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (file) {
            state.isUploading = true;
            const reader = new FileReader();
            reader.onload = (event) => {
                socket.emit('upload_file', {
                    session_id: state.currentSession,
                    filename: file.name,
                    data: event.target.result
                });
            };
            reader.readAsArrayBuffer(file);
        }
    };
    input.click();
}

function handleDownload() {
    if (!state.currentSession) {
        showError('No session selected');
        return;
    }

    const selectedFile = elements.fileList.querySelector('.selected');
    if (!selectedFile) {
        showError('No file selected');
        return;
    }

    const fileName = selectedFile.querySelector('.font-bold').textContent;
    socket.emit('download_file', {
        session_id: state.currentSession,
        filename: fileName
    });
}

function handleTransferComplete(data) {
    state.isUploading = false;
    state.isDownloading = false;
    elements.progressBar.style.display = 'none';
    appendToTerminal(`Transfer complete: ${data.filename}`);
    refreshFileList();
}

function handleTransferError(data) {
    state.isUploading = false;
    state.isDownloading = false;
    elements.progressBar.style.display = 'none';
    showError(`Transfer failed: ${data.error}`);
}

function refreshFileList() {
    if (state.currentSession) {
        socket.emit('file_action', {
            session_id: state.currentSession,
            action: 'refresh',
            path: elements.currentPath.value
        });
    }
}

// Utility Functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showError(message) {
    appendToTerminal(`Error: ${message}`);
}

function clearSystemInfo() {
    elements.systemInfo.innerHTML = '';
}

function clearFileList() {
    elements.fileList.innerHTML = '';
    elements.currentPath.value = '/';
}

// Event Listeners
elements.terminalInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const command = elements.terminalInput.value;
        if (command.trim() && state.currentSession) {
            socket.emit('command', {
                session_id: state.currentSession,
                command: command
            });
            elements.terminalInput.value = '';
        }
    }
});

elements.uploadBtn.addEventListener('click', handleUpload);
elements.downloadBtn.addEventListener('click', handleDownload);
elements.refreshBtn.addEventListener('click', refreshFileList);

// Initial load
updateSessionsList(); 