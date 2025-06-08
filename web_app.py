from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import json
import time
import uuid
import psutil
import platform
import threading
import eventlet

# Use eventlet for better WebSocket performance
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Session management
class Session:
    def __init__(self, session_id, client_info):
        self.id = session_id
        self.client_info = client_info
        self.last_seen = time.time()
        self.encryption_key = None
        self.current_path = '/'
        self.system_info = {}
        self.file_list = []

    def update_last_seen(self):
        self.last_seen = time.time()

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.client_info.get('ip', 'Unknown'),
            'os': self.client_info.get('os', 'Unknown'),
            'username': self.client_info.get('username', 'Unknown'),
            'last_seen': self.last_seen
        }

# Store active sessions
active_sessions = {}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/sessions')
def get_sessions():
    return jsonify([session.to_dict() for session in active_sessions.values()])

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('client_connected')
def handle_client_connected(data):
    session_id = str(uuid.uuid4())
    session = Session(session_id, data)
    active_sessions[session_id] = session
    emit('session_created', {'session_id': session_id}, broadcast=True)
    print(f'New client connected: {session_id}')

@socketio.on('client_disconnected')
def handle_client_disconnected(data):
    session_id = data.get('session_id')
    if session_id in active_sessions:
        del active_sessions[session_id]
        emit('session_removed', {'session_id': session_id}, broadcast=True)
        print(f'Client disconnected: {session_id}')

@socketio.on('select_session')
def handle_select_session(data):
    session_id = data.get('session_id')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        emit('system_info_update', {
            'session_id': session_id,
            'info': session.system_info
        })
        emit('file_list_update', {
            'session_id': session_id,
            'files': session.file_list,
            'current_path': session.current_path
        })

@socketio.on('system_info')
def handle_system_info(data):
    session_id = data.get('session_id')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.system_info = data.get('info', {})
        session.update_last_seen()
        emit('system_info_update', {
            'session_id': session_id,
            'info': session.system_info
        }, broadcast=True)

@socketio.on('file_list')
def handle_file_list(data):
    session_id = data.get('session_id')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.file_list = data.get('files', [])
        session.current_path = data.get('current_path', '/')
        session.update_last_seen()
        emit('file_list_update', {
            'session_id': session_id,
            'files': session.file_list,
            'current_path': session.current_path
        }, broadcast=True)

@socketio.on('command')
def handle_command(data):
    session_id = data.get('session_id')
    command = data.get('command')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        # Forward command to client
        emit('execute_command', {
            'session_id': session_id,
            'command': command
        }, broadcast=True)

@socketio.on('command_output')
def handle_command_output(data):
    session_id = data.get('session_id')
    output = data.get('output')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('command_output', {
            'session_id': session_id,
            'output': output
        }, broadcast=True)

@socketio.on('file_action')
def handle_file_action(data):
    session_id = data.get('session_id')
    action = data.get('action')
    path = data.get('path')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('file_action', {
            'session_id': session_id,
            'action': action,
            'path': path
        }, broadcast=True)

@socketio.on('upload_file')
def handle_upload_file(data):
    session_id = data.get('session_id')
    filename = data.get('filename')
    file_data = data.get('data')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('upload_file', {
            'session_id': session_id,
            'filename': filename,
            'data': file_data
        }, broadcast=True)

@socketio.on('download_file')
def handle_download_file(data):
    session_id = data.get('session_id')
    filename = data.get('filename')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('download_file', {
            'session_id': session_id,
            'filename': filename
        }, broadcast=True)

@socketio.on('transfer_progress')
def handle_transfer_progress(data):
    session_id = data.get('session_id')
    progress = data.get('progress')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('transfer_progress', {
            'session_id': session_id,
            'progress': progress
        }, broadcast=True)

@socketio.on('transfer_complete')
def handle_transfer_complete(data):
    session_id = data.get('session_id')
    filename = data.get('filename')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('transfer_complete', {
            'session_id': session_id,
            'filename': filename
        }, broadcast=True)

@socketio.on('transfer_error')
def handle_transfer_error(data):
    session_id = data.get('session_id')
    error = data.get('error')
    if session_id in active_sessions:
        session = active_sessions[session_id]
        session.update_last_seen()
        emit('transfer_error', {
            'session_id': session_id,
            'error': error
        }, broadcast=True)

# Session cleanup thread
def cleanup_sessions():
    while True:
        current_time = time.time()
        for session_id, session in list(active_sessions.items()):
            if current_time - session.last_seen > 60:  # Remove sessions inactive for 60 seconds
                del active_sessions[session_id]
                emit('session_removed', {'session_id': session_id}, broadcast=True)
        time.sleep(10)

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 