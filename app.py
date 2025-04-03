# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import json
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Data storage setup
DATA_FILE = 'data.json'

class LicenseManager:
    def __init__(self):
        self.data = {'licenses': {}}
        self.load_data()

    def load_data(self):
        try:
            with open(DATA_FILE, 'r') as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.save_data()

    def save_data(self):
        with open(DATA_FILE, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_license(self, key, expiry, device_limit, username):
        if key in self.data['licenses']:
            return False
        self.data['licenses'][key] = {
            'expiry': expiry,
            'device_limit': device_limit,
            'username': username,
            'devices': [],
            'created_at': str(datetime.now())
        }
        self.save_data()
        return True

    def verify_device(self, key, hwid, ip):
        license = self.data['licenses'].get(key)
        if not license:
            return {'status': 'error', 'message': 'Invalid license key'}
        
        if datetime.strptime(license['expiry'], '%Y-%m-%d') < datetime.now():
            return {'status': 'error', 'message': 'License expired'}
        
        existing_devices = [d for d in license['devices'] if d['hwid'] == hwid or d['ip'] == ip]
        if existing_devices:
            return {'status': 'success', 'message': 'Device already registered'}
        
        if len(license['devices']) >= license['device_limit']:
            return {'status': 'error', 'message': 'Device limit reached'}
        
        license['devices'].append({
            'hwid': hwid,
            'ip': ip,
            'last_seen': str(datetime.now())
        })
        self.save_data()
        return {'status': 'success', 'message': 'Device registered'}

manager = LicenseManager()

# Web routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == '6969':
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('panel'))
        return render_template('login.html', error='Invalid password')
    return render_template('login.html')

@app.route('/panel')
def panel():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('panel.html', licenses=manager.data['licenses'])

@app.route('/add_key', methods=['POST'])
def add_key():
    key = str(uuid.uuid4())
    expiry = request.form.get('expiry')
    device_limit = int(request.form.get('device_limit'))
    username = request.form.get('username')
    manager.add_license(key, expiry, device_limit, username)
    return redirect(url_for('panel'))

@app.route('/remove_key/<key>')
def remove_key(key):
    manager.data['licenses'].pop(key, None)
    manager.save_data()
    return redirect(url_for('panel'))

# API endpoints
@app.route('/api/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify_license():
    data = request.get_json()
    required = ['license_key', 'hwid', 'ip']
    if not all(k in data for k in required):
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400
    
    result = manager.verify_device(
        data['license_key'],
        data['hwid'],
        data['ip']
    )
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)