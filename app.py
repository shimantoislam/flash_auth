# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import json
import uuid
import os

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration
DATA_FILE = 'data.json'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class LicenseManager:
    def __init__(self):
        self.data = {'licenses': {}}
        self.load_data()

    def load_data(self):
        try:
            with open(DATA_FILE, 'r') as f:
                self.data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {'licenses': {}}
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
            'created_at': str(datetime.now()),
            'active': False
        }
        self.save_data()
        return True

    def verify_device(self, key, hwid, ip):
        if key not in self.data['licenses']:
            return {'status': 'error', 'message': 'Invalid license key'}
        
        license = self.data['licenses'][key]
        
        if datetime.strptime(license['expiry'], '%Y-%m-%d') < datetime.now():
            return {'status': 'error', 'message': 'License expired'}
        
        # Check if device already exists
        for device in license['devices']:
            if device['hwid'] == hwid or device['ip'] == ip:
                device['last_seen'] = str(datetime.now())
                self.save_data()
                return {'status': 'success', 'message': 'Device already registered'}
        
        if len(license['devices']) >= license['device_limit']:
            return {'status': 'error', 'message': 'Device limit reached'}
        
        license['devices'].append({
            'hwid': hwid,
            'ip': ip,
            'last_seen': str(datetime.now()),
            'first_seen': str(datetime.now())
        })
        license['active'] = True
        self.save_data()
        return {'status': 'success', 'message': 'Device registered'}

manager = LicenseManager()

# Web routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('panel'))
    
    if request.method == 'POST':
        if request.form.get('password') == '6969':
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('panel'))
        return render_template('login.html', error='Invalid password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
def panel():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Calculate remaining days for each license
    licenses = manager.data['licenses']
    for key in licenses:
        expiry_date = datetime.strptime(licenses[key]['expiry'], '%Y-%m-%d')
        remaining_days = (expiry_date - datetime.now()).days
        licenses[key]['remaining_days'] = remaining_days if remaining_days > 0 else 0
    
    return render_template('panel.html', licenses=licenses)

@app.route('/add_key', methods=['POST'])
def add_key():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    key = str(uuid.uuid4())
    expiry = request.form.get('expiry')
    device_limit = int(request.form.get('device_limit'))
    username = request.form.get('username')
    
    if not all([expiry, device_limit, username]):
        return redirect(url_for('panel'))
    
    manager.add_license(key, expiry, device_limit, username)
    return redirect(url_for('panel'))

@app.route('/remove_key/<key>')
def remove_key(key):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if key in manager.data['licenses']:
        manager.data['licenses'].pop(key)
        manager.save_data()
    return redirect(url_for('panel'))

@app.route('/license_details/<key>')
def license_details(key):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if key not in manager.data['licenses']:
        return redirect(url_for('panel'))
    
    license = manager.data['licenses'][key]
    expiry_date = datetime.strptime(license['expiry'], '%Y-%m-%d')
    remaining_days = (expiry_date - datetime.now()).days
    
    return render_template('license_details.html', 
                         license_key=key,
                         license=license,
                         remaining_days=remaining_days)

# API endpoints
@app.route('/api/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify_license():
    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400
    
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

# Static files
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
