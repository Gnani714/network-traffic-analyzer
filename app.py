from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os, threading, json, csv, time
from datetime import datetime
from utils.data_processor import process_csv
from utils.lstm_model import LSTMModel
from utils.packet_capture import PacketCapture
from utils.anomaly_detector import AnomalyDetector
from utils.optimizer import get_optimization_suggestions

app = Flask(__name__)
app.secret_key = "network_monitor_secret_key_2024"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

lstm_model = LSTMModel()
packet_capture = PacketCapture()
anomaly_detector = AnomalyDetector()
live_traffic_data = []
capture_active = False
active_file = None
active_analysis = None

os.makedirs('uploads', exist_ok=True)
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {"admin": "admin123", "user": "user123"}

def save_users(u):
    with open(USERS_FILE, 'w') as f:
        json.dump(u, f)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user=session['user'])

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        users = load_users()
        if username in users and users[username] == password:
            session['user'] = username
            return redirect(url_for('index'))
        error = "Invalid username or password."
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET','POST'])
def signup():
    error = None; success = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        confirm  = request.form.get('confirm','')
        if not username or not password:
            error = "Username and password are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            users = load_users()
            if username in users:
                error = "Username already exists."
            else:
                users[username] = password
                save_users(users)
                success = "Account created! You can now log in."
    return render_template('signup.html', error=error, success=success)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

def list_csv_files():
    files = []
    for fname in sorted(os.listdir('uploads'), reverse=True):
        if fname.endswith('.csv'):
            path = os.path.join('uploads', fname)
            size = os.path.getsize(path)
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M')
            files.append({'name': fname, 'size': size, 'modified': mtime})
    return files

@app.route('/files')
def get_files():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'files': list_csv_files(), 'active': active_file})

@app.route('/delete_file', methods=['POST'])
def delete_file():
    global active_file, active_analysis
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    fname = request.json.get('filename','')
    path = os.path.join('uploads', fname)
    if os.path.exists(path) and fname.endswith('.csv'):
        os.remove(path)
        if active_file == fname:
            active_file = None
            active_analysis = None
        return jsonify({'success': True})
    return jsonify({'error': 'File not found'})

def _analyze_file(fname):
    global active_file, active_analysis
    filepath = os.path.join('uploads', fname)
    if not os.path.exists(filepath):
        return {'success': False, 'error': 'File not found'}
    result = process_csv(filepath)
    if not result['success']:
        return result
    training_result = lstm_model.train(result)
    predictions = lstm_model.predict(result['packet_lengths'][-50:])
    anomalies = anomaly_detector.detect(result['packet_lengths'])
    suggestions = get_optimization_suggestions(anomalies, result['packet_lengths'])
    result['training'] = training_result
    result['predictions'] = predictions
    result['anomalies'] = anomalies
    result['suggestions'] = suggestions
    active_file = fname
    active_analysis = result
    return result

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    file = request.files['file']
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Only CSV files are supported'})
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    return jsonify(_analyze_file(file.filename))

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    fname = request.json.get('filename','')
    return jsonify(_analyze_file(fname))

@app.route('/active_analysis')
def get_active_analysis():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if active_analysis:
        return jsonify(active_analysis)
    return jsonify({'success': False, 'error': 'No file analyzed yet'})

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_active, live_traffic_data
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if capture_active:
        return jsonify({'message': 'Capture already running'})
    live_traffic_data = []
    capture_active = True
    def worker():
        global capture_active
        try:
            packet_capture.start(callback=live_traffic_data.append, max_packets=500)
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            capture_active = False
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'message': 'Capture started'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_active
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    capture_active = False
    packet_capture.stop()
    saved_file = None
    if live_traffic_data:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f'live_capture_{ts}.csv'
        filepath = os.path.join('uploads', fname)
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['time','protocol','length','src','dst'])
            writer.writeheader()
            writer.writerows(live_traffic_data)
        _analyze_file(fname)
        saved_file = fname
    return jsonify({'message': 'Capture stopped', 'packets_captured': len(live_traffic_data), 'saved_file': saved_file})

@app.route('/live_data')
def live_data():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    recent = live_traffic_data[-100:]
    lengths = [p.get('length', 0) for p in recent]
    anomalies = anomaly_detector.detect(lengths) if recent else []
    suggestions = get_optimization_suggestions(anomalies, lengths)
    return jsonify({
        'packets': recent[-30:],
        'all_lengths': lengths,
        'all_times': list(range(len(lengths))),
        'total': len(live_traffic_data),
        'active': capture_active,
        'anomalies': anomalies,
        'suggestions': suggestions
    })

@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    if not data or 'values' not in data:
        return jsonify({'error': 'No data provided'})
    predictions = lstm_model.predict(data['values'])
    return jsonify({'predictions': predictions})

@app.route('/status')
def status():
    return jsonify({'model_trained': lstm_model.is_trained, 'capture_active': capture_active,
                    'packets_captured': len(live_traffic_data), 'active_file': active_file})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)