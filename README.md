# AI-Based Network Traffic Monitoring System

## 🛡️ Overview
Real-time network traffic monitoring, anomaly detection, and prediction using LSTM neural networks.

## ⚙️ Setup & Run

### 1. Install Python dependencies
```bash
pip install flask numpy pandas
```

### 2. (Optional) Full LSTM with TensorFlow
```bash
pip install tensorflow
```

### 3. (Optional) Real packet capture
```bash
pip install scapy
# Linux/Mac: Run as sudo for live capture
# Windows: Install Npcap from https://npcap.com
```

### 4. Run the app
```bash
python app.py
```

### 5. Open browser
```
http://localhost:5000
```

## 🔑 Login Credentials
| Username | Password |
|----------|----------|
| admin    | admin123 |
| user     | user123  |

## 📁 Project Structure
```
network_monitor/
├── app.py                  # Flask main application
├── requirements.txt        # Python dependencies
├── templates/
│   ├── login.html          # Login page
│   └── index.html          # Main dashboard
├── utils/
│   ├── data_processor.py   # CSV parsing & feature engineering
│   ├── lstm_model.py       # LSTM model (TF or NumPy fallback)
│   ├── anomaly_detector.py # Z-score anomaly detection
│   ├── packet_capture.py   # Scapy or simulated capture
│   └── optimizer.py        # Optimization recommendations
└── uploads/                # Uploaded CSV files (auto-created)
```

## 🌟 Features
- **CSV Upload**: Upload Wireshark .csv exports for analysis
- **Live Monitoring**: Real-time packet capture (simulated or via Scapy)
- **LSTM Prediction**: Predict future traffic patterns
- **Anomaly Detection**: Z-score based statistical detection
- **Optimization Suggestions**: AI-powered network recommendations
- **Authentication**: Login/logout system

## 📊 CSV Format
Supports Wireshark CSV export format. Columns auto-detected:
- Time/Timestamp
- Length/Size/Bytes (required)
- Protocol
- Source/Destination

## 🚀 Technologies
- Python + Flask (Backend)
- TensorFlow/Keras or NumPy (LSTM Model)
- Scapy (Packet Capture)
- Chart.js (Visualization)
- HTML/CSS (Frontend)
