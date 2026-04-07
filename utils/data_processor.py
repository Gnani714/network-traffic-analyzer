import pandas as pd
import numpy as np
import random
import os
from datetime import datetime, timedelta


def process_csv(filepath):
    """Process uploaded CSV file and extract network traffic features."""
    try:
        df = pd.read_csv(filepath)

        # Flexible column detection
        col_map = {}
        for col in df.columns:
            cl = col.lower().strip()
            if any(k in cl for k in ['time', 'timestamp', 'date']):
                col_map['time'] = col
            elif any(k in cl for k in ['len', 'length', 'size', 'bytes']):
                col_map['length'] = col
            elif any(k in cl for k in ['proto', 'protocol']):
                col_map['protocol'] = col
            elif any(k in cl for k in ['src', 'source']):
                col_map['src'] = col
            elif any(k in cl for k in ['dst', 'dest']):
                col_map['dst'] = col

        if 'length' not in col_map:
            # Use first numeric column
            num_cols = df.select_dtypes(include=[np.number]).columns
            if len(num_cols) > 0:
                col_map['length'] = num_cols[0]
            else:
                return {'success': False, 'error': 'No numeric columns found for packet length'}

        lengths = pd.to_numeric(df[col_map['length']], errors='coerce').dropna().values
        timestamps = list(range(len(lengths)))

        if 'protocol' in col_map:
            protocol_counts = df[col_map['protocol']].value_counts().head(5).to_dict()
            protocol_counts = {str(k): int(v) for k, v in protocol_counts.items()}
        else:
            protocol_counts = {'TCP': int(len(lengths) * 0.6), 'UDP': int(len(lengths) * 0.25),
                               'HTTP': int(len(lengths) * 0.1), 'Other': int(len(lengths) * 0.05)}

        features = _build_features(lengths)
        stats = _compute_stats(lengths)

        return {
            'success': True,
            'filename': os.path.basename(filepath),
            'rows': len(df),
            'columns': list(df.columns),
            'timestamps': timestamps[:200],
            'packet_lengths': [float(x) for x in lengths[:200]],
            'protocol_counts': protocol_counts,
            'features': features,
            'stats': stats
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def generate_sample_data(n=300):
    """Generate realistic sample network traffic data."""
    np.random.seed(42)
    base = np.random.normal(500, 150, n)
    # Add periodic pattern
    t = np.linspace(0, 4 * np.pi, n)
    seasonal = 100 * np.sin(t)
    # Add random spikes (anomalies)
    spikes = np.zeros(n)
    for i in random.sample(range(n), 15):
        spikes[i] = random.choice([-1, 1]) * random.uniform(400, 800)

    lengths = np.abs(base + seasonal + spikes)
    lengths = np.clip(lengths, 40, 1500)

    timestamps = list(range(n))
    protocol_counts = {
        'TCP': int(n * 0.58),
        'UDP': int(n * 0.22),
        'HTTP': int(n * 0.12),
        'HTTPS': int(n * 0.05),
        'Other': int(n * 0.03)
    }

    features = _build_features(lengths)
    stats = _compute_stats(lengths)

    return {
        'timestamps': timestamps,
        'packet_lengths': [float(x) for x in lengths],
        'protocol_counts': protocol_counts,
        'features': features,
        'stats': stats
    }


def _build_features(lengths, window=10):
    """Build feature sequences for LSTM."""
    features = []
    for i in range(window, len(lengths)):
        window_data = lengths[i - window:i]
        feat = [
            float(np.mean(window_data)),
            float(np.std(window_data)),
            float(np.min(window_data)),
            float(np.max(window_data)),
            float(lengths[i])
        ]
        features.append(feat)
    return features


def _compute_stats(lengths):
    return {
        'total_packets': len(lengths),
        'avg_length': round(float(np.mean(lengths)), 2),
        'max_length': round(float(np.max(lengths)), 2),
        'min_length': round(float(np.min(lengths)), 2),
        'std_dev': round(float(np.std(lengths)), 2),
        'total_bytes': int(np.sum(lengths))
    }
