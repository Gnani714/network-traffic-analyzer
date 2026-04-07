import numpy as np


class AnomalyDetector:
    """Statistical anomaly detection for network traffic."""

    def __init__(self, z_threshold=2.5, window=20):
        self.z_threshold = z_threshold
        self.window = window

    def detect(self, packet_lengths):
        """Detect anomalies using Z-score method with sliding window."""
        if not packet_lengths or len(packet_lengths) < 5:
            return []

        lengths = np.array(packet_lengths, dtype=float)
        anomalies = []

        global_mean = np.mean(lengths)
        global_std = np.std(lengths) if np.std(lengths) > 0 else 1

        for i, val in enumerate(lengths):
            # Use sliding window for local stats
            start = max(0, i - self.window)
            window_data = lengths[start:i + 1]
            local_mean = np.mean(window_data)
            local_std = np.std(window_data) if np.std(window_data) > 0 else 1

            z_score = abs((val - local_mean) / local_std)
            global_z = abs((val - global_mean) / global_std)

            if z_score > self.z_threshold or global_z > self.z_threshold * 1.2:
                severity = 'high' if z_score > self.z_threshold * 1.5 else 'medium'
                atype = 'spike' if val > local_mean else 'drop'
                anomalies.append({
                    'index': i,
                    'value': round(float(val), 2),
                    'expected': round(float(local_mean), 2),
                    'z_score': round(float(z_score), 2),
                    'severity': severity,
                    'type': atype
                })

        return anomalies
