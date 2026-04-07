import numpy as np


def get_optimization_suggestions(anomalies, packet_lengths):
    """Generate intelligent optimization suggestions based on traffic analysis."""
    suggestions = []

    if not packet_lengths:
        return [{'type': 'info', 'message': 'Capture or upload traffic data to get suggestions.'}]

    lengths = np.array(packet_lengths, dtype=float)
    mean_len = np.mean(lengths)
    std_len = np.std(lengths)
    high_anomalies = [a for a in anomalies if a.get('severity') == 'high']
    medium_anomalies = [a for a in anomalies if a.get('severity') == 'medium']

    anomaly_rate = len(anomalies) / len(lengths) if lengths.size > 0 else 0

    # Anomaly-based suggestions
    if len(high_anomalies) > 3:
        suggestions.append({
            'type': 'critical',
            'icon': '🚨',
            'title': 'High Anomaly Rate Detected',
            'message': f'{len(high_anomalies)} critical anomalies found. Possible DDoS or network attack. '
                       'Investigate source IPs immediately and consider rate limiting.'
        })

    if anomaly_rate > 0.15:
        suggestions.append({
            'type': 'warning',
            'icon': '⚠️',
            'title': 'Unstable Traffic Pattern',
            'message': f'{round(anomaly_rate * 100, 1)}% anomaly rate exceeds threshold. '
                       'Consider implementing traffic shaping policies or QoS rules.'
        })

    # Packet size suggestions
    if mean_len > 1200:
        suggestions.append({
            'type': 'warning',
            'icon': '📦',
            'title': 'Large Average Packet Size',
            'message': f'Average packet size is {round(mean_len, 0)} bytes. '
                       'Consider enabling packet fragmentation or MTU optimization to reduce latency.'
        })
    elif mean_len < 100:
        suggestions.append({
            'type': 'info',
            'icon': '🔬',
            'title': 'Small Packet Overhead',
            'message': f'Average packet size is only {round(mean_len, 0)} bytes. '
                       'High ratio of small packets may indicate chattiness. Consider TCP buffering/Nagle algorithm.'
        })

    # Variance-based suggestions
    if std_len > mean_len * 0.8:
        suggestions.append({
            'type': 'warning',
            'icon': '📊',
            'title': 'High Traffic Variability',
            'message': f'Traffic variance (σ={round(std_len, 0)}) is very high. '
                       'Implement traffic smoothing with weighted fair queuing (WFQ) or token bucket algorithms.'
        })

    # Congestion detection
    spikes = [a for a in anomalies if a.get('type') == 'spike']
    if len(spikes) > 5:
        suggestions.append({
            'type': 'warning',
            'icon': '🌊',
            'title': 'Bandwidth Spikes Detected',
            'message': f'{len(spikes)} traffic spikes detected. '
                       'Consider upgrading bandwidth or implementing burst traffic controls on edge routers.'
        })

    drops = [a for a in anomalies if a.get('type') == 'drop']
    if len(drops) > 3:
        suggestions.append({
            'type': 'info',
            'icon': '📉',
            'title': 'Traffic Drops Observed',
            'message': f'{len(drops)} unexpected traffic drops detected. '
                       'Check for packet loss, interface errors, or misconfigured firewall rules.'
        })

    # Good traffic
    if not suggestions:
        suggestions.append({
            'type': 'success',
            'icon': '✅',
            'title': 'Traffic Looks Healthy',
            'message': 'No significant anomalies detected. Network traffic is within normal parameters. '
                       'Continue monitoring for any emerging patterns.'
        })

    # General best practices
    suggestions.append({
        'type': 'tip',
        'icon': '💡',
        'title': 'Best Practice',
        'message': 'Enable SNMP monitoring and set up automated alerts for sustained anomaly rates above 10%. '
                   'Consider deploying a NetFlow collector for deeper traffic analysis.'
    })

    return suggestions
