import random
import time
import threading


class PacketCapture:
    """
    Network packet capture module.
    Uses Scapy for real capture, falls back to simulation if unavailable.
    """

    def __init__(self):
        self._running = False
        self._use_scapy = self._check_scapy()

    def _check_scapy(self):
        try:
            from scapy.all import sniff
            return True
        except ImportError:
            return False

    def start(self, callback, interface=None, max_packets=200, timeout=30):
        """Start packet capture."""
        self._running = True

        if self._use_scapy:
            self._capture_real(callback, interface, max_packets, timeout)
        else:
            self._capture_simulated(callback, max_packets)

    def _capture_real(self, callback, interface, max_packets, timeout):
        """Real packet capture using Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP

            def process_packet(pkt):
                if not self._running:
                    return
                packet_info = {
                    'time': time.time(),
                    'length': len(pkt),
                    'protocol': 'Other',
                    'src': '0.0.0.0',
                    'dst': '0.0.0.0'
                }
                if IP in pkt:
                    packet_info['src'] = pkt[IP].src
                    packet_info['dst'] = pkt[IP].dst
                    if TCP in pkt:
                        packet_info['protocol'] = 'TCP'
                    elif UDP in pkt:
                        packet_info['protocol'] = 'UDP'
                    else:
                        packet_info['protocol'] = 'IP'
                callback(packet_info)

            sniff(prn=process_packet, count=max_packets,
                  timeout=timeout, store=False,
                  iface=interface if interface else None,
                  stop_filter=lambda _: not self._running)
        except Exception as e:
            print(f"Scapy capture failed: {e}, using simulation")
            self._capture_simulated(callback, max_packets)

    def _capture_simulated(self, callback, max_packets):
        """Simulate packet capture for demo/testing."""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
        sources = [f'192.168.1.{i}' for i in range(1, 20)] + \
                  [f'10.0.0.{i}' for i in range(1, 10)]

        count = 0
        while self._running and count < max_packets:
            # Simulate realistic packet sizes
            proto = random.choice(protocols)
            if proto in ('HTTP', 'HTTPS'):
                length = random.randint(200, 1400)
            elif proto == 'DNS':
                length = random.randint(40, 120)
            elif proto == 'ICMP':
                length = random.randint(28, 84)
            else:
                length = int(abs(random.normalvariate(500, 200)))
                length = max(40, min(1500, length))

            # Occasional spike
            if random.random() < 0.05:
                length = random.randint(1300, 1500)

            packet_info = {
                'time': round(time.time(), 3),
                'length': length,
                'protocol': proto,
                'src': random.choice(sources),
                'dst': random.choice(sources)
            }
            callback(packet_info)
            count += 1
            time.sleep(random.uniform(0.05, 0.3))  # Realistic inter-packet delay

        self._running = False

    def stop(self):
        self._running = False
