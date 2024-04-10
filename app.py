from flask import Flask, render_template  # Ensure this line is exactly as shown
from flask_socketio import SocketIO
from threading import Thread, Event
import time
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

packet_counts = {}
blocked_ips = set()
thread_stop_event = Event()
DDoS_ATTACK_THRESHOLD = 100  # Threshold for DDoS detection
DDoS_ATTACKS = [
    {"ip": "192.168.0.101", "start_after_sec": 10, "num_packets": 200, "interval": 0.05, "is_ddos": True, "prevent": True},
    {"ip": "192.168.0.102", "start_after_sec": 25, "num_packets": 200, "interval": 0.05, "is_ddos": True, "prevent": True},
    {"ip": "192.168.0.103", "start_after_sec": 40, "num_packets": 200, "interval": 0.05, "is_ddos": True, "prevent": True},
    {"ip": "192.168.0.104", "start_after_sec": 55, "num_packets": 200, "interval": 0.05, "is_ddos": True, "prevent": False},
    {"ip": "192.168.0.105", "start_after_sec": 70, "num_packets": 200, "interval": 0.05, "is_ddos": True, "prevent": False}
]

def simulate_traffic(attack):
    """Simulate traffic for DDoS and normal activity."""
    time.sleep(attack["start_after_sec"])
    for _ in range(attack["num_packets"]):
        if thread_stop_event.is_set() or (attack["prevent"] and attack["ip"] in blocked_ips):
            break
        packet_received(attack["ip"], attack["is_ddos"])
        time.sleep(attack["interval"])

def simulate_inconsistent_traffic():
    """Simulate inconsistent traffic from various IPs."""
    inconsistent_ips = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    while not thread_stop_event.is_set():
        src_ip = random.choice(inconsistent_ips)
        packet_received(src_ip, is_ddos=False)
        time.sleep(random.uniform(0.1, 1))  # Random interval for more realistic simulation

def packet_received(src_ip, is_ddos):
    """Handle packet reception, counting, and DDoS detection."""
    if src_ip in blocked_ips:
        return  # Ignore packets from blocked IPs
    packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
    count = packet_counts[src_ip]
    print(f"Packet received from {src_ip}: {count} packets")  # Log to terminal
    socketio.emit('packet_info', {'src_ip': src_ip, 'count': count})  # Emit to web

    if is_ddos and count > DDoS_ATTACK_THRESHOLD:
        block_ip(src_ip, is_ddos)

def block_ip(src_ip, is_ddos):
    """Block the IP if it's part of a DDoS attack and notify the client."""
    if is_ddos:
        print(f"DDoS attack detected from {src_ip} - Blocking IP")
        blocked_ips.add(src_ip)
        socketio.emit('ddos_detected', {'src_ip': src_ip, 'prevented': True, 'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")})
    else:
        print(f"DDoS attack from {src_ip} not prevented")

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_detection')
def start_detection():
    """Start the detection process and simulate DDoS attacks and inconsistent traffic."""
    global thread_stop_event
    thread_stop_event.clear()

    # Start threads for each simulated DDoS attack
    for attack in DDoS_ATTACKS:
        Thread(target=simulate_traffic, args=(attack,), daemon=True).start()

    # Start a thread for inconsistent traffic simulation
    Thread(target=simulate_inconsistent_traffic, daemon=True).start()

@socketio.on('stop_detection')
def stop_detection():
    """Stop the detection process."""
    thread_stop_event.set()

if __name__ == '__main__':
    socketio.run(app, debug=True)
