from flask import Flask, render_template
from scapy.all import ARP, Ether, srp, conf
import socket

app = Flask(__name__)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # connect to an arbitrary public IP
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_network_prefix(ip):
    parts = ip.split('.')
    return '.'.join(parts[:3]) + '.0/24'

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    conf.L3socket = conf.L3socket or conf.L3RawSocket
    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

@app.route('/')
def index():
    local_ip = get_local_ip()
    ip_range = get_network_prefix(local_ip)
    devices = scan_network(ip_range)
    return render_template('index.html', devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
