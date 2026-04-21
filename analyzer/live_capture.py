from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
from datetime import datetime

def traiter_paquet(paquet):
    if IP in paquet:
        src_ip   = paquet[IP].src
        dst_ip   = paquet[IP].dst
        size     = len(paquet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if TCP in paquet:
            protocol = 'TCP'
            src_port = paquet[TCP].sport
            dst_port = paquet[TCP].dport
        elif UDP in paquet:
            protocol = 'UDP'
            src_port = paquet[UDP].sport
            dst_port = paquet[UDP].dport
        elif ICMP in paquet:
            protocol = 'ICMP'
            src_port = 0
            dst_port = 0
        else:
            protocol = 'AUTRE'
            src_port = 0
            dst_port = 0

        conn = sqlite3.connect('data.db')
        conn.execute('''
            INSERT INTO packets
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size))
        conn.commit()
        conn.close()

        print(f"{timestamp} | {protocol} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def start_capture(nb_paquets=100):
    print("Capture en cours... (Ctrl+C pour arreter)")
    sniff(filter="ip", prn=traiter_paquet, count=nb_paquets)
    print("Capture terminee.")

if __name__ == "__main__":
    start_capture(100)