import sqlite3
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from datetime import datetime

def parse_pcap(filepath):
    print("Lecture du fichier : " + filepath)
    
    paquets = rdpcap(filepath)
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    
    compteur = 0

    for paquet in paquets:
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

            cursor.execute('''
                INSERT INTO packets 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size))

            compteur += 1

    conn.commit()
    conn.close()
    print(str(compteur) + " paquets enregistres dans la base de donnees.")

if __name__ == "__main__":
    parse_pcap('pcap_samples/scan.pcap')