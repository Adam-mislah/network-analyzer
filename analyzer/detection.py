import sqlite3
from datetime import datetime, timedelta

def detecter_scan_ports(seuil_ports=10, fenetre_secondes=60):
    """
    Detecte si une IP a contacte plus de X ports differents
    sur une meme destination en moins de Y secondes.
    """
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()

    limite_temps = (datetime.now() - timedelta(seconds=fenetre_secondes)).strftime('%Y-%m-%d %H:%M:%S')

    resultats = cursor.execute('''
        SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as nb_ports
        FROM packets
        WHERE timestamp > ?
        AND protocol = 'TCP'
        GROUP BY src_ip, dst_ip
        HAVING nb_ports >= ?
        ORDER BY nb_ports DESC
    ''', (limite_temps, seuil_ports)).fetchall()

    conn.close()
    return [{"src": r[0], "dst": r[1], "nb_ports": r[2]} for r in resultats]

def detecter_flood(seuil_paquets=50, fenetre_secondes=10):
    """
    Detecte si une IP envoie un nombre anormal de paquets
    en tres peu de temps.
    """
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()

    limite_temps = (datetime.now() - timedelta(seconds=fenetre_secondes)).strftime('%Y-%m-%d %H:%M:%S')

    resultats = cursor.execute('''
        SELECT src_ip, COUNT(*) as nb_paquets
        FROM packets
        WHERE timestamp > ?
        GROUP BY src_ip
        HAVING nb_paquets >= ?
        ORDER BY nb_paquets DESC
    ''', (limite_temps, seuil_paquets)).fetchall()

    conn.close()
    return [{"src": r[0], "nb_paquets": r[1]} for r in resultats]

def get_alertes():
    alertes = []

    scans = detecter_scan_ports()
    for s in scans:
        alertes.append({
            "type": "SCAN DE PORTS",
            "niveau": "DANGER",
            "message": s["src"] + " a scanne " + str(s["nb_ports"]) + " ports sur " + s["dst"]
        })

    floods = detecter_flood()
    for f in floods:
        alertes.append({
            "type": "FLOOD",
            "niveau": "WARNING",
            "message": f["src"] + " a envoye " + str(f["nb_paquets"]) + " paquets en 10 secondes"
        })

    return alertes

if __name__ == "__main__":
    print("=== Analyse en cours ===")
    alertes = get_alertes()
    if alertes:
        for a in alertes:
            print("[" + a["niveau"] + "] " + a["type"] + " : " + a["message"])
    else:
        print("Aucune anomalie detectee.")