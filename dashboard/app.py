from flask import Flask, render_template, jsonify
import sqlite3
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from analyzer.detection import get_alertes

app = Flask(__name__)

def get_data():
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()

    total = cursor.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    protocoles = cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM packets
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchall()

    top_src = cursor.execute("""
        SELECT src_ip, COUNT(*) as count
        FROM packets
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    top_ports = cursor.execute("""
        SELECT dst_port, COUNT(*) as count
        FROM packets
        GROUP BY dst_port
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    recents = cursor.execute("""
        SELECT timestamp, src_ip, dst_ip, protocol, dst_port, size
        FROM packets
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    return {
        "total": total,
        "protocoles": [{"label": p[0], "count": p[1]} for p in protocoles],
        "top_src":    [{"ip": s[0], "count": s[1]} for s in top_src],
        "top_ports":  [{"port": p[0], "count": p[1]} for p in top_ports],
        "recents":    [{"time": r[0], "src": r[1], "dst": r[2],
                        "proto": r[3], "port": r[4], "size": r[5]}
                       for r in recents],
        "alertes":    get_alertes()
    }

@app.route('/api/stats')
def stats():
    return jsonify(get_data())

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    print("Dashboard disponible sur http://127.0.0.1:5000")
    app.run(debug=True)