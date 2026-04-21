import sqlite3

def init_db():
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip    TEXT,
            dst_ip    TEXT,
            protocol  TEXT,
            src_port  INTEGER,
            dst_port  INTEGER,
            size      INTEGER
        )
    ''')

    conn.commit()
    conn.close()
    print("Base de donnees prete.")

if __name__ == "__main__":
    print("Demarrage...")
    init_db()
    print("Termine.")