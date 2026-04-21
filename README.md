# Network Analyzer — Traffic Analysis & Security Dashboard

Dashboard d'analyse de trafic réseau en temps réel avec détection d'anomalies.

## Fonctionnalités

- Capture de trafic réseau en temps réel sur la machine locale
- Analyse de fichiers PCAP (captures réseau)
- Dashboard web avec graphiques interactifs (protocoles, IPs, ports)
- Détection automatique de scans de ports et de flood
- Alertes visuelles en temps réel
- Rafraîchissement automatique toutes les 10 secondes

## Stack technique

Python · Scapy · Flask · SQLite · Chart.js · HTML/CSS

## Lancer le projet

### 1. Installer les dépendances
pip install flask scapy

### 2. Initialiser la base de données
python database/db.py

### 3. Lancer le dashboard
python dashboard/app.py

### 4. Analyser un fichier PCAP
python analyzer/pcap_parser.py

### 5. Capture en temps réel
python analyzer/live_capture.py

Le dashboard est accessible sur http://127.0.0.1:5000

## Architecture

network-analyzer/
├── analyzer/
│   ├── pcap_parser.py      # Analyse de fichiers PCAP
│   ├── live_capture.py     # Capture réseau en temps réel
│   └── detection.py        # Détection d'anomalies
├── dashboard/
│   ├── app.py              # Serveur Flask
│   └── templates/
│       └── index.html      # Interface web
├── database/
│   └── db.py               # Base de données SQLite
├── pcap_samples/           # Fichiers PCAP de test
└── README.md

## Détection d'anomalies

- Scan de ports : détecte une IP qui contacte plus de 10 ports différents en moins de 60 secondes
- Flood : détecte une IP qui envoie plus de 50 paquets en moins de 10 secondes

## Concepts abordés

- Protocoles réseau TCP/UDP/ICMP
- Analyse de paquets réseau avec Scapy
- Architecture client-serveur avec Flask
- Détection d'intrusion basique (IDS)
- Visualisation de données réseau

## Auteur

Adam Mislah — Etudiant BUT Réseaux & Télécommunications