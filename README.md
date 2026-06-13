# 🏠🔒 SecureHome

**Auditeur de sécurité pour réseaux domestiques connectés**

SecureHome est un outil complet d'audit de cybersécurité conçu pour analyser, évaluer et sécuriser les réseaux domestiques. Il détecte les appareils connectés, teste les mots de passe par défaut, recherche les failles connues (CVE), calcule un score de sécurité et envoie des alertes en temps réel.

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)
![nmap](https://img.shields.io/badge/nmap-Scanner-4682B4?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 🎯 Fonctionnalités

| Module | Description |
|--------|-------------|
| 📡 **Scanner réseau** | Découverte automatique de tous les appareils connectés (IP, MAC, fabricant, hostname) |
| 🔌 **Scanner de ports** | Détection des ports ouverts et des services actifs avec évaluation des risques |
| 🔑 **Audit mots de passe** | Test automatique des identifiants par défaut (admin/admin, root/root, etc.) |
| 🛡️ **Analyse CVE** | Recherche de vulnérabilités connues via l'API NIST NVD pour chaque appareil |
| 📊 **Score de sécurité** | Algorithme pondéré multi-critères donnant une note de 0 à 100 |
| 📱 **Alertes Android** | Notifications push en temps réel via ntfy.sh + mode surveillance continue |
| 📄 **Rapport PDF** | Document professionnel avec graphiques, tableaux et recommandations |
| 🌐 **Dashboard web** | Interface moderne accessible depuis n'importe quel appareil du réseau |

---

## 📸 Aperçu

### Dashboard Web
Le dashboard affiche en temps réel le score de sécurité du réseau, les appareils détectés, les vulnérabilités et les recommandations.

### Rapport PDF
Un rapport professionnel exportable avec jauge de score, graphiques en barres et recommandations personnalisées.

### Terminal
```
  ┌────────────────────────────────────────────┐
  │                                            │
  │   🟠  SCORE RÉSEAU : 46/100  (D)          │
  │      Faible                                │
  │                                            │
  └────────────────────────────────────────────┘

  🟠 [████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░] 46%
```

---

## 🏗️ Architecture du projet

```
SecureHome/
├── securehome/
│   ├── __init__.py
│   ├── scanner/                    # Phase 1 — Découverte réseau
│   │   ├── __init__.py
│   │   ├── network_scanner.py      # Scan ARP + identification fabricant (OUI)
│   │   └── port_scanner.py         # Scan de ports + évaluation des risques
│   ├── analyzer/                   # Phase 2 & 3 — Audit et analyse
│   │   ├── __init__.py
│   │   ├── credential_db.py        # Base de données des credentials par défaut
│   │   ├── password_auditor.py     # Test HTTP Basic Auth automatisé
│   │   └── cve_analyzer.py         # Interrogation API NVD/NIST
│   ├── scoring/                    # Phase 4 — Notation
│   │   ├── __init__.py
│   │   └── security_score.py       # Algorithme de scoring pondéré
│   ├── alerts/                     # Phase 5 — Notifications
│   │   ├── __init__.py
│   │   └── notifier.py             # Push notifications via ntfy.sh
│   ├── reports/                    # Phase 6 — Rapports
│   │   ├── __init__.py
│   │   └── pdf_report.py           # Génération PDF avec ReportLab + matplotlib
│   └── web/                        # Phase 7 — Interface web
│       ├── __init__.py
│       ├── app.py                  # Serveur Flask + API REST
│       └── templates/
│           └── dashboard.html      # Dashboard HTML/CSS/JS + Chart.js
├── data/                           # Résultats de scans (gitignored)
├── tests/
├── docs/
├── requirements.txt
├── start_securehome.bat            # Lancement automatique Windows
├── .gitignore
└── README.md
```

---

## 🚀 Installation

### Prérequis

- **Python 3.12+** — [Télécharger](https://www.python.org/downloads/)
- **nmap** — [Télécharger](https://nmap.org/download.html)
- **Git** — [Télécharger](https://git-scm.com/downloads)
- **Windows 11** (compatible Windows 10)

### Installation

```bash
# Cloner le dépôt
git clone https://github.com/ryderbailleux3-stack/securehome.git
cd securehome

# Créer l'environnement virtuel
python -m venv venv

# Activer le venv
# Windows PowerShell :
venv\Scripts\activate
# Windows CMD :
venv\Scripts\activate.bat

# Installer les dépendances
pip install -r requirements.txt
```

### Dépendances

```
python-nmap
requests
flask
reportlab
matplotlib
```

---

## 💻 Utilisation

> ⚠️ **Important** : Lancez toujours en tant qu'**Administrateur** pour que nmap puisse détecter les adresses MAC.

### Scanner réseau
```bash
python -m securehome.scanner.network_scanner
```
Découvre tous les appareils connectés au réseau local avec leur adresse IP, MAC, fabricant et hostname.

### Scanner de ports
```bash
python -m securehome.scanner.port_scanner
```
Scanne les ports ouverts de chaque appareil avec évaluation du niveau de risque (CRITIQUE → FAIBLE).

### Audit des mots de passe
```bash
python -m securehome.analyzer.password_auditor
```
Teste automatiquement les identifiants par défaut connus (admin/admin, root/root, etc.) sur les interfaces web des appareils.

### Analyse CVE
```bash
python -m securehome.analyzer.cve_analyzer
```
Interroge l'API NIST NVD pour rechercher les vulnérabilités connues associées à chaque fabricant détecté.

### Score de sécurité
```bash
python -m securehome.scoring.security_score
```
Calcule un score de 0 à 100 basé sur 4 critères pondérés :
- **Mots de passe** (35%) — Credentials par défaut
- **CVE** (30%) — Failles connues
- **Ports** (20%) — Surface d'attaque
- **Chiffrement** (15%) — HTTPS vs HTTP

### Alertes Android
```bash
python -m securehome.alerts.notifier
```
Configure et envoie des notifications push sur votre téléphone via [ntfy.sh](https://ntfy.sh). Inclut un mode surveillance continue.

### Rapport PDF
```bash
python -m securehome.reports.pdf_report
```
Génère un rapport PDF professionnel avec jauge de score, graphiques, inventaire des appareils et recommandations.

### Dashboard web
```bash
python -m securehome.web.app
```
Lance le dashboard web accessible à `http://127.0.0.1:5000` (ou `http://<IP-locale>:5000` depuis d'autres appareils du réseau).

---

## 📊 Algorithme de scoring

Le score de sécurité est calculé selon un algorithme pondéré multi-critères :

```
Score global = Score_MDP (35%) + Score_CVE (30%) + Score_Ports (20%) + Score_Chiffrement (15%)
```

| Critère | Poids | Pénalités |
|---------|-------|-----------|
| Mots de passe | 35% | -35 si credential par défaut trouvé |
| CVE | 30% | -15 par CVE critique, -8 par élevée, -3 par moyenne |
| Ports | 20% | -20 par port critique (Telnet), -10 par élevé (FTP, SMB) |
| Chiffrement | 15% | -15 si HTTP sans HTTPS |

Le score réseau combine la moyenne des appareils (60%) et le score minimum (40%), car un réseau est aussi sûr que son maillon le plus faible.

| Score | Note | Niveau |
|-------|------|--------|
| 90-100 | A+ | Excellent |
| 80-89 | A | Très bon |
| 70-79 | B | Bon |
| 60-69 | C | Moyen |
| 40-59 | D | Faible |
| 20-39 | E | Critique |
| 0-19 | F | Danger |

---

## 🔧 Technologies utilisées

| Technologie | Usage |
|-------------|-------|
| **Python 3.12** | Langage principal |
| **nmap / python-nmap** | Scan réseau et détection de services |
| **Flask** | Serveur web et API REST |
| **Chart.js** | Graphiques interactifs dans le dashboard |
| **ReportLab** | Génération de rapports PDF |
| **matplotlib** | Graphiques dans les rapports PDF |
| **ntfy.sh** | Notifications push Android |
| **API NIST NVD** | Base de données des vulnérabilités CVE |
| **SQLite** | Stockage local des résultats |

---

## ⚖️ Avertissement légal

**Ce projet est conçu EXCLUSIVEMENT pour auditer votre propre réseau domestique.**

Scanner, tester ou accéder à un réseau informatique sans autorisation est un **délit pénal** sanctionné par :
- **Article 323-1 du Code pénal français** : jusqu'à 2 ans d'emprisonnement et 60 000 € d'amende
- **Article 323-3** : altération de données, jusqu'à 5 ans et 150 000 €

L'auteur décline toute responsabilité en cas d'utilisation malveillante ou non autorisée de cet outil.

---

## 👤 Auteur

Développé par **Hugo Bailleux** — Élève en Première MP3D (Bac Technologique)

Projet réalisé dans le cadre d'un portfolio de cybersécurité pour candidature en licence informatique spécialisée cybersécurité.

📧 Contact : [GitHub](https://github.com/ryderbailleux3-stack)

---

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.