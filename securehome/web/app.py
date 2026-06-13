"""
SecureHome — Dashboard Web (Backend Flask)
============================================
Ce module fournit une interface web pour visualiser les résultats
de l'audit de sécurité de ton réseau domestique.

CONCEPT : ARCHITECTURE CLIENT-SERVEUR
----------------------------------------
Le dashboard fonctionne avec 2 parties :
  1. Le SERVEUR (Flask) : tourne sur ton PC, fait les scans,
     et fournit les données via une API REST.
  2. Le CLIENT (navigateur) : affiche les données dans une page
     web avec des graphiques interactifs.

CONCEPT : API REST
--------------------
Notre serveur expose des "endpoints" (URLs) que le client peut
appeler pour récupérer des données au format JSON :
  GET /api/scan          → Lance un scan et retourne les résultats
  GET /api/last-scan     → Retourne le dernier scan sauvegardé
  GET /api/score         → Retourne le dernier score calculé
  GET /api/quick-scan    → Scan rapide (réseau seulement)

CONCEPT : FLASK
-----------------
Flask est un micro-framework web Python. "Micro" parce qu'il est
léger et simple — parfait pour notre usage. On définit des routes
(URLs) et Flask appelle la bonne fonction pour chaque requête.

  @app.route("/api/scan")
  def lancer_scan():
      ...
      return jsonify(resultats)

Le décorateur @app.route dit à Flask : "quand quelqu'un visite
cette URL, exécute cette fonction et renvoie le résultat."
"""

from flask import Flask, render_template, jsonify, request
import json
import os
import sys
import glob
import threading
from datetime import datetime

# Ajoute le dossier parent au path pour les imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from securehome.scanner.network_scanner import (
    scanner_reseau,
    verifier_admin,
    Appareil,
)
from securehome.scanner.port_scanner import scanner_reseau_complet
from securehome.analyzer.cve_analyzer import analyser_appareil as analyser_cve
from securehome.analyzer.credential_db import trouver_credentials
from securehome.analyzer.password_auditor import tester_http_basic


# =============================================================================
# INITIALISATION FLASK
# =============================================================================

# __name__ dit à Flask où trouver les fichiers (templates, static)
app = Flask(__name__, template_folder="templates")

# Variable globale pour stocker l'état du scan en cours
scan_en_cours = False
dernier_scan = None


# =============================================================================
# ROUTES PAGES HTML
# =============================================================================

@app.route("/")
def index():
    """
    Route principale — affiche le dashboard.

    CONCEPT : TEMPLATES
    --------------------
    render_template() charge un fichier HTML depuis le dossier
    'templates/' et le renvoie au navigateur. Flask utilise
    le moteur Jinja2 pour injecter des variables Python dans le HTML.
    """
    return render_template("dashboard.html")


# =============================================================================
# API REST — ENDPOINTS JSON
# =============================================================================

@app.route("/api/quick-scan")
def api_quick_scan():
    """
    Scan rapide : découverte réseau uniquement (sans ports, CVE, etc.)
    Rapide (~10s), parfait pour un premier aperçu.
    """
    global scan_en_cours

    if scan_en_cours:
        return jsonify({"erreur": "Un scan est déjà en cours"}), 429

    scan_en_cours = True

    try:
        resultat = scanner_reseau()

        appareils = []
        for a in resultat.appareils:
            appareils.append({
                "ip": a.ip,
                "mac": a.mac,
                "fabricant": a.fabricant,
                "hostname": a.hostname,
            })

        return jsonify({
            "statut": "ok",
            "date": resultat.date,
            "reseau": resultat.reseau,
            "nombre_appareils": resultat.nombre_appareils,
            "duree": resultat.duree_secondes,
            "appareils": appareils,
        })

    except Exception as e:
        return jsonify({"erreur": str(e)}), 500

    finally:
        scan_en_cours = False


@app.route("/api/full-scan")
def api_full_scan():
    """
    Scan complet : réseau + ports + test credentials + CVE.
    Plus long (~2-3 min) mais donne toutes les informations.
    """
    global scan_en_cours, dernier_scan

    if scan_en_cours:
        return jsonify({"erreur": "Un scan est déjà en cours"}), 429

    scan_en_cours = True

    try:
        # Étape 1 : Scan réseau + ports
        resultat_scan = scanner_reseau_complet(vitesse="rapide")

        appareils_data = []

        for appareil in resultat_scan.appareils:
            if appareil.mac == "Inconnu":
                continue

            appareil_info = {
                "ip": appareil.ip,
                "mac": appareil.mac,
                "fabricant": appareil.fabricant,
                "hostname": appareil.hostname,
                "ports_ouverts": appareil.ports_ouverts,
                "services": appareil.services,
                "mdp_defaut": False,
                "cves": [],
                "score": 100,
                "problemes": [],
            }

            # Étape 2 : Test des credentials
            ports_web = [80, 443, 8080, 8443]
            ports_web_ouverts = [p for p in appareil.ports_ouverts if p in ports_web]

            credentials = trouver_credentials(appareil.fabricant, appareil.ports_ouverts)

            for port in ports_web_ouverts:
                protocole = "https" if port in [443, 8443] else "http"
                for cred in credentials[:5]:  # Limite pour la vitesse
                    res = tester_http_basic(
                        appareil.ip, port, protocole,
                        cred.utilisateur, cred.mot_de_passe,
                        cred.chemin_login,
                    )
                    if res.succes:
                        appareil_info["mdp_defaut"] = True
                        appareil_info["problemes"].append(
                            f"Mot de passe par défaut : {cred.utilisateur}/{cred.mot_de_passe}"
                        )
                        break
                if appareil_info["mdp_defaut"]:
                    break

            # Étape 3 : CVE
            analyse_cve_result = analyser_cve(appareil)
            for cve in analyse_cve_result.cves_trouvees[:5]:
                appareil_info["cves"].append({
                    "id": cve.id_cve,
                    "score": cve.score_cvss,
                    "severite": cve.severite,
                    "description": cve.description[:150],
                    "lien": cve.lien,
                })

            # Étape 4 : Score simplifié
            score = 100
            if appareil_info["mdp_defaut"]:
                score -= 35
                appareil_info["problemes"].append("Credential par défaut")

            nb_critiques = sum(1 for c in appareil_info["cves"] if c["severite"] == "CRITIQUE")
            nb_eleves = sum(1 for c in appareil_info["cves"] if c["severite"] == "ÉLEVÉ")
            score -= nb_critiques * 15
            score -= nb_eleves * 8
            if nb_critiques:
                appareil_info["problemes"].append(f"{nb_critiques} CVE critique(s)")
            if nb_eleves:
                appareil_info["problemes"].append(f"{nb_eleves} CVE élevée(s)")

            for port in appareil.ports_ouverts:
                if port in [23, 21]:
                    score -= 15
                    appareil_info["problemes"].append(f"Port dangereux : {port}")

            appareil_info["score"] = max(0, min(100, score))
            appareils_data.append(appareil_info)

        # Score réseau global
        if appareils_data:
            scores = [a["score"] for a in appareils_data]
            score_reseau = round(sum(scores) / len(scores) * 0.6 + min(scores) * 0.4)
        else:
            score_reseau = 0

        dernier_scan = {
            "statut": "ok",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reseau": resultat_scan.reseau,
            "score_reseau": score_reseau,
            "nombre_appareils": len(appareils_data),
            "appareils": appareils_data,
        }

        # Sauvegarde
        os.makedirs("data", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        chemin = os.path.join("data", f"dashboard_{timestamp}.json")
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump(dernier_scan, f, indent=2, ensure_ascii=False)

        return jsonify(dernier_scan)

    except Exception as e:
        return jsonify({"erreur": str(e)}), 500

    finally:
        scan_en_cours = False


@app.route("/api/last-scan")
def api_last_scan():
    """Retourne le dernier scan sauvegardé."""
    global dernier_scan

    if dernier_scan:
        return jsonify(dernier_scan)

    # Cherche le dernier fichier JSON sauvegardé
    fichiers = glob.glob("data/dashboard_*.json")
    if not fichiers:
        # Cherche aussi les fichiers de score
        fichiers = glob.glob("data/score_securite_*.json")

    if not fichiers:
        return jsonify({"erreur": "Aucun scan précédent trouvé"}), 404

    # Prend le plus récent
    dernier_fichier = max(fichiers, key=os.path.getmtime)

    try:
        with open(dernier_fichier, "r", encoding="utf-8") as f:
            donnees = json.load(f)
        return jsonify(donnees)
    except Exception as e:
        return jsonify({"erreur": str(e)}), 500


@app.route("/api/status")
def api_status():
    """Retourne le statut du serveur."""
    return jsonify({
        "statut": "en ligne",
        "scan_en_cours": scan_en_cours,
        "version": "1.0.0",
        "heure": datetime.now().strftime("%H:%M:%S"),
    })


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":

    print(f"\n{'='*60}")
    print(f"  🌐 SecureHome — Dashboard Web")
    print(f"{'='*60}")

    if not verifier_admin():
        print("\n  ⚠️  Lance VS Code en Administrateur pour les scans !")

    print(f"\n  🚀 Serveur démarré !")
    print(f"  📡 Ouvre ton navigateur à : http://127.0.0.1:5000")
    print(f"  ⏹️  Ctrl+C pour arrêter le serveur\n")

    # debug=False en production, True pendant le développement
    # host="0.0.0.0" pour accéder depuis d'autres appareils du réseau
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )