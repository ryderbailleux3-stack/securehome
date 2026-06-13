"""
SecureHome — Module Alertes Android
======================================
Ce module envoie des notifications push sur ton téléphone Android
quand SecureHome détecte un problème de sécurité sur le réseau.

CONCEPT : NOTIFICATIONS PUSH
-------------------------------
Une notification push, c'est un message envoyé par un serveur
directement sur ton téléphone, même si l'app n'est pas ouverte.

Il existe 2 approches :
  1. POLLING : le téléphone demande régulièrement "y'a du nouveau ?"
     → Consomme de la batterie, délai entre les vérifications
  2. PUSH : le serveur envoie la notif quand il a quelque chose
     → Instantané, économe en batterie

On utilise l'approche PUSH via ntfy.sh.

CONCEPT : ntfy.sh
-------------------
ntfy.sh est un service de notifications push gratuit et open-source.
Le principe est simple comme un pub/sub (publication/abonnement) :

  1. Ton téléphone s'ABONNE à un "topic" (un canal)
  2. Notre programme PUBLIE un message sur ce topic
  3. ntfy.sh POUSSE la notification sur ton téléphone

C'est juste une requête HTTP POST :
  POST https://ntfy.sh/mon-topic
  Body: "Alerte ! Mot de passe par défaut trouvé sur la Bbox"

Pas besoin de compte, pas besoin de clé API, pas besoin de serveur.

CONCEPT : ADB (Android Debug Bridge)
--------------------------------------
ADB permet de communiquer avec ton téléphone Android depuis le PC.
On peut aussi envoyer des notifications directement via ADB,
mais ntfy.sh est plus pratique car ça marche même à distance.
"""

import requests
import subprocess
import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

# Import de nos modules
from ..scanner.network_scanner import verifier_admin
from ..scoring.security_score import calculer_score_reseau


# =============================================================================
# CONFIGURATION
# =============================================================================

# URL de base de ntfy.sh
NTFY_URL = "https://ntfy.sh"

# Fichier de configuration pour sauvegarder le topic
CONFIG_FILE = os.path.join("data", "config_alertes.json")

# Seuils d'alerte — à partir de quel score on envoie une notification
SEUILS = {
    "critique": 30,    # Score ≤ 30 → alerte critique
    "warning": 60,     # Score ≤ 60 → alerte warning
    "info": 80,        # Score ≤ 80 → alerte info
}

# Priorités ntfy (1=min, 5=max)
# ntfy.sh utilise des niveaux de priorité qui changent le son
# et l'affichage de la notification sur Android
PRIORITES_NTFY = {
    "critique": 5,     # Urgent — son fort, notification persistante
    "warning": 4,      # Haute — son normal
    "info": 3,         # Normale — son par défaut
    "succes": 2,       # Basse — silencieuse
}


@dataclass
class ConfigAlertes:
    """Configuration des alertes push."""
    topic: str = ""                  # Topic ntfy.sh (ex: "securehome-hugo")
    alertes_actives: bool = True     # Activer/désactiver les alertes
    seuil_notification: int = 80     # Envoyer une alerte si score < seuil
    derniere_alerte: str = ""        # Date de la dernière alerte envoyée
    adb_device_id: str = ""          # ID ADB du téléphone (optionnel)


def charger_config():
    """
    Charge la configuration des alertes depuis le fichier JSON.

    CONCEPT : PERSISTENCE DE CONFIGURATION
    ----------------------------------------
    On sauvegarde les préférences de l'utilisateur (topic, seuils)
    dans un fichier JSON pour ne pas les redemander à chaque fois.
    C'est le pattern "fichier de configuration" utilisé par
    presque tous les logiciels.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                donnees = json.load(f)
                return ConfigAlertes(**donnees)
        except (json.JSONDecodeError, TypeError):
            pass
    return ConfigAlertes()


def sauvegarder_config(config):
    """Sauvegarde la configuration dans un fichier JSON."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

    donnees = {
        "topic": config.topic,
        "alertes_actives": config.alertes_actives,
        "seuil_notification": config.seuil_notification,
        "derniere_alerte": config.derniere_alerte,
        "adb_device_id": config.adb_device_id,
    }

    with open(donnees_chemin := CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(donnees, f, indent=2, ensure_ascii=False)


def configurer_topic():
    """
    Guide l'utilisateur pour configurer le topic ntfy.sh.

    Un topic ntfy.sh est comme un canal privé :
    - Tu choisis un nom unique (ex: securehome-hugo-abc123)
    - Ton téléphone s'abonne à ce topic via l'app ntfy
    - Notre programme publie les alertes sur ce topic
    - IMPORTANT : utilise un nom difficile à deviner pour éviter
      que quelqu'un d'autre ne lise tes notifications
    """
    config = charger_config()

    print(f"\n  📱 CONFIGURATION DES ALERTES")
    print(f"  {'─'*50}")

    if config.topic:
        print(f"  Topic actuel : {config.topic}")
        modifier = input("  Modifier ? (o/n) : ").strip().lower()
        if modifier != "o":
            return config

    print(f"\n  Pour recevoir les alertes sur ton téléphone :")
    print(f"  1. Installe l'app 'ntfy' depuis le Play Store")
    print(f"  2. Ouvre l'app → '+' → entre ton nom de topic")
    print(f"  3. Appuie sur 'Subscribe'")
    print(f"\n  ⚠️  Choisis un nom unique et difficile à deviner !")
    print(f"  Exemple : securehome-hugo-2026")

    topic = input(f"\n  Ton topic ntfy : ").strip()

    if not topic:
        print("  ❌ Topic vide. Configuration annulée.")
        return config

    config.topic = topic
    sauvegarder_config(config)
    print(f"  ✅ Topic configuré : {topic}\n")

    # Test d'envoi
    print(f"  📤 Envoi d'une notification de test...")
    succes = envoyer_notification(
        topic=topic,
        titre="🏠 SecureHome — Test",
        message="Si tu vois cette notification, les alertes sont bien configurées !",
        priorite=PRIORITES_NTFY["info"],
        tags=["white_check_mark", "house"],
    )

    if succes:
        print(f"  ✅ Notification envoyée ! Vérifie ton téléphone.")
    else:
        print(f"  ❌ Échec de l'envoi. Vérifie ta connexion internet.")

    return config


def envoyer_notification(topic, titre, message, priorite=3, tags=None):
    """
    Envoie une notification push via ntfy.sh.

    CONCEPT : REQUÊTE HTTP POST
    -----------------------------
    ntfy.sh reçoit les notifications via une simple requête POST :

    POST https://ntfy.sh/{topic}
    Headers:
      Title: "Titre de la notification"
      Priority: 3 (1=min, 5=max)
      Tags: "warning,house"  (emojis dans la notification)
    Body:
      "Contenu du message"

    C'est une des APIs les plus simples qui existe — pas de JSON,
    pas d'authentification, juste du texte brut.
    """
    if not topic:
        return False

    url = f"{NTFY_URL}/{topic}"

    # En-têtes de la notification
   # On utilise le format JSON de ntfy pour supporter les caractères Unicode
    # (les en-têtes HTTP sont limités au latin-1, pas d'emojis possibles)
    donnees_json = {
        "topic": topic,
        "title": titre,
        "message": message,
        "priority": priorite,
    }

    if tags:
        donnees_json["tags"] = tags

    try:
        reponse = requests.post(
            url,
            json=donnees_json,
            timeout=10,
        )

        return reponse.status_code == 200

    except requests.exceptions.RequestException as e:
        print(f"  ❌ Erreur d'envoi ntfy : {str(e)[:50]}")
        return False


def envoyer_alerte_score(config, score_reseau):
    """
    Envoie une alerte basée sur le score de sécurité du réseau.

    CONCEPT : SEUILS D'ALERTE
    ---------------------------
    On ne veut pas spammer l'utilisateur avec des notifications.
    On envoie une alerte uniquement si le score est en dessous
    d'un seuil configurable.

    Le contenu et la priorité de la notification changent selon
    la gravité :
      Score ≤ 30 → 🔴 CRITIQUE (priorité max, son urgent)
      Score ≤ 60 → 🟠 WARNING (priorité haute)
      Score ≤ 80 → 🟡 INFO (priorité normale)
      Score > 80 → ✅ OK (notification basse priorité)
    """
    if not config.topic or not config.alertes_actives:
        return

    score = score_reseau.score_global
    note = score_reseau.note

    # Détermine le niveau d'alerte
    if score <= SEUILS["critique"]:
        niveau = "critique"
        emoji = "🔴"
        tags = ["rotating_light", "warning"]
        priorite = PRIORITES_NTFY["critique"]
    elif score <= SEUILS["warning"]:
        niveau = "warning"
        emoji = "🟠"
        tags = ["warning", "house"]
        priorite = PRIORITES_NTFY["warning"]
    elif score <= SEUILS["info"]:
        niveau = "info"
        emoji = "🟡"
        tags = ["information_source", "house"]
        priorite = PRIORITES_NTFY["info"]
    else:
        niveau = "succes"
        emoji = "✅"
        tags = ["white_check_mark", "house"]
        priorite = PRIORITES_NTFY["succes"]

    # Construit le titre
    titre = f"{emoji} SecureHome — Score: {score}/100 ({note})"

    # Construit le message avec les détails
    lignes = [
        f"Score réseau : {score}/100 ({note})",
        f"Appareils analysés : {score_reseau.nombre_appareils}",
        "",
    ]

    # Ajoute le détail par appareil
    for appareil in sorted(score_reseau.appareils, key=lambda a: a.score_global):
        note_a, couleur_a, _ = _attribuer_note_simple(appareil.score_global)
        lignes.append(f"  {couleur_a} {appareil.fabricant[:20]} : {appareil.score_global}/100 ({note_a})")

    # Ajoute les problèmes principaux
    if score_reseau.resume_problemes:
        lignes.append("")
        lignes.append("Problèmes :")
        for p in score_reseau.resume_problemes[:3]:
            # Nettoie les emojis pour ntfy (certains passent mal)
            p_clean = p.replace("🔴", "[!]").replace("🟠", "[!]").replace("🟡", "[-]")
            lignes.append(f"  {p_clean}")

    message = "\n".join(lignes)

    # Envoie la notification
    succes = envoyer_notification(
        topic=config.topic,
        titre=titre,
        message=message,
        priorite=priorite,
        tags=tags,
    )

    if succes:
        config.derniere_alerte = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sauvegarder_config(config)

    return succes


def envoyer_alerte_appareil(config, appareil):
    """Envoie une alerte spécifique pour un appareil vulnérable."""
    if not config.topic or not config.alertes_actives:
        return

    if appareil.score_global > config.seuil_notification:
        return  # Score acceptable, pas d'alerte

    titre = f"⚠️ {appareil.fabricant} — Score: {appareil.score_global}/100"

    lignes = [
        f"IP : {appareil.ip}",
        f"Hostname : {appareil.hostname}",
        f"Score : {appareil.score_global}/100 ({appareil.note})",
        "",
    ]

    if appareil.problemes:
        lignes.append("Problèmes :")
        for p in appareil.problemes:
            p_clean = p.replace("🔴", "[!]").replace("🟠", "[!]").replace("🟡", "[-]")
            lignes.append(f"  {p_clean}")

    if appareil.recommandations:
        lignes.append("")
        lignes.append("Actions :")
        for r in appareil.recommandations[:2]:
            lignes.append(f"  → {r[:80]}")

    message = "\n".join(lignes)

    envoyer_notification(
        topic=config.topic,
        titre=titre,
        message=message,
        priorite=PRIORITES_NTFY["warning"],
        tags=["warning", "iphone"],
    )


def _attribuer_note_simple(score):
    """Version simplifiée de attribuer_note pour éviter l'import circulaire."""
    if score >= 90:
        return "A+", "✅", "Excellent"
    elif score >= 80:
        return "A", "✅", "Très bon"
    elif score >= 70:
        return "B", "🟢", "Bon"
    elif score >= 60:
        return "C", "🟡", "Moyen"
    elif score >= 50:
        return "C-", "🟡", "Passable"
    elif score >= 40:
        return "D", "🟠", "Faible"
    elif score >= 30:
        return "D-", "🟠", "Très faible"
    elif score >= 20:
        return "E", "🔴", "Critique"
    else:
        return "F", "🔴", "Danger"


def envoyer_notification_adb(message, titre="SecureHome"):
    """
    Envoie une notification directement via ADB (méthode alternative).

    CONCEPT : ADB (Android Debug Bridge)
    --------------------------------------
    ADB est un outil en ligne de commande qui communique avec
    les appareils Android connectés en USB ou Wi-Fi.

    La commande 'am broadcast' permet d'envoyer un "intent"
    Android, qui peut déclencher une notification via une app
    comme 'Notification Forwarder'.

    C'est moins pratique que ntfy.sh mais fonctionne sans internet.
    """
    try:
        # Vérifie que ADB est disponible
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if "device" not in result.stdout:
            print("  ❌ Aucun appareil ADB détecté")
            return False

        # Envoie la notification via ADB shell
        # On utilise 'cmd notification post' qui fonctionne sur Android 8+
        cmd = [
            "adb", "shell",
            "cmd", "notification", "post",
            "-t", titre,
            "securehome_alert",
            message[:200],  # Limite de taille
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0

    except FileNotFoundError:
        print("  ❌ ADB non trouvé. Vérifie que ADB est dans le PATH.")
        return False
    except subprocess.TimeoutExpired:
        print("  ❌ Timeout ADB — téléphone déconnecté ?")
        return False


def lancer_scan_avec_alertes():
    """
    Lance un scan complet avec scoring ET envoie les alertes.

    C'est la fonction qui combine toutes les phases :
    Phase 1 (scan) → Phase 2 (mdp) → Phase 3 (CVE) →
    Phase 4 (score) → Phase 5 (alertes)
    """
    print(f"\n{'='*60}")
    print(f"  📱 SecureHome — Scan avec Alertes Push")
    print(f"{'='*60}\n")

    # Charge ou configure le topic
    config = charger_config()
    if not config.topic:
        config = configurer_topic()
        if not config.topic:
            print("  ❌ Pas de topic configuré. Alertes désactivées.")

    # Lance le scoring complet (qui inclut scan + mdp + CVE)
    print(f"\n  🔄 Lancement du scan et scoring complet...\n")
    score_reseau = calculer_score_reseau()

    if score_reseau is None:
        print("  ❌ Échec du scoring.")
        return

    # Envoie les alertes
    if config.topic:
        print(f"\n{'='*60}")
        print(f"  📤 ENVOI DES ALERTES")
        print(f"{'='*60}\n")

        # Alerte globale réseau
        print(f"  📡 Alerte réseau (score: {score_reseau.score_global}/100)...", end=" ", flush=True)
        succes = envoyer_alerte_score(config, score_reseau)
        print(f"{'✅ Envoyée' if succes else '❌ Échec'}")

        # Alertes par appareil vulnérable
        for appareil in score_reseau.appareils:
            if appareil.score_global < config.seuil_notification:
                print(f"  📱 Alerte {appareil.fabricant[:20]} "
                      f"(score: {appareil.score_global}/100)...", end=" ", flush=True)
                envoyer_alerte_appareil(config, appareil)
                print("✅")

        print(f"\n  ✅ Alertes envoyées ! Vérifie ton téléphone.")
    else:
        print(f"\n  ⏩ Alertes désactivées (pas de topic configuré)")

    print()


def mode_surveillance():
    """
    CONCEPT : MODE SURVEILLANCE CONTINUE
    --------------------------------------
    Ce mode lance un scan toutes les X minutes et envoie
    des alertes si le score change ou si un nouveau problème
    est détecté.

    C'est le principe d'un "daemon" ou "service" : un programme
    qui tourne en arrière-plan en continu.
    """
    import time

    config = charger_config()
    if not config.topic:
        config = configurer_topic()

    print(f"\n  🔄 MODE SURVEILLANCE")
    print(f"  {'─'*50}")
    print(f"  Topic          : {config.topic}")
    print(f"  Seuil alerte   : score < {config.seuil_notification}")
    print(f"  Appuie sur Ctrl+C pour arrêter\n")

    intervalle = input("  Intervalle entre les scans (en minutes, défaut=30) : ").strip()
    try:
        intervalle = int(intervalle) if intervalle else 30
    except ValueError:
        intervalle = 30

    print(f"\n  ⏰ Scan toutes les {intervalle} minutes")
    print(f"  {'─'*50}\n")

    dernier_score = None

    try:
        while True:
            print(f"\n  🕐 Scan à {datetime.now().strftime('%H:%M:%S')}")

            # Lance le scoring
            score_reseau = calculer_score_reseau()

            if score_reseau:
                score_actuel = score_reseau.score_global

                # Envoie une alerte si le score a changé ou est bas
                if dernier_score is None or score_actuel != dernier_score:
                    if config.topic:
                        envoyer_alerte_score(config, score_reseau)
                        print(f"  📤 Alerte envoyée (score: {score_actuel}/100)")

                dernier_score = score_actuel

            # Attend l'intervalle
            print(f"\n  💤 Prochain scan dans {intervalle} minutes...")
            print(f"     (Ctrl+C pour arrêter)\n")
            time.sleep(intervalle * 60)

    except KeyboardInterrupt:
        print(f"\n\n  ⏹️  Surveillance arrêtée.")
        print(f"  Dernier score : {dernier_score}/100\n")


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":

    print(f"\n{'='*60}")
    print(f"  📱 SecureHome — Alertes Android")
    print(f"{'='*60}")

    # Vérification admin
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    print(f"\n  Que veux-tu faire ?")
    print(f"    1. Configurer les alertes (topic ntfy)")
    print(f"    2. Lancer un scan avec alertes")
    print(f"    3. Mode surveillance continue")
    print(f"    4. Envoyer une notification de test")

    choix = input(f"\n  Ton choix (1/2/3/4) : ").strip()

    if choix == "1":
        configurer_topic()

    elif choix == "2":
        lancer_scan_avec_alertes()

    elif choix == "3":
        mode_surveillance()

    elif choix == "4":
        config = charger_config()
        if not config.topic:
            config = configurer_topic()
        if config.topic:
            print(f"  📤 Envoi d'une notification de test...")
            succes = envoyer_notification(
                topic=config.topic,
                titre="🏠 SecureHome — Test",
                message="Notification de test envoyée avec succès !",
                priorite=3,
                tags=["white_check_mark", "house"],
            )
            print(f"  {'✅ Envoyée !' if succes else '❌ Échec'}")
    else:
        print(f"  Choix invalide.")

    print(f"\n  ✅ Terminé !")
    print(f"  → Prochaine étape : Rapport PDF (Phase 6)\n")