"""
SecureHome — Module Scanner de Ports
=====================================
Ce module scanne les ports ouverts sur chaque appareil du réseau.

CONCEPT : QU'EST-CE QU'UN PORT ?
----------------------------------
Imagine une adresse IP comme un immeuble, et les ports comme les portes.
Chaque service (site web, SSH, email...) écoute derrière une porte précise.

Ports courants à connaître :
  - Port 21    : FTP (transfert de fichiers)
  - Port 22    : SSH (connexion sécurisée à distance)
  - Port 23    : Telnet (connexion NON sécurisée — dangereux !)
  - Port 53    : DNS (résolution de noms de domaine)
  - Port 80    : HTTP (site web non chiffré)
  - Port 443   : HTTPS (site web chiffré)
  - Port 445   : SMB (partage de fichiers Windows)
  - Port 554   : RTSP (flux vidéo — caméras IP)
  - Port 8080  : HTTP alternatif (souvent interfaces d'admin)
  - Port 8443  : HTTPS alternatif

CONCEPT : SCAN SYN vs CONNECT
-------------------------------
nmap propose 2 méthodes principales :
  - SYN scan (-sS) : Envoie un paquet SYN sans terminer la connexion.
    Plus rapide et plus discret. Nécessite les droits admin.
  - Connect scan (-sT) : Établit une connexion TCP complète.
    Plus lent mais ne nécessite pas les droits admin.

On utilise -sS (SYN) car on a les droits admin.

CONCEPT : DÉTECTION DE VERSION (-sV)
--------------------------------------
nmap peut aussi identifier QUEL logiciel tourne derrière un port ouvert
et sa VERSION. Exemple : port 80 → "nginx 1.18.0" ou "Apache 2.4.51".
Connaître la version est crucial pour chercher les CVE en Phase 3.
"""

import nmap
import socket
import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict

# On importe les classes et fonctions du module network_scanner
# Le "." signifie "dans le même package (dossier scanner)"
from .network_scanner import (
    Appareil,
    ResultatScan,
    scanner_reseau,
    verifier_admin,
    sauvegarder_resultats,
)


# =============================================================================
# PORTS À SCANNER
# =============================================================================
# On ne scanne pas les 65535 ports (trop long sur un réseau domestique).
# On cible les ports les plus intéressants pour la sécurité IoT.

PORTS_CIBLES = {
    # --- Accès à distance (les plus dangereux pour la sécurité) ---
    21: "FTP",          # Transfert de fichiers — souvent mal sécurisé
    22: "SSH",          # Shell sécurisé — OK si mot de passe fort
    23: "Telnet",       # Shell NON chiffré — très dangereux !
    2222: "SSH-alt",    # Port SSH alternatif (courant sur les NAS)

    # --- Interfaces web (panneaux d'administration) ---
    80: "HTTP",         # Interface web standard
    443: "HTTPS",       # Interface web chiffrée
    8080: "HTTP-alt",   # Interface web alternative
    8443: "HTTPS-alt",  # Interface HTTPS alternative
    8888: "HTTP-admin", # Souvent utilisé pour l'admin
    8000: "HTTP-dev",   # Serveur de développement

    # --- Partage de fichiers ---
    139: "NetBIOS",     # Partage Windows ancien — vulnérable
    445: "SMB",         # Partage Windows moderne — cible fréquente
    548: "AFP",         # Partage Apple
    2049: "NFS",        # Partage Linux/Unix

    # --- Bases de données (ne devraient JAMAIS être exposées) ---
    3306: "MySQL",      # Base de données MySQL
    5432: "PostgreSQL", # Base de données PostgreSQL
    6379: "Redis",      # Cache Redis — souvent sans mot de passe !
    27017: "MongoDB",   # Base NoSQL — souvent ouverte par défaut

    # --- Multimédia et IoT ---
    554: "RTSP",        # Flux vidéo (caméras IP)
    1883: "MQTT",       # Protocole IoT (domotique)
    8883: "MQTT-TLS",   # MQTT chiffré
    5353: "mDNS",       # Découverte de services (Bonjour/Avahi)
    1900: "UPnP/SSDP",  # Universal Plug and Play — souvent vulnérable

    # --- Autres services courants ---
    25: "SMTP",         # Email sortant
    53: "DNS",          # Résolution de noms
    161: "SNMP",        # Supervision réseau — infos sensibles
    5000: "Synology",   # Interface NAS Synology
    9090: "Cockpit",    # Interface admin Linux
    32400: "Plex",      # Serveur multimédia Plex
}


# =============================================================================
# NIVEAUX DE RISQUE PAR PORT
# =============================================================================
# Chaque port ouvert représente un niveau de risque différent.
# Un port Telnet ouvert est bien plus dangereux qu'un port HTTPS.

RISQUE_PORT = {
    23: "CRITIQUE",    # Telnet = mots de passe en clair sur le réseau
    21: "ÉLEVÉ",       # FTP = souvent accès anonyme ou credentials faibles
    139: "ÉLEVÉ",      # NetBIOS = vulnérabilités historiques (WannaCry)
    445: "ÉLEVÉ",      # SMB = même chose, cible n°1 des ransomwares
    161: "ÉLEVÉ",      # SNMP = fuite d'informations si communauté "public"
    6379: "ÉLEVÉ",     # Redis = souvent sans authentification
    27017: "ÉLEVÉ",    # MongoDB = idem, accès libre par défaut
    1883: "ÉLEVÉ",     # MQTT = rarement protégé sur les réseaux domestiques
    3306: "MOYEN",     # MySQL = risqué si exposé, mais souvent protégé
    5432: "MOYEN",     # PostgreSQL = idem
    22: "MOYEN",       # SSH = sécurisé si bon mot de passe, sinon brute-forcé
    80: "MOYEN",       # HTTP = pas chiffré, interface admin potentielle
    554: "MOYEN",      # RTSP = flux vidéo accessible
    8080: "MOYEN",     # HTTP-alt = interface admin potentielle
    1900: "MOYEN",     # UPnP = peut exposer des services internes
    443: "FAIBLE",     # HTTPS = chiffré, relativement sûr
    8443: "FAIBLE",    # HTTPS-alt = idem
    53: "FAIBLE",      # DNS = normal sur un routeur
    5353: "FAIBLE",    # mDNS = découverte locale, peu risqué
}


def obtenir_liste_ports():
    """
    Génère la chaîne de ports pour nmap.

    CONCEPT : FORMAT DES PORTS NMAP
    --------------------------------
    nmap accepte les ports sous forme de liste séparée par des virgules :
    "21,22,23,80,443,8080"

    On convertit les clés de notre dictionnaire PORTS_CIBLES en cette chaîne.
    """
    return ",".join(str(p) for p in sorted(PORTS_CIBLES.keys()))


def evaluer_risque_port(port):
    """Retourne le niveau de risque d'un port ouvert."""
    return RISQUE_PORT.get(port, "INFO")


def scanner_ports(appareil, vitesse="rapide"):
    """
    Scanne les ports ouverts sur UN appareil donné.

    CONCEPT : ARGUMENTS NMAP UTILISÉS
    -----------------------------------
      -sS : SYN scan (rapide, discret, besoin d'être admin)
      -sV : Détection de version (quel logiciel et quelle version)
      --version-intensity 3 : Niveau de détail pour la détection (0-9, 3 = équilibré)
      -T4 : Timing agressif (acceptable en réseau local)
      -Pn : Pas de ping préalable (on sait déjà que l'hôte est up)
      -p  : Liste des ports à scanner

    Retourne l'appareil enrichi avec les ports ouverts et les services.
    """
    nm = nmap.PortScanner()

    # Construit la liste de ports à scanner
    ports = obtenir_liste_ports()

    # Choisit les arguments selon la vitesse demandée
    if vitesse == "rapide":
        # Scan rapide : juste voir si le port est ouvert
        arguments = f"-sS -T4 -Pn --min-rate 200 -p {ports}"
    else:
        # Scan complet : avec détection de version des services
        arguments = f"-sS -sV --version-intensity 3 -T4 -Pn -p {ports}"

    try:
        nm.scan(hosts=appareil.ip, arguments=arguments)
    except nmap.PortScannerError as e:
        print(f"    ❌ Erreur scan ports {appareil.ip}: {e}")
        return appareil

    # Vérifie que l'hôte a répondu
    if appareil.ip not in nm.all_hosts():
        return appareil

    hote = nm[appareil.ip]

    # Parcourt les résultats pour le protocole TCP
    if "tcp" in hote:
        for port, infos in hote["tcp"].items():
            # "state" peut être : open, closed, filtered
            if infos["state"] == "open":
                appareil.ports_ouverts.append(port)

                # Récupère les infos du service
                nom_service = infos.get("name", PORTS_CIBLES.get(port, "inconnu"))
                produit = infos.get("product", "")
                version = infos.get("version", "")
                risque = evaluer_risque_port(port)

                # Stocke tout dans le dictionnaire services
                appareil.services[str(port)] = {
                    "nom": nom_service,
                    "produit": produit,
                    "version": version,
                    "risque": risque,
                    "description": PORTS_CIBLES.get(port, "Service inconnu"),
                }

    return appareil


def scanner_reseau_complet(vitesse="rapide"):
    """
    Effectue un scan complet : découverte réseau + scan de ports.

    1. D'abord on découvre les appareils (ping sweep)
    2. Ensuite on scanne les ports de chaque appareil trouvé
    3. On assemble le tout dans un ResultatScan enrichi
    """
    # Étape 1 : Découverte réseau
    resultat = scanner_reseau()

    if resultat.nombre_appareils == 0:
        print("  ⚠️  Aucun appareil trouvé. Scan de ports annulé.")
        return resultat

    # Étape 2 : Scan de ports sur chaque appareil
    print(f"\n{'='*60}")
    print(f"  🔍 SCAN DE PORTS — {resultat.nombre_appareils} appareils")
    print(f"  Mode : {'rapide (ports ouverts)' if vitesse == 'rapide' else 'complet (ports + versions)'}")
    print(f"{'='*60}\n")

    for i, appareil in enumerate(resultat.appareils, 1):
        # On ne scanne pas notre propre PC (MAC "Inconnu" = machine locale)
        if appareil.mac == "Inconnu":
            print(f"  [{i}/{resultat.nombre_appareils}] {appareil.ip:<17} ⏩ Ignoré (machine locale)")
            continue

        print(f"  [{i}/{resultat.nombre_appareils}] {appareil.ip:<17} ({appareil.fabricant})...", end=" ", flush=True)

        # Lance le scan de ports
        appareil = scanner_ports(appareil, vitesse)

        # Affiche le résumé
        nb_ports = len(appareil.ports_ouverts)
        if nb_ports > 0:
            ports_str = ", ".join(str(p) for p in appareil.ports_ouverts)
            print(f"✅ {nb_ports} port(s) : {ports_str}")
        else:
            print(f"🔒 Aucun port ouvert")

    return resultat


def afficher_rapport_ports(resultat):
    """Affiche un rapport détaillé des ports ouverts et des risques."""

    print(f"\n{'='*60}")
    print(f"  📊 RAPPORT DE SÉCURITÉ — PORTS OUVERTS")
    print(f"{'='*60}\n")

    # Compteurs globaux pour le résumé
    total_ports = 0
    ports_critiques = 0
    ports_eleves = 0

    for appareil in resultat.appareils:
        if not appareil.ports_ouverts:
            continue

        total_ports += len(appareil.ports_ouverts)

        # En-tête de l'appareil
        print(f"  📱 {appareil.ip} — {appareil.fabricant} ({appareil.hostname})")
        print(f"  {'─'*56}")

        for port in sorted(appareil.ports_ouverts):
            info = appareil.services.get(str(port), {})
            nom = info.get("nom", "inconnu")
            produit = info.get("produit", "")
            version = info.get("version", "")
            risque = info.get("risque", "INFO")
            description = info.get("description", "")

            # Icône selon le risque
            icones_risque = {
                "CRITIQUE": "🔴",
                "ÉLEVÉ": "🟠",
                "MOYEN": "🟡",
                "FAIBLE": "🟢",
                "INFO": "⚪",
            }
            icone = icones_risque.get(risque, "⚪")

            # Comptage des risques
            if risque == "CRITIQUE":
                ports_critiques += 1
            elif risque == "ÉLEVÉ":
                ports_eleves += 1

            # Ligne du port
            version_str = f" ({produit} {version})" if produit else ""
            print(f"    {icone} Port {port:<6} {description:<18} {risque:<10}{version_str}")

            # Avertissement spécifique pour les ports dangereux
            if port == 23:
                print(f"      ⚠️  Telnet transmet les mots de passe EN CLAIR !")
                print(f"      → Recommandation : désactiver Telnet, utiliser SSH")
            elif port == 21:
                print(f"      ⚠️  FTP est souvent configuré avec accès anonyme")
                print(f"      → Recommandation : utiliser SFTP à la place")
            elif port == 6379:
                print(f"      ⚠️  Redis est souvent sans authentification !")
                print(f"      → Recommandation : ajouter un mot de passe")
            elif port == 1883:
                print(f"      ⚠️  MQTT sans TLS = données IoT en clair")
                print(f"      → Recommandation : activer MQTT over TLS (port 8883)")

        print()

    # Résumé global
    print(f"  {'='*56}")
    print(f"  📈 RÉSUMÉ")
    print(f"  {'─'*56}")
    print(f"    Ports ouverts totaux   : {total_ports}")
    print(f"    🔴 Risque CRITIQUE     : {ports_critiques}")
    print(f"    🟠 Risque ÉLEVÉ        : {ports_eleves}")

    if ports_critiques > 0:
        print(f"\n  🚨 ALERTE : {ports_critiques} port(s) à risque critique détecté(s) !")
        print(f"     Des actions correctives sont fortement recommandées.")
    elif ports_eleves > 0:
        print(f"\n  ⚠️  ATTENTION : {ports_eleves} port(s) à risque élevé détecté(s).")
        print(f"     Vérifiez la configuration de ces services.")
    else:
        print(f"\n  ✅ Aucun risque critique ou élevé détecté. Bonne hygiène réseau !")

    print()


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":

    # Avertissement légal
    print("\n  ⚖️  AVERTISSEMENT LÉGAL")
    print("  " + "─" * 56)
    print("  Ce programme scanne UNIQUEMENT votre réseau domestique.")
    print("  Scanner un réseau sans autorisation est un délit pénal.")
    print("  (Art. 323-1 du Code pénal français)")
    print("  " + "─" * 56)

    # Vérification admin
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    # Demande le mode de scan
    print("\n  Quel type de scan ?")
    print("    1. Rapide — ports ouverts uniquement (~1-2 min)")
    print("    2. Complet — ports + versions des services (~3-5 min)")
    choix = input("\n  Ton choix (1/2) : ").strip()

    vitesse = "complet" if choix == "2" else "rapide"

    # Lance le scan complet
    resultat = scanner_reseau_complet(vitesse)

    # Affiche le rapport de sécurité
    afficher_rapport_ports(resultat)

    # Sauvegarde
    sauvegarder_resultats(resultat)

    print("  ✅ Scan complet terminé !")
    print("  → Prochaine étape : tester les mots de passe par défaut (Phase 2)\n")