"""
SecureHome — Module Scanner Réseau
===================================
Ce module scanne le réseau local pour découvrir tous les appareils connectés.

Comment ça marche ?
-------------------
1. On récupère l'adresse IP de ta machine et le masque de sous-réseau
   pour savoir quelle plage d'IP scanner (ex: 192.168.1.0/24)

2. On utilise nmap avec un "ping sweep" (-sn) : nmap envoie des paquets
   ARP sur le réseau local. Chaque appareil qui répond révèle son IP
   et son adresse MAC.

3. À partir de l'adresse MAC, on identifie le fabricant grâce à l'OUI
   (les 3 premiers octets). Ex: "AA:BB:CC:xx:xx:xx" → on cherche "AA:BB:CC"
   dans une base de données IEEE.

Prérequis :
-----------
- nmap installé sur Windows (https://nmap.org/download.html)
- Lancer le script en tant qu'Administrateur (pour voir les adresses MAC)
"""

import nmap  # python-nmap : interface Python pour piloter nmap
import socket  # Module standard : pour obtenir le nom d'hôte et l'IP locale
import struct  # Module standard : pour manipuler des données binaires (octets)
import json  # Module standard : pour sauvegarder les résultats en JSON
import ctypes  # Module standard : pour vérifier les droits administrateur (Windows)
import sys  # Module standard : pour quitter le programme proprement
import os  # Module standard : pour les chemins de fichiers
from datetime import datetime  # Pour horodater le scan
from dataclasses import dataclass, field, asdict  # Pour créer des classes de données propres


# =============================================================================
# CONCEPT : DATACLASS
# =============================================================================
# Une dataclass, c'est une classe Python simplifiée pour stocker des données.
# Au lieu d'écrire __init__, __repr__, __eq__ à la main, Python les génère.
# C'est comme un formulaire avec des champs prédéfinis.

@dataclass
class Appareil:
    """Représente un appareil détecté sur le réseau."""
    ip: str                          # Adresse IP (ex: "192.168.1.42")
    mac: str = "Inconnu"             # Adresse MAC (ex: "DC:A6:32:xx:xx:xx")
    fabricant: str = "Inconnu"       # Nom du fabricant (ex: "Raspberry Pi")
    hostname: str = "Inconnu"        # Nom de l'hôte sur le réseau
    ports_ouverts: list = field(default_factory=list)  # Liste des ports ouverts (Phase 2+)
    services: dict = field(default_factory=dict)       # Services détectés par port


@dataclass
class ResultatScan:
    """Contient tous les résultats d'un scan complet."""
    date: str = ""                               # Quand le scan a été fait
    reseau: str = ""                             # Quel réseau a été scanné
    nombre_appareils: int = 0                    # Combien d'appareils trouvés
    appareils: list = field(default_factory=list) # Liste des objets Appareil
    duree_secondes: float = 0.0                  # Combien de temps a duré le scan


# =============================================================================
# CONCEPT : OUI (Organizationally Unique Identifier)
# =============================================================================
# Chaque carte réseau dans le monde a une adresse MAC unique de 6 octets.
# Les 3 premiers octets sont attribués par l'IEEE au fabricant.
#
# Exemple : DC:A6:32:xx:xx:xx
#           ^^^^^^^^
#           OUI = "DCA632" → Raspberry Pi Trading Ltd
#
# nmap connaît déjà beaucoup de fabricants, mais parfois il renvoie "Unknown".
# On ajoute ici un dictionnaire de secours avec les marques IoT les plus courantes.

OUI_FABRICANTS = {
    # Routeurs et FAI français
    "00:07:CB": "Freebox",
    "14:0C:76": "Freebox",
    "24:95:04": "Freebox",
    "34:27:92": "Freebox",
    "40:CA:63": "Freebox",
    "68:A3:78": "Freebox",
    "F4:CA:E5": "Freebox",
    "E4:9E:12": "Freebox",
    "00:1E:58": "Livebox (Orange)",
    "00:23:89": "Livebox (Orange)",
    "28:BE:03": "Livebox (Orange)",
    "30:23:03": "Livebox (Orange)",
    "A4:4B:15": "Livebox (Orange)",
    "DC:39:6F": "Livebox (Orange)",
    "18:D6:C7": "SFR Box",
    "68:15:90": "SFR Box",
    "E0:63:E5": "Bouygues Bbox",

    # Appareils IoT courants
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "18:FE:34": "ESP8266 (Espressif)",
    "24:0A:C4": "ESP32 (Espressif)",
    "AC:67:B2": "ESP32 (Espressif)",
    "30:AE:A4": "ESP32 (Espressif)",
    "CC:50:E3": "ESP32 (Espressif)",
    "84:CC:A8": "ESP32 (Espressif)",

    # Téléphones et tablettes
    "FC:DB:B3": "Google (Pixel)",
    "94:EB:2C": "Google (Pixel)",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google (Pixel/Nest)",
    "F4:F5:D8": "Google",
    "38:F7:3D": "Amazon (Echo/Alexa)",
    "74:C2:46": "Amazon (Echo/Alexa)",
    "A0:02:DC": "Amazon",
    "44:65:0D": "Amazon",
    "F0:F6:1C": "Apple",
    "AC:DE:48": "Apple",
    "A8:51:AB": "Samsung",
    "8C:F5:A3": "Samsung",
    "00:26:37": "Samsung",
    "BC:72:B1": "Samsung",
    "34:14:B5": "Xiaomi",
    "64:A2:F9": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "04:CF:8C": "Xiaomi",

    # Objets connectés maison
    "68:37:E9": "TP-Link (Tapo/Kasa)",
    "00:31:92": "TP-Link",
    "50:C7:BF": "TP-Link",
    "B0:A7:B9": "TP-Link",
    "B0:BE:76": "TP-Link",
    "98:DA:C4": "TP-Link",
    "D8:47:32": "TP-Link",
    "00:18:E7": "Caméra IP (Hikvision)",
    "C0:56:E3": "Caméra IP (Hikvision)",
    "44:19:B6": "Caméra IP (Hikvision)",
    "54:C4:15": "Caméra IP (Hikvision)",
    "7C:BD:06": "Sonos",
    "00:0E:58": "Sonos",
    "B8:E9:37": "Sonos",
    "78:28:CA": "Sonos",
    "5C:AA:FD": "Sonos",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "00:1D:C9": "ASUS (Routeur)",
    "2C:56:DC": "ASUS",
    "AC:9E:17": "ASUS",
    "04:D4:C4": "ASUS",
    "50:46:5D": "NETGEAR",
    "C4:04:15": "NETGEAR",
    "CC:40:D0": "NETGEAR",
    "94:B4:0F": "NETGEAR",
    "B0:C5:54": "D-Link",
    "1C:7E:E5": "D-Link",
    "28:10:7B": "D-Link",
}


def verifier_admin():
    """
    CONCEPT : PRIVILÈGES ADMINISTRATEUR
    ------------------------------------
    Pour voir les adresses MAC des autres appareils, nmap doit envoyer
    des requêtes ARP "raw" (brutes). Windows exige les droits admin pour ça.

    ctypes.windll.shell32.IsUserAnAdmin() renvoie 1 si admin, 0 sinon.
    """
    try:
        est_admin = ctypes.windll.shell32.IsUserAnAdmin()
        return est_admin != 0
    except AttributeError:
        # On n'est pas sur Windows (Linux/Mac) — on continue quand même
        return True


def obtenir_ip_locale():
    """
    CONCEPT : SOCKET UDP POUR TROUVER SON IP
    -----------------------------------------
    Astuce classique en réseau : on crée un socket UDP vers une IP externe
    (ici 8.8.8.8 = DNS Google), SANS envoyer de données.
    Le système choisit automatiquement la bonne interface réseau locale,
    et on peut lire quelle IP locale il a utilisée.

    On ne se connecte pas vraiment à Google — c'est juste pour forcer
    le système à choisir quelle carte réseau utiliser.
    """
    try:
        # socket.SOCK_DGRAM = UDP (pas besoin de connexion, léger)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Pas de données envoyées, juste un "bind"
        ip_locale = s.getsockname()[0]  # Récupère l'IP choisie par le système
        s.close()
        return ip_locale
    except Exception:
        return "127.0.0.1"  # Fallback : localhost


def calculer_plage_reseau(ip_locale):
    """
    CONCEPT : NOTATION CIDR ET MASQUE DE SOUS-RÉSEAU
    -------------------------------------------------
    Ton réseau local utilise typiquement un masque /24, ce qui veut dire :
    - Les 24 premiers bits de l'IP identifient le RÉSEAU
    - Les 8 derniers bits identifient la MACHINE

    Exemple : IP = 192.168.1.42, masque /24
    → Réseau = 192.168.1.0/24
    → Plage = 192.168.1.1 à 192.168.1.254 (254 machines possibles)

    On prend l'IP locale et on remplace le dernier octet par ".0/24".
    """
    # Sépare l'IP en octets : "192.168.1.42" → ["192", "168", "1", "42"]
    octets = ip_locale.split(".")
    # Remplace le dernier octet par "0/24" pour couvrir tout le sous-réseau
    plage = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return plage


def identifier_fabricant(mac, fabricant_nmap=""):
    """
    Identifie le fabricant à partir de l'adresse MAC.

    Stratégie en 2 étapes :
    1. Si nmap a déjà trouvé le fabricant → on le garde
    2. Sinon → on cherche dans notre dictionnaire OUI_FABRICANTS
    """
    # Si nmap a déjà trouvé quelque chose d'utile, on le garde
    if fabricant_nmap and fabricant_nmap.lower() not in ("unknown", ""):
        return fabricant_nmap

    # Sinon, on extrait le préfixe OUI (les 3 premiers octets de la MAC)
    # "DC:A6:32:11:22:33" → "DC:A6:32"
    prefixe_oui = mac[:8].upper()

    # On cherche dans notre dictionnaire
    return OUI_FABRICANTS.get(prefixe_oui, "Inconnu")


def resoudre_hostname(ip):
    """
    CONCEPT : RÉSOLUTION DNS INVERSE
    ---------------------------------
    À partir d'une IP, on demande au serveur DNS "quel est le nom de cet appareil ?"
    C'est l'inverse de la résolution normale (nom → IP).

    Pas tous les appareils ont un hostname configuré — d'où le try/except.
    """
    try:
        # gethostbyaddr renvoie (hostname, aliases, addresses)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        # herror = "host error" — l'appareil n'a pas de nom DNS
        return "Inconnu"


def scanner_reseau(plage_reseau=None):
    """
    Fonction principale : scanne le réseau et retourne un ResultatScan.

    CONCEPT : PING SWEEP AVEC NMAP
    --------------------------------
    nmap -sn (scan no-port) envoie des requêtes ARP sur le réseau local.
    ARP = Address Resolution Protocol : "Qui a l'IP 192.168.1.X ? Dites-moi votre MAC."

    Chaque appareil qui répond est considéré comme "en ligne" (up).
    Avec les droits admin, on récupère aussi l'adresse MAC de chaque appareil.

    Flags utilisés :
      -sn  : Pas de scan de ports (juste la découverte d'hôtes)
      -T4  : Timing agressif (plus rapide, acceptable sur un réseau local)
      --min-rate 100 : Envoie au moins 100 paquets/sec (accélère le scan)
    """
    debut = datetime.now()

    # --- Étape 1 : Préparer le scan ---
    if plage_reseau is None:
        ip_locale = obtenir_ip_locale()
        plage_reseau = calculer_plage_reseau(ip_locale)

    print(f"\n{'='*60}")
    print(f"  🏠 SecureHome — Scanner Réseau")
    print(f"{'='*60}")
    print(f"  📡 Réseau cible : {plage_reseau}")
    print(f"  🕐 Début du scan : {debut.strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")
    print("  ⏳ Scan en cours... (peut prendre 10-30 secondes)\n")

    # --- Étape 2 : Lancer nmap ---
    nm = nmap.PortScanner()  # Crée une instance du scanner

    try:
        # Lance le scan : -sn = pas de ports, -T4 = rapide
        nm.scan(hosts=plage_reseau, arguments="-sn -T4 --min-rate 100")
    except nmap.PortScannerError as e:
        print(f"  ❌ Erreur nmap : {e}")
        print("  → Vérifie que nmap est installé et dans le PATH")
        sys.exit(1)

    # --- Étape 3 : Analyser les résultats ---
    appareils = []

    for ip in nm.all_hosts():
        # nm[ip] contient toutes les infos que nmap a trouvées sur cette IP
        hote = nm[ip]

        # Vérifie que l'hôte est bien "up" (a répondu au scan)
        if hote.state() != "up":
            continue

        # Récupère l'adresse MAC (disponible seulement avec droits admin)
        mac = "Inconnu"
        fabricant_nmap = ""

        if "addresses" in hote and "mac" in hote["addresses"]:
            mac = hote["addresses"]["mac"]

        # nmap fournit parfois le fabricant dans la section "vendor"
        if "vendor" in hote and mac in hote["vendor"]:
            fabricant_nmap = hote["vendor"][mac]

        # Identifie le fabricant (nmap ou notre dictionnaire OUI)
        fabricant = identifier_fabricant(mac, fabricant_nmap)

        # Résolution DNS inverse pour trouver le hostname
        hostname = resoudre_hostname(ip)

        # Crée l'objet Appareil et l'ajoute à la liste
        appareil = Appareil(
            ip=ip,
            mac=mac,
            fabricant=fabricant,
            hostname=hostname,
        )
        appareils.append(appareil)

    # --- Étape 4 : Trier par IP ---
    # On trie les appareils par adresse IP pour un affichage logique
    # socket.inet_aton convertit "192.168.1.42" en bytes pour un tri numérique
    # (sinon "192.168.1.9" viendrait APRÈS "192.168.1.100" en tri alphabétique)
    appareils.sort(key=lambda a: socket.inet_aton(a.ip))

    # --- Étape 5 : Construire le résultat ---
    fin = datetime.now()
    duree = (fin - debut).total_seconds()

    resultat = ResultatScan(
        date=debut.strftime("%Y-%m-%d %H:%M:%S"),
        reseau=plage_reseau,
        nombre_appareils=len(appareils),
        appareils=appareils,
        duree_secondes=round(duree, 2),
    )

    return resultat


def afficher_resultats(resultat):
    """Affiche les résultats du scan de manière lisible dans le terminal."""

    print(f"\n{'='*60}")
    print(f"  📊 RÉSULTATS DU SCAN")
    print(f"{'='*60}")
    print(f"  📅 Date     : {resultat.date}")
    print(f"  🌐 Réseau   : {resultat.reseau}")
    print(f"  📱 Appareils: {resultat.nombre_appareils} détectés")
    print(f"  ⏱️  Durée    : {resultat.duree_secondes}s")
    print(f"{'='*60}\n")

    if not resultat.appareils:
        print("  ⚠️  Aucun appareil détecté.")
        print("  → Lance le script en tant qu'Administrateur")
        print("  → Vérifie que tu es connecté au réseau\n")
        return

    # En-tête du tableau
    print(f"  {'N°':<4} {'IP':<17} {'MAC':<19} {'Fabricant':<22} {'Hostname'}")
    print(f"  {'─'*4} {'─'*17} {'─'*19} {'─'*22} {'─'*20}")

    for i, appareil in enumerate(resultat.appareils, 1):
        # Tronque les chaînes trop longues pour garder un tableau lisible
        fabricant = appareil.fabricant[:20] if len(appareil.fabricant) > 20 else appareil.fabricant
        hostname = appareil.hostname[:20] if len(appareil.hostname) > 20 else appareil.hostname

        print(f"  {i:<4} {appareil.ip:<17} {appareil.mac:<19} {fabricant:<22} {hostname}")

    print()


def sauvegarder_resultats(resultat, dossier="data"):
    """
    Sauvegarde les résultats en JSON pour les réutiliser plus tard.

    CONCEPT : SÉRIALISATION JSON
    -----------------------------
    JSON (JavaScript Object Notation) est un format texte universel
    pour stocker des données structurées. On convertit nos objets Python
    en dictionnaires, puis en texte JSON.

    On utilise asdict() de dataclasses pour convertir automatiquement
    nos Appareil et ResultatScan en dictionnaires.
    """
    # Crée le dossier data/ s'il n'existe pas
    os.makedirs(dossier, exist_ok=True)

    # Nom du fichier avec la date pour garder un historique
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = os.path.join(dossier, f"scan_{timestamp}.json")

    # Convertit le ResultatScan et tous ses Appareil en dictionnaire
    donnees = asdict(resultat)

    # Écrit le JSON avec indentation pour la lisibilité
    # ensure_ascii=False permet d'écrire les accents français correctement
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(donnees, f, indent=2, ensure_ascii=False)

    print(f"  💾 Résultats sauvegardés : {chemin}\n")
    return chemin


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
# __name__ == "__main__" signifie : "ce code ne s'exécute QUE si on lance
# CE fichier directement" (pas quand il est importé par un autre module).

if __name__ == "__main__":

    # Avertissement légal
    print("\n  ⚖️  AVERTISSEMENT LÉGAL")
    print("  " + "─" * 56)
    print("  Ce programme scanne UNIQUEMENT votre réseau domestique.")
    print("  Scanner un réseau sans autorisation est un délit pénal.")
    print("  (Art. 323-1 du Code pénal français)")
    print("  " + "─" * 56)

    # Vérification des droits administrateur
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        print("  → Clic droit sur VS Code → 'Exécuter en tant qu'administrateur'")
        print("  → Ou : clic droit sur PowerShell → 'Exécuter en tant qu'admin'\n")
        sys.exit(1)

    # Lance le scan
    resultat = scanner_reseau()

    # Affiche les résultats
    afficher_resultats(resultat)

    # Sauvegarde en JSON
    sauvegarder_resultats(resultat)

    print("  ✅ Scan terminé ! Tu connais maintenant tous les appareils")
    print("  de ton réseau. Prochaine étape : tester leurs mots de passe.\n")