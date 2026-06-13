"""
SecureHome — Base de Données des Credentials par Défaut
========================================================
Ce module contient les identifiants par défaut connus des fabricants
d'appareils connectés (routeurs, caméras, décodeurs, NAS, etc.).

CONCEPT : POURQUOI C'EST UN PROBLÈME ?
----------------------------------------
Les fabricants livrent leurs appareils avec des identifiants génériques
comme admin/admin ou admin/1234. Si l'utilisateur ne les change pas,
n'importe qui sur le réseau peut accéder à l'interface d'administration
et modifier la configuration de l'appareil.

C'est l'une des premières choses que vérifient les pentesters
(testeurs de pénétration) lors d'un audit de sécurité.

SOURCES : Les credentials listés ici proviennent de :
  - Documentation officielle des fabricants (manuels utilisateur)
  - Bases de données publiques (cirt.net, routerpasswords.com)
  - Rapports de sécurité publics

AVERTISSEMENT : Ces informations sont publiques. Les utiliser sur un
réseau qui ne vous appartient pas est un délit pénal.
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class CredentialParDefaut:
    """
    Représente un couple identifiant/mot de passe par défaut.

    CONCEPT : DATACLASS TYPÉE
    --------------------------
    On utilise des "type hints" (str, List, etc.) pour documenter
    quel type de données chaque champ attend.
    Python ne les vérifie pas à l'exécution, mais ça aide à comprendre
    le code et les IDE (VS Code) s'en servent pour l'autocomplétion.
    """
    fabricant: str              # Nom du fabricant (ex: "Bouygues Bbox")
    modele: str = ""            # Modèle si spécifique (ex: "Bbox Fibre")
    utilisateur: str = "admin"  # Identifiant par défaut
    mot_de_passe: str = "admin" # Mot de passe par défaut
    protocole: str = "http"     # Protocole à tester (http, https, ssh, telnet)
    port: int = 80              # Port sur lequel tester
    chemin_login: str = "/"     # Chemin de la page de login (ex: "/login.html")
    methode_auth: str = "basic" # Type d'authentification (basic, form, digest)
    notes: str = ""             # Informations supplémentaires


# =============================================================================
# BASE DE DONNÉES DES CREDENTIALS PAR DÉFAUT
# =============================================================================
# Organisée par catégorie d'appareil pour la lisibilité.
# Chaque entrée = un couple identifiant/mot de passe à tester.

CREDENTIALS_DB: List[CredentialParDefaut] = [

    # ─────────────────────────────────────────────────────────────
    # BOX INTERNET — FAI FRANÇAIS
    # ─────────────────────────────────────────────────────────────

    # Bouygues Bbox
    CredentialParDefaut(
        fabricant="Sagemcom",
        modele="Bbox (Bouygues)",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="https",
        port=443,
        chemin_login="/login.html",
        notes="Credential historique Bbox. Les modèles récents utilisent l'auth physique.",
    ),
    CredentialParDefaut(
        fabricant="Sagemcom",
        modele="Bbox (Bouygues)",
        utilisateur="admin",
        mot_de_passe="password",
        protocole="https",
        port=443,
        chemin_login="/login.html",
    ),

    # Freebox
    CredentialParDefaut(
        fabricant="Freebox",
        modele="Freebox Server",
        utilisateur="freebox",
        mot_de_passe="",
        protocole="http",
        port=80,
        chemin_login="/login.php",
        notes="Freebox OS demande une auth via l'écran LCD de la box.",
    ),
    CredentialParDefaut(
        fabricant="Freebox",
        modele="Freebox Server",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),

    # Livebox (Orange)
    CredentialParDefaut(
        fabricant="Livebox",
        modele="Livebox (Orange)",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
        chemin_login="/",
        notes="Les Livebox récentes ont un mot de passe sur l'étiquette.",
    ),
    CredentialParDefaut(
        fabricant="Livebox",
        modele="Livebox (Orange)",
        utilisateur="admin",
        mot_de_passe="1234",
        protocole="http",
        port=80,
    ),

    # SFR Box
    CredentialParDefaut(
        fabricant="SFR",
        modele="SFR Box",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),
    CredentialParDefaut(
        fabricant="SFR",
        modele="SFR Box",
        utilisateur="admin",
        mot_de_passe="password",
        protocole="http",
        port=80,
    ),

    # ─────────────────────────────────────────────────────────────
    # ROUTEURS WI-FI
    # ─────────────────────────────────────────────────────────────

    # TP-Link
    CredentialParDefaut(
        fabricant="TP-Link",
        modele="Routeur TP-Link",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),

    # ASUS
    CredentialParDefaut(
        fabricant="ASUS",
        modele="Routeur ASUS",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
        chemin_login="/Main_Login.asp",
    ),

    # NETGEAR
    CredentialParDefaut(
        fabricant="NETGEAR",
        modele="Routeur NETGEAR",
        utilisateur="admin",
        mot_de_passe="password",
        protocole="http",
        port=80,
    ),
    CredentialParDefaut(
        fabricant="NETGEAR",
        modele="Routeur NETGEAR",
        utilisateur="admin",
        mot_de_passe="1234",
        protocole="http",
        port=80,
    ),

    # D-Link
    CredentialParDefaut(
        fabricant="D-Link",
        modele="Routeur D-Link",
        utilisateur="admin",
        mot_de_passe="",
        protocole="http",
        port=80,
        notes="D-Link utilise souvent un mot de passe vide par défaut !",
    ),
    CredentialParDefaut(
        fabricant="D-Link",
        modele="Routeur D-Link",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),

    # Linksys
    CredentialParDefaut(
        fabricant="Linksys",
        modele="Routeur Linksys",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),
    CredentialParDefaut(
        fabricant="Linksys",
        modele="Routeur Linksys",
        utilisateur="",
        mot_de_passe="admin",
        protocole="http",
        port=80,
        notes="Linksys : parfois pas d'utilisateur, juste le mot de passe.",
    ),

    # ─────────────────────────────────────────────────────────────
    # DÉCODEURS TV
    # ─────────────────────────────────────────────────────────────

    CredentialParDefaut(
        fabricant="Arcadyan",
        modele="Décodeur TV Bouygues",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="https",
        port=8443,
    ),
    CredentialParDefaut(
        fabricant="Arcadyan",
        modele="Décodeur TV Bouygues",
        utilisateur="admin",
        mot_de_passe="password",
        protocole="https",
        port=8443,
    ),
    CredentialParDefaut(
        fabricant="Arcadyan",
        modele="Décodeur TV",
        utilisateur="root",
        mot_de_passe="root",
        protocole="https",
        port=8443,
    ),

    # ─────────────────────────────────────────────────────────────
    # CAMÉRAS IP
    # ─────────────────────────────────────────────────────────────

    # Hikvision
    CredentialParDefaut(
        fabricant="Hikvision",
        modele="Caméra IP Hikvision",
        utilisateur="admin",
        mot_de_passe="12345",
        protocole="http",
        port=80,
    ),
    CredentialParDefaut(
        fabricant="Hikvision",
        modele="Caméra IP Hikvision",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),

    # Dahua
    CredentialParDefaut(
        fabricant="Dahua",
        modele="Caméra IP Dahua",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=80,
    ),

    # ─────────────────────────────────────────────────────────────
    # OBJETS CONNECTÉS / IoT
    # ─────────────────────────────────────────────────────────────

    # Philips Hue
    CredentialParDefaut(
        fabricant="Philips Hue",
        modele="Bridge Hue",
        utilisateur="",
        mot_de_passe="",
        protocole="http",
        port=80,
        chemin_login="/api",
        methode_auth="form",
        notes="Hue Bridge utilise l'appairage physique, pas de mot de passe web.",
    ),

    # Sonos
    CredentialParDefaut(
        fabricant="Sonos",
        modele="Enceinte Sonos",
        utilisateur="admin",
        mot_de_passe="admin",
        protocole="http",
        port=1400,
        notes="Sonos expose une API HTTP locale sur le port 1400.",
    ),

    # ─────────────────────────────────────────────────────────────
    # CREDENTIALS GÉNÉRIQUES (testés sur tout appareil inconnu)
    # ─────────────────────────────────────────────────────────────

    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="admin",
        mot_de_passe="admin",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="admin",
        mot_de_passe="password",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="admin",
        mot_de_passe="1234",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="admin",
        mot_de_passe="",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="root",
        mot_de_passe="root",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="root",
        mot_de_passe="",
    ),
    CredentialParDefaut(
        fabricant="Générique",
        modele="Tout appareil",
        utilisateur="user",
        mot_de_passe="user",
    ),
]


def trouver_credentials(fabricant: str, ports_ouverts: list = None) -> List[CredentialParDefaut]:
    """
    Cherche les credentials par défaut correspondant à un fabricant.

    CONCEPT : CORRESPONDANCE FLOUE (FUZZY MATCHING)
    ------------------------------------------------
    Le nom du fabricant détecté par nmap ne correspond pas toujours
    exactement à ce qu'on a dans la base. Par exemple, nmap peut dire
    "Sagemcom Broadband SAS" alors que dans notre BDD c'est "Sagemcom".

    On fait une recherche "floue" : si le nom du fabricant dans la BDD
    est CONTENU dans le nom détecté (ou l'inverse), c'est un match.

    On ajoute aussi les credentials génériques qui marchent partout.
    """
    resultats = []
    fabricant_lower = fabricant.lower()

    for cred in CREDENTIALS_DB:
        cred_fabricant = cred.fabricant.lower()

        # Match exact ou partiel dans les deux sens
        if cred_fabricant in fabricant_lower or fabricant_lower in cred_fabricant:
            # Si on connaît les ports ouverts, ne garder que les credentials
            # dont le port correspond à un port ouvert sur l'appareil
            if ports_ouverts and cred.port not in ports_ouverts:
                continue
            resultats.append(cred)

    # Ajoute les credentials génériques si l'appareil a des ports web ouverts
    ports_web = [80, 443, 8080, 8443, 8888, 8000]
    if ports_ouverts:
        a_port_web = any(p in ports_ouverts for p in ports_web)
    else:
        a_port_web = True  # Si on ne sait pas, on teste quand même

    if a_port_web:
        for cred in CREDENTIALS_DB:
            if cred.fabricant == "Générique" and cred not in resultats:
                resultats.append(cred)

    return resultats


def afficher_stats_db():
    """Affiche les statistiques de la base de credentials."""
    fabricants = set(c.fabricant for c in CREDENTIALS_DB if c.fabricant != "Générique")
    generiques = sum(1 for c in CREDENTIALS_DB if c.fabricant == "Générique")

    print(f"\n  📚 Base de credentials par défaut")
    print(f"  {'─'*40}")
    print(f"    Fabricants couverts : {len(fabricants)}")
    print(f"    Credentials totaux  : {len(CREDENTIALS_DB)}")
    print(f"    Génériques          : {generiques}")
    print(f"    Spécifiques         : {len(CREDENTIALS_DB) - generiques}")
    print(f"\n    Fabricants : {', '.join(sorted(fabricants))}\n")


if __name__ == "__main__":
    afficher_stats_db()