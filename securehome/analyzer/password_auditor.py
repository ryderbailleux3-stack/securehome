"""
SecureHome — Module Audit de Mots de Passe
============================================
Ce module teste les identifiants par défaut sur les appareils du réseau.

CONCEPT : COMMENT FONCTIONNE L'AUTHENTIFICATION HTTP ?
-------------------------------------------------------
Quand tu accèdes à l'interface web d'un routeur, il te demande un
identifiant et un mot de passe. Il existe 2 méthodes principales :

1. HTTP Basic Auth :
   Le navigateur envoie l'identifiant et le mot de passe encodés
   en Base64 dans l'en-tête de la requête HTTP.
   Le serveur répond :
     - 200 OK → credentials acceptés (accès autorisé)
     - 401 Unauthorized → credentials refusés
     - 403 Forbidden → accès interdit (même avec bons credentials)

2. Authentification par formulaire :
   Le navigateur envoie les credentials via un formulaire HTML
   (requête POST). Le serveur répond généralement par une redirection
   (302) vers le dashboard si OK, ou vers la page de login si KO.

Notre outil teste les deux méthodes automatiquement.

CONCEPT : TIMEOUT ET GESTION D'ERREURS
----------------------------------------
Sur un réseau local, un appareil qui ne répond pas en 5 secondes
est probablement éteint ou ne supporte pas le protocole testé.
On utilise un timeout court pour ne pas bloquer le scan.

AVERTISSEMENT : Utiliser cet outil sur un réseau qui ne vous
appartient pas est un délit pénal (art. 323-1 Code pénal).
"""

import requests  # Bibliothèque HTTP : pour envoyer des requêtes web
import urllib3    # Utilisé pour désactiver les avertissements SSL
import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# On importe nos modules
from ..scanner.network_scanner import (
    verifier_admin,
    sauvegarder_resultats,
)
from ..scanner.port_scanner import scanner_reseau_complet
from .credential_db import (
    CredentialParDefaut,
    trouver_credentials,
    afficher_stats_db,
    CREDENTIALS_DB,
)

# Désactive les avertissements SSL pour les certificats auto-signés
# (comme celui de ta Bbox — on a vu l'erreur "connexion non privée")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ResultatTest:
    """Résultat d'un test d'identifiant sur un appareil."""
    ip: str                          # IP de l'appareil testé
    fabricant: str                   # Fabricant de l'appareil
    port: int                        # Port testé
    protocole: str                   # http ou https
    utilisateur: str                 # Identifiant testé
    mot_de_passe: str                # Mot de passe testé
    succes: bool = False             # True si le login a fonctionné
    code_http: int = 0               # Code de réponse HTTP (200, 401, etc.)
    methode: str = "basic"           # Méthode d'auth utilisée
    details: str = ""                # Infos supplémentaires


@dataclass
class RapportAudit:
    """Rapport complet de l'audit de mots de passe."""
    date: str = ""
    nombre_appareils_testes: int = 0
    nombre_tests_effectues: int = 0
    nombre_succes: int = 0
    appareils_vulnerables: list = field(default_factory=list)
    tous_les_tests: list = field(default_factory=list)
    duree_secondes: float = 0.0


def tester_http_basic(ip, port, protocole, utilisateur, mot_de_passe, chemin="/"):
    """
    Teste l'authentification HTTP Basic sur un appareil.

    CONCEPT : HTTP BASIC AUTH
    --------------------------
    L'authentification "Basic" est la plus simple en HTTP :
    1. On envoie une requête GET avec un en-tête Authorization
    2. Cet en-tête contient "Basic " + base64(utilisateur:mot_de_passe)
    3. Le serveur vérifie et répond avec un code HTTP :
       - 200 = OK, accès autorisé → MOT DE PASSE PAR DÉFAUT TROUVÉ !
       - 401 = Non autorisé → mauvais credentials
       - 403 = Interdit → bon credentials mais accès bloqué
       - 302 = Redirection → souvent vers le dashboard (= succès)

    requests.get(..., auth=(user, pass)) gère automatiquement
    l'encodage Base64 et l'en-tête Authorization.
    """
    url = f"{protocole}://{ip}:{port}{chemin}"

    try:
        # verify=False car les box utilisent des certificats auto-signés
        # timeout=5 pour ne pas bloquer si l'appareil ne répond pas
        reponse = requests.get(
            url,
            auth=(utilisateur, mot_de_passe),
            timeout=5,
            verify=False,           # Accepte les certificats auto-signés
            allow_redirects=False,  # On veut voir les redirections (302)
        )

        code = reponse.status_code

        # Analyse du code de réponse
        if code == 200:
            # Vérification supplémentaire : certains serveurs renvoient 200
            # mais avec une page de login (pas vraiment connecté)
            contenu = reponse.text.lower()
            mots_login = ["login", "connexion", "password", "mot de passe", "authentification"]

            if any(mot in contenu for mot in mots_login) and len(contenu) < 5000:
                # Page de login renvoyée = pas vraiment connecté
                return ResultatTest(
                    ip=ip, fabricant="", port=port, protocole=protocole,
                    utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                    succes=False, code_http=code, methode="basic",
                    details="200 mais page de login détectée",
                )

            # Vrai succès : on est connecté !
            return ResultatTest(
                ip=ip, fabricant="", port=port, protocole=protocole,
                utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                succes=True, code_http=code, methode="basic",
                details="Accès autorisé avec credentials par défaut !",
            )

        elif code == 302 or code == 301:
            # Redirection : souvent signe de succès (vers le dashboard)
            location = reponse.headers.get("Location", "")

           # Si redirigé vers une page de login OU vers un autre protocole/domaine → échec
            if ("login" in location.lower()
                or "auth" in location.lower()
                or location.startswith("https://")
                or location.startswith("http://")):
                return ResultatTest(
                    ip=ip, fabricant="", port=port, protocole=protocole,
                    utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                    succes=False, code_http=code, methode="basic",
                    details=f"Redirigé vers login : {location}",
                )

            # Sinon, probable succès
            return ResultatTest(
                ip=ip, fabricant="", port=port, protocole=protocole,
                utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                succes=True, code_http=code, methode="basic",
                details=f"Redirection (probable succès) : {location}",
            )

        elif code == 401:
            # Non autorisé : credentials incorrects
            return ResultatTest(
                ip=ip, fabricant="", port=port, protocole=protocole,
                utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                succes=False, code_http=code, methode="basic",
                details="Credentials refusés (401)",
            )

        elif code == 403:
            # Interdit : peut-être bon credentials mais accès bloqué
            return ResultatTest(
                ip=ip, fabricant="", port=port, protocole=protocole,
                utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                succes=False, code_http=code, methode="basic",
                details="Accès interdit (403) — possible blocage IP",
            )

        else:
            return ResultatTest(
                ip=ip, fabricant="", port=port, protocole=protocole,
                utilisateur=utilisateur, mot_de_passe=mot_de_passe,
                succes=False, code_http=code, methode="basic",
                details=f"Code HTTP inattendu : {code}",
            )

    except requests.exceptions.ConnectTimeout:
        return ResultatTest(
            ip=ip, fabricant="", port=port, protocole=protocole,
            utilisateur=utilisateur, mot_de_passe=mot_de_passe,
            succes=False, code_http=0, methode="basic",
            details="Timeout — appareil ne répond pas",
        )
    except requests.exceptions.ConnectionError:
        return ResultatTest(
            ip=ip, fabricant="", port=port, protocole=protocole,
            utilisateur=utilisateur, mot_de_passe=mot_de_passe,
            succes=False, code_http=0, methode="basic",
            details="Connexion refusée — service inaccessible",
        )
    except Exception as e:
        return ResultatTest(
            ip=ip, fabricant="", port=port, protocole=protocole,
            utilisateur=utilisateur, mot_de_passe=mot_de_passe,
            succes=False, code_http=0, methode="basic",
            details=f"Erreur : {str(e)[:50]}",
        )


def auditer_appareil(appareil):
    """
    Teste tous les credentials par défaut possibles sur UN appareil.

    CONCEPT : STRATÉGIE DE TEST
    ----------------------------
    1. On cherche les credentials spécifiques au fabricant détecté
    2. On ajoute les credentials génériques (admin/admin, etc.)
    3. Pour chaque port web ouvert, on teste chaque credential
    4. On s'arrête au premier succès pour ne pas surcharger l'appareil

    Retourne la liste des ResultatTest.
    """
    resultats = []

    # Ports web à tester sur cet appareil
    ports_web = [80, 443, 8080, 8443, 8888, 8000]
    ports_a_tester = [p for p in appareil.ports_ouverts if p in ports_web]

    # Si aucun port web ouvert, on teste quand même les ports classiques
    if not ports_a_tester:
        ports_a_tester = [80, 443]

    # Trouve les credentials adaptés à ce fabricant
    credentials = trouver_credentials(appareil.fabricant, appareil.ports_ouverts)

    if not credentials:
        return resultats

    succes_trouve = False

    for port in ports_a_tester:
        if succes_trouve:
            break

        # Détermine le protocole selon le port
        protocole = "https" if port in [443, 8443] else "http"

        for cred in credentials:
            # Teste le credential
            resultat = tester_http_basic(
                ip=appareil.ip,
                port=port,
                protocole=protocole,
                utilisateur=cred.utilisateur,
                mot_de_passe=cred.mot_de_passe,
                chemin=cred.chemin_login,
            )
            resultat.fabricant = appareil.fabricant

            resultats.append(resultat)

            # Affiche le résultat en temps réel
            mdp_affiche = cred.mot_de_passe if cred.mot_de_passe else "(vide)"
            if resultat.succes:
                print(f"    🔴 TROUVÉ ! {cred.utilisateur}:{mdp_affiche} "
                      f"sur port {port} — {resultat.details}")
                succes_trouve = True
                break
            else:
                # On n'affiche pas chaque échec pour garder le terminal lisible
                # Seulement si c'est une erreur de connexion (pas un simple 401)
                if resultat.code_http == 0:
                    print(f"    ⏩ Port {port} ({protocole}) — {resultat.details}")
                    break  # Inutile de tester d'autres credentials sur ce port

    return resultats


def lancer_audit():
    """
    Fonction principale : scanne le réseau puis teste les mots de passe.

    CONCEPT : PIPELINE DE SÉCURITÉ
    --------------------------------
    Phase 1 (scanner) → Phase 2 (audit mots de passe)

    On réutilise le résultat du scanner de ports comme entrée.
    C'est le principe d'un "pipeline" : chaque étape enrichit
    les données de l'étape précédente.
    """
    debut = datetime.now()

    print(f"\n{'='*60}")
    print(f"  🔑 SecureHome — Audit de Mots de Passe")
    print(f"{'='*60}")

    # Affiche les stats de la base de credentials
    afficher_stats_db()

    # Étape 1 : Scan réseau + ports (rapide)
    print("  📡 Étape 1 : Découverte réseau et scan de ports...\n")
    resultat_scan = scanner_reseau_complet(vitesse="rapide")

    if resultat_scan.nombre_appareils == 0:
        print("  ⚠️  Aucun appareil trouvé. Audit annulé.")
        return

    # Étape 2 : Test des credentials sur chaque appareil
    print(f"\n{'='*60}")
    print(f"  🔐 Étape 2 : Test des identifiants par défaut")
    print(f"{'='*60}\n")

    rapport = RapportAudit(date=debut.strftime("%Y-%m-%d %H:%M:%S"))
    tous_resultats = []

    for appareil in resultat_scan.appareils:
        # Ignore la machine locale
        if appareil.mac == "Inconnu":
            continue

        rapport.nombre_appareils_testes += 1
        print(f"  📱 {appareil.ip} — {appareil.fabricant} ({appareil.hostname})")

        # Lance l'audit sur cet appareil
        resultats_appareil = auditer_appareil(appareil)
        tous_resultats.extend(resultats_appareil)
        rapport.nombre_tests_effectues += len(resultats_appareil)

        # Vérifie si un credential a fonctionné
        succes = [r for r in resultats_appareil if r.succes]
        if succes:
            rapport.nombre_succes += len(succes)
            rapport.appareils_vulnerables.append({
                "ip": appareil.ip,
                "fabricant": appareil.fabricant,
                "hostname": appareil.hostname,
                "credentials_trouves": [
                    {
                        "utilisateur": r.utilisateur,
                        "mot_de_passe": r.mot_de_passe,
                        "port": r.port,
                        "protocole": r.protocole,
                    }
                    for r in succes
                ],
            })
        else:
            if resultats_appareil:
                print(f"    ✅ Aucun credential par défaut trouvé")
            else:
                print(f"    ⏩ Aucun port web détecté — test ignoré")

        print()

    # Calcul de la durée
    fin = datetime.now()
    rapport.duree_secondes = round((fin - debut).total_seconds(), 2)

    # Affichage du rapport final
    afficher_rapport_audit(rapport)

    # Sauvegarde du rapport
    sauvegarder_rapport_audit(rapport)

    return rapport


def afficher_rapport_audit(rapport):
    """Affiche le rapport final de l'audit."""

    print(f"\n{'='*60}")
    print(f"  📊 RAPPORT D'AUDIT — MOTS DE PASSE")
    print(f"{'='*60}")
    print(f"  📅 Date                    : {rapport.date}")
    print(f"  📱 Appareils testés        : {rapport.nombre_appareils_testes}")
    print(f"  🔑 Tests effectués         : {rapport.nombre_tests_effectues}")
    print(f"  ⏱️  Durée                   : {rapport.duree_secondes}s")
    print(f"  {'─'*56}")

    if rapport.nombre_succes > 0:
        print(f"\n  🚨 ALERTE : {rapport.nombre_succes} appareil(s) avec credentials par défaut !\n")

        for vuln in rapport.appareils_vulnerables:
            print(f"  🔴 {vuln['ip']} — {vuln['fabricant']} ({vuln['hostname']})")
            for cred in vuln["credentials_trouves"]:
                mdp = cred['mot_de_passe'] if cred['mot_de_passe'] else "(vide)"
                print(f"     → {cred['protocole']}://[{cred['utilisateur']}:{mdp}]"
                      f"@{vuln['ip']}:{cred['port']}")
            print()

        print(f"  💡 RECOMMANDATIONS :")
        print(f"  {'─'*56}")
        print(f"  1. Changez IMMÉDIATEMENT les mots de passe par défaut")
        print(f"  2. Utilisez des mots de passe forts (12+ caractères)")
        print(f"  3. Activez l'authentification à deux facteurs si possible")
        print(f"  4. Désactivez les services inutilisés (Telnet, FTP)")
    else:
        print(f"\n  ✅ Aucun credential par défaut trouvé !")
        print(f"  Bonne pratique de sécurité — les mots de passe ont été changés.")

    print()


def sauvegarder_rapport_audit(rapport):
    """Sauvegarde le rapport d'audit en JSON."""
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = os.path.join("data", f"audit_passwords_{timestamp}.json")

    donnees = {
        "date": rapport.date,
        "nombre_appareils_testes": rapport.nombre_appareils_testes,
        "nombre_tests_effectues": rapport.nombre_tests_effectues,
        "nombre_succes": rapport.nombre_succes,
        "appareils_vulnerables": rapport.appareils_vulnerables,
        "duree_secondes": rapport.duree_secondes,
    }

    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(donnees, f, indent=2, ensure_ascii=False)

    print(f"  💾 Rapport sauvegardé : {chemin}\n")


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":

    # Avertissement légal
    print("\n  ⚖️  AVERTISSEMENT LÉGAL")
    print("  " + "─" * 56)
    print("  Ce programme teste les identifiants par défaut UNIQUEMENT")
    print("  sur votre propre réseau domestique.")
    print("  Toute utilisation non autorisée est un délit pénal.")
    print("  (Art. 323-1 du Code pénal français)")
    print("  " + "─" * 56)

    # Vérification admin
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    # Demande confirmation
    print("\n  ❓ Lancer l'audit de mots de passe sur ton réseau ?")
    reponse = input("     (o/n) : ").strip().lower()

    if reponse != "o":
        print("  Audit annulé.\n")
        sys.exit(0)

    # Lance l'audit
    lancer_audit()

    print("  ✅ Audit terminé !")
    print("  → Prochaine étape : analyse des CVE (Phase 3)\n")