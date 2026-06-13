"""
SecureHome — Module Analyse CVE
=================================
Ce module recherche les failles de sécurité connues (CVE) pour
chaque appareil détecté sur le réseau.

CONCEPT : QU'EST-CE QU'UN CVE ?
---------------------------------
CVE = Common Vulnerabilities and Exposures
C'est un système mondial d'identification des failles de sécurité.

Chaque faille reçoit un identifiant unique :
  CVE-[année]-[numéro]
  Exemple : CVE-2023-44487 (faille HTTP/2 "Rapid Reset")

CONCEPT : CVSS (Common Vulnerability Scoring System)
-----------------------------------------------------
Chaque CVE reçoit un score de gravité de 0.0 à 10.0 :
  - 0.0       : Aucun impact
  - 0.1 - 3.9 : FAIBLE — peu d'impact, difficile à exploiter
  - 4.0 - 6.9 : MOYEN — impact modéré
  - 7.0 - 8.9 : ÉLEVÉ — impact important, exploitation probable
  - 9.0 - 10.0: CRITIQUE — impact maximum, exploitation facile

CONCEPT : API NVD (National Vulnerability Database)
----------------------------------------------------
Le NIST (National Institute of Standards and Technology) fournit
une API REST gratuite pour interroger leur base de CVE :
  https://services.nvd.nist.gov/rest/json/cves/2.0

On peut chercher par mot-clé (nom du fabricant, du produit) et
l'API renvoie les CVE correspondantes avec leur score CVSS.

Limites de l'API :
  - Sans clé API : 5 requêtes par 30 secondes
  - Avec clé API : 50 requêtes par 30 secondes
  On n'a pas besoin de clé pour notre usage domestique.
"""

import requests
import json
import os
import time
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

# Import de nos modules
from ..scanner.network_scanner import verifier_admin
from ..scanner.port_scanner import scanner_reseau_complet


# =============================================================================
# CONFIGURATION
# =============================================================================

# URL de l'API NVD (version 2.0)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Délai entre les requêtes API (en secondes) pour respecter les limites
DELAI_ENTRE_REQUETES = 6  # 5 requêtes max par 30 secondes → 6s entre chaque

# Nombre maximum de CVE à récupérer par appareil
MAX_CVE_PAR_APPAREIL = 10

# Dossier pour le cache local des CVE
DOSSIER_CACHE = os.path.join("data", "cache_cve")

# Durée de validité du cache (en heures)
# On ne re-télécharge pas les CVE si le cache a moins de 24h
DUREE_CACHE_HEURES = 24


@dataclass
class CVE:
    """
    Représente une faille de sécurité connue.

    CONCEPT : STRUCTURE D'UN CVE
    -----------------------------
    Chaque CVE contient :
    - Un identifiant unique (ex: CVE-2023-44487)
    - Une description du problème
    - Un score CVSS (gravité)
    - Les produits affectés
    - La date de publication
    """
    id_cve: str                     # Ex: "CVE-2023-44487"
    description: str = ""           # Description de la faille
    score_cvss: float = 0.0         # Score de gravité (0-10)
    severite: str = "INCONNUE"      # CRITIQUE, ÉLEVÉ, MOYEN, FAIBLE
    date_publication: str = ""      # Quand la faille a été publiée
    produits_affectes: list = field(default_factory=list)  # Liste des produits
    lien: str = ""                  # URL vers la page NVD du CVE
    vecteur_attaque: str = ""       # NETWORK, ADJACENT, LOCAL, PHYSICAL


@dataclass
class AnalyseCVE:
    """Résultat de l'analyse CVE pour un appareil."""
    ip: str
    fabricant: str
    hostname: str
    cves_trouvees: List[CVE] = field(default_factory=list)
    nombre_critiques: int = 0
    nombre_eleves: int = 0
    nombre_moyens: int = 0
    nombre_faibles: int = 0
    score_risque_max: float = 0.0


@dataclass
class RapportCVE:
    """Rapport complet de l'analyse CVE sur tout le réseau."""
    date: str = ""
    nombre_appareils_analyses: int = 0
    total_cves: int = 0
    appareils: List[AnalyseCVE] = field(default_factory=list)
    duree_secondes: float = 0.0


# =============================================================================
# CORRESPONDANCE FABRICANT → MOTS-CLÉS DE RECHERCHE
# =============================================================================
# L'API NVD cherche par mot-clé. On associe chaque fabricant détecté
# aux termes de recherche les plus pertinents pour trouver des CVE.

MOTS_CLES_FABRICANT = {
    # Box internet françaises
    "sagemcom": ["sagemcom", "sagemcom router"],
    "sagemcom broadband": ["sagemcom", "sagemcom router"],
    "freebox": ["freebox", "free mobile router"],
    "livebox": ["livebox", "orange livebox"],
    "sfr": ["sfr box", "sfr router"],
    "bouygues": ["bouygues bbox", "bbox"],

    # Routeurs
    "tp-link": ["tp-link", "tplink"],
    "asus": ["asus router", "asus rt-"],
    "netgear": ["netgear"],
    "d-link": ["d-link", "dlink"],
    "linksys": ["linksys"],

    # IoT et maison connectée
    "amazon": ["amazon echo", "amazon alexa"],
    "amazon technologies": ["amazon echo", "amazon alexa", "amazon fire"],
    "google": ["google home", "google nest"],
    "philips hue": ["philips hue"],
    "sonos": ["sonos"],
    "hikvision": ["hikvision"],
    "dahua": ["dahua"],
    "arcadyan": ["arcadyan"],

    # Micro-contrôleurs
    "espressif": ["esp32", "esp8266"],
    "raspberry pi": ["raspberry pi"],

    # Téléphones
    "samsung": ["samsung mobile"],
    "xiaomi": ["xiaomi"],
    "apple": ["apple ios"],
}


def classifier_severite(score):
    """
    Classifie un score CVSS en catégorie de sévérité.

    CONCEPT : ÉCHELLE CVSS v3.1
    ----------------------------
    Le CVSS v3.1 utilise cette échelle officielle :
      0.0       → AUCUN
      0.1 - 3.9 → FAIBLE
      4.0 - 6.9 → MOYEN
      7.0 - 8.9 → ÉLEVÉ
      9.0 - 10.0 → CRITIQUE
    """
    if score >= 9.0:
        return "CRITIQUE"
    elif score >= 7.0:
        return "ÉLEVÉ"
    elif score >= 4.0:
        return "MOYEN"
    elif score > 0:
        return "FAIBLE"
    else:
        return "AUCUN"


def obtenir_mots_cles(fabricant):
    """
    Trouve les mots-clés de recherche CVE pour un fabricant donné.

    On fait une recherche floue : si le fabricant détecté contient
    un des noms dans notre dictionnaire, on utilise ces mots-clés.
    """
    fabricant_lower = fabricant.lower()

    for cle, mots in MOTS_CLES_FABRICANT.items():
        if cle in fabricant_lower or fabricant_lower in cle:
            return mots

    # Si pas trouvé, on utilise le nom du fabricant directement
    # en nettoyant les suffixes courants (Inc, Ltd, SAS, etc.)
    nom_nettoye = fabricant_lower
    for suffixe in [" inc", " ltd", " sas", " gmbh", " corp", " technologies"]:
        nom_nettoye = nom_nettoye.replace(suffixe, "")
    nom_nettoye = nom_nettoye.strip()

    if nom_nettoye:
        return [nom_nettoye]
    return []


def charger_cache(mot_cle):
    """
    CONCEPT : CACHE LOCAL
    ----------------------
    Pour ne pas surcharger l'API NVD (et accélérer le programme),
    on sauvegarde les résultats de chaque recherche dans un fichier JSON.
    Si le cache existe et a moins de 24h, on le réutilise directement.

    C'est un pattern très courant en développement : le "cache".
    """
    os.makedirs(DOSSIER_CACHE, exist_ok=True)

    # Nom du fichier cache basé sur le mot-clé (nettoyé pour le filesystem)
    nom_fichier = mot_cle.replace(" ", "_").replace("/", "_") + ".json"
    chemin = os.path.join(DOSSIER_CACHE, nom_fichier)

    if not os.path.exists(chemin):
        return None

    # Vérifie si le cache n'est pas expiré
    date_modif = datetime.fromtimestamp(os.path.getmtime(chemin))
    if datetime.now() - date_modif > timedelta(hours=DUREE_CACHE_HEURES):
        return None  # Cache expiré

    try:
        with open(chemin, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def sauvegarder_cache(mot_cle, donnees):
    """Sauvegarde les résultats de recherche CVE dans le cache local."""
    os.makedirs(DOSSIER_CACHE, exist_ok=True)

    nom_fichier = mot_cle.replace(" ", "_").replace("/", "_") + ".json"
    chemin = os.path.join(DOSSIER_CACHE, nom_fichier)

    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(donnees, f, indent=2, ensure_ascii=False)


def rechercher_cves_nvd(mot_cle):
    """
    Interroge l'API NVD pour chercher des CVE par mot-clé.

    CONCEPT : REQUÊTE API REST
    ---------------------------
    On envoie une requête GET à l'API NVD avec des paramètres :
      - keywordSearch : le mot-clé à chercher
      - resultsPerPage : nombre max de résultats
      - keywordExactMatch : correspondance exacte (optionnel)

    L'API renvoie du JSON avec la liste des CVE trouvées.

    CONCEPT : GESTION DU RATE LIMITING
    ------------------------------------
    L'API NVD limite le nombre de requêtes par période.
    Si on dépasse, elle renvoie une erreur 403 ou 429.
    On attend DELAI_ENTRE_REQUETES secondes entre chaque requête.
    """
    # Vérifie d'abord le cache
    cache = charger_cache(mot_cle)
    if cache is not None:
        return cache

    # Paramètres de la requête
    params = {
        "keywordSearch": mot_cle,
        "resultsPerPage": MAX_CVE_PAR_APPAREIL,
    }

    # En-têtes HTTP (l'API NVD recommande de s'identifier)
    headers = {
        "User-Agent": "SecureHome/1.0 (Educational Security Auditor)",
    }

    try:
        reponse = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30,  # L'API NVD peut être lente
        )

        if reponse.status_code == 200:
            donnees = reponse.json()
            # Sauvegarde dans le cache
            sauvegarder_cache(mot_cle, donnees)
            return donnees

        elif reponse.status_code == 403 or reponse.status_code == 429:
            # Rate limited — on attend et on réessaie
            print(f"      ⏳ Rate limit atteint, attente 30s...")
            time.sleep(30)
            reponse = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30
            )
            if reponse.status_code == 200:
                donnees = reponse.json()
                sauvegarder_cache(mot_cle, donnees)
                return donnees

        print(f"      ⚠️  Erreur API NVD : HTTP {reponse.status_code}")
        return None

    except requests.exceptions.Timeout:
        print(f"      ⚠️  Timeout API NVD (30s) — serveur lent")
        return None
    except requests.exceptions.ConnectionError:
        print(f"      ❌ Impossible de contacter l'API NVD")
        print(f"         Vérifie ta connexion internet")
        return None
    except Exception as e:
        print(f"      ❌ Erreur inattendue : {str(e)[:60]}")
        return None


def extraire_cves(donnees_nvd):
    """
    Parse les données JSON de l'API NVD et crée des objets CVE.

    CONCEPT : PARSING JSON IMBRIQUÉ
    ---------------------------------
    L'API NVD renvoie du JSON très imbriqué. Par exemple, le score CVSS
    peut être dans :
      vulnerabilities[i].cve.metrics.cvssMetricV31[0].cvssData.baseScore

    On utilise .get() avec des valeurs par défaut à chaque niveau
    pour éviter les erreurs si un champ est absent.
    """
    cves = []

    if not donnees_nvd or "vulnerabilities" not in donnees_nvd:
        return cves

    for item in donnees_nvd["vulnerabilities"]:
        cve_data = item.get("cve", {})

        # --- Identifiant ---
        id_cve = cve_data.get("id", "")

        # --- Description ---
        # L'API fournit les descriptions en plusieurs langues
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        # Tronque la description si trop longue
        if len(description) > 200:
            description = description[:197] + "..."

        # --- Score CVSS ---
        # On cherche d'abord CVSS v3.1, puis v3.0, puis v2.0
        score_cvss = 0.0
        vecteur = ""
        metrics = cve_data.get("metrics", {})

        # CVSS v3.1 (le plus récent et précis)
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
            score_cvss = cvss.get("baseScore", 0.0)
            vecteur = cvss.get("attackVector", "")
        # CVSS v3.0 (fallback)
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
            score_cvss = cvss.get("baseScore", 0.0)
            vecteur = cvss.get("attackVector", "")
        # CVSS v2.0 (ancien format)
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
            score_cvss = cvss.get("baseScore", 0.0)
            vecteur = cvss.get("accessVector", "")

        # --- Date de publication ---
        date_pub = cve_data.get("published", "")[:10]  # Garde juste YYYY-MM-DD

        # --- Lien NVD ---
        lien = f"https://nvd.nist.gov/vuln/detail/{id_cve}"

        # --- Construction de l'objet CVE ---
        cve = CVE(
            id_cve=id_cve,
            description=description,
            score_cvss=score_cvss,
            severite=classifier_severite(score_cvss),
            date_publication=date_pub,
            lien=lien,
            vecteur_attaque=vecteur,
        )
        cves.append(cve)

    # Trie par score CVSS décroissant (les plus graves en premier)
    cves.sort(key=lambda c: c.score_cvss, reverse=True)

    return cves


def analyser_appareil(appareil):
    """
    Analyse les CVE pour un appareil donné.

    Stratégie :
    1. Détermine les mots-clés de recherche selon le fabricant
    2. Pour chaque mot-clé, interroge l'API NVD
    3. Déduplique les CVE trouvées (même CVE trouvée par plusieurs mots-clés)
    4. Classe par sévérité
    """
    analyse = AnalyseCVE(
        ip=appareil.ip,
        fabricant=appareil.fabricant,
        hostname=appareil.hostname,
    )

    # Trouve les mots-clés pour ce fabricant
    mots_cles = obtenir_mots_cles(appareil.fabricant)

    if not mots_cles:
        return analyse

    # Ensemble des CVE déjà trouvées (pour dédupliquer)
    cves_vues = set()

    for mot_cle in mots_cles:
        print(f"    🔍 Recherche : \"{mot_cle}\"...", end=" ", flush=True)

        # Interroge l'API NVD
        donnees = rechercher_cves_nvd(mot_cle)

        if donnees is None:
            print("❌ Erreur")
            continue

        # Extrait les CVE de la réponse
        cves = extraire_cves(donnees)

        # Compte les nouvelles CVE (pas encore vues)
        nouvelles = 0
        for cve in cves:
            if cve.id_cve not in cves_vues:
                cves_vues.add(cve.id_cve)
                analyse.cves_trouvees.append(cve)
                nouvelles += 1

        total = donnees.get("totalResults", 0)
        print(f"✅ {nouvelles} CVE (sur {total} résultats NVD)")

        # Respecte le rate limit de l'API
        time.sleep(DELAI_ENTRE_REQUETES)

    # --- Comptage par sévérité ---
    for cve in analyse.cves_trouvees:
        if cve.severite == "CRITIQUE":
            analyse.nombre_critiques += 1
        elif cve.severite == "ÉLEVÉ":
            analyse.nombre_eleves += 1
        elif cve.severite == "MOYEN":
            analyse.nombre_moyens += 1
        elif cve.severite == "FAIBLE":
            analyse.nombre_faibles += 1

        # Score max
        if cve.score_cvss > analyse.score_risque_max:
            analyse.score_risque_max = cve.score_cvss

    # Trie les CVE par score décroissant
    analyse.cves_trouvees.sort(key=lambda c: c.score_cvss, reverse=True)

    return analyse


def lancer_analyse_cve():
    """
    Fonction principale : scanne le réseau puis cherche les CVE.

    CONCEPT : PIPELINE ENRICHI
    ----------------------------
    Phase 1 (scanner) → Phase 2 (mots de passe) → Phase 3 (CVE)

    Chaque phase ajoute des informations aux données collectées.
    """
    debut = datetime.now()

    print(f"\n{'='*60}")
    print(f"  🛡️  SecureHome — Analyse CVE")
    print(f"{'='*60}")
    print(f"  Source : NIST National Vulnerability Database (NVD)")
    print(f"  API    : {NVD_API_URL}")
    print(f"  Cache  : {DOSSIER_CACHE} ({DUREE_CACHE_HEURES}h de validité)")
    print(f"{'='*60}")

    # Étape 1 : Scan réseau
    print(f"\n  📡 Étape 1 : Découverte réseau...\n")
    resultat_scan = scanner_reseau_complet(vitesse="rapide")

    if resultat_scan.nombre_appareils == 0:
        print("  ⚠️  Aucun appareil trouvé. Analyse annulée.")
        return

    # Étape 2 : Analyse CVE pour chaque appareil
    print(f"\n{'='*60}")
    print(f"  🔎 Étape 2 : Recherche de CVE par appareil")
    print(f"  ⏳ Peut prendre quelques minutes (respect du rate limit API)")
    print(f"{'='*60}\n")

    rapport = RapportCVE(date=debut.strftime("%Y-%m-%d %H:%M:%S"))

    for appareil in resultat_scan.appareils:
        # Ignore la machine locale et les fabricants inconnus
        if appareil.mac == "Inconnu" or appareil.fabricant == "Inconnu":
            continue

        rapport.nombre_appareils_analyses += 1
        print(f"  📱 {appareil.ip} — {appareil.fabricant} ({appareil.hostname})")

        # Lance l'analyse CVE
        analyse = analyser_appareil(appareil)
        rapport.appareils.append(analyse)
        rapport.total_cves += len(analyse.cves_trouvees)

        # Résumé pour cet appareil
        if analyse.cves_trouvees:
            print(f"    📊 {len(analyse.cves_trouvees)} CVE trouvées "
                  f"(max CVSS: {analyse.score_risque_max})")
        else:
            print(f"    ✅ Aucune CVE trouvée")
        print()

    # Calcul de la durée
    fin = datetime.now()
    rapport.duree_secondes = round((fin - debut).total_seconds(), 2)

    # Affichage du rapport
    afficher_rapport_cve(rapport)

    # Sauvegarde
    sauvegarder_rapport_cve(rapport)

    return rapport


def afficher_rapport_cve(rapport):
    """Affiche le rapport détaillé des CVE trouvées."""

    print(f"\n{'='*60}")
    print(f"  📊 RAPPORT CVE — FAILLES CONNUES")
    print(f"{'='*60}")
    print(f"  📅 Date              : {rapport.date}")
    print(f"  📱 Appareils analysés: {rapport.nombre_appareils_analyses}")
    print(f"  🛡️  CVE totales       : {rapport.total_cves}")
    print(f"  ⏱️  Durée             : {rapport.duree_secondes}s")
    print(f"{'='*60}\n")

    if rapport.total_cves == 0:
        print("  ✅ Aucune CVE connue trouvée pour les appareils du réseau.")
        print("  Cela ne garantit pas l'absence de failles, mais c'est bon signe.\n")
        return

    for analyse in rapport.appareils:
        if not analyse.cves_trouvees:
            continue

        # En-tête de l'appareil
        print(f"  📱 {analyse.ip} — {analyse.fabricant} ({analyse.hostname})")
        print(f"  {'─'*56}")
        print(f"    CVE: {len(analyse.cves_trouvees)} | "
              f"🔴 {analyse.nombre_critiques} critiques | "
              f"🟠 {analyse.nombre_eleves} élevées | "
              f"🟡 {analyse.nombre_moyens} moyennes | "
              f"🟢 {analyse.nombre_faibles} faibles")
        print()

        # Détail des CVE (les 5 plus graves)
        for i, cve in enumerate(analyse.cves_trouvees[:5], 1):
            # Icône selon la sévérité
            icones = {
                "CRITIQUE": "🔴",
                "ÉLEVÉ": "🟠",
                "MOYEN": "🟡",
                "FAIBLE": "🟢",
                "AUCUN": "⚪",
                "INCONNUE": "⚪",
            }
            icone = icones.get(cve.severite, "⚪")

            print(f"    {icone} {cve.id_cve} — CVSS {cve.score_cvss} ({cve.severite})")
            print(f"       {cve.description}")
            if cve.vecteur_attaque:
                print(f"       Vecteur : {cve.vecteur_attaque} | Publié : {cve.date_publication}")
            print(f"       🔗 {cve.lien}")
            print()

        # Si plus de 5 CVE, indique combien ne sont pas affichées
        restantes = len(analyse.cves_trouvees) - 5
        if restantes > 0:
            print(f"    ... et {restantes} autres CVE. Voir le rapport JSON.\n")

    # Résumé global
    total_critiques = sum(a.nombre_critiques for a in rapport.appareils)
    total_eleves = sum(a.nombre_eleves for a in rapport.appareils)

    print(f"  {'='*56}")
    print(f"  📈 RÉSUMÉ GLOBAL")
    print(f"  {'─'*56}")

    if total_critiques > 0:
        print(f"  🚨 {total_critiques} CVE CRITIQUES détectées !")
        print(f"     → Mettez à jour le firmware de vos appareils")
        print(f"     → Consultez le site du fabricant pour les correctifs")
    elif total_eleves > 0:
        print(f"  ⚠️  {total_eleves} CVE de niveau ÉLEVÉ détectées.")
        print(f"     → Vérifiez les mises à jour disponibles")
    else:
        print(f"  ✅ Aucune CVE critique ou élevée. Bon niveau de sécurité !")

    print()


def sauvegarder_rapport_cve(rapport):
    """Sauvegarde le rapport CVE en JSON."""
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = os.path.join("data", f"rapport_cve_{timestamp}.json")

    # Convertit les objets en dictionnaires
    donnees = {
        "date": rapport.date,
        "nombre_appareils_analyses": rapport.nombre_appareils_analyses,
        "total_cves": rapport.total_cves,
        "duree_secondes": rapport.duree_secondes,
        "appareils": [],
    }

    for analyse in rapport.appareils:
        appareil_dict = {
            "ip": analyse.ip,
            "fabricant": analyse.fabricant,
            "hostname": analyse.hostname,
            "nombre_critiques": analyse.nombre_critiques,
            "nombre_eleves": analyse.nombre_eleves,
            "nombre_moyens": analyse.nombre_moyens,
            "nombre_faibles": analyse.nombre_faibles,
            "score_risque_max": analyse.score_risque_max,
            "cves": [asdict(cve) for cve in analyse.cves_trouvees],
        }
        donnees["appareils"].append(appareil_dict)

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
    print("  Ce programme analyse les failles connues des appareils")
    print("  de votre réseau domestique via la base publique NVD/NIST.")
    print("  " + "─" * 56)

    # Vérification admin
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    # Lance l'analyse
    lancer_analyse_cve()

    print("  ✅ Analyse CVE terminée !")
    print("  → Prochaine étape : Score de sécurité automatique (Phase 4)\n")