"""
SecureHome — Module Score de Sécurité
=======================================
Ce module calcule un score de sécurité (0-100) pour chaque appareil
et pour l'ensemble du réseau domestique.

CONCEPT : SCORING PONDÉRÉ
---------------------------
Le score final est calculé à partir de plusieurs critères, chacun
ayant un "poids" (importance relative) différent :

  Critère                    Poids    Pourquoi ?
  ─────────────────────────  ─────    ──────────────────────────────
  Mots de passe par défaut    35%     Faille n°1 sur les IoT
  CVE critiques/élevées       30%     Failles exploitables connues
  Ports dangereux ouverts     20%     Surface d'attaque exposée
  Chiffrement (HTTPS)         15%     Protection des communications

Le score commence à 100 (parfait) et on SOUSTRAIT des points
pour chaque problème trouvé. Plus le score est bas, plus le
réseau est vulnérable.

CONCEPT : NORMALISATION
-------------------------
Pour que le score reste entre 0 et 100, on utilise la normalisation :
  score_final = max(0, min(100, score_calculé))
Ça empêche d'avoir un score négatif ou supérieur à 100.

CONCEPT : SEUILS DE DÉCISION
------------------------------
  90-100  : Excellent ✅  — Réseau bien sécurisé
  70-89   : Bon 🟢       — Quelques améliorations possibles
  50-69   : Moyen 🟡     — Risques modérés, actions recommandées
  30-49   : Faible 🟠    — Risques importants, actions nécessaires
  0-29    : Critique 🔴  — Réseau très vulnérable, actions urgentes
"""

import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

# Import de nos modules
from ..scanner.network_scanner import verifier_admin
from ..scanner.port_scanner import (
    scanner_reseau_complet,
    RISQUE_PORT,
)
from ..analyzer.credential_db import trouver_credentials
from ..analyzer.password_auditor import tester_http_basic
from ..analyzer.cve_analyzer import (
    analyser_appareil as analyser_cve_appareil,
    classifier_severite,
)


# =============================================================================
# POIDS DES CRITÈRES (doivent totaliser 100)
# =============================================================================

POIDS = {
    "mots_de_passe": 35,   # Credential par défaut = la pire faille
    "cve": 30,             # Failles connues
    "ports": 20,           # Ports dangereux ouverts
    "chiffrement": 15,     # HTTPS vs HTTP
}

# Vérification que les poids totalisent 100
assert sum(POIDS.values()) == 100, "Les poids doivent totaliser 100 !"


# =============================================================================
# PÉNALITÉS PAR TYPE DE PROBLÈME
# =============================================================================
# Chaque problème détecté retire un certain nombre de points.

PENALITES = {
    # Mots de passe
    "mdp_defaut_trouve": 35,          # Credential par défaut trouvé = score 0 sur ce critère
    "mdp_port_web_sans_auth": 10,     # Port web ouvert sans authentification

    # CVE par sévérité
    "cve_critique": 15,               # Chaque CVE critique
    "cve_elevee": 8,                  # Chaque CVE élevée
    "cve_moyenne": 3,                 # Chaque CVE moyenne
    "cve_faible": 1,                  # Chaque CVE faible

    # Ports par niveau de risque
    "port_critique": 20,              # Telnet, etc.
    "port_eleve": 10,                 # FTP, SMB, Redis...
    "port_moyen": 3,                  # HTTP, SSH...
    "port_faible": 1,                 # HTTPS

    # Chiffrement
    "http_sans_https": 15,            # Interface web en HTTP sans HTTPS
    "pas_interface_web": 0,           # Pas d'interface web = neutre
}


@dataclass
class ScoreAppareil:
    """Score de sécurité détaillé pour un appareil."""
    ip: str
    fabricant: str
    hostname: str
    mac: str = ""

    # Score global
    score_global: int = 100
    note: str = "A+"
    couleur: str = "🟢"

    # Scores par critère (chacun sur le poids du critère)
    score_mots_de_passe: int = 0
    score_cve: int = 0
    score_ports: int = 0
    score_chiffrement: int = 0

    # Détails des problèmes trouvés
    problemes: list = field(default_factory=list)
    recommandations: list = field(default_factory=list)

    # Données brutes
    ports_ouverts: list = field(default_factory=list)
    mdp_defaut_trouve: bool = False
    nombre_cve: int = 0
    cve_critiques: int = 0
    cve_elevees: int = 0


@dataclass
class ScoreReseau:
    """Score de sécurité global du réseau."""
    date: str = ""
    score_global: int = 100
    note: str = "A+"
    couleur: str = "🟢"
    nombre_appareils: int = 0
    appareils: List[ScoreAppareil] = field(default_factory=list)
    resume_problemes: list = field(default_factory=list)
    resume_recommandations: list = field(default_factory=list)
    duree_secondes: float = 0.0


def attribuer_note(score):
    """
    Convertit un score numérique en note lettrée.

    CONCEPT : CLASSIFICATION PAR SEUILS
    --------------------------------------
    On utilise des seuils prédéfinis pour transformer un nombre
    en catégorie compréhensible. C'est le même principe que les
    notes scolaires A/B/C/D/F.
    """
    if score >= 90:
        return "A+", "🟢", "Excellent"
    elif score >= 80:
        return "A", "🟢", "Très bon"
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


def calculer_score_mots_de_passe(appareil, score_appareil):
    """
    Calcule le score pour le critère "mots de passe".

    Score max = POIDS["mots_de_passe"] (35 points)
    - Si credential par défaut trouvé → 0 points (pénalité totale)
    - Si aucun credential trouvé → 35 points (score max)
    """
    score = POIDS["mots_de_passe"]  # Commence au max

    # Ports web à tester
    ports_web = [80, 443, 8080, 8443, 8888, 8000]
    ports_web_ouverts = [p for p in appareil.ports_ouverts if p in ports_web]

    if not ports_web_ouverts:
        # Pas de port web ouvert = pas de risque de credential web
        score_appareil.score_mots_de_passe = score
        return score

    # Teste les credentials par défaut
    credentials = trouver_credentials(appareil.fabricant, appareil.ports_ouverts)

    for port in ports_web_ouverts:
        protocole = "https" if port in [443, 8443] else "http"

        for cred in credentials:
            resultat = tester_http_basic(
                ip=appareil.ip,
                port=port,
                protocole=protocole,
                utilisateur=cred.utilisateur,
                mot_de_passe=cred.mot_de_passe,
                chemin=cred.chemin_login,
            )

            if resultat.succes:
                penalite = PENALITES["mdp_defaut_trouve"]
                score = max(0, score - penalite)
                score_appareil.mdp_defaut_trouve = True
                score_appareil.problemes.append(
                    f"🔴 Mot de passe par défaut trouvé : "
                    f"{cred.utilisateur}/{cred.mot_de_passe} "
                    f"sur port {port}"
                )
                score_appareil.recommandations.append(
                    "Changez IMMÉDIATEMENT le mot de passe par défaut. "
                    "Utilisez un mot de passe fort (12+ caractères, "
                    "avec majuscules, chiffres et symboles)."
                )
                # On arrête dès le premier succès
                score_appareil.score_mots_de_passe = score
                return score

    score_appareil.score_mots_de_passe = score
    return score


def calculer_score_cve(appareil, score_appareil):
    """
    Calcule le score pour le critère "CVE".

    Score max = POIDS["cve"] (30 points)
    Pénalités cumulatives par sévérité de CVE trouvée.
    Le score est plafonné à 0 minimum (pas de négatif).
    """
    score = POIDS["cve"]

    # Analyse CVE de l'appareil
    print(f"      🔍 Recherche CVE...", end=" ", flush=True)
    analyse = analyser_cve_appareil(appareil)

    score_appareil.nombre_cve = len(analyse.cves_trouvees)
    score_appareil.cve_critiques = analyse.nombre_critiques
    score_appareil.cve_elevees = analyse.nombre_eleves

    # Applique les pénalités
    penalite_totale = 0
    penalite_totale += analyse.nombre_critiques * PENALITES["cve_critique"]
    penalite_totale += analyse.nombre_eleves * PENALITES["cve_elevee"]
    penalite_totale += analyse.nombre_moyens * PENALITES["cve_moyenne"]
    penalite_totale += analyse.nombre_faibles * PENALITES["cve_faible"]

    score = max(0, score - penalite_totale)

    # Ajoute les problèmes détectés
    if analyse.nombre_critiques > 0:
        score_appareil.problemes.append(
            f"🔴 {analyse.nombre_critiques} CVE critique(s) connue(s)"
        )
        score_appareil.recommandations.append(
            "Mettez à jour le firmware de l'appareil. "
            "Consultez le site du fabricant pour les correctifs."
        )
    if analyse.nombre_eleves > 0:
        score_appareil.problemes.append(
            f"🟠 {analyse.nombre_eleves} CVE de niveau élevé"
        )

    print(f"✅ {len(analyse.cves_trouvees)} CVE")
    score_appareil.score_cve = score
    return score


def calculer_score_ports(appareil, score_appareil):
    """
    Calcule le score pour le critère "ports ouverts".

    Score max = POIDS["ports"] (20 points)
    Chaque port ouvert retire des points selon son niveau de risque.
    """
    score = POIDS["ports"]

    score_appareil.ports_ouverts = list(appareil.ports_ouverts)

    for port in appareil.ports_ouverts:
        risque = RISQUE_PORT.get(port, "INFO")

        if risque == "CRITIQUE":
            score = max(0, score - PENALITES["port_critique"])
            score_appareil.problemes.append(
                f"🔴 Port {port} ouvert — risque CRITIQUE"
            )
            score_appareil.recommandations.append(
                f"Fermez le port {port} ou désactivez le service associé."
            )
        elif risque == "ÉLEVÉ":
            score = max(0, score - PENALITES["port_eleve"])
            score_appareil.problemes.append(
                f"🟠 Port {port} ouvert — risque élevé"
            )
        elif risque == "MOYEN":
            score = max(0, score - PENALITES["port_moyen"])
        elif risque == "FAIBLE":
            score = max(0, score - PENALITES["port_faible"])

    score_appareil.score_ports = score
    return score


def calculer_score_chiffrement(appareil, score_appareil):
    """
    Calcule le score pour le critère "chiffrement".

    Score max = POIDS["chiffrement"] (15 points)
    - Si l'appareil a HTTPS (443, 8443) → bon
    - Si l'appareil a HTTP sans HTTPS → mauvais
    - Si pas d'interface web → neutre (score max)
    """
    score = POIDS["chiffrement"]

    ports_http = [80, 8080, 8888, 8000]
    ports_https = [443, 8443]

    a_http = any(p in appareil.ports_ouverts for p in ports_http)
    a_https = any(p in appareil.ports_ouverts for p in ports_https)

    if a_http and not a_https:
        # HTTP sans HTTPS = pas de chiffrement
        score = max(0, score - PENALITES["http_sans_https"])
        score_appareil.problemes.append(
            "🟡 Interface web en HTTP (non chiffrée)"
        )
        score_appareil.recommandations.append(
            "Activez HTTPS sur l'interface d'administration "
            "pour chiffrer les communications."
        )
    elif a_http and a_https:
        # HTTP + HTTPS = acceptable mais pourrait forcer HTTPS
        score = max(0, score - 3)  # Petite pénalité
        score_appareil.problemes.append(
            "🟡 HTTP et HTTPS actifs — HTTP devrait être désactivé"
        )

    score_appareil.score_chiffrement = score
    return score


def calculer_score_appareil(appareil):
    """
    Calcule le score de sécurité complet pour UN appareil.

    CONCEPT : AGRÉGATION PONDÉRÉE
    --------------------------------
    Le score global est la somme des scores de chaque critère :
      score_global = score_mdp + score_cve + score_ports + score_chiffrement

    Comme chaque critère a son propre poids (35+30+20+15=100),
    le résultat est automatiquement sur 100.
    """
    score_appareil = ScoreAppareil(
        ip=appareil.ip,
        fabricant=appareil.fabricant,
        hostname=appareil.hostname,
        mac=appareil.mac,
    )

    print(f"\n  📱 {appareil.ip} — {appareil.fabricant} ({appareil.hostname})")
    print(f"  {'─'*56}")

    # Calcul de chaque critère
    print(f"    🔑 Mots de passe...", end=" ", flush=True)
    s_mdp = calculer_score_mots_de_passe(appareil, score_appareil)
    print(f"{'✅' if s_mdp == POIDS['mots_de_passe'] else '⚠️'} {s_mdp}/{POIDS['mots_de_passe']}")

    s_cve = calculer_score_cve(appareil, score_appareil)
    print(f"      Score CVE : {s_cve}/{POIDS['cve']}")

    print(f"    🔌 Ports ouverts...", end=" ", flush=True)
    s_ports = calculer_score_ports(appareil, score_appareil)
    print(f"{'✅' if s_ports == POIDS['ports'] else '⚠️'} {s_ports}/{POIDS['ports']}")

    print(f"    🔒 Chiffrement...", end=" ", flush=True)
    s_chiffr = calculer_score_chiffrement(appareil, score_appareil)
    print(f"{'✅' if s_chiffr == POIDS['chiffrement'] else '⚠️'} {s_chiffr}/{POIDS['chiffrement']}")

    # Score global = somme des scores par critère
    score_appareil.score_global = s_mdp + s_cve + s_ports + s_chiffr

    # Normalisation (entre 0 et 100)
    score_appareil.score_global = max(0, min(100, score_appareil.score_global))

    # Attribution de la note
    note, couleur, _ = attribuer_note(score_appareil.score_global)
    score_appareil.note = note
    score_appareil.couleur = couleur

    print(f"\n    📊 SCORE : {couleur} {score_appareil.score_global}/100 ({note})")

    return score_appareil


def calculer_score_reseau():
    """
    Fonction principale : calcule le score de sécurité de tout le réseau.

    Le score global du réseau est la MOYENNE pondérée des scores
    de chaque appareil, avec un poids plus fort pour les appareils
    critiques (routeur, caméras) que pour les simples clients (téléphone).
    """
    debut = datetime.now()

    print(f"\n{'='*60}")
    print(f"  📊 SecureHome — Score de Sécurité")
    print(f"{'='*60}")
    print(f"  Algorithme : scoring pondéré multi-critères")
    print(f"  Critères   : mots de passe ({POIDS['mots_de_passe']}%), "
          f"CVE ({POIDS['cve']}%), ports ({POIDS['ports']}%), "
          f"chiffrement ({POIDS['chiffrement']}%)")
    print(f"{'='*60}")

    # Étape 1 : Scan réseau + ports
    print(f"\n  📡 Étape 1 : Scan réseau et ports...\n")
    resultat_scan = scanner_reseau_complet(vitesse="rapide")

    if resultat_scan.nombre_appareils == 0:
        print("  ⚠️  Aucun appareil trouvé.")
        return

    # Étape 2 : Calcul du score pour chaque appareil
    print(f"\n{'='*60}")
    print(f"  🔐 Étape 2 : Calcul des scores de sécurité")
    print(f"{'='*60}")

    score_reseau = ScoreReseau(
        date=debut.strftime("%Y-%m-%d %H:%M:%S"),
    )

    for appareil in resultat_scan.appareils:
        # Ignore la machine locale et les appareils inconnus
        if appareil.mac == "Inconnu":
            continue

        score = calculer_score_appareil(appareil)
        score_reseau.appareils.append(score)

    score_reseau.nombre_appareils = len(score_reseau.appareils)

    # Étape 3 : Score global du réseau
    if score_reseau.appareils:
        # Le score réseau = moyenne des scores appareils
        # MAIS le score le plus bas a un impact majoré (le maillon faible)
        scores = [a.score_global for a in score_reseau.appareils]
        moyenne = sum(scores) / len(scores)
        minimum = min(scores)

        # Le score réseau combine la moyenne (60%) et le minimum (40%)
        # Parce qu'un réseau est aussi sûr que son maillon le plus faible
        score_reseau.score_global = round(moyenne * 0.6 + minimum * 0.4)
        score_reseau.score_global = max(0, min(100, score_reseau.score_global))

    note, couleur, description = attribuer_note(score_reseau.score_global)
    score_reseau.note = note
    score_reseau.couleur = couleur

    # Collecte les problèmes et recommandations uniques
    problemes_vus = set()
    recos_vues = set()
    for appareil in score_reseau.appareils:
        for p in appareil.problemes:
            if p not in problemes_vus:
                problemes_vus.add(p)
                score_reseau.resume_problemes.append(p)
        for r in appareil.recommandations:
            if r not in recos_vues:
                recos_vues.add(r)
                score_reseau.resume_recommandations.append(r)

    # Calcul durée
    fin = datetime.now()
    score_reseau.duree_secondes = round((fin - debut).total_seconds(), 2)

    # Affichage
    afficher_rapport_score(score_reseau)

    # Sauvegarde
    sauvegarder_rapport_score(score_reseau)

    return score_reseau


def afficher_rapport_score(score_reseau):
    """Affiche le rapport de score de sécurité complet."""

    print(f"\n{'='*60}")
    print(f"  📊 RAPPORT DE SÉCURITÉ — SCORE GLOBAL")
    print(f"{'='*60}\n")

    # Grande bannière avec le score
    note, couleur, description = attribuer_note(score_reseau.score_global)

    print(f"  ┌────────────────────────────────────────────┐")
    print(f"  │                                            │")
    print(f"  │   {couleur}  SCORE RÉSEAU : {score_reseau.score_global}/100  ({note})          │")
    print(f"  │      {description:<38} │")
    print(f"  │                                            │")
    print(f"  └────────────────────────────────────────────┘\n")

    # Barre de progression visuelle
    barre_pleine = score_reseau.score_global // 2  # Sur 50 caractères
    barre_vide = 50 - barre_pleine
    if score_reseau.score_global >= 70:
        couleur_barre = "🟢"
    elif score_reseau.score_global >= 50:
        couleur_barre = "🟡"
    elif score_reseau.score_global >= 30:
        couleur_barre = "🟠"
    else:
        couleur_barre = "🔴"

    print(f"  {couleur_barre} [{'█' * barre_pleine}{'░' * barre_vide}] {score_reseau.score_global}%\n")

    # Détail par appareil
    print(f"  📱 SCORES PAR APPAREIL")
    print(f"  {'─'*56}")

    # Trie les appareils par score croissant (les pires en premier)
    appareils_tries = sorted(score_reseau.appareils, key=lambda a: a.score_global)

    for appareil in appareils_tries:
        note_a, couleur_a, _ = attribuer_note(appareil.score_global)
        barre = appareil.score_global // 5  # Sur 20 caractères
        vide = 20 - barre

        print(f"  {couleur_a} {appareil.score_global:>3}/100 ({note_a:<2}) "
              f"[{'█' * barre}{'░' * vide}] "
              f"{appareil.fabricant[:15]:<15} {appareil.ip}")

    # Détail des critères pour chaque appareil
    print(f"\n  📋 DÉTAIL DES CRITÈRES")
    print(f"  {'─'*56}")
    print(f"  {'Appareil':<18} {'MDP':>5} {'CVE':>5} {'Ports':>5} {'Chiffr.':>7} {'TOTAL':>6}")
    print(f"  {'─'*18} {'─'*5} {'─'*5} {'─'*5} {'─'*7} {'─'*6}")

    for a in appareils_tries:
        nom = a.fabricant[:16]
        print(f"  {nom:<18} {a.score_mots_de_passe:>4}  {a.score_cve:>4}  "
              f"{a.score_ports:>4}   {a.score_chiffrement:>4}   {a.score_global:>4}")

    print(f"  {'─'*18} {'─'*5} {'─'*5} {'─'*5} {'─'*7} {'─'*6}")
    print(f"  {'Max possible':<18} {POIDS['mots_de_passe']:>4}  {POIDS['cve']:>4}  "
          f"{POIDS['ports']:>4}   {POIDS['chiffrement']:>4}    100")

    # Problèmes détectés
    if score_reseau.resume_problemes:
        print(f"\n  ⚠️  PROBLÈMES DÉTECTÉS")
        print(f"  {'─'*56}")
        for i, probleme in enumerate(score_reseau.resume_problemes, 1):
            print(f"    {i}. {probleme}")

    # Recommandations
    if score_reseau.resume_recommandations:
        print(f"\n  💡 RECOMMANDATIONS")
        print(f"  {'─'*56}")
        for i, reco in enumerate(score_reseau.resume_recommandations, 1):
            print(f"    {i}. {reco}")

    # Infos supplémentaires
    print(f"\n  📅 Date  : {score_reseau.date}")
    print(f"  ⏱️  Durée : {score_reseau.duree_secondes}s")
    print()


def sauvegarder_rapport_score(score_reseau):
    """Sauvegarde le rapport de score en JSON."""
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = os.path.join("data", f"score_securite_{timestamp}.json")

    donnees = {
        "date": score_reseau.date,
        "score_global": score_reseau.score_global,
        "note": score_reseau.note,
        "nombre_appareils": score_reseau.nombre_appareils,
        "duree_secondes": score_reseau.duree_secondes,
        "problemes": score_reseau.resume_problemes,
        "recommandations": score_reseau.resume_recommandations,
        "appareils": [],
    }

    for a in score_reseau.appareils:
        appareil_dict = {
            "ip": a.ip,
            "fabricant": a.fabricant,
            "hostname": a.hostname,
            "mac": a.mac,
            "score_global": a.score_global,
            "note": a.note,
            "scores_detail": {
                "mots_de_passe": a.score_mots_de_passe,
                "cve": a.score_cve,
                "ports": a.score_ports,
                "chiffrement": a.score_chiffrement,
            },
            "problemes": a.problemes,
            "recommandations": a.recommandations,
            "mdp_defaut_trouve": a.mdp_defaut_trouve,
            "nombre_cve": a.nombre_cve,
            "ports_ouverts": a.ports_ouverts,
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
    print("  Ce programme audite la sécurité de votre réseau domestique.")
    print("  Utilisation sur des réseaux non autorisés = délit pénal.")
    print("  (Art. 323-1 du Code pénal français)")
    print("  " + "─" * 56)

    # Vérification admin
    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    # Lance le scoring complet
    calculer_score_reseau()

    print("  ✅ Scoring terminé !")
    print("  → Prochaine étape : Alertes Android (Phase 5)\n")