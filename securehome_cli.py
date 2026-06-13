"""
SecureHome — Point d'Entrée Principal
========================================
Lance SecureHome avec une seule commande :
    python main.py

Un menu interactif te permet de choisir quelle fonctionnalité lancer.
"""

import sys
import os

# Ajoute le dossier courant au path pour les imports
sys.path.insert(0, os.path.dirname(__file__))

from securehome.scanner.network_scanner import verifier_admin


BANNER = """
  ╔════════════════════════════════════════════════════════╗
  ║                                                        ║
  ║   🏠🔒  SecureHome v1.0                                ║
  ║   Auditeur de sécurité pour maisons connectées         ║
  ║                                                        ║
  ╚════════════════════════════════════════════════════════╝
"""

MENU = """
  Que veux-tu faire ?
  ──────────────────────────────────────────────────

    1. 📡  Scan réseau          — Découvrir les appareils
    2. 🔌  Scan de ports        — Détecter les services ouverts
    3. 🔑  Audit mots de passe  — Tester les credentials par défaut
    4. 🛡️   Analyse CVE          — Chercher les failles connues
    5. 📊  Score de sécurité    — Calculer la note du réseau
    6. 📱  Alertes Android      — Configurer les notifications
    7. 📄  Rapport PDF          — Générer un document complet
    8. 🌐  Dashboard web        — Lancer l'interface graphique
    9. 🔄  Scan complet         — Tout lancer d'un coup (1→5)
    0. ❌  Quitter

  ──────────────────────────────────────────────────
"""


def lancer_scan_reseau():
    from securehome.scanner.network_scanner import scanner_reseau, afficher_resultats, sauvegarder_resultats
    resultat = scanner_reseau()
    afficher_resultats(resultat)
    sauvegarder_resultats(resultat)


def lancer_scan_ports():
    from securehome.scanner.port_scanner import scanner_reseau_complet, afficher_rapport_ports
    resultat = scanner_reseau_complet(vitesse="rapide")
    afficher_rapport_ports(resultat)


def lancer_audit_mdp():
    from securehome.analyzer.password_auditor import lancer_audit
    lancer_audit()


def lancer_analyse_cve():
    from securehome.analyzer.cve_analyzer import lancer_analyse_cve
    lancer_analyse_cve()


def lancer_scoring():
    from securehome.scoring.security_score import calculer_score_reseau
    calculer_score_reseau()


def lancer_alertes():
    from securehome.alerts.notifier import configurer_topic, lancer_scan_avec_alertes, mode_surveillance

    print(f"\n  📱 ALERTES ANDROID")
    print(f"    1. Configurer le topic ntfy")
    print(f"    2. Scan avec alertes")
    print(f"    3. Mode surveillance continue")
    print(f"    4. Notification de test")

    choix = input(f"\n  Ton choix (1/2/3/4) : ").strip()

    if choix == "1":
        configurer_topic()
    elif choix == "2":
        lancer_scan_avec_alertes()
    elif choix == "3":
        mode_surveillance()
    elif choix == "4":
        from securehome.alerts.notifier import charger_config, envoyer_notification
        config = charger_config()
        if not config.topic:
            configurer_topic()
            config = charger_config()
        if config.topic:
            succes = envoyer_notification(
                topic=config.topic,
                titre="SecureHome — Test",
                message="Notification de test OK !",
                priorite=3,
                tags=["white_check_mark", "house"],
            )
            print(f"  {'✅ Envoyée !' if succes else '❌ Échec'}")


def lancer_rapport_pdf():
    from securehome.reports.pdf_report import lancer_rapport
    chemin = lancer_rapport()
    if chemin:
        ouvrir = input("  Ouvrir le PDF ? (o/n) : ").strip().lower()
        if ouvrir == "o":
            os.startfile(chemin)


def lancer_dashboard():
    from securehome.web.app import app
    print(f"\n  🌐 Dashboard web")
    print(f"  📡 Ouvre ton navigateur à : http://127.0.0.1:5000")
    print(f"  📱 Depuis ton téléphone   : http://192.168.1.140:5000")
    print(f"  ⏹️  Ctrl+C pour arrêter\n")
    app.run(host="0.0.0.0", port=5000, debug=False)


def lancer_scan_complet():
    print(f"\n  🔄 SCAN COMPLET — Toutes les phases")
    print(f"  {'─'*50}")
    print(f"  Phase 1 → Scan réseau")
    print(f"  Phase 2 → Scan de ports")
    print(f"  Phase 3 → Audit mots de passe")
    print(f"  Phase 4 → Analyse CVE")
    print(f"  Phase 5 → Score de sécurité")
    print(f"  {'─'*50}\n")

    confirmer = input("  Lancer ? (o/n) : ").strip().lower()
    if confirmer != "o":
        print("  Annulé.")
        return

    from securehome.scoring.security_score import calculer_score_reseau
    calculer_score_reseau()


def main():
    print(BANNER)

    # Avertissement légal
    print("  ⚖️  Usage exclusif sur votre propre réseau domestique.")
    print("  Scanner un réseau sans autorisation = délit pénal.\n")

    # Vérification admin
    if not verifier_admin():
        print("  ⚠️  Lance ce programme en Administrateur !")
        print("  → Clic droit sur VS Code → Exécuter en tant qu'admin\n")
        sys.exit(1)

    actions = {
        "1": lancer_scan_reseau,
        "2": lancer_scan_ports,
        "3": lancer_audit_mdp,
        "4": lancer_analyse_cve,
        "5": lancer_scoring,
        "6": lancer_alertes,
        "7": lancer_rapport_pdf,
        "8": lancer_dashboard,
        "9": lancer_scan_complet,
    }

    while True:
        print(MENU)
        choix = input("  Ton choix : ").strip()

        if choix == "0":
            print("\n  👋 À bientôt !\n")
            break

        action = actions.get(choix)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n\n  ⏹️  Interrompu.\n")
            except Exception as e:
                print(f"\n  ❌ Erreur : {e}\n")
        else:
            print("\n  ❌ Choix invalide.\n")

        input("\n  Appuie sur Entrée pour revenir au menu...")


if __name__ == "__main__":
    main()