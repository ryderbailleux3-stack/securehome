"""
SecureHome — Module Rapport PDF
==================================
Ce module génère un rapport PDF professionnel contenant tous les
résultats de l'audit de sécurité du réseau domestique.

CONCEPT : GÉNÉRATION PDF AVEC REPORTLAB
------------------------------------------
ReportLab est une bibliothèque Python pour créer des PDF.
On "dessine" le contenu page par page :
  - Texte (titres, paragraphes)
  - Tableaux (liste d'appareils)
  - Images (graphiques générés par matplotlib)
  - Formes (barres de score, icônes)

CONCEPT : DATA VISUALIZATION
-------------------------------
Les graphiques sont générés par matplotlib puis insérés dans le PDF.
matplotlib crée une image PNG en mémoire (BytesIO), et ReportLab
l'intègre directement dans le PDF sans fichier temporaire.
"""

import os
import sys
import json
import glob
import io
from datetime import datetime
from dataclasses import dataclass

# ReportLab — Génération PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, mm
from reportlab.lib.colors import (
    HexColor, white, black, grey, lightgrey,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable,
)
from reportlab.graphics.shapes import Drawing, Rect, Circle, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# matplotlib — Graphiques
import matplotlib
matplotlib.use('Agg')  # Mode sans fenêtre (pas besoin d'écran)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Import de nos modules
from ..scanner.network_scanner import verifier_admin
from ..scoring.security_score import calculer_score_reseau


# =============================================================================
# COULEURS DU THÈME
# =============================================================================

COULEURS = {
    "fond": HexColor("#0f172a"),
    "fond_clair": HexColor("#1e293b"),
    "accent_vert": HexColor("#10b981"),
    "accent_rouge": HexColor("#ef4444"),
    "accent_orange": HexColor("#f59e0b"),
    "accent_jaune": HexColor("#eab308"),
    "accent_bleu": HexColor("#3b82f6"),
    "accent_violet": HexColor("#8b5cf6"),
    "accent_cyan": HexColor("#06b6d4"),
    "texte": HexColor("#e2e8f0"),
    "texte_gris": HexColor("#94a3b8"),
    "bordure": HexColor("#334155"),
}


def couleur_score(score):
    """Retourne la couleur correspondant au score."""
    if score >= 80:
        return COULEURS["accent_vert"]
    elif score >= 60:
        return COULEURS["accent_jaune"]
    elif score >= 40:
        return COULEURS["accent_orange"]
    else:
        return COULEURS["accent_rouge"]


def note_score(score):
    """Retourne la note lettrée du score."""
    if score >= 90: return "A+"
    elif score >= 80: return "A"
    elif score >= 70: return "B"
    elif score >= 60: return "C"
    elif score >= 50: return "C-"
    elif score >= 40: return "D"
    elif score >= 30: return "D-"
    elif score >= 20: return "E"
    else: return "F"


def description_score(score):
    """Retourne la description du score."""
    if score >= 90: return "Excellent"
    elif score >= 80: return "Très bon"
    elif score >= 70: return "Bon"
    elif score >= 60: return "Moyen"
    elif score >= 50: return "Passable"
    elif score >= 40: return "Faible"
    elif score >= 30: return "Très faible"
    elif score >= 20: return "Critique"
    else: return "Danger"


# =============================================================================
# STYLES DE TEXTE
# =============================================================================

def creer_styles():
    """Crée les styles de paragraphe pour le PDF."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='TitrePrincipal',
        fontName='Helvetica-Bold',
        fontSize=28,
        textColor=COULEURS["accent_vert"],
        spaceAfter=6,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name='SousTitre',
        fontName='Helvetica',
        fontSize=12,
        textColor=COULEURS["texte_gris"],
        spaceAfter=20,
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name='TitreSection',
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=COULEURS["accent_cyan"],
        spaceBefore=20,
        spaceAfter=10,
    ))

    styles.add(ParagraphStyle(
        name='TitreSousSection',
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=COULEURS["accent_bleu"],
        spaceBefore=12,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name='TexteNormal',
        fontName='Helvetica',
        fontSize=10,
        textColor=black,
        spaceAfter=6,
        leading=14,
    ))

    styles.add(ParagraphStyle(
        name='TextePetit',
        fontName='Helvetica',
        fontSize=8,
        textColor=grey,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name='Probleme',
        fontName='Helvetica',
        fontSize=10,
        textColor=HexColor("#dc2626"),
        spaceAfter=4,
        leftIndent=20,
    ))

    styles.add(ParagraphStyle(
        name='Recommandation',
        fontName='Helvetica',
        fontSize=10,
        textColor=HexColor("#059669"),
        spaceAfter=4,
        leftIndent=20,
    ))

    return styles


# =============================================================================
# GRAPHIQUES MATPLOTLIB
# =============================================================================

def generer_graphique_jauge(score):
    """
    Génère un graphique en forme de jauge (demi-cercle) pour le score.
    Retourne l'image sous forme de bytes (BytesIO).
    """
    fig, ax = plt.subplots(figsize=(4, 2.5))

    # Demi-cercle de fond
    theta_fond = [i * 3.14159 / 100 for i in range(101)]
    x_fond = [1.5 * __import__('math').cos(t) for t in theta_fond]
    y_fond = [1.5 * __import__('math').sin(t) for t in theta_fond]

    # Demi-cercle du score
    theta_score = [i * 3.14159 / 100 for i in range(score + 1)]
    x_score = [1.5 * __import__('math').cos(t) for t in theta_score]
    y_score = [1.5 * __import__('math').sin(t) for t in theta_score]

    # Couleurs
    if score >= 80:
        couleur = '#10b981'
    elif score >= 60:
        couleur = '#eab308'
    elif score >= 40:
        couleur = '#f59e0b'
    else:
        couleur = '#ef4444'

    ax.fill_between(x_fond, 0, y_fond, color='#e2e8f0', alpha=0.3)
    ax.fill_between(x_score, 0, y_score, color=couleur, alpha=0.8)

    # Texte du score
    ax.text(0, 0.5, f"{score}", fontsize=36, fontweight='bold',
            ha='center', va='center', color=couleur)
    ax.text(0, 0.05, f"/ 100 ({note_score(score)})", fontsize=11,
            ha='center', va='center', color='#64748b')

    ax.set_xlim(-2, 2)
    ax.set_ylim(-0.3, 2)
    ax.set_aspect('equal')
    ax.axis('off')
    plt.tight_layout()

    # Sauvegarde en mémoire
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return buf


def generer_graphique_barres(appareils):
    """Génère un graphique en barres des scores par appareil."""
    if not appareils:
        return None

    noms = [a.fabricant[:18] for a in appareils]
    scores = [a.score_global for a in appareils]
    couleurs = []
    for s in scores:
        if s >= 80: couleurs.append('#10b981')
        elif s >= 60: couleurs.append('#eab308')
        elif s >= 40: couleurs.append('#f59e0b')
        else: couleurs.append('#ef4444')

    fig, ax = plt.subplots(figsize=(6, 3))
    bars = ax.barh(noms, scores, color=couleurs, edgecolor='white', linewidth=0.5)

    # Ajouter les valeurs sur les barres
    for bar, score in zip(bars, scores):
        ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height()/2,
                f'{score}', va='center', fontsize=9, fontweight='bold',
                color='#334155')

    ax.set_xlim(0, 110)
    ax.set_xlabel('Score de sécurité', fontsize=9, color='#64748b')
    ax.tick_params(axis='both', colors='#64748b', labelsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cbd5e1')
    ax.spines['bottom'].set_color('#cbd5e1')
    ax.invert_yaxis()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return buf


def generer_graphique_criteres(appareils):
    """Génère un graphique des scores moyens par critère."""
    if not appareils:
        return None

    criteres = ['Mots de passe', 'CVE', 'Ports', 'Chiffrement']
    max_vals = [35, 30, 20, 15]
    moyennes = [0, 0, 0, 0]

    for a in appareils:
        moyennes[0] += a.score_mots_de_passe
        moyennes[1] += a.score_cve
        moyennes[2] += a.score_ports
        moyennes[3] += a.score_chiffrement

    n = len(appareils)
    moyennes = [round(m / n, 1) for m in moyennes]
    pcts = [round(m / mx * 100) if mx > 0 else 0 for m, mx in zip(moyennes, max_vals)]

    couleurs_criteres = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6']

    fig, ax = plt.subplots(figsize=(6, 3))
    bars = ax.bar(criteres, pcts, color=couleurs_criteres, edgecolor='white',
                  linewidth=0.5, width=0.6)

    for bar, pct, moy, mx in zip(bars, pcts, moyennes, max_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{moy}/{mx}', ha='center', fontsize=9, fontweight='bold',
                color='#334155')

    ax.set_ylim(0, 120)
    ax.set_ylabel('Score (%)', fontsize=9, color='#64748b')
    ax.tick_params(axis='both', colors='#64748b', labelsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cbd5e1')
    ax.spines['bottom'].set_color('#cbd5e1')
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return buf


# =============================================================================
# CONSTRUCTION DU PDF
# =============================================================================

def generer_rapport_pdf(score_reseau, chemin_sortie=None):
    """
    Génère le rapport PDF complet.

    CONCEPT : PLATYPUS (ReportLab)
    --------------------------------
    Platypus est le moteur de mise en page de ReportLab.
    On construit une liste d'éléments (paragraphes, images,
    tableaux, espacements) et Platypus les dispose automatiquement
    sur les pages, avec des sauts de page automatiques.
    """
    if chemin_sortie is None:
        os.makedirs("data", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        chemin_sortie = os.path.join("data", f"rapport_securite_{timestamp}.pdf")

    # Crée le document PDF format A4
    doc = SimpleDocTemplate(
        chemin_sortie,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    # Styles de texte
    styles = creer_styles()

    # Liste des éléments du PDF
    elements = []

    # ─────────────────────────────────────────────────────────────
    # PAGE 1 : PAGE DE COUVERTURE
    # ─────────────────────────────────────────────────────────────

    elements.append(Spacer(1, 3 * cm))
    elements.append(Paragraph("SecureHome", styles['TitrePrincipal']))
    elements.append(Paragraph(
        "Rapport d'Audit de Sécurité Réseau",
        styles['SousTitre']
    ))

    elements.append(Spacer(1, 1 * cm))

    # Jauge du score
    buf_jauge = generer_graphique_jauge(score_reseau.score_global)
    img_jauge = Image(buf_jauge, width=10 * cm, height=6.5 * cm)
    img_jauge.hAlign = 'CENTER'
    elements.append(img_jauge)

    elements.append(Spacer(1, 0.5 * cm))
    elements.append(Paragraph(
        f"Score global : {score_reseau.score_global}/100 — "
        f"{description_score(score_reseau.score_global)}",
        styles['SousTitre']
    ))

    elements.append(Spacer(1, 1.5 * cm))

    # Infos du rapport
    infos = [
        ["Date de l'audit", score_reseau.date],
        ["Appareils analysés", str(score_reseau.nombre_appareils)],
        ["Durée du scan", f"{score_reseau.duree_secondes}s"],
        ["Outil", "SecureHome v1.0"],
    ]

    table_infos = Table(infos, colWidths=[6 * cm, 8 * cm])
    table_infos.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), COULEURS["accent_cyan"]),
        ('TEXTCOLOR', (1, 0), (1, -1), black),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('LEFTPADDING', (1, 0), (1, -1), 12),
    ]))
    elements.append(table_infos)

    elements.append(Spacer(1, 2 * cm))
    elements.append(Paragraph(
        "Ce rapport est généré automatiquement par SecureHome. "
        "Il est destiné à un usage personnel sur votre propre réseau domestique. "
        "Scanner un réseau sans autorisation est un délit pénal "
        "(Art. 323-1 du Code pénal français).",
        styles['TextePetit']
    ))

    elements.append(PageBreak())

    # ─────────────────────────────────────────────────────────────
    # PAGE 2 : VUE D'ENSEMBLE
    # ─────────────────────────────────────────────────────────────

    elements.append(Paragraph("Vue d'ensemble", styles['TitreSection']))
    elements.append(HRFlowable(
        width="100%", thickness=1,
        color=COULEURS["accent_cyan"], spaceAfter=12
    ))

    # Graphique des scores par appareil
    buf_barres = generer_graphique_barres(score_reseau.appareils)
    if buf_barres:
        elements.append(Paragraph(
            "Scores de sécurité par appareil",
            styles['TitreSousSection']
        ))
        img_barres = Image(buf_barres, width=15 * cm, height=7.5 * cm)
        img_barres.hAlign = 'CENTER'
        elements.append(img_barres)
        elements.append(Spacer(1, 0.5 * cm))

    # Graphique des critères
    buf_criteres = generer_graphique_criteres(score_reseau.appareils)
    if buf_criteres:
        elements.append(Paragraph(
            "Scores moyens par critère",
            styles['TitreSousSection']
        ))
        img_criteres = Image(buf_criteres, width=15 * cm, height=7.5 * cm)
        img_criteres.hAlign = 'CENTER'
        elements.append(img_criteres)

    elements.append(PageBreak())

    # ─────────────────────────────────────────────────────────────
    # PAGE 3 : INVENTAIRE DES APPAREILS
    # ─────────────────────────────────────────────────────────────

    elements.append(Paragraph("Inventaire des appareils", styles['TitreSection']))
    elements.append(HRFlowable(
        width="100%", thickness=1,
        color=COULEURS["accent_cyan"], spaceAfter=12
    ))

    # Tableau des appareils
    donnees_tableau = [
        ['Score', 'IP', 'Fabricant', 'Hostname', 'Ports', 'CVE']
    ]

    for a in sorted(score_reseau.appareils, key=lambda x: x.score_global):
        ports_str = ', '.join(str(p) for p in a.ports_ouverts[:4])
        if len(a.ports_ouverts) > 4:
            ports_str += '...'

        donnees_tableau.append([
            f"{a.score_global}/100",
            a.ip,
            a.fabricant[:20],
            a.hostname[:18] if a.hostname != "Inconnu" else "-",
            ports_str or "Aucun",
            str(a.nombre_cve),
        ])

    table_appareils = Table(
        donnees_tableau,
        colWidths=[2.2 * cm, 3.2 * cm, 3.8 * cm, 3.5 * cm, 2.5 * cm, 1.5 * cm]
    )

    # Style du tableau
    style_tableau = [
        # En-tête
        ('BACKGROUND', (0, 0), (-1, 0), COULEURS["accent_cyan"]),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),

        # Corps
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, COULEURS["bordure"]),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]

    # Colorie les scores
    for i, a in enumerate(sorted(score_reseau.appareils, key=lambda x: x.score_global), 1):
        if a.score_global < 40:
            style_tableau.append(('TEXTCOLOR', (0, i), (0, i), COULEURS["accent_rouge"]))
        elif a.score_global < 60:
            style_tableau.append(('TEXTCOLOR', (0, i), (0, i), COULEURS["accent_orange"]))
        elif a.score_global < 80:
            style_tableau.append(('TEXTCOLOR', (0, i), (0, i), COULEURS["accent_jaune"]))
        else:
            style_tableau.append(('TEXTCOLOR', (0, i), (0, i), COULEURS["accent_vert"]))

        # Alternance de couleurs
        if i % 2 == 0:
            style_tableau.append(('BACKGROUND', (0, i), (-1, i), HexColor("#f8fafc")))

    table_appareils.setStyle(TableStyle(style_tableau))
    elements.append(table_appareils)

    elements.append(Spacer(1, 1 * cm))

    # ─────────────────────────────────────────────────────────────
    # DÉTAIL PAR APPAREIL
    # ─────────────────────────────────────────────────────────────

    elements.append(Paragraph("Détail par appareil", styles['TitreSection']))
    elements.append(HRFlowable(
        width="100%", thickness=1,
        color=COULEURS["accent_cyan"], spaceAfter=12
    ))

    for a in sorted(score_reseau.appareils, key=lambda x: x.score_global):
        # En-tête appareil
        score_couleur_hex = (
            "#10b981" if a.score_global >= 80
            else "#eab308" if a.score_global >= 60
            else "#f59e0b" if a.score_global >= 40
            else "#ef4444"
        )

        elements.append(Paragraph(
            f'<font color="{score_couleur_hex}">[{a.score_global}/100]</font> '
            f'{a.fabricant} — {a.ip}',
            styles['TitreSousSection']
        ))

        # Infos de base
        elements.append(Paragraph(
            f'Hostname : {a.hostname} | MAC : {a.mac} | '
            f'Ports ouverts : {len(a.ports_ouverts)} | CVE : {a.nombre_cve}',
            styles['TexteNormal']
        ))

        # Scores détaillés
        elements.append(Paragraph(
            f'MDP : {a.score_mots_de_passe}/35 | '
            f'CVE : {a.score_cve}/30 | '
            f'Ports : {a.score_ports}/20 | '
            f'Chiffrement : {a.score_chiffrement}/15',
            styles['TexteNormal']
        ))

        # Problèmes
        if a.problemes:
            for p in a.problemes:
                p_clean = p.replace("🔴", "[!]").replace("🟠", "[!]").replace("🟡", "[-]")
                elements.append(Paragraph(f"• {p_clean}", styles['Probleme']))

        # Recommandations
        if a.recommandations:
            for r in a.recommandations:
                elements.append(Paragraph(f"→ {r}", styles['Recommandation']))

        elements.append(Spacer(1, 0.5 * cm))

    # ─────────────────────────────────────────────────────────────
    # DERNIÈRE PAGE : RECOMMANDATIONS GLOBALES
    # ─────────────────────────────────────────────────────────────

    elements.append(PageBreak())
    elements.append(Paragraph("Recommandations", styles['TitreSection']))
    elements.append(HRFlowable(
        width="100%", thickness=1,
        color=COULEURS["accent_cyan"], spaceAfter=12
    ))

    if score_reseau.resume_recommandations:
        for i, reco in enumerate(score_reseau.resume_recommandations, 1):
            elements.append(Paragraph(
                f"<b>{i}.</b> {reco}",
                styles['TexteNormal']
            ))
            elements.append(Spacer(1, 0.3 * cm))
    else:
        elements.append(Paragraph(
            "Aucune recommandation particulière. Votre réseau est bien sécurisé.",
            styles['TexteNormal']
        ))

    # Bonnes pratiques générales
    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph("Bonnes pratiques générales", styles['TitreSousSection']))

    bonnes_pratiques = [
        "Changez tous les mots de passe par défaut de vos appareils.",
        "Mettez à jour régulièrement le firmware de votre routeur et box internet.",
        "Désactivez les services inutilisés (Telnet, FTP, UPnP).",
        "Utilisez des mots de passe forts (12+ caractères, majuscules, chiffres, symboles).",
        "Activez le chiffrement WPA3 sur votre réseau Wi-Fi si possible.",
        "Vérifiez périodiquement les appareils connectés à votre réseau.",
        "Séparez les objets IoT sur un réseau Wi-Fi invité dédié.",
        "Relancez SecureHome régulièrement pour détecter les nouvelles vulnérabilités.",
    ]

    for bp in bonnes_pratiques:
        elements.append(Paragraph(f"• {bp}", styles['TexteNormal']))

    # Footer
    elements.append(Spacer(1, 2 * cm))
    elements.append(HRFlowable(
        width="100%", thickness=0.5, color=lightgrey, spaceAfter=8
    ))
    elements.append(Paragraph(
        f"Rapport généré par SecureHome v1.0 — {datetime.now().strftime('%d/%m/%Y à %H:%M')} "
        f"— Projet éducatif de cybersécurité",
        styles['TextePetit']
    ))

    # ─────────────────────────────────────────────────────────────
    # GÉNÉRATION DU PDF
    # ─────────────────────────────────────────────────────────────

    doc.build(elements)
    return chemin_sortie


def lancer_rapport():
    """Lance un scan complet puis génère le rapport PDF."""
    print(f"\n{'='*60}")
    print(f"  📄 SecureHome — Génération du Rapport PDF")
    print(f"{'='*60}\n")

    # Lance le scoring complet
    print("  🔄 Lancement du scan et scoring...\n")
    score_reseau = calculer_score_reseau()

    if score_reseau is None:
        print("  ❌ Échec du scoring. Rapport annulé.")
        return

    # Génère le PDF
    print(f"\n  📝 Génération du rapport PDF...")
    chemin = generer_rapport_pdf(score_reseau)
    print(f"  ✅ Rapport généré : {chemin}")
    print(f"\n  📂 Tu peux l'ouvrir avec :")
    print(f"     start {chemin}\n")

    return chemin


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":

    print("\n  ⚖️  AVERTISSEMENT LÉGAL")
    print("  " + "─" * 56)
    print("  Ce programme audite votre réseau domestique et génère")
    print("  un rapport PDF des résultats.")
    print("  " + "─" * 56)

    if not verifier_admin():
        print("\n  ⚠️  Ce script doit être lancé en Administrateur !")
        sys.exit(1)

    chemin = lancer_rapport()

    if chemin:
        # Ouvre automatiquement le PDF
        ouvrir = input("  Ouvrir le PDF maintenant ? (o/n) : ").strip().lower()
        if ouvrir == "o":
            os.startfile(chemin)

    print("  ✅ Terminé !\n")