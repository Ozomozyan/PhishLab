"""
eval_robustness.py
==================

Mesure la robustesse adverse du detecteur deploye et produit :
  * reports/robustness.json  - chiffres detailles par attaque
  * reports/robustness.png   - graphique detection (reference / attaquee / defendue)

C'est la piece maitresse de la demonstration : on montre qu'un modele "nu"
peut etre contourne par des techniques d'evasion simples, et que la chaine de
defense (canonicalisation Unicode + URL, garde image-only) restaure l'essentiel
de la detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from phishlab.detector import PhishDetector, emails_from_dataframe
from phishlab.adversarial import evaluate_robustness

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

TEAL = "#2DE1C2"
CORAL = "#FF6B6B"
INK = "#0B1F33"
SLATE = "#33506B"
PAPER = "#F4F7FA"

ATTACK_LABELS = {
    "char_spacing": "Espacement\n(p a s s w o r d)",
    "homoglyph": "Homoglyphes\n(Unicode)",
    "leetspeak": "Leetspeak\n(p4ssw0rd)",
    "zero_width": "Caractères\ninvisibles",
    "url_obfuscation": "Obfuscation\nd'URL",
    "image_only": "Email tout\nen image",
}


def main():
    det = PhishDetector.load(str(ROOT / "models" / "phishdetector.joblib"))
    df = pd.read_csv(ROOT / "data" / "phishlab_dataset.csv").fillna("")
    phish_fams = {"invoice", "reset", "hr", "delivery", "account",
                  "prize", "ceo", "support"}
    pool = df[df["family"].isin(phish_fams)]
    sample = pool.sample(min(300, len(pool)), random_state=1)
    emails = emails_from_dataframe(sample)

    rows, clean = evaluate_robustness(det, emails, seed=0)
    data = [r.as_dict() for r in rows]

    report = {
        "baseline_detection": round(clean, 3),
        "n_phishing_detected": rows[0].n if rows else 0,
        "threshold": det.phish_threshold,
        "attacks": data,
        "interpretation": {
            "definition": ("Taux de détection = part des phishing scorés au-dessus "
                           "du seuil 'phishing' (%.2f)." % det.phish_threshold),
            "lecture": ("'chute' = détection perdue sous attaque ; 'récup' = "
                        "détection restaurée par les défenses."),
        },
    }
    (REPORTS / "robustness.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2))
    print("Écrit:", REPORTS / "robustness.json")

    # ----- Figure -----
    names = [d["attack"] for d in data]
    attacked = [d["detection_attacked"] for d in data]
    defended = [d["detection_defended"] for d in data]
    x = np.arange(len(names))
    w = 0.38

    fig, ax = plt.subplots(figsize=(11, 5.6))
    fig.patch.set_facecolor("white")
    ax.set_facecolor(PAPER)

    ax.axhline(clean, color=INK, lw=1.6, ls="--", alpha=0.7,
               label=f"Détection de référence ({clean:.0%})")
    b1 = ax.bar(x - w / 2, attacked, w, color=CORAL, label="Sous attaque (modèle nu)",
                edgecolor="white", linewidth=0.8)
    b2 = ax.bar(x + w / 2, defended, w, color=TEAL, label="Avec défenses",
                edgecolor="white", linewidth=0.8)

    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.0%}", (bar.get_x() + bar.get_width() / 2, h),
                        ha="center", va="bottom", fontsize=8.5,
                        color=INK, fontweight="bold", xytext=(0, 2),
                        textcoords="offset points")

    ax.set_xticks(x)
    ax.set_xticklabels([ATTACK_LABELS.get(n, n) for n in names], fontsize=9)
    ax.set_ylabel("Taux de détection du phishing", fontsize=11, color=INK)
    ax.set_ylim(0, 1.12)
    ax.set_yticks(np.arange(0, 1.01, 0.2))
    ax.set_yticklabels([f"{v:.0%}" for v in np.arange(0, 1.01, 0.2)])
    ax.set_title("Robustesse adverse : impact des attaques d'évasion et effet des défenses",
                 fontsize=12.5, color=INK, fontweight="bold", pad=14)
    ax.legend(loc="lower right", framealpha=0.95, fontsize=9.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(SLATE)
    ax.grid(axis="y", color="white", linewidth=1.1)
    ax.set_axisbelow(True)

    plt.tight_layout()
    fig.savefig(REPORTS / "robustness.png", dpi=150, facecolor="white")
    print("Écrit:", REPORTS / "robustness.png")

    # Résumé console
    print(f"\nRéférence: {clean:.1%}  (n={report['n_phishing_detected']})")
    for d in data:
        print(f"  {d['attack']:16s} attaqué={d['detection_attacked']:.0%}  "
              f"défendu={d['detection_defended']:.0%}  "
              f"(chute {d['drop']:+.0%}, récup {d['recovered']:+.0%})")


if __name__ == "__main__":
    main()
