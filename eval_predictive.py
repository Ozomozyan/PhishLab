"""
eval_predictive.py
=================

Produit les livrables de la simulation prédictive :
  * reports/predictive.json        — projections + test de robustesse prospectif
  * reports/predictive_trends.png  — courbes de diffusion (historique + projection)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from phishlab.detector import PhishDetector, emails_from_dataframe
from phishlab.predictive import (
    project_all, evaluate_future, TECHNIQUE_LABELS,
)

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

INK = "#0B1F33"
PAPER = "#F4F7FA"
SLATE = "#33506B"
PALETTE = ["#2DE1C2", "#FF6B6B", "#5B8DEF", "#F5A623", "#9B59B6", "#1ABC9C"]


def main():
    projections = project_all(2028)

    # ----- Figure : courbes de diffusion -----
    fig, ax = plt.subplots(figsize=(11, 6))
    fig.patch.set_facecolor("white")
    ax.set_facecolor(PAPER)

    for i, proj in enumerate(projections):
        color = PALETTE[i % len(PALETTE)]
        hist_years = sorted(proj.history)
        hist_vals = [proj.history[y] for y in hist_years]
        fore_years = sorted(proj.forecast)
        fore_vals = [proj.forecast[y] for y in fore_years]
        # historique : trait plein
        ax.plot(hist_years, hist_vals, "-o", color=color, lw=2.2, ms=4,
                label=TECHNIQUE_LABELS[proj.technique])
        # projection : pointillés, relié au dernier point historique
        bridge_x = [hist_years[-1]] + fore_years
        bridge_y = [hist_vals[-1]] + fore_vals
        ax.plot(bridge_x, bridge_y, "--", color=color, lw=2.0, alpha=0.85)
        ax.scatter(fore_years, fore_vals, color=color, s=22, marker="D",
                   zorder=3, edgecolor="white", linewidth=0.6)

    # séparation présent / futur
    ax.axvline(2025.5, color=SLATE, lw=1.2, ls=":", alpha=0.7)
    ax.text(2025.6, 0.93, "projection", color=SLATE, fontsize=9.5,
            style="italic", va="top")

    ax.set_title("Évolution et projection des techniques de phishing",
                 fontsize=13, color=INK, fontweight="bold", pad=12)
    ax.set_xlabel("Année", fontsize=11, color=INK)
    ax.set_ylabel("Prévalence estimée", fontsize=11, color=INK)
    ax.set_ylim(0, 1.0)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0%", "20%", "40%", "60%", "80%", "100%"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(SLATE)
    ax.grid(True, color="white", linewidth=1.0)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", framealpha=0.95, fontsize=9, ncol=2)

    plt.tight_layout()
    fig.savefig(REPORTS / "predictive_trends.png", dpi=150, facecolor="white")
    print("Écrit:", REPORTS / "predictive_trends.png")

    # ----- Test de robustesse prospectif -----
    det = PhishDetector.load(str(ROOT / "models" / "phishdetector.joblib"))
    df = pd.read_csv(ROOT / "data" / "phishlab_dataset.csv").fillna("")
    phish_fams = {"invoice", "reset", "hr", "delivery", "account",
                  "prize", "ceo", "support"}
    pool = df[df["family"].isin(phish_fams)]
    emails = emails_from_dataframe(pool.sample(min(250, len(pool)), random_state=2))
    rows, clean = evaluate_future(det, emails)

    report = {
        "projections": [p.as_dict() for p in projections],
        "future_robustness": {
            "baseline_detection": round(clean, 3),
            "variants": [r.as_dict() for r in rows],
        },
        "note": ("Projections logistiques à partir de tendances sectorielles "
                 "indicatives. Le test prospectif empile des évasions montantes "
                 "(texte poli IA + homoglyphes + caractères invisibles) pour "
                 "mesurer la résilience et justifier le ré-entraînement continu."),
    }
    (REPORTS / "predictive.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2))
    print("Écrit:", REPORTS / "predictive.json")

    print(f"\nRobustesse prospective (réf. {clean:.0%}) :")
    for r in rows:
        d = r.as_dict()
        print(f"  {d['variant']:16s} attaqué={d['detection_attacked']:.0%}  "
              f"défendu={d['detection_defended']:.0%}")


if __name__ == "__main__":
    main()
