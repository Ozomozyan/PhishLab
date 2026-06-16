"""
train.py
========
Entraîne et évalue les modèles de détection PhishLab.

Produit :
    - models/phishdetector.joblib        (meilleur modèle, prêt à déployer)
    - models/scorer_export.json          (poids linéaires pour la démo embarquée)
    - reports/metrics.json               (toutes les métriques)
    - reports/*.png                      (figures pour la soutenance)

Métriques (cf. plan d'évaluation du cahier des charges) :
    précision, rappel, F1, ROC-AUC, PR-AUC, matrice de confusion, calibration,
    et performance détaillée PAR FAMILLE d'attaque.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix, roc_curve,
    precision_recall_curve, brier_score_loss,
)
from sklearn.calibration import calibration_curve

from phishlab.detector import (
    PhishDetector, emails_from_dataframe, FEATURE_NAMES,
)
from phishlab.features import clean_text_for_nlp, extract_features, features_to_vector

ROOT = Path(__file__).parent
DATA = ROOT / "data" / "phishlab_dataset.csv"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
MODELS.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)

# Palette cohérente avec la charte de la présentation (sombre + teal)
TEAL = "#2DE1C2"
CORAL = "#FF6B6B"
INK = "#0B1F33"
plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "font.size": 11, "axes.titlesize": 13, "axes.titleweight": "bold",
})


def evaluate(detector: PhishDetector, emails_test, y_test, fam_test):
    """Calcule l'ensemble des métriques pour un détecteur entraîné."""
    proba = detector.predict_proba(emails_test)
    pred = (proba >= 0.5).astype(int)

    metrics = {
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "roc_auc": roc_auc_score(y_test, proba),
        "pr_auc": average_precision_score(y_test, proba),
        "brier": brier_score_loss(y_test, proba),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }

    # Performance par famille (rappel sur phishing / spécificité sur bénin)
    # On utilise la VRAIE famille (connue) plutôt que le label éventuellement bruité.
    PHISH_FAMILIES = {"invoice", "reset", "hr", "delivery", "account",
                      "prize", "ceo", "support"}
    per_family = {}
    df = pd.DataFrame({"y": y_test, "p": proba, "fam": fam_test})
    for fam, g in df.groupby("fam"):
        is_phish_fam = fam in PHISH_FAMILIES
        if is_phish_fam:                  # famille phishing -> taux de détection
            detected = (g["p"] >= 0.5).mean()
            per_family[fam] = {"type": "phishing", "detection_rate": float(detected),
                               "n": int(len(g)), "mean_score": float(g["p"].mean())}
        else:                              # famille bénigne -> taux de faux positifs
            fp = (g["p"] >= 0.5).mean()
            per_family[fam] = {"type": "benign", "false_positive_rate": float(fp),
                               "n": int(len(g)), "mean_score": float(g["p"].mean())}
    metrics["per_family"] = per_family
    return metrics, proba


def plot_confusion(cm, title, path):
    fig, ax = plt.subplots(figsize=(4.6, 4))
    cm = np.array(cm)
    im = ax.imshow(cm, cmap="BuGn")
    labels = ["Bénin", "Phishing"]
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(labels); ax.set_yticklabels(labels)
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title(title)
    total = cm.sum()
    for i in range(2):
        for j in range(2):
            pct = 100 * cm[i, j] / total
            ax.text(j, i, f"{cm[i,j]}\n({pct:.1f}%)", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else INK, fontsize=12)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_roc_pr(y_test, scores_by_model, path):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))
    colors = {"logreg": TEAL, "rf": "#5B8DEF", "xgb": CORAL}
    for name, proba in scores_by_model.items():
        fpr, tpr, _ = roc_curve(y_test, proba)
        auc = roc_auc_score(y_test, proba)
        ax1.plot(fpr, tpr, color=colors.get(name), lw=2,
                 label=f"{name.upper()} (AUC={auc:.3f})")
        prec, rec, _ = precision_recall_curve(y_test, proba)
        ap = average_precision_score(y_test, proba)
        ax2.plot(rec, prec, color=colors.get(name), lw=2,
                 label=f"{name.upper()} (AP={ap:.3f})")
    ax1.plot([0, 1], [0, 1], "--", color="gray", lw=1)
    ax1.set_xlabel("Taux de faux positifs"); ax1.set_ylabel("Taux de vrais positifs")
    ax1.set_title("Courbe ROC"); ax1.legend(loc="lower right", fontsize=9)
    ax2.set_xlabel("Rappel"); ax2.set_ylabel("Précision")
    ax2.set_title("Courbe Précision-Rappel"); ax2.legend(loc="lower left", fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_calibration(y_test, proba, path):
    fig, ax = plt.subplots(figsize=(5, 4.4))
    frac_pos, mean_pred = calibration_curve(y_test, proba, n_bins=10, strategy="quantile")
    ax.plot([0, 1], [0, 1], "--", color="gray", label="Calibration parfaite")
    ax.plot(mean_pred, frac_pos, "o-", color=TEAL, lw=2, label="Modèle")
    ax.set_xlabel("Risque prédit moyen"); ax.set_ylabel("Fraction réelle de phishing")
    ax.set_title("Diagramme de calibration"); ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_feature_importance(df_train, y_train, path):
    """Importance des features tabulaires via un RandomForest dédié."""
    from sklearn.ensemble import RandomForestClassifier
    emails = emails_from_dataframe(df_train)
    Xtab = np.array([features_to_vector(extract_features(e)) for e in emails])
    rf = RandomForestClassifier(n_estimators=250, random_state=42, n_jobs=-1)
    rf.fit(Xtab, y_train)
    imp = rf.feature_importances_
    order = np.argsort(imp)[::-1][:15]
    fig, ax = plt.subplots(figsize=(7.5, 5))
    names = [FEATURE_NAMES[i] for i in order][::-1]
    vals = imp[order][::-1]
    ax.barh(names, vals, color=TEAL)
    ax.set_title("Top 15 features tabulaires (importance RandomForest)")
    ax.set_xlabel("Importance")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
    return {FEATURE_NAMES[i]: float(imp[i]) for i in np.argsort(imp)[::-1]}


def plot_family_detection(per_family, path):
    fams = [(k, v) for k, v in per_family.items() if v["type"] == "phishing"]
    fams.sort(key=lambda kv: kv[1]["detection_rate"])
    names = [k for k, _ in fams]
    rates = [v["detection_rate"] * 100 for _, v in fams]
    fig, ax = plt.subplots(figsize=(7.5, 4.4))
    bars = ax.barh(names, rates, color=TEAL)
    for b, r in zip(bars, rates):
        ax.text(r - 4, b.get_y() + b.get_height() / 2, f"{r:.1f}%",
                ha="right", va="center", color="white", fontsize=10, fontweight="bold")
    ax.set_xlim(0, 100)
    ax.set_title("Taux de détection par famille d'attaque")
    ax.set_xlabel("% de phishing détecté")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def export_linear_scorer(detector: PhishDetector, path: Path):
    """
    Exporte un scorer linéaire LÉGER (poids des features tabulaires + termes les
    plus pesants) au format JSON. Permet une démo 100% côté navigateur, sans
    serveur Python - illustre la portabilité 'edge' du cahier des charges.
    """
    weights = detector._linear_word_weights()
    if weights is None:
        return False
    # Coefficients tabulaires
    from sklearn.linear_model import LogisticRegression
    from sklearn.calibration import CalibratedClassifierCV
    clf = detector.model
    ests = [c.estimator for c in clf.calibrated_classifiers_]
    coef = np.mean([e.coef_[0] for e in ests], axis=0)
    intercept = float(np.mean([e.intercept_[0] for e in ests]))
    n_tab = len(FEATURE_NAMES)
    tab_coef = coef[:n_tab]

    # Standardisation : on stocke moyenne/échelle pour reproduire le scaling.
    scaler_mean = detector.scaler.mean_.tolist()
    scaler_scale = detector.scaler.scale_.tolist()

    # On garde les 400 termes-mots les plus discriminants (poids + idf).
    names = detector.tfidf_word.get_feature_names_out()
    idf = detector.tfidf_word.idf_
    word_coef = coef[n_tab:n_tab + len(names)]
    impact = np.abs(word_coef)
    top = np.argsort(impact)[::-1][:400]
    terms = {names[j]: {"w": float(word_coef[j]), "idf": float(idf[j])} for j in top}

    payload = {
        "feature_names": FEATURE_NAMES,
        "tab_coef": tab_coef.tolist(),
        "scaler_mean": scaler_mean,
        "scaler_scale": scaler_scale,
        "intercept": intercept,
        "terms": terms,
        "suspect_threshold": detector.suspect_threshold,
        "phish_threshold": detector.phish_threshold,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False))
    return True


def main():
    print("Chargement du dataset...")
    df = pd.read_csv(DATA).fillna("")
    df_train, df_test = train_test_split(
        df, test_size=0.25, stratify=df["label"], random_state=42)
    print(f"  Train: {len(df_train)}  Test: {len(df_test)}")

    emails_train = emails_from_dataframe(df_train)
    emails_test = emails_from_dataframe(df_test)
    # Entrainement sur etiquettes "heuristiques" bruitees (~3% d'erreurs).
    # On rapporte deux mesures :
    #   * OPERATIONNELLE (titre) : evaluee contre les memes etiquettes bruitees
    #     que produirait la chaine d'annotation en production. Aucun systeme reel
    #     ne dispose d'une verite parfaite -> c'est le chiffre honnete a presenter.
    #   * INTRINSEQUE (borne sup.) : evaluee contre la verite terrain propre.
    #     Tres elevee car les donnees synthetiques sont structurellement
    #     separables -> documente comme plafond, pas comme perf. terrain reelle.
    has_noisy = "noisy_label" in df_train.columns
    y_train = (df_train["noisy_label"] if has_noisy else df_train["label"]).astype(int).tolist()
    y_test = (df_test["noisy_label"] if has_noisy else df_test["label"]).astype(int).tolist()
    y_test_clean = df_test["label"].astype(int).tolist()    # verite terrain propre
    fam_test = df_test["family"].tolist()
    if has_noisy:
        n_noise = int((df_train["label"] != df_train["noisy_label"]).sum())
        n_noise_te = int((pd.Series(y_test) != pd.Series(y_test_clean)).sum())
        print(f"  Bruit d'etiquettes  train={n_noise}/{len(df_train)} "
              f"({n_noise/len(df_train)*100:.1f}%)  test={n_noise_te}/{len(df_test)} "
              f"({n_noise_te/len(df_test)*100:.1f}%)")
        print(f"  Metriques titre = operationnelles (etiquettes bruitees)")

    all_metrics = {}
    scores_by_model = {}
    detectors = {}

    for mtype in ["logreg", "rf", "xgb"]:
        print(f"\n=== Entraînement: {mtype} ===")
        det = PhishDetector(model_type=mtype, calibrate=True)
        det.fit(emails_train, y_train)
        m, proba = evaluate(det, emails_test, y_test, fam_test)
        all_metrics[mtype] = m
        scores_by_model[mtype] = proba
        detectors[mtype] = det
        print(f"  Précision={m['precision']:.3f}  Rappel={m['recall']:.3f}  "
              f"F1={m['f1']:.3f}  ROC-AUC={m['roc_auc']:.3f}  "
              f"PR-AUC={m['pr_auc']:.3f}  Brier={m['brier']:.4f}")

    # Sélection du meilleur modèle par F1 (équilibre précision/rappel)
    best = max(all_metrics, key=lambda k: all_metrics[k]["f1"])
    print(f"\nMeilleur modèle (F1): {best}")

    # Borne superieure "intrinseque" : le meme modele evalue contre la verite
    # terrain PROPRE. Tres haute (donnees synthetiques separables) -> sert de
    # plafond documente, pas de performance terrain. L'ecart avec la mesure
    # operationnelle = cout du bruit d'etiquetage.
    intrinsic = {}
    for mtype in ["logreg", "rf", "xgb"]:
        p = scores_by_model[mtype]
        pred = (p >= 0.5).astype(int)
        intrinsic[mtype] = {
            "precision": float(precision_score(y_test_clean, pred)),
            "recall": float(recall_score(y_test_clean, pred)),
            "f1": float(f1_score(y_test_clean, pred)),
            "roc_auc": float(roc_auc_score(y_test_clean, p)),
        }
    print(f"  [intrinseque/propre] {best}: F1={intrinsic[best]['f1']:.3f} "
          f"(plafond, donnees separables)")
    print(f"  [operationnel/bruit] {best}: F1={all_metrics[best]['f1']:.3f} "
          f"(chiffre presente)")

    # Pour la démo embarquée, on a besoin d'un modèle LINÉAIRE -> on entraîne/garde logreg
    deploy = detectors["logreg"]
    deploy.save(str(MODELS / "phishdetector.joblib"))
    exported = export_linear_scorer(deploy, MODELS / "scorer_export.json")
    print(f"Modèle déployé sauvegardé. Scorer JSON exporté: {exported}")

    # Figures
    print("\nGénération des figures...")
    plot_confusion(all_metrics[best]["confusion_matrix"],
                   f"Matrice de confusion ({best.upper()})",
                   REPORTS / "confusion_matrix.png")
    plot_roc_pr(y_test, scores_by_model, REPORTS / "roc_pr_curves.png")
    plot_calibration(y_test, scores_by_model["logreg"], REPORTS / "calibration.png")
    feat_imp = plot_feature_importance(df_train, y_train, REPORTS / "feature_importance.png")
    plot_family_detection(all_metrics[best]["per_family"], REPORTS / "family_detection.png")

    # Sauvegarde des métriques
    out = {
        "dataset": {"total": len(df), "train": len(df_train), "test": len(df_test),
                    "phishing": int(df["label"].sum()), "benign": int((1 - df["label"]).sum())},
        "label_protocol": {
            "train_labels": "noisy_label" if has_noisy else "label",
            "headline_eval_labels": "noisy_label (operationnel)" if has_noisy else "label",
            "label_noise_rate": 0.03 if has_noisy else 0.0,
            "note": ("Metriques titre = contre etiquettes bruitees (realiste). "
                     "Bloc 'intrinsic' = contre verite propre (plafond, "
                     "donnees synthetiques separables)."),
        },
        "models": all_metrics,
        "intrinsic_clean": intrinsic,
        "best_model": best,
        "feature_importance_top": dict(list(feat_imp.items())[:15]),
    }
    (REPORTS / "metrics.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"Métriques écrites: {REPORTS / 'metrics.json'}")
    print("\nTerminé.")


if __name__ == "__main__":
    main()
