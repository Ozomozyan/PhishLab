"""
PhishLab - Couche d'explicabilité
=================================

Objectif (cf. cahier des charges §3.2) : ne jamais se contenter de dire
« c'est du phishing », mais expliquer POURQUOI, en langage naturel, avec mise
en surbrillance des éléments suspects.

Deux niveaux d'explication, combinés :

1. Attribution par feature (style SHAP).
   Le modèle déployé est linéaire (régression logistique). Pour un modèle
   linéaire, les valeurs de Shapley ont une forme fermée EXACTE :

       phi_i = w_i * (x_i - E[x_i])

   c.-à-d. la contribution d'une feature = son poids × son écart à la moyenne
   du jeu d'entraînement (dans l'espace standardisé). La somme des phi_i vaut
   exactement (logit(x) - logit_baseline). On obtient donc une explication
   additive, fidèle et instantanée - sans échantillonnage. C'est l'équivalent
   de `shap.LinearExplainer`. Une variante s'appuyant réellement sur la
   librairie `shap` est fournie (`shap_values_kernel`) pour le rapport.

2. Traduction en langage naturel + surbrillance.
   Chaque feature qui pèse dans le verdict est traduite via HUMAN_LABELS, et on
   localise dans le texte les passages concernés (URL suspecte, mots d'urgence,
   demande d'identifiants, domaine lookalike, homoglyphes) pour les surligner
   dans le dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import unicodedata

from .features import (
    Email, extract_features, FEATURE_NAMES, HUMAN_LABELS,
    URGENCY_TERMS, CREDENTIAL_TERMS, LURE_TERMS, GENERIC_GREETINGS,
    TARGET_BRANDS, _URL_RE, _normalize, _registered_domain,
    _nearest_brand_distance, _has_homoglyph, HOMOGLYPH_MAP,
)


# --------------------------------------------------------------------------- #
# Structures de sortie
# --------------------------------------------------------------------------- #
@dataclass
class Reason:
    """Une raison compréhensible du verdict."""
    feature: str
    text: str                 # explication en langage naturel
    weight: float             # contribution signée au score (logit)
    direction: str            # "augmente" | "diminue" le risque

    def as_dict(self) -> dict:
        return {"feature": self.feature, "text": self.text,
                "weight": round(self.weight, 4), "direction": self.direction}


@dataclass
class Highlight:
    """Un passage à surligner dans le texte (offsets caractères)."""
    start: int
    end: int
    kind: str                 # url | urgency | credential | lure | greeting | homoglyph | lookalike
    snippet: str
    note: str

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "kind": self.kind,
                "snippet": self.snippet, "note": self.note}


@dataclass
class Explanation:
    score: float
    label: str
    reasons: list[Reason] = field(default_factory=list)
    protective: list[Reason] = field(default_factory=list)   # facteurs rassurants
    highlights: list[Highlight] = field(default_factory=list)
    nlp_terms: list[tuple[str, float]] = field(default_factory=list)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "summary": self.summary,
            "reasons": [r.as_dict() for r in self.reasons],
            "protective": [r.as_dict() for r in self.protective],
            "highlights": [h.as_dict() for h in self.highlights],
            "nlp_terms": [[t, round(w, 4)] for t, w in self.nlp_terms],
        }


# --------------------------------------------------------------------------- #
# Attribution linéaire exacte (SHAP fermé pour modèle linéaire)
# --------------------------------------------------------------------------- #
def linear_tabular_attributions(detector, email: Email) -> dict[str, float]:
    """phi_i = coef_i * (x_std_i - mean_std_i) pour chaque feature tabulaire.

    Renvoie {feature: contribution_signée_au_logit}. Positif = pousse vers
    'phishing'. Fonctionne uniquement si le modèle déployé est linéaire ; sinon
    renvoie {} (on retombera sur l'explication par règles)."""
    coefs = _tabular_coefficients(detector)
    if coefs is None:
        return {}

    feats = extract_features(email)
    x = [float(feats[name]) for name in FEATURE_NAMES]
    # standardisation identique à l'entraînement
    mean = detector.scaler.mean_
    scale = detector.scaler.scale_
    phi = {}
    for i, name in enumerate(FEATURE_NAMES):
        x_std = (x[i] - mean[i]) / scale[i]
        # E[x_std] = 0 par construction (StandardScaler), donc phi = coef * x_std
        phi[name] = float(coefs[i] * x_std)
    return phi


def _tabular_coefficients(detector):
    """Récupère le vecteur de coefficients correspondant au bloc tabulaire.

    L'ordre des colonnes dans la matrice fusionnée est : [tabulaire | mots |
    caractères]. On extrait les `len(FEATURE_NAMES)` premiers coefficients du
    modèle linéaire (en dépliant la calibration si nécessaire)."""
    model = detector.model
    # déplier CalibratedClassifierCV -> estimateur linéaire de base
    base = _unwrap_linear(model)
    if base is None or not hasattr(base, "coef_"):
        return None
    coef = base.coef_[0]
    n_tab = len(FEATURE_NAMES)
    if len(coef) < n_tab:
        return None
    return coef[:n_tab]


def _unwrap_linear(model):
    """Atteint l'estimateur linéaire sous une éventuelle calibration."""
    if hasattr(model, "coef_"):
        return model
    # CalibratedClassifierCV : moyenne des coef des plis calibrés
    calibrated = getattr(model, "calibrated_classifiers_", None)
    if calibrated:
        import numpy as np
        coefs = []
        for cc in calibrated:
            est = getattr(cc, "estimator", None) or getattr(cc, "base_estimator", None)
            if est is not None and hasattr(est, "coef_"):
                coefs.append(est.coef_[0])
        if coefs:
            class _Avg:
                coef_ = np.mean(coefs, axis=0)[None, :]
            return _Avg()
    return None


# --------------------------------------------------------------------------- #
# Localisation des passages suspects (surbrillance)
# --------------------------------------------------------------------------- #
def find_highlights(email: Email) -> list[Highlight]:
    """Repère dans subject+body les segments à surligner pour le dashboard."""
    text = email.full_text()
    text_norm = _normalize(text)
    highlights: list[Highlight] = []

    # 1) URLs - suspectes (lookalike / TLD à risque / IP / raccourcisseur) vs neutres
    for m in _URL_RE.finditer(text):
        url = m.group(0)
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        regd = _registered_domain(host)
        dist = _nearest_brand_distance(host)
        note, kind = "Lien présent dans le message", "url"
        if dist == 0 or (0 < dist <= 2):
            note = f"Domaine très proche d'une marque connue ({regd}) - possible typosquatting"
        elif re.search(r"\.(tk|ml|ga|cf|gq|xyz|top|live|icu|online|click|link|rest|zip)$", regd):
            note = f"Extension de domaine à risque ({regd})"
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}", host):
            note = "L'URL pointe vers une adresse IP brute"
        elif url.lower().startswith("http://"):
            note = "Lien non chiffré (http) - destination à vérifier"
        highlights.append(Highlight(m.start(), m.end(), kind, url, note))

    # 2) Termes lexicaux (urgence / identifiants / appât / salutation générique)
    for terms, kind, note in [
        (URGENCY_TERMS, "urgency", "Crée un sentiment d'urgence"),
        (CREDENTIAL_TERMS, "credential", "Demande d'identifiants / informations sensibles"),
        (LURE_TERMS, "lure", "Promesse de gain / appât"),
        (GENERIC_GREETINGS, "greeting", "Formule d'appel générique (envoi de masse)"),
    ]:
        for term in terms:
            for m in re.finditer(re.escape(_normalize(term)), text_norm):
                # remappe l'offset normalisé sur le texte original (même longueur)
                s, e = m.start(), m.end()
                if e <= len(text):
                    highlights.append(Highlight(s, e, kind, text[s:e], note))

    # 3) Homoglyphes (caractères non-ASCII visuellement latins)
    for i, ch in enumerate(text):
        if ch in HOMOGLYPH_MAP:
            highlights.append(Highlight(
                i, i + 1, "homoglyph", ch,
                f"Caractère trompeur '{ch}' imitant '{HOMOGLYPH_MAP[ch]}'"))

    # dédoublonnage + tri + limitation du chevauchement
    highlights = _dedup_highlights(highlights)
    return highlights


def _dedup_highlights(hs: list[Highlight]) -> list[Highlight]:
    seen = set()
    out = []
    for h in sorted(hs, key=lambda x: (x.start, -(x.end - x.start))):
        key = (h.start, h.end, h.kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


# --------------------------------------------------------------------------- #
# Explication complète
# --------------------------------------------------------------------------- #
def explain(detector, email: Email, max_reasons: int = 6) -> Explanation:
    """Produit l'explication complète d'un verdict pour un email donné."""
    pred = detector.analyze(email)
    phi = linear_tabular_attributions(detector, email)

    reasons: list[Reason] = []
    protective: list[Reason] = []

    if phi:
        # trie par contribution signée
        ordered = sorted(phi.items(), key=lambda kv: kv[1], reverse=True)
        for name, w in ordered:
            if name not in HUMAN_LABELS:
                continue
            if w > 0.05:
                reasons.append(Reason(name, HUMAN_LABELS[name], w, "augmente"))
            elif w < -0.05:
                protective.append(Reason(name, _protective_text(name), w, "diminue"))
        reasons = reasons[:max_reasons]
        protective = protective[:3]
    else:
        # fallback : règles pures sur les features actives
        feats = extract_features(email)
        for name, val in feats.items():
            if val and name in HUMAN_LABELS:
                reasons.append(Reason(name, HUMAN_LABELS[name], float(val), "augmente"))
        reasons = reasons[:max_reasons]

    highlights = find_highlights(email)
    summary = _summarize(pred.score, pred.label, reasons, protective)

    return Explanation(
        score=pred.score, label=pred.label,
        reasons=reasons, protective=protective,
        highlights=highlights, nlp_terms=pred.nlp_top_terms,
        summary=summary,
    )


_PROTECTIVE_TEXTS = {
    "spf_fail": "L'authentification SPF est valide (expéditeur autorisé)",
    "dkim_fail": "La signature DKIM est valide (message non altéré)",
    "dmarc_fail": "La politique DMARC est respectée",
    "auth_missing": "Le message est correctement authentifié (SPF/DKIM/DMARC)",
    "url_suspicious_tld": "Les liens pointent vers des domaines de confiance",
    "sender_display_domain_mismatch": "Le domaine d'envoi correspond au nom affiché",
    "urgency_term_count": "Ton neutre, sans pression temporelle",
    "credential_term_count": "Aucune demande d'identifiants",
}


def _protective_text(name: str) -> str:
    return _PROTECTIVE_TEXTS.get(name, f"Facteur rassurant : {name}")


def _summarize(score: float, label: str, reasons, protective) -> str:
    pct = round(score * 100)
    if label == "phishing":
        head = f"⚠️ Risque élevé ({pct}%) - ce message présente plusieurs signaux d'attaque."
    elif label == "suspect":
        head = f"Prudence ({pct}%) - ce message présente des éléments ambigus."
    else:
        head = f"Risque faible ({pct}%) - aucun signal fort de phishing détecté."
    if reasons:
        head += " Principaux signaux : " + " ; ".join(r.text for r in reasons[:2]) + "."
    return head


# --------------------------------------------------------------------------- #
# Variante SHAP « réelle » (librairie shap) - pour le rapport d'évaluation
# --------------------------------------------------------------------------- #
def shap_values_kernel(detector, emails_background, email: Email, nsamples: int = 100):
    """Calcule des valeurs SHAP via KernelExplainer sur le bloc tabulaire.

    Plus lente (échantillonnage), fournie pour démontrer la cohérence avec
    l'attribution linéaire fermée. Renvoie un dict {feature: shap_value}."""
    import numpy as np
    import shap

    def f(X):
        # X : matrice (n, n_features) tabulaires standardisées -> proba phishing
        base = _unwrap_linear(detector.model)
        if base is None:
            raise RuntimeError("Modèle non linéaire : utiliser TreeExplainer.")
        import scipy.sparse as sp
        # reconstruit le logit tabulaire uniquement
        coef = base.coef_[0][:len(FEATURE_NAMES)]
        logits = X @ coef
        return 1 / (1 + np.exp(-logits))

    bg = np.array([
        [(extract_features(e)[n] - detector.scaler.mean_[i]) / detector.scaler.scale_[i]
         for i, n in enumerate(FEATURE_NAMES)]
        for e in emails_background
    ])
    x = np.array([[(extract_features(email)[n] - detector.scaler.mean_[i]) / detector.scaler.scale_[i]
                   for i, n in enumerate(FEATURE_NAMES)]])
    explainer = shap.KernelExplainer(f, shap.kmeans(bg, min(10, len(bg))))
    vals = explainer.shap_values(x, nsamples=nsamples, silent=True)
    vals = np.array(vals).reshape(-1)
    return dict(zip(FEATURE_NAMES, vals.tolist()))


if __name__ == "__main__":
    from .detector import PhishDetector
    det = PhishDetector.load("models/phishdetector.joblib")
    e = Email(
        subject="URGENT: Votre compte PayPal sera suspendu",
        body="Cher client, activité suspecte détectée. Vérifiez votre mot de passe "
             "immédiatement : http://paypa1-secure.tk/login sinon votre compte sera "
             "bloqué définitivement !!!",
        sender_display="PayPal Service",
        sender_email="security@account-verify.gmail.com",
        reply_to="noreply@random-domain.xyz",
        spf="fail", dkim="none", dmarc="fail",
    )
    exp = explain(det, e)
    print(exp.summary)
    print("\nRaisons (augmentent le risque) :")
    for r in exp.reasons:
        print(f"  +{r.weight:+.3f}  {r.text}")
    print("\nFacteurs protecteurs :")
    for r in exp.protective:
        print(f"  {r.weight:+.3f}  {r.text}")
    print(f"\n{len(exp.highlights)} passages surlignés.")
