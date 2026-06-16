"""
phishlab.predictive
===================

Simulation predictive (cf. cahier des charges §5) - le volet "anticiper demain".

Trois etapes :

  1. ANALYSE HISTORIQUE
     On modelise l'evolution de l'adoption des techniques de phishing sur
     plusieurs annees (tendances documentees : raccourcisseurs d'URL, kits
     pheche-en-tant-que-service, homoglyphes, QR-codes "quishing", textes
     polis par IA generative, contournement MFA / consentement OAuth).

  2. PROJECTION
     On extrapole chaque tendance (modele logistique de diffusion) vers un
     horizon futur pour estimer la prevalence probable des techniques en 2026+.

  3. TEST DE ROBUSTESSE PROSPECTIF
     On fabrique des leurres "du futur" en COMBINANT les techniques montantes
     (evasions empilees + texte poli facon IA, sans fautes ni sur-urgence) et on
     mesure la perte de detection du modele actuel. Cela identifie les angles
     morts et justifie le re-entrainement continu + la surveillance de derive.

Tout reste synthetique et hors-ligne. Aucune capacite offensive operationnelle
n'est produite : on empile des transformations de surface deja publiques pour
mesurer la resilience defensive, conformement au cadre ethique du projet.
"""

from __future__ import annotations

import math
import random
import re
from dataclasses import dataclass
from pathlib import Path

from .features import Email
from .adversarial import (
    attack_homoglyph, attack_zero_width, attack_leetspeak,
    attack_char_spacing, sanitize_email, _clone,
)


# --------------------------------------------------------------------------- #
# 1. Historique (prevalence approximative par technique, 0-1)
# --------------------------------------------------------------------------- #
# Valeurs indicatives reconstituees a partir de tendances publiees du secteur.
# Elles servent a illustrer une dynamique, pas a fournir des statistiques exactes.
HISTORY = {
    2019: {"url_shortener": 0.20, "lookalike_domain": 0.35, "homoglyph": 0.05,
           "ai_polished": 0.02, "qr_code": 0.01, "mfa_bypass": 0.02},
    2020: {"url_shortener": 0.27, "lookalike_domain": 0.40, "homoglyph": 0.08,
           "ai_polished": 0.03, "qr_code": 0.02, "mfa_bypass": 0.04},
    2021: {"url_shortener": 0.33, "lookalike_domain": 0.46, "homoglyph": 0.12,
           "ai_polished": 0.05, "qr_code": 0.04, "mfa_bypass": 0.08},
    2022: {"url_shortener": 0.38, "lookalike_domain": 0.52, "homoglyph": 0.18,
           "ai_polished": 0.10, "qr_code": 0.09, "mfa_bypass": 0.14},
    2023: {"url_shortener": 0.42, "lookalike_domain": 0.57, "homoglyph": 0.24,
           "ai_polished": 0.22, "qr_code": 0.17, "mfa_bypass": 0.22},
    2024: {"url_shortener": 0.45, "lookalike_domain": 0.61, "homoglyph": 0.30,
           "ai_polished": 0.38, "qr_code": 0.27, "mfa_bypass": 0.31},
    2025: {"url_shortener": 0.47, "lookalike_domain": 0.64, "homoglyph": 0.35,
           "ai_polished": 0.52, "qr_code": 0.36, "mfa_bypass": 0.40},
}

TECHNIQUE_LABELS = {
    "url_shortener": "Raccourcisseurs d'URL",
    "lookalike_domain": "Domaines sosies (typosquat)",
    "homoglyph": "Homoglyphes Unicode",
    "ai_polished": "Texte poli par IA générative",
    "qr_code": "QR-codes (quishing)",
    "mfa_bypass": "Contournement MFA / OAuth",
}


# --------------------------------------------------------------------------- #
# 2. Projection logistique
# --------------------------------------------------------------------------- #
@dataclass
class Projection:
    technique: str
    history: dict          # année -> prévalence
    forecast: dict         # année future -> prévalence estimée

    def as_dict(self) -> dict:
        return {"technique": self.technique,
                "label": TECHNIQUE_LABELS.get(self.technique, self.technique),
                "history": self.history, "forecast": self.forecast}


def _fit_logistic_growth(years, values):
    """Ajuste grossièrement une courbe logistique p(t)=L/(1+e^{-k(t-t0)}).

    Méthode simple et robuste : on borne L à 0.95, puis on estime k et t0 par
    régression linéaire sur le logit des prévalences observées."""
    L = 0.95
    ys, ts = [], []
    for t, v in zip(years, values):
        v = min(max(v, 1e-3), L - 1e-3)
        ys.append(math.log(v / (L - v)))     # logit
        ts.append(t)
    n = len(ts)
    mt = sum(ts) / n
    my = sum(ys) / n
    num = sum((t - mt) * (y - my) for t, y in zip(ts, ys))
    den = sum((t - mt) ** 2 for t in ts) or 1.0
    k = num / den
    b = my - k * mt
    return L, k, b


def project_technique(technique: str, horizon: int = 2028) -> Projection:
    years = sorted(HISTORY)
    values = [HISTORY[y][technique] for y in years]
    L, k, b = _fit_logistic_growth(years, values)
    forecast = {}
    for t in range(years[-1] + 1, horizon + 1):
        p = L / (1.0 + math.exp(-(k * t + b)))
        forecast[t] = round(min(max(p, 0.0), 0.99), 3)
    return Projection(technique, {y: HISTORY[y][technique] for y in years}, forecast)


def project_all(horizon: int = 2028) -> list:
    return [project_technique(tech, horizon) for tech in TECHNIQUE_LABELS]


# --------------------------------------------------------------------------- #
# 3. Leurres "du futur" : combinaison de techniques montantes
# --------------------------------------------------------------------------- #
_GENERIC_GREETINGS_RE = re.compile(
    r"\b(cher|chère)\s+(client|utilisateur|membre|abonné)e?\b[ ,:]*", re.IGNORECASE)
_OVER_URGENCY_RE = re.compile(
    r"\b(urgent|immédiatement|tout de suite|sous 24h|maintenant)\b", re.IGNORECASE)


def make_ai_polished(email: Email) -> Email:
    """Simule un leurre rédigé par une IA générative : suppression des marqueurs
    grossiers (formule générique, sur-urgence, multiples « ! ») et personnalisation.
    Le texte reste malveillant mais « propre » -> évite les indices textuels naïfs."""
    body = email.body or ""
    body = _GENERIC_GREETINGS_RE.sub("Bonjour Camille, ", body)
    body = _OVER_URGENCY_RE.sub("dans les meilleurs délais", body)
    body = re.sub(r"!{2,}", ".", body)
    body = re.sub(r"\s+", " ", body).strip()
    # Cadre professionnel crédible
    if "cordialement" not in body.lower():
        body += " Cordialement, le service client."
    subj = _OVER_URGENCY_RE.sub("", email.subject or "").strip(" :-") or email.subject
    return _clone(email, subject=subj, body=body)


def make_composite_future(email: Email, seed: int | None = None) -> Email:
    """Empile les évasions montantes : texte poli IA + homoglyphes discrets +
    caractères invisibles. Représente un leurre « 2026 » plausible."""
    if seed is not None:
        random.seed(seed)
    e = make_ai_polished(email)
    body = attack_homoglyph(e.body, p=0.35)
    body = attack_zero_width(body, p=0.15)
    subj = attack_homoglyph(e.subject, p=0.35)
    return _clone(e, subject=subj, body=body)


FUTURE_VARIANTS = {
    "ia_polie": make_ai_polished,
    "composite_2026": make_composite_future,
}


# --------------------------------------------------------------------------- #
# Test de robustesse prospectif
# --------------------------------------------------------------------------- #
@dataclass
class FutureRow:
    variant: str
    detection_attacked: float
    detection_defended: float
    n: int

    def as_dict(self) -> dict:
        return {"variant": self.variant,
                "detection_attacked": round(self.detection_attacked, 3),
                "detection_defended": round(self.detection_defended, 3),
                "drop": round(1.0 - self.detection_attacked, 3),
                "recovered": round(self.detection_defended - self.detection_attacked, 3),
                "n": self.n}


def _rate(detector, emails) -> float:
    if not emails:
        return 0.0
    s = detector.predict_proba(emails)
    return float((s >= detector.phish_threshold).mean())


def evaluate_future(detector, phishing_emails: list, seed: int = 0):
    """Sur les phishing détectés aujourd'hui, mesure la détection face aux
    variantes 'du futur' (nu vs défendu)."""
    base = detector.predict_proba(phishing_emails)
    detected = [e for e, s in zip(phishing_emails, base)
                if s >= detector.phish_threshold]
    rows = []
    for name, fn in FUTURE_VARIANTS.items():
        random.seed(seed)
        attacked = [fn(e) for e in detected]
        defended = [sanitize_email(a) for a in attacked]
        rows.append(FutureRow(name, _rate(detector, attacked),
                              _rate(detector, defended), len(detected)))
    clean = len(detected) / len(phishing_emails) if phishing_emails else 0.0
    return rows, clean


# --------------------------------------------------------------------------- #
# Démo CLI
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print("=== Projection des techniques de phishing (horizon 2028) ===\n")
    for proj in project_all(2028):
        d = proj.as_dict()
        last_hist = d["history"][max(d["history"])]
        last_fore = d["forecast"][max(d["forecast"])]
        arrow = "↑" if last_fore > last_hist else "→"
        print(f"  {d['label']:34s} 2025={last_hist:.0%}  ->  2028≈{last_fore:.0%}  {arrow}")

    print("\n=== Test de robustesse prospectif ===")
    import pandas as pd
    from .detector import PhishDetector, emails_from_dataframe
    root = Path(__file__).resolve().parent.parent
    det = PhishDetector.load(str(root / "models" / "phishdetector.joblib"))
    df = pd.read_csv(root / "data" / "phishlab_dataset.csv").fillna("")
    phish_fams = {"invoice", "reset", "hr", "delivery", "account",
                  "prize", "ceo", "support"}
    pool = df[df["family"].isin(phish_fams)]
    emails = emails_from_dataframe(pool.sample(min(250, len(pool)), random_state=2))
    rows, clean = evaluate_future(det, emails)
    print(f"Détection de référence : {clean:.1%}  (n={rows[0].n})")
    for r in rows:
        d = r.as_dict()
        print(f"  {d['variant']:16s} attaqué={d['detection_attacked']:.0%}  "
              f"défendu={d['detection_defended']:.0%}  (chute {d['drop']:+.0%})")
