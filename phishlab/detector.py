"""
phishlab.detector
=================
Moteur de détection : fusion d'un signal TABULAIRE (features ingéniérées) et
d'un signal TEXTE (TF-IDF mots + caractères).

Conformément au cahier des charges, on commence par un baseline solide
(Régression Logistique / Random Forest) avant de complexifier (XGBoost). Le
même pipeline accepte les trois backends pour comparaison.

La sortie est :
    - un score de risque calibré dans [0, 1]
    - un label : "benin" / "suspect" / "phishing" (seuils configurables)

Le détecteur est sérialisable (joblib) pour un déploiement léger.
"""
from __future__ import annotations

import joblib
import numpy as np
from dataclasses import dataclass
from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

try:
    from xgboost import XGBClassifier
    _HAS_XGB = True
except Exception:                       # pragma: no cover
    _HAS_XGB = False

from .features import (
    Email, extract_features, features_to_vector, clean_text_for_nlp,
    FEATURE_NAMES,
)


# Seuils de décision : en dessous de SUSPECT -> bénin, au dessus de PHISH -> phishing.
DEFAULT_SUSPECT_THRESHOLD = 0.40
DEFAULT_PHISH_THRESHOLD = 0.70


@dataclass
class Prediction:
    score: float                 # risque calibré [0,1]
    label: str                   # "benin" | "suspect" | "phishing"
    tabular: dict[str, float]    # features tabulaires calculées
    nlp_top_terms: list[tuple[str, float]]  # termes TF-IDF les plus influents

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "tabular": self.tabular,
            "nlp_top_terms": self.nlp_top_terms,
        }


class PhishDetector:
    """Détecteur entraînable et sérialisable."""

    def __init__(self, model_type: str = "logreg",
                 suspect_threshold: float = DEFAULT_SUSPECT_THRESHOLD,
                 phish_threshold: float = DEFAULT_PHISH_THRESHOLD,
                 calibrate: bool = True):
        self.model_type = model_type
        self.suspect_threshold = suspect_threshold
        self.phish_threshold = phish_threshold
        self.calibrate = calibrate

        # Vectoriseur TF-IDF : mots (1-2 grammes) - capte le vocabulaire de phishing.
        self.tfidf_word = TfidfVectorizer(
            analyzer="word", ngram_range=(1, 2), min_df=3, max_df=0.9,
            max_features=8000, sublinear_tf=True,
        )
        # Vectoriseur caractères (3-5 grammes) - robuste à l'obfuscation/typos.
        self.tfidf_char = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), min_df=3,
            max_features=6000, sublinear_tf=True,
        )
        self.scaler = StandardScaler()
        self.model = None
        self._fitted = False

    # ------------------------------------------------------------------ #
    # Construction des matrices de features
    # ------------------------------------------------------------------ #
    def _build_matrix(self, emails: list[Email], fit: bool):
        texts = [clean_text_for_nlp(e) for e in emails]
        tab = np.array([features_to_vector(extract_features(e)) for e in emails],
                       dtype=float)

        if fit:
            Xw = self.tfidf_word.fit_transform(texts)
            Xc = self.tfidf_char.fit_transform(texts)
            Xt = self.scaler.fit_transform(tab)
        else:
            Xw = self.tfidf_word.transform(texts)
            Xc = self.tfidf_char.transform(texts)
            Xt = self.scaler.transform(tab)

        X = hstack([csr_matrix(Xt), Xw, Xc]).tocsr()
        return X, tab

    def _make_model(self):
        if self.model_type == "logreg":
            return LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")
        if self.model_type == "rf":
            return RandomForestClassifier(
                n_estimators=300, max_depth=None, min_samples_leaf=2,
                class_weight="balanced", n_jobs=-1, random_state=42)
        if self.model_type == "xgb":
            if not _HAS_XGB:
                raise RuntimeError("xgboost non disponible")
            return XGBClassifier(
                n_estimators=400, max_depth=6, learning_rate=0.1,
                subsample=0.9, colsample_bytree=0.8, eval_metric="logloss",
                n_jobs=-1, random_state=42, tree_method="hist")
        raise ValueError(f"model_type inconnu: {self.model_type}")

    # ------------------------------------------------------------------ #
    # Entraînement / prédiction
    # ------------------------------------------------------------------ #
    def fit(self, emails: list[Email], labels: list[int]):
        X, _ = self._build_matrix(emails, fit=True)
        base = self._make_model()
        if self.calibrate:
            # Calibration des probabilités (sigmoïde) - important : "80% de risque"
            # doit refléter ~80% de phishing réel (cf. plan d'évaluation).
            self.model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
            self.model.fit(X, labels)
        else:
            self.model = base
            self.model.fit(X, labels)
        self._fitted = True
        return self

    def predict_proba(self, emails: list[Email]) -> np.ndarray:
        X, _ = self._build_matrix(emails, fit=False)
        return self.model.predict_proba(X)[:, 1]

    def _label_for(self, score: float) -> str:
        if score >= self.phish_threshold:
            return "phishing"
        if score >= self.suspect_threshold:
            return "suspect"
        return "benin"

    def analyze(self, email: Email, top_terms: int = 8) -> Prediction:
        """Analyse complète d'un email unique -> Prediction."""
        score = float(self.predict_proba([email])[0])
        tab = extract_features(email)
        nlp_terms = self._nlp_contributions(email, k=top_terms)
        return Prediction(score=score, label=self._label_for(score),
                          tabular=tab, nlp_top_terms=nlp_terms)

    # ------------------------------------------------------------------ #
    # Contributions NLP (approche linéaire si dispo, sinon présence TF-IDF)
    # ------------------------------------------------------------------ #
    def _nlp_contributions(self, email: Email, k: int = 8) -> list[tuple[str, float]]:
        """Termes TF-IDF (mots) les plus présents/pesants dans cet email."""
        text = clean_text_for_nlp(email)
        vec = self.tfidf_word.transform([text])
        if vec.nnz == 0:
            return []
        names = self.tfidf_word.get_feature_names_out()
        idx = vec.indices
        vals = vec.data

        # Si le modèle est linéaire (logreg calibré), on pondère par le poids appris.
        weights = self._linear_word_weights()
        scored = []
        for j, v in zip(idx, vals):
            w = weights.get(j, 0.0) if weights else 1.0
            scored.append((names[j], float(v * w)))
        scored.sort(key=lambda t: abs(t[1]), reverse=True)
        return scored[:k]

    def _linear_word_weights(self) -> dict[int, float] | None:
        """Récupère les coefficients linéaires alignés sur l'espace 'mots' TF-IDF."""
        clf = self.model
        # Démêle la calibration pour atteindre le LogisticRegression sous-jacent.
        if isinstance(clf, CalibratedClassifierCV):
            try:
                ests = [c.estimator for c in clf.calibrated_classifiers_]
                if not all(isinstance(e, LogisticRegression) for e in ests):
                    return None
                coef = np.mean([e.coef_[0] for e in ests], axis=0)
            except Exception:
                return None
        elif isinstance(clf, LogisticRegression):
            coef = clf.coef_[0]
        else:
            return None

        # Offsets dans la matrice concaténée : [tabular | word | char]
        n_tab = len(FEATURE_NAMES)
        n_word = len(self.tfidf_word.get_feature_names_out())
        word_coef = coef[n_tab:n_tab + n_word]
        return {j: float(word_coef[j]) for j in range(n_word)}

    # ------------------------------------------------------------------ #
    # Persistance
    # ------------------------------------------------------------------ #
    def save(self, path: str):
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "PhishDetector":
        return joblib.load(path)


def emails_from_dataframe(df) -> list[Email]:
    """Construit des objets Email à partir du DataFrame du dataset."""
    emails = []
    for _, r in df.iterrows():
        attachments = []
        if isinstance(r.get("attachments"), str) and r["attachments"].strip():
            attachments = r["attachments"].split(";")
        emails.append(Email(
            subject=str(r.get("subject", "") or ""),
            body=str(r.get("body", "") or ""),
            sender_display=str(r.get("sender_display", "") or ""),
            sender_email=str(r.get("sender_email", "") or ""),
            reply_to=str(r.get("reply_to", "") or ""),
            spf=str(r.get("spf", "none") or "none"),
            dkim=str(r.get("dkim", "none") or "none"),
            dmarc=str(r.get("dmarc", "none") or "none"),
            attachments=attachments,
            has_html=bool(int(r.get("has_html", 0) or 0)),
            num_recipients=int(r.get("num_recipients", 1) or 1),
        ))
    return emails
