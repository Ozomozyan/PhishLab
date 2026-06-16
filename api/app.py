"""
api/app.py — Backend Flask de PhishLab
=====================================

API REST légère qui expose le détecteur, l'explicabilité, la simulation et la
simulation prédictive. Sert aussi le tableau de bord statique.

Endpoints :
  GET  /                  -> tableau de bord (dashboard.html)
  GET  /api/health        -> état du service
  POST /api/analyze       -> { email } -> score + label + explication complète
  GET  /api/metrics       -> métriques d'évaluation (reports/metrics.json)
  GET  /api/robustness    -> robustesse adverse (reports/robustness.json)
  GET  /api/predictive    -> simulation prédictive (reports/predictive.json)
  POST /api/simulate      -> { training } -> rapport de campagne de sensibilisation
  GET  /api/inbox         -> boîte de réception d'entraînement (leurres synthétiques)

Lancement :
    python api/app.py          (http://127.0.0.1:5000)
"""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory

from phishlab.detector import PhishDetector
from phishlab.features import Email
from phishlab import explainer as EXP
from phishlab import simulator as SIM

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
STATIC = ROOT / "web"

app = Flask(__name__, static_folder=None)

# Chargement unique du modèle au démarrage.
_DETECTOR = None


def get_detector() -> PhishDetector:
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = PhishDetector.load(str(MODELS / "phishdetector.joblib"))
    return _DETECTOR


def _email_from_payload(data: dict) -> Email:
    return Email(
        subject=data.get("subject", "") or "",
        body=data.get("body", "") or "",
        sender_display=data.get("sender_display", "") or "",
        sender_email=data.get("sender_email", "") or "",
        reply_to=data.get("reply_to", "") or "",
        spf=data.get("spf", "none") or "none",
        dkim=data.get("dkim", "none") or "none",
        dmarc=data.get("dmarc", "none") or "none",
        attachments=data.get("attachments", []) or [],
        has_html=bool(data.get("has_html", False)),
        num_recipients=int(data.get("num_recipients", 1) or 1),
    )


# --------------------------------------------------------------------------- #
# Pages statiques
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(STATIC, "dashboard.html")


@app.route("/web/<path:fname>")
def web_assets(fname):
    return send_from_directory(STATIC, fname)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "model_loaded": _DETECTOR is not None})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True, silent=True) or {}
    email = _email_from_payload(data)
    det = get_detector()
    exp = EXP.explain(det, email)
    return jsonify(exp.as_dict())


@app.route("/api/metrics")
def metrics():
    p = REPORTS / "metrics.json"
    if not p.exists():
        return jsonify({"error": "metrics.json absent — lancez train.py"}), 404
    return jsonify(json.loads(p.read_text()))


@app.route("/api/robustness")
def robustness():
    p = REPORTS / "robustness.json"
    if not p.exists():
        return jsonify({"error": "robustness.json absent — lancez eval_robustness.py"}), 404
    return jsonify(json.loads(p.read_text()))


@app.route("/api/predictive")
def predictive():
    p = REPORTS / "predictive.json"
    if not p.exists():
        return jsonify({"error": "predictive.json absent — lancez eval_predictive.py"}), 404
    return jsonify(json.loads(p.read_text()))


@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.get_json(force=True, silent=True) or {}
    training = data.get("training", "aucune")
    results = SIM.run_campaign(training=training)
    return jsonify({"training": training,
                    "scenarios": [r.as_dict() for r in results]})


@app.route("/api/inbox")
def inbox():
    n = int(request.args.get("n", 2))
    return jsonify({"emails": SIM.build_training_inbox(n_per_family=n)})


if __name__ == "__main__":
    print("PhishLab API -> http://127.0.0.1:5000")
    get_detector()
    app.run(host="127.0.0.1", port=5000, debug=False)
