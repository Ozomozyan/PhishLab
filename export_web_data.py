"""
export_web_data.py
=================

Rassemble en un seul fichier JSON tout ce dont le tableau de bord autonome a
besoin pour scorer un email DANS LE NAVIGATEUR, sans serveur :

  * paramètres du scorer linéaire (coefficients, standardisation, seuils, termes)
  * lexiques exacts (marques, urgence, identifiants, appâts, TLD à risque...)
  * libellés explicatifs (HUMAN_LABELS + protections)
  * quelques emails d'exemple (phishing / suspect / bénin)

Le JSON est ensuite injecté tel quel dans dashboard.html (clé PHISHLAB_DATA).
"""

from __future__ import annotations

import json
from pathlib import Path

from phishlab import features as F

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / "models"
WEB = ROOT / "web"
WEB.mkdir(exist_ok=True)


def to_list(x):
    return sorted(x) if isinstance(x, (set, frozenset)) else list(x)


def main():
    scorer = json.loads((MODELS / "scorer_export.json").read_text())

    data = {
        "scorer": scorer,
        "feature_names": F.FEATURE_NAMES,
        "lexicons": {
            "brands": to_list(F.TARGET_BRANDS),
            "urgency": to_list(F.URGENCY_TERMS),
            "credential": to_list(F.CREDENTIAL_TERMS),
            "lure": to_list(F.LURE_TERMS),
            "greetings": to_list(F.GENERIC_GREETINGS),
            "free_providers": to_list(F.FREE_EMAIL_PROVIDERS),
            "suspicious_tlds": to_list(F.SUSPICIOUS_TLDS),
            "shorteners": to_list(F.URL_SHORTENERS),
            "dangerous_ext": to_list(F.DANGEROUS_EXTENSIONS),
            "homoglyphs": list(F.HOMOGLYPH_MAP.keys()),
        },
        "human_labels": F.HUMAN_LABELS,
        "samples": SAMPLES,
    }
    out = WEB / "phishlab_data.json"
    out.write_text(json.dumps(data, ensure_ascii=False))
    kb = out.stat().st_size / 1024
    print(f"Écrit: {out}  ({kb:.0f} Ko)")
    print(f"  features={len(data['feature_names'])}  "
          f"termes={len(scorer['terms'])}  "
          f"marques={len(data['lexicons']['brands'])}  "
          f"homoglyphes={len(data['lexicons']['homoglyphs'])}")


# Emails d'exemple (synthétiques) pour la démonstration.
SAMPLES = [
    {
        "name": "Phishing — PayPal (typosquat)",
        "kind": "phishing",
        "subject": "URGENT : votre compte PayPaI sera suspendu sous 24h",
        "body": ("Cher client,\n\nNous avons détecté une activité suspecte sur votre "
                 "compte. Pour éviter sa suspension, confirmez immédiatement votre "
                 "mot de passe et votre carte bancaire en cliquant ici :\n"
                 "http://paypa1-secure.verify-account.tk/login\n\n"
                 "Sans action sous 24 heures, votre compte sera définitivement bloqué.\n\n"
                 "Service Sécurité PayPal"),
        "sender_display": "PayPal Sécurité",
        "sender_email": "service@paypa1-secure.tk",
        "reply_to": "no-reply@mail-paypal.xyz",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "has_html": False, "attachments": [],
    },
    {
        "name": "Phishing — Fraude au président (BEC)",
        "kind": "phishing",
        "subject": "Demande urgente et confidentielle",
        "body": ("Bonjour,\n\nJe suis en réunion et injoignable par téléphone. "
                 "J'ai besoin que vous procédiez à un virement urgent de 24 800 € "
                 "vers un nouveau fournisseur. C'est strictement confidentiel, ne "
                 "communiquez avec personne d'autre. Je vous envoie le RIB dès que "
                 "possible. Merci de traiter cela dans l'heure.\n\nLe Directeur Général"),
        "sender_display": "Jean Dupont (DG)",
        "sender_email": "dg.direction@gmail.com",
        "reply_to": "", "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "has_html": False, "attachments": [],
    },
    {
        "name": "Phishing — Réinit. Microsoft (typosquat)",
        "kind": "phishing",
        "subject": "Microsoft : activité inhabituelle, réinitialisez votre mot de passe",
        "body": ("Cher utilisateur,\n\nNous avons détecté une connexion inhabituelle à "
                 "votre compte Microsoft depuis un nouvel appareil. Par mesure de "
                 "sécurité, votre accès a été temporairement limité.\n\n"
                 "Vous devez réinitialiser votre mot de passe immédiatement pour "
                 "rétablir l'accès :\nhttp://micros0ft-securite.account-verify.tk/reset\n\n"
                 "Sans action sous 24 heures, votre compte sera définitivement désactivé.\n\n"
                 "Équipe de sécurité Microsoft"),
        "sender_display": "Microsoft Sécurité",
        "sender_email": "no-reply@micros0ft-securite.tk",
        "reply_to": "support@account-verify.tk",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "has_html": False, "attachments": [],
    },
    {
        "name": "Bénin — Reçu d'achat légitime",
        "kind": "benin",
        "subject": "Votre reçu Amazon — commande 402-7731902",
        "body": ("Bonjour Camille,\n\nMerci pour votre commande. Votre colis sera "
                 "livré entre le 12 et le 14 juin. Vous pouvez suivre votre commande "
                 "depuis votre compte : https://www.amazon.fr/orders\n\n"
                 "Montant total : 37,49 €.\n\nÀ bientôt,\nL'équipe Amazon"),
        "sender_display": "Amazon.fr",
        "sender_email": "commande@amazon.fr",
        "reply_to": "", "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "has_html": False, "attachments": [],
    },
    {
        "name": "Bénin — Alerte sécurité légitime (piège difficile)",
        "kind": "benin",
        "subject": "Nouvelle connexion détectée sur votre compte",
        "body": ("Bonjour,\n\nUne nouvelle connexion à votre compte a été détectée "
                 "depuis Paris, France. Si c'était bien vous, aucune action n'est "
                 "nécessaire. Sinon, vous pouvez sécuriser votre compte depuis les "
                 "paramètres habituels de votre application.\n\n"
                 "L'équipe Sécurité."),
        "sender_display": "Sécurité du compte",
        "sender_email": "security@notifications.monservice.com",
        "reply_to": "", "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "has_html": False, "attachments": [],
    },
]


if __name__ == "__main__":
    main()
