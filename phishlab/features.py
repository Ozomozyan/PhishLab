"""
phishlab.features
=================
Extraction de caractéristiques (features) à partir d'un email.

Ce module transforme un email brut (sujet, corps, métadonnées) en un vecteur de
features numériques interprétables. Chaque feature est conçue pour être
EXPLICABLE : on doit pouvoir dire à l'utilisateur "ton email est suspect PARCE
QUE telle feature a telle valeur".

On distingue deux familles :
  - features TABULAIRES  -> utilisées par le modèle baseline (LR / RF / XGBoost)
                            et expliquées via SHAP/LIME
  - signal TEXTE         -> sujet + corps nettoyés, passés au vectoriseur TF-IDF

Aucune dépendance lourde : uniquement la librairie standard Python.
"""
from __future__ import annotations

import re
import math
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Ressources lexicales (marques ciblées, mots d'urgence, etc.)
# ---------------------------------------------------------------------------

# Marques les plus usurpées dans le phishing réel (rapports APWG / Cofense).
TARGET_BRANDS = [
    "paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook",
    "instagram", "linkedin", "dhl", "fedex", "ups", "laposte", "chronopost",
    "ameli", "impots", "caf", "orange", "free", "sfr", "bouygues", "sncf",
    "banque", "creditagricole", "bnpparibas", "societegenerale", "lcl",
    "office365", "outlook", "docusign", "dropbox", "wetransfer", "coinbase",
    "binance", "revolut", "n26", "boursorama", "spotify", "adobe",
]

# Mots / expressions d'urgence (FR + EN), normalisés en minuscules.
URGENCY_TERMS = [
    "urgent", "immédiat", "immediat", "immediately", "maintenant", "now",
    "aujourd'hui", "today", "expire", "expired", "expiration", "dernier délai",
    "deadline", "24h", "48h", "dès que possible", "asap", "rapidement",
    "action requise", "action required", "attention", "warning", "alerte",
    "alert", "suspendu", "suspended", "bloqué", "blocked", "verrouillé",
    "locked", "limité", "limited", "dernière chance", "last chance",
    "ne tardez pas", "sans délai", "compte fermé", "définitivement",
]

# Demandes d'identifiants / d'informations sensibles.
CREDENTIAL_TERMS = [
    "mot de passe", "password", "identifiant", "login", "code pin", "pin code",
    "carte bancaire", "credit card", "numéro de carte", "card number", "cvv",
    "cvc", "iban", "rib", "code de sécurité", "security code", "vérifiez votre",
    "verify your", "confirmez votre", "confirm your", "mettez à jour",
    "update your", "réactiver", "reactivate", "valider votre compte",
    "validate your account", "coordonnées bancaires", "social security",
    "sécurité sociale", "numéro de sécurité", "se connecter", "sign in",
]

# Appâts financiers / promesses de gain.
LURE_TERMS = [
    "gagné", "won", "gagnant", "winner", "félicitations", "congratulations",
    "remboursement", "refund", "cadeau", "gift", "bon d'achat", "voucher",
    "prime", "bonus", "loterie", "lottery", "héritage", "inheritance",
    "million", "récompense", "reward", "offre exclusive", "exclusive offer",
    "gratuit", "free", "cashback", "crypto", "bitcoin", "investissement",
]

# Salutations génériques (signe de campagne de masse).
GENERIC_GREETINGS = [
    "cher client", "dear customer", "dear user", "cher utilisateur",
    "bonjour cher", "dear valued", "dear member", "cher membre",
    "dear account holder", "to whom it may concern", "dear sir/madam",
]

# Fournisseurs d'email gratuits (suspect si un "service officiel" les utilise).
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
    "outlook.com", "outlook.fr", "live.com", "live.fr", "aol.com", "gmx.com",
    "gmx.fr", "protonmail.com", "yandex.com", "mail.ru", "icloud.com",
    "free.fr", "laposte.net", "orange.fr", "sfr.fr", "wanadoo.fr",
]

# TLD à risque élevé (souvent abusés, peu coûteux / peu régulés).
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "online", "site",
    "work", "click", "link", "fit", "loan", "review", "country", "stream",
    "download", "racing", "win", "bid", "men", "date", "buzz", "icu", "cam",
    "rest", "zip", "mov", "support", "live", "monster", "su", "cc",
]

# Raccourcisseurs d'URL (masquent la destination réelle).
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly",
    "tiny.cc", "lnkd.in", "soo.gd", "s2r.co",
]

# Extensions de pièces jointes dangereuses.
DANGEROUS_EXTENSIONS = [
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar", "ps1",
    "msi", "hta", "iso", "img", "lnk", "html", "htm", "svg", "zip", "rar",
    "7z", "docm", "xlsm", "pptm", "ace",
]

# Caractères homoglyphes Unicode -> latin (sous-ensemble représentatif).
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ա": "a",
    "ｏ": "o", "０": "0", "１": "1", "ⅼ": "l", "ℓ": "l", "𝐚": "a", "𝟎": "0",
    "ﬁ": "fi", "ν": "v", "ρ": "p", "α": "a", "ε": "e", "ο": "o", "τ": "t",
}

# Regex utilitaires
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_WORD_RE = re.compile(r"\b\w+\b", re.UNICODE)


# ---------------------------------------------------------------------------
# Représentation d'un email
# ---------------------------------------------------------------------------

@dataclass
class Email:
    """Email brut à analyser. Seuls subject/body sont obligatoires."""
    subject: str = ""
    body: str = ""
    sender_display: str = ""            # nom affiché de l'expéditeur
    sender_email: str = ""              # adresse réelle de l'expéditeur
    reply_to: str = ""                  # adresse reply-to
    spf: str = "none"                   # pass | fail | softfail | none
    dkim: str = "none"                  # pass | fail | none
    dmarc: str = "none"                 # pass | fail | none
    attachments: list[str] = field(default_factory=list)  # noms de fichiers
    has_html: bool = False              # corps en HTML
    num_recipients: int = 1

    def full_text(self) -> str:
        return f"{self.subject}\n{self.body}"


# ---------------------------------------------------------------------------
# Fonctions utilitaires de bas niveau
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Minuscule + suppression des accents pour le matching lexical."""
    text = text.lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text


def _count_terms(text_norm: str, terms: list[str]) -> int:
    return sum(text_norm.count(_normalize(t)) for t in terms)


def _domain_of(email_or_url: str) -> str:
    """Extrait le domaine d'une adresse email ou d'une URL."""
    s = email_or_url.strip().lower()
    if "@" in s and "://" not in s:
        return s.split("@")[-1].strip().strip(">")
    m = re.search(r"https?://([^/\s:]+)", s)
    if m:
        host = m.group(1)
        return host[4:] if host.startswith("www.") else host
    return ""


def _registered_domain(host: str) -> str:
    """Approxime le domaine enregistré (les 2 derniers labels)."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _tld_of(host: str) -> str:
    return host.split(".")[-1] if "." in host else ""


def _shannon_entropy(s: str) -> float:
    """Entropie de Shannon des caractères (les domaines DGA ont une entropie élevée)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _levenshtein(a: str, b: str) -> int:
    """Distance d'édition (pour détecter les domaines lookalike)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _digit_letter_substitution(host: str) -> bool:
    """Détecte les substitutions chiffre<->lettre type paypa1, g00gle, micr0soft."""
    leet = host.translate(str.maketrans("01345", "oleas"))
    base = re.sub(r"[^a-z]", "", _registered_domain(host).split(".")[0])
    leet_base = re.sub(r"[^a-z]", "", leet.split(".")[0])
    for brand in TARGET_BRANDS:
        if base != brand and leet_base == brand:
            return True
    return False


def _has_homoglyph(text: str) -> bool:
    return any(ch in HOMOGLYPH_MAP for ch in text)


def _nearest_brand_distance(host: str) -> int:
    """Plus petite distance d'édition entre le domaine et une marque ciblée."""
    label = re.sub(r"[^a-z0-9]", "", _registered_domain(host).split(".")[0])
    if not label:
        return 99
    best = 99
    for brand in TARGET_BRANDS:
        d = _levenshtein(label, brand)
        # On ignore l'égalité parfaite (légitime) sauf si le TLD diffère ;
        # ici on veut surtout les "presque-égaux".
        if 0 < d < best:
            best = d
    return best


# ---------------------------------------------------------------------------
# Extraction principale des features
# ---------------------------------------------------------------------------

#: Ordre canonique des features tabulaires (sert de schéma pour le modèle).
FEATURE_NAMES: list[str] = [
    "url_count",
    "url_has_ip",
    "url_max_len",
    "url_max_subdomains",
    "url_has_at_symbol",
    "url_uses_shortener",
    "url_suspicious_tld",
    "url_https_ratio",
    "url_max_entropy",
    "lookalike_brand_distance",
    "digit_letter_substitution",
    "has_homoglyph",
    "sender_display_domain_mismatch",
    "reply_to_mismatch",
    "free_provider_official_claim",
    "sender_suspicious_tld",
    "urgency_term_count",
    "credential_term_count",
    "lure_term_count",
    "generic_greeting",
    "exclamation_ratio",
    "uppercase_ratio",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "auth_missing",
    "has_attachment",
    "dangerous_attachment",
    "body_length",
    "link_text_mismatch",
]


def extract_features(email: Email) -> dict[str, float]:
    """Calcule le vecteur de features tabulaires (dict nom -> valeur)."""
    text = email.full_text()
    text_norm = _normalize(text)

    urls = _URL_RE.findall(text)
    url_hosts = [_domain_of(u) for u in urls]

    # ---- Features d'URL -------------------------------------------------
    url_count = len(urls)
    url_has_ip = int(any(_IP_HOST_RE.match(u) for u in urls))
    url_max_len = max((len(u) for u in urls), default=0)
    url_max_subdomains = max((h.count(".") for h in url_hosts), default=0)
    url_has_at = int(any("@" in u.split("://", 1)[-1].split("/")[0] for u in urls))
    url_shortener = int(any(_registered_domain(h) in URL_SHORTENERS for h in url_hosts))
    url_susp_tld = int(any(_tld_of(h) in SUSPICIOUS_TLDS for h in url_hosts))
    https_ratio = (sum(u.lower().startswith("https") for u in urls) / url_count) if url_count else 1.0
    url_max_entropy = max((_shannon_entropy(h.split(".")[0]) for h in url_hosts), default=0.0)

    # ---- Lookalike / homoglyphes ---------------------------------------
    lookalike_dist = min((_nearest_brand_distance(h) for h in url_hosts), default=99)
    lookalike_dist = min(lookalike_dist, 9)  # on borne pour le modèle
    digit_sub = int(any(_digit_letter_substitution(h) for h in url_hosts))
    homoglyph = int(_has_homoglyph(text) or any(_has_homoglyph(h) for h in url_hosts))

    # ---- Features d'expéditeur -----------------------------------------
    sender_dom = _domain_of(email.sender_email)
    reply_dom = _domain_of(email.reply_to)
    display_norm = _normalize(email.sender_display)

    # Le nom affiché prétend être une marque mais le domaine ne correspond pas ?
    display_mismatch = 0
    for brand in TARGET_BRANDS:
        if brand in display_norm and sender_dom and brand not in sender_dom:
            display_mismatch = 1
            break

    reply_mismatch = int(bool(reply_dom) and bool(sender_dom)
                         and _registered_domain(reply_dom) != _registered_domain(sender_dom))

    # "Service officiel" (marque dans le nom affiché ou le sujet) mais via un
    # fournisseur d'email gratuit -> très suspect.
    claims_official = any(b in display_norm or b in text_norm for b in TARGET_BRANDS)
    free_official = int(claims_official and sender_dom in FREE_EMAIL_PROVIDERS)

    sender_susp_tld = int(_tld_of(sender_dom) in SUSPICIOUS_TLDS)

    # ---- Features textuelles -------------------------------------------
    urgency = _count_terms(text_norm, URGENCY_TERMS)
    credential = _count_terms(text_norm, CREDENTIAL_TERMS)
    lure = _count_terms(text_norm, LURE_TERMS)
    generic = int(any(g in text_norm for g in (_normalize(x) for x in GENERIC_GREETINGS)))

    n_chars = max(len(text), 1)
    exclamation_ratio = text.count("!") / n_chars
    letters = [c for c in text if c.isalpha()]
    uppercase_ratio = (sum(c.isupper() for c in letters) / len(letters)) if letters else 0.0

    # ---- Authentification ----------------------------------------------
    spf_fail = int(email.spf.lower() in ("fail", "softfail"))
    dkim_fail = int(email.dkim.lower() == "fail")
    dmarc_fail = int(email.dmarc.lower() == "fail")
    auth_missing = int(email.spf.lower() == "none" and email.dkim.lower() == "none"
                       and email.dmarc.lower() == "none")

    # ---- Pièces jointes -------------------------------------------------
    has_attach = int(len(email.attachments) > 0)
    dangerous_attach = 0
    for fn in email.attachments:
        ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
        # double extension (facture.pdf.exe) ou extension dangereuse
        if ext in DANGEROUS_EXTENSIONS:
            dangerous_attach = 1
            break

    # ---- Structure HTML : texte de lien != href ------------------------
    link_text_mismatch = 0
    if email.has_html:
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                             email.body, re.IGNORECASE | re.DOTALL):
            href_dom = _domain_of(m.group(1))
            shown = re.sub(r"<[^>]+>", "", m.group(2))
            shown_dom = _domain_of(shown) if "http" in shown.lower() else ""
            if shown_dom and href_dom and _registered_domain(shown_dom) != _registered_domain(href_dom):
                link_text_mismatch = 1
                break

    return {
        "url_count": float(url_count),
        "url_has_ip": float(url_has_ip),
        "url_max_len": float(url_max_len),
        "url_max_subdomains": float(url_max_subdomains),
        "url_has_at_symbol": float(url_has_at),
        "url_uses_shortener": float(url_shortener),
        "url_suspicious_tld": float(url_susp_tld),
        "url_https_ratio": float(https_ratio),
        "url_max_entropy": float(url_max_entropy),
        "lookalike_brand_distance": float(lookalike_dist),
        "digit_letter_substitution": float(digit_sub),
        "has_homoglyph": float(homoglyph),
        "sender_display_domain_mismatch": float(display_mismatch),
        "reply_to_mismatch": float(reply_mismatch),
        "free_provider_official_claim": float(free_official),
        "sender_suspicious_tld": float(sender_susp_tld),
        "urgency_term_count": float(urgency),
        "credential_term_count": float(credential),
        "lure_term_count": float(lure),
        "generic_greeting": float(generic),
        "exclamation_ratio": float(exclamation_ratio),
        "uppercase_ratio": float(uppercase_ratio),
        "spf_fail": float(spf_fail),
        "dkim_fail": float(dkim_fail),
        "dmarc_fail": float(dmarc_fail),
        "auth_missing": float(auth_missing),
        "has_attachment": float(has_attach),
        "dangerous_attachment": float(dangerous_attach),
        "body_length": float(len(email.body)),
        "link_text_mismatch": float(link_text_mismatch),
    }


def features_to_vector(feats: dict[str, float]) -> list[float]:
    """Convertit le dict de features en vecteur ordonné selon FEATURE_NAMES."""
    return [feats[name] for name in FEATURE_NAMES]


def clean_text_for_nlp(email: Email) -> str:
    """Texte normalisé pour le vectoriseur TF-IDF (sujet + corps, URLs masquées)."""
    raw = email.full_text()
    raw = _URL_RE.sub(" URL_TOKEN ", raw)
    raw = _EMAIL_RE.sub(" EMAIL_TOKEN ", raw)
    raw = _normalize(raw)
    raw = re.sub(r"[^a-z0-9_\s]", " ", raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw


# Petit feature human-readable pour l'explicabilité par règles.
HUMAN_LABELS = {
    "url_has_ip": "L'URL pointe vers une adresse IP brute au lieu d'un nom de domaine",
    "url_uses_shortener": "Le lien utilise un raccourcisseur d'URL qui masque la vraie destination",
    "url_suspicious_tld": "Le domaine utilise une extension (TLD) souvent abusée par les attaquants",
    "lookalike_brand_distance": "Le domaine ressemble de très près à une marque connue (typosquatting)",
    "digit_letter_substitution": "Le domaine remplace des lettres par des chiffres pour imiter une marque (ex: paypa1.com)",
    "has_homoglyph": "Le texte contient des caractères Unicode visuellement identiques à des lettres latines (homoglyphes)",
    "sender_display_domain_mismatch": "Le nom affiché imite une marque mais le domaine d'envoi ne correspond pas",
    "reply_to_mismatch": "L'adresse de réponse (reply-to) diffère de l'expéditeur affiché",
    "free_provider_official_claim": "Un 'service officiel' vous écrit depuis une boîte mail gratuite (gmail, outlook...)",
    "sender_suspicious_tld": "Le domaine de l'expéditeur utilise une extension à risque",
    "urgency_term_count": "Le message crée un sentiment d'urgence pour vous faire agir vite",
    "credential_term_count": "Le message demande des identifiants ou des informations sensibles",
    "lure_term_count": "Le message promet un gain, un remboursement ou une récompense (appât)",
    "generic_greeting": "La formule d'appel est générique ('Cher client') typique d'un envoi de masse",
    "spf_fail": "L'authentification SPF a échoué (l'expéditeur n'est pas autorisé pour ce domaine)",
    "dkim_fail": "La signature DKIM a échoué (le message a pu être altéré ou usurpé)",
    "dmarc_fail": "La politique DMARC a échoué (forte présomption d'usurpation)",
    "auth_missing": "Aucune authentification email (SPF/DKIM/DMARC) n'est présente",
    "dangerous_attachment": "Une pièce jointe a une extension dangereuse (exécutable, script, archive...)",
    "link_text_mismatch": "Le texte d'un lien affiche un domaine différent de sa vraie destination",
    "url_has_at_symbol": "Une URL contient un symbole '@' qui peut détourner la destination réelle",
    "uppercase_ratio": "Usage excessif de majuscules (ton alarmiste)",
    "exclamation_ratio": "Usage excessif de points d'exclamation",
}


if __name__ == "__main__":
    # Démonstration rapide
    e = Email(
        subject="URGENT: Votre compte PayPal sera suspendu",
        body="Cher client, nous avons détecté une activité suspecte. "
             "Vérifiez votre mot de passe immédiatement: http://paypa1-secure.tk/login "
             "sinon votre compte sera bloqué définitivement !!!",
        sender_display="PayPal Service",
        sender_email="security@account-verify.gmail.com",
        reply_to="noreply@random-domain.xyz",
        spf="fail", dkim="none", dmarc="fail",
    )
    feats = extract_features(e)
    for k, v in feats.items():
        if v:
            print(f"{k:35s} {v}")
