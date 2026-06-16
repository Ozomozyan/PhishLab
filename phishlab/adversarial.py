"""
PhishLab - Robustesse adversariale (cahier des charges §3.5)
===========================================================

On se met à la place de l'attaquant : comment contourner le détecteur ? Puis on
met en place les défenses et on mesure ce qu'elles récupèrent.

Attaques d'évasion implémentées
-------------------------------
* char_spacing   : « v é r i f i e z   v o t r e   m o t   d e   p a s s e »
* homoglyph      : substitution de caractères latins par des homoglyphes
                   Unicode (cyrillique/grec) visuellement identiques
* leetspeak      : a->@/4, e->3, i->1, o->0, s->5 ...
* zero_width     : insertion de caractères de largeur nulle entre les lettres
* url_obfuscation: encodage %, sous-domaines trompeurs, symbole @, IP décimale
* image_only     : le contenu passe dans une « image » -> texte quasi vide
                   (contourne toute analyse textuelle)

Défenses (pipeline de canonicalisation)
---------------------------------------
* normalisation Unicode NFKC + table d'homoglyphes inverse
* dé-espacement des mots fragmentés
* suppression des caractères de largeur nulle
* canonicalisation d'URL (décodage %, extraction de l'hôte réel, @ -> hôte droit)
* dé-leet partiel
* scoring d'incertitude / abstention : near-boundary -> 'suspect'
* ensemble : moyenne de plusieurs modèles pour réduire la variance

Le protocole d'évaluation prend un échantillon de phishing détecté, applique
chaque attaque (mesure la chute du taux de détection), puis applique les défenses
(mesure la récupération).
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata
import random

from .features import Email, HOMOGLYPH_MAP, _URL_RE, _registered_domain

# Table inverse : homoglyphe -> caractère latin canonique
_INV_HOMOGLYPH = {k: v for k, v in HOMOGLYPH_MAP.items()}
# Quelques homoglyphes supplémentaires fréquents
_INV_HOMOGLYPH.update({
    "е": "e", "о": "o", "а": "a", "с": "c", "р": "p", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "Ι": "I", "Ο": "O",
    "Α": "A", "Ε": "E", "Ρ": "P", "Τ": "T", "Η": "H", "Κ": "K", "Μ": "M",
    "Ν": "N", "Β": "B", "Χ": "X", "ⅼ": "l", "ո": "n",
})

_ZERO_WIDTH = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]

_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
_DELEET = {"4": "a", "3": "e", "0": "o", "5": "s", "7": "t",
           "@": "a", "$": "s", "1": "i"}


# --------------------------------------------------------------------------- #
# ATTAQUES
# --------------------------------------------------------------------------- #
def attack_char_spacing(text: str, p: float = 0.75) -> str:
    """Insère des espaces entre les lettres des mots sensibles."""
    def space_word(w: str) -> str:
        return " ".join(list(w)) if len(w) >= 4 and random.random() < p else w
    return " ".join(space_word(w) for w in text.split(" "))


def attack_homoglyph(text: str, p: float = 0.6) -> str:
    latin_to_homo = {
        "e": "е", "o": "о", "a": "а", "c": "с", "p": "р", "x": "х",
        "y": "у", "s": "ѕ", "i": "і", "d": "ԁ", "j": "ј", "g": "ɡ",
    }
    out = []
    for ch in text:
        low = ch.lower()
        if low in latin_to_homo and random.random() < p:
            sub = latin_to_homo[low]
            out.append(sub.upper() if ch.isupper() else sub)
        else:
            out.append(ch)
    return "".join(out)


def attack_leetspeak(text: str, p: float = 0.5) -> str:
    out = []
    for ch in text:
        low = ch.lower()
        if low in _LEET and random.random() < p:
            out.append(_LEET[low])
        else:
            out.append(ch)
    return "".join(out)


def attack_zero_width(text: str, p: float = 0.3) -> str:
    out = []
    for ch in text:
        out.append(ch)
        if ch.isalpha() and random.random() < p:
            out.append(random.choice(_ZERO_WIDTH))
    return "".join(out)


def attack_url_obfuscation(email: Email) -> Email:
    """Obscurcit les URLs : encodage %, @, sous-domaine trompeur.

    La variante la plus efficace encode l'HOTE lui-meme en %xx : l'extracteur de
    features ne reconnait alors plus le TLD a risque ni la marque imitee
    (caracteres masques), ce qui fait chuter les signaux URL. La canonicalisation
    (decodage %xx) cote defense restaure l'hote reel."""
    def obf(url: str) -> str:
        m = re.match(r"(https?://)([^/]+)(.*)", url)
        if not m:
            return url
        scheme, host, rest = m.groups()
        trick = random.choice([
            f"{scheme}{_percent_encode_host(host)}{rest}",                     # hote encode -> evade les features
            f"{scheme}{host}@evil-{random.randint(1,99)}.tk{rest}",            # @ redirige l'hote reel
            f"{scheme}secure-login.{host}.verify-account.xyz{rest}",          # marque en sous-domaine
            f"{scheme}{_percent_encode_host(host)}{_percent_encode(rest)}",   # hote + chemin encodes
        ])
        return trick
    new_body = _URL_RE.sub(lambda mm: obf(mm.group(0)), email.body)
    return _clone(email, body=new_body)


def _percent_encode_host(host: str) -> str:
    """Encode en %xx les lettres de l'hôte (masque TLD et marque imitée)."""
    return "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in host)


def attack_image_only(email: Email) -> Email:
    """Simule un email « tout en image » : le texte disparaît, une pièce jointe
    image le remplace. Contourne toute analyse textuelle."""
    return _clone(
        email,
        subject=email.subject if random.random() < 0.5 else "",
        body=random.choice(["", "Voir l'image ci-jointe.", "[image]"]),
        attachments=list(email.attachments) + ["message.png"],
        has_html=True,
    )


def _percent_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" if c.isalpha() and random.random() < 0.5 else c
                   for c in s)


ATTACKS_TEXT = {
    "char_spacing": attack_char_spacing,
    "homoglyph": attack_homoglyph,
    "leetspeak": attack_leetspeak,
    "zero_width": attack_zero_width,
}
ATTACKS_EMAIL = {
    "url_obfuscation": attack_url_obfuscation,
    "image_only": attack_image_only,
}


def apply_attack(email: Email, name: str) -> Email:
    """Applique une attaque nommée à un email, renvoie un nouvel Email."""
    if name in ATTACKS_TEXT:
        fn = ATTACKS_TEXT[name]
        return _clone(email, subject=fn(email.subject), body=fn(email.body))
    if name in ATTACKS_EMAIL:
        return ATTACKS_EMAIL[name](email)
    raise ValueError(f"Attaque inconnue : {name}")


# --------------------------------------------------------------------------- #
# DÉFENSES - pipeline de canonicalisation
# --------------------------------------------------------------------------- #
def strip_zero_width(text: str) -> str:
    return "".join(c for c in text if c not in _ZERO_WIDTH)


def normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(_INV_HOMOGLYPH.get(c, c) for c in text)


def despace_words(text: str) -> str:
    """Recolle les séquences « m o t » -> « mot ».

    Heuristique : une suite de >=3 tokens d'un seul caractère alphanumérique
    séparés par des espaces est recollée."""
    def repl(m: re.Match) -> str:
        chunk = m.group(0)
        letters = [t for t in chunk.split(" ") if t]
        return "".join(letters)
    # 3+ lettres isolées consécutives
    pattern = re.compile(r"(?:\b\w\b[ ]){2,}\b\w\b")
    return pattern.sub(repl, text)


def deleet(text: str) -> str:
    """Dé-leet prudent : uniquement à l'intérieur de mots majoritairement
    alphabétiques (évite de casser les vrais nombres / montants)."""
    def fix_token(tok: str) -> str:
        alpha = sum(c.isalpha() for c in tok)
        if alpha >= max(2, len(tok) - 2):  # surtout des lettres
            return "".join(_DELEET.get(c, c) for c in tok)
        return tok
    return " ".join(fix_token(t) for t in text.split(" "))


def canonicalize_url(url: str) -> str:
    """Décode les URLs et extrait l'hôte réellement contacté."""
    from urllib.parse import unquote
    url = unquote(url)
    m = re.match(r"(https?://)([^/]+)(.*)", url)
    if not m:
        return url
    scheme, authority, rest = m.groups()
    # symbole @ : l'hôte réel est ce qui suit le dernier @
    if "@" in authority:
        authority = authority.split("@")[-1]
    return f"{scheme}{authority}{rest}"


def sanitize_email(email: Email) -> Email:
    """Applique l'ensemble du pipeline défensif et renvoie un email nettoyé,
    prêt à être (re)scoré par le détecteur."""
    def clean_text(t: str) -> str:
        t = strip_zero_width(t)
        t = normalize_homoglyphs(t)
        t = despace_words(t)
        t = deleet(t)
        return t
    new_body = _URL_RE.sub(lambda m: canonicalize_url(m.group(0)), email.body)
    return _clone(email, subject=clean_text(email.subject), body=clean_text(new_body))


# --------------------------------------------------------------------------- #
# Scoring robuste : ensemble + incertitude
# --------------------------------------------------------------------------- #
def uncertainty_band(score: float, low: float = 0.35, high: float = 0.65) -> str:
    """Renvoie 'incertain' si le score est proche de la frontière de décision.
    Permet l'abstention plutôt qu'une fausse certitude."""
    return "incertain" if low <= score <= high else "confiant"


def image_only_guard(email: Email) -> bool:
    """Détecte un email quasi sans texte mais avec image -> à traiter comme
    suspect par défaut (l'analyse textuelle est aveugle)."""
    txt = (email.subject + " " + email.body).strip()
    has_image = any(a.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg"))
                    for a in email.attachments)
    return has_image and len(re.sub(r"\W+", "", txt)) < 25


# --------------------------------------------------------------------------- #
# PROTOCOLE D'ÉVALUATION
# --------------------------------------------------------------------------- #
@dataclass
class RobustnessRow:
    attack: str
    detection_clean: float       # détection avant attaque
    detection_attacked: float    # détection sous attaque (modèle nu)
    detection_defended: float    # détection sous attaque + défenses
    n: int

    def as_dict(self) -> dict:
        return {
            "attack": self.attack,
            "detection_clean": round(self.detection_clean, 3),
            "detection_attacked": round(self.detection_attacked, 3),
            "detection_defended": round(self.detection_defended, 3),
            "drop": round(self.detection_clean - self.detection_attacked, 3),
            "recovered": round(self.detection_defended - self.detection_attacked, 3),
            "n": self.n,
        }


def _detection_rate(detector, emails: list[Email]) -> float:
    if not emails:
        return 0.0
    scores = detector.predict_proba(emails)
    th = detector.phish_threshold
    return float((scores >= th).mean())


def _detection_rate_with_guard(detector, emails: list[Email]) -> float:
    """Détection avec garde image-only : un email aveugle compte comme détecté
    (traité comme suspect/bloqué) si le garde se déclenche."""
    if not emails:
        return 0.0
    scores = detector.predict_proba(emails)
    th = detector.phish_threshold
    hits = 0
    for e, s in zip(emails, scores):
        if s >= th or image_only_guard(e):
            hits += 1
    return hits / len(emails)


def evaluate_robustness(detector, phishing_emails: list[Email],
                        seed: int = 0) -> list[RobustnessRow]:
    """Mesure, attaque par attaque, la détection clean / attaquée / défendue."""
    random.seed(seed)
    # on part des phishing effectivement détectés au départ (mesure honnête de
    # l'effet d'évasion : on veut savoir combien on en PERD)
    base_scores = detector.predict_proba(phishing_emails)
    detected = [e for e, s in zip(phishing_emails, base_scores)
                if s >= detector.phish_threshold]
    clean_rate = len(detected) / len(phishing_emails) if phishing_emails else 0.0

    rows = []
    for name in list(ATTACKS_TEXT) + list(ATTACKS_EMAIL):
        random.seed(seed)
        attacked = [apply_attack(e, name) for e in detected]
        random.seed(seed)
        defended = [sanitize_email(a) for a in attacked]

        if name == "image_only":
            det_att = _detection_rate(detector, attacked)
            det_def = _detection_rate_with_guard(detector, defended)
        else:
            det_att = _detection_rate(detector, attacked)
            det_def = _detection_rate(detector, defended)

        rows.append(RobustnessRow(
            attack=name,
            detection_clean=1.0,                 # par construction (détectés au départ)
            detection_attacked=det_att,
            detection_defended=det_def,
            n=len(detected),
        ))
    return rows, clean_rate


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _clone(email: Email, **changes) -> Email:
    base = dict(
        subject=email.subject, body=email.body,
        sender_display=email.sender_display, sender_email=email.sender_email,
        reply_to=email.reply_to, spf=email.spf, dkim=email.dkim, dmarc=email.dmarc,
        attachments=list(email.attachments), has_html=email.has_html,
        num_recipients=email.num_recipients,
    )
    base.update(changes)
    return Email(**base)


if __name__ == "__main__":
    import pandas as pd
    from pathlib import Path
    from .detector import PhishDetector, emails_from_dataframe

    root = Path(__file__).resolve().parent.parent
    det = PhishDetector.load(str(root / "models" / "phishdetector.joblib"))
    df = pd.read_csv(root / "data" / "phishlab_dataset.csv").fillna("")
    phish_fams = {"invoice", "reset", "hr", "delivery", "account",
                  "prize", "ceo", "support"}
    sample = df[df["family"].isin(phish_fams)].sample(
        min(300, int((df["family"].isin(phish_fams)).sum())), random_state=1)
    emails = emails_from_dataframe(sample)

    rows, clean = evaluate_robustness(det, emails, seed=0)
    print(f"Détection de référence (phishing) : {clean:.3f}  sur n={len(emails)}\n")
    print(f"{'attaque':16s} {'attaqué':>8s} {'défendu':>8s} {'chute':>7s} {'récup':>7s}")
    print("-" * 52)
    for r in rows:
        d = r.as_dict()
        print(f"{d['attack']:16s} {d['detection_attacked']:8.3f} "
              f"{d['detection_defended']:8.3f} {d['drop']:7.3f} {d['recovered']:7.3f}")
