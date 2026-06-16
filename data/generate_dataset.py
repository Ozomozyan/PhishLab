"""
phishlab.data.generate_dataset
==============================
Générateur de dataset SYNTHÉTIQUE et documenté.

Conformément au cahier des charges, nous générons un corpus réaliste à partir de
templates + augmentation, en documentant clairement les biais et limites. Aucune
vraie donnée personnelle n'est utilisée : tout est fabriqué.

Familles d'attaque couvertes (phishing) :
    - invoice    : arnaque à la facture / paiement
    - reset      : fausse réinitialisation de mot de passe
    - hr         : demande RH / paie frauduleuse (BEC)
    - delivery   : échec de livraison
    - account    : suspension / vérification de compte
    - prize      : loterie / gain / remboursement
    - ceo        : fraude au président (Business Email Compromise)
    - support    : faux support technique

Classes benign (non-phishing) :
    - newsletter, receipt, shipping, colleague, calendar, notification, marketing

Sortie : un CSV avec une colonne par champ d'email + label (0=benign, 1=phishing)
et une colonne `family` pour l'analyse fine.
"""
from __future__ import annotations

import csv
import random
import argparse
from pathlib import Path


# ---------------------------------------------------------------------------
# Briques de génération
# ---------------------------------------------------------------------------

FIRST_NAMES = ["Marie", "Pierre", "Sophie", "Lucas", "Emma", "Thomas", "Julie",
               "Nicolas", "Camille", "Antoine", "Laura", "Maxime", "Sarah",
               "John", "Emily", "David", "Anna", "Michael", "Laura", "Daniel"]
LAST_NAMES = ["Martin", "Bernard", "Dubois", "Durand", "Moreau", "Laurent",
              "Simon", "Michel", "Garcia", "Roux", "Smith", "Johnson", "Brown",
              "Müller", "Rossi", "Lopez", "Nguyen", "Petit", "Leroy", "Fontaine"]
COMPANIES = ["Acme", "Globex", "Initech", "Umbrella", "Soylent", "Hooli",
             "Vandelay", "Wonka", "Stark", "Wayne", "Cyberdyne", "Tyrell"]

LEGIT_BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "amazon": "amazon.fr", "google": "google.com", "netflix": "netflix.com",
    "linkedin": "linkedin.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "laposte": "laposte.fr", "chronopost": "chronopost.fr", "ameli": "ameli.fr",
    "impots": "impots.gouv.fr", "orange": "orange.fr", "spotify": "spotify.com",
    "docusign": "docusign.net", "dropbox": "dropbox.com", "sncf": "sncf-connect.com",
}

# Pour fabriquer des domaines malveillants "lookalike".
PHISH_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top", "online", "click", "info",
              "support", "live", "icu", "buzz", "site", "com", "net"]
PHISH_PREFIXES = ["secure", "account", "verify", "login", "update", "service",
                  "confirm", "security", "mail", "billing", "support", "auth",
                  "id", "my", "portal", "web", "client", "espace"]


def _person():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def _slug(name: str) -> str:
    return name.lower().replace(" ", ".")


def _lookalike_domain(brand: str) -> str:
    """Fabrique un domaine trompeur ressemblant à `brand`."""
    style = random.random()
    base = brand
    if style < 0.25:                       # substitution chiffre (paypa1)
        base = brand.replace("l", "1", 1) if "l" in brand else brand.replace("o", "0", 1)
    elif style < 0.45:                     # préfixe/suffixe (secure-paypal)
        return f"{random.choice(PHISH_PREFIXES)}-{brand}.{random.choice(PHISH_TLDS)}"
    elif style < 0.6:                      # marque en sous-domaine (paypal.secure-x.tk)
        return f"{brand}.{random.choice(PHISH_PREFIXES)}-{random.randint(1,99)}.{random.choice(PHISH_TLDS)}"
    elif style < 0.75:                     # caractère doublé (paypall)
        i = random.randint(1, len(brand) - 1)
        base = brand[:i] + brand[i] + brand[i:]
    elif style < 0.9:                      # tiret + mot (paypal-france)
        return f"{brand}-{random.choice(['france','support','help','login'])}.{random.choice(PHISH_TLDS)}"
    return f"{base}.{random.choice(PHISH_TLDS)}"


def _phish_url(brand: str) -> str:
    dom = _lookalike_domain(brand)
    path = random.choice(["login", "verify", "account/update", "secure/confirm",
                           "signin", "auth/validate", "billing/pay", "reset",
                           "track", "facture/regler", "espace-client"])
    scheme = "http" if random.random() < 0.55 else "https"
    # Parfois une URL sur IP brute
    if random.random() < 0.12:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{path}"
    # Parfois un raccourcisseur
    if random.random() < 0.12:
        sh = random.choice(["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy"])
        return f"https://{sh}/{random.choice('abcdefghjkmnpqrstuvwxyz')}{random.randint(1000,9999)}"
    return f"{scheme}://{dom}/{path}"


def _legit_url(domain: str) -> str:
    path = random.choice(["", "account", "orders", "help", "settings", "fr/aide",
                           "compte", "mon-espace", "support", "billing", "profil"])
    return f"https://{domain}/{path}".rstrip("/")


def _maybe(prob: float) -> bool:
    return random.random() < prob


# ---------------------------------------------------------------------------
# Templates PHISHING (renvoient un dict de champs)
# ---------------------------------------------------------------------------

def gen_invoice() -> dict:
    brand = random.choice(["microsoft", "amazon", "orange", "docusign", "paypal"])
    amount = random.choice(["349,99", "1 280,00", "89,90", "2 450,00", "599,00"])
    url = _phish_url(brand)
    subject = random.choice([
        f"Facture impayée n°{random.randint(10000,99999)} - Action requise",
        f"URGENT: Votre paiement de {amount}€ a échoué",
        f"Rappel: facture en attente de règlement",
        f"Votre commande {brand.capitalize()} - paiement requis",
    ])
    body = (
        f"Bonjour,\n\nNous vous informons qu'une facture de {amount}€ reste impayée. "
        f"Votre compte sera suspendu si le règlement n'est pas effectué sous 24h.\n\n"
        f"Réglez immédiatement votre facture ici : {url}\n\n"
        f"Cordialement,\nService Facturation {brand.capitalize()}"
    )
    return _phish_record(brand, subject, body, url, family="invoice",
                         attach=["facture_impayee.pdf.exe"] if _maybe(0.3) else [])


def gen_reset() -> dict:
    brand = random.choice(["google", "microsoft", "apple", "linkedin", "netflix", "spotify"])
    url = _phish_url(brand)
    subject = random.choice([
        f"Réinitialisation de votre mot de passe {brand.capitalize()}",
        "Demande de changement de mot de passe",
        f"[{brand.capitalize()}] Activité suspecte détectée",
        "Action requise : sécurisez votre compte",
    ])
    body = (
        f"Cher utilisateur,\n\nNous avons détecté une connexion inhabituelle à votre compte. "
        f"Pour des raisons de sécurité, vous devez vérifier votre mot de passe maintenant.\n\n"
        f"Cliquez ici pour réinitialiser : {url}\n\n"
        f"Si vous n'agissez pas sous 48h, votre compte sera verrouillé.\n\n"
        f"L'équipe de sécurité {brand.capitalize()}"
    )
    return _phish_record(brand, subject, body, url, family="reset")


def gen_hr() -> dict:
    company = random.choice(COMPANIES)
    url = _phish_url("docusign")
    subject = random.choice([
        "Mise à jour de vos coordonnées bancaires (paie)",
        "Bulletin de paie - signature requise",
        "RH: changement de votre RIB pour le salaire",
        "Document RH confidentiel à valider",
    ])
    body = (
        f"Bonjour,\n\nDans le cadre de la mise à jour de notre système de paie, "
        f"merci de confirmer vos coordonnées bancaires (RIB / IBAN) avant la fin de la journée.\n\n"
        f"Accédez au formulaire sécurisé : {url}\n\n"
        f"Ceci est obligatoire pour recevoir votre prochain salaire.\n\n"
        f"Service Ressources Humaines - {company}"
    )
    return _phish_record("docusign", subject, body, url, family="hr",
                         sender_brand_name=f"RH {company}")


def gen_delivery() -> dict:
    brand = random.choice(["dhl", "fedex", "chronopost", "laposte", "amazon"])
    url = _phish_url(brand)
    fee = random.choice(["1,99", "2,50", "0,99", "3,40"])
    subject = random.choice([
        f"[{brand.capitalize()}] Votre colis n'a pas pu être livré",
        "Échec de livraison - action nécessaire",
        f"Colis en attente : frais de douane de {fee}€",
        "Reprogrammez votre livraison",
    ])
    body = (
        f"Bonjour,\n\nVotre colis n'a pas pu être livré en raison d'une adresse incomplète. "
        f"Des frais de réexpédition de {fee}€ sont requis pour reprogrammer la livraison.\n\n"
        f"Confirmez votre adresse et payez les frais ici : {url}\n\n"
        f"Sans action sous 72h, votre colis sera retourné à l'expéditeur.\n\n"
        f"{brand.upper()} Livraison"
    )
    return _phish_record(brand, subject, body, url, family="delivery")


def gen_account() -> dict:
    brand = random.choice(["paypal", "amazon", "netflix", "apple", "orange", "ameli"])
    url = _phish_url(brand)
    subject = random.choice([
        f"Votre compte {brand.capitalize()} a été limité",
        "Vérification de compte requise",
        f"[Important] Suspension de votre compte {brand.capitalize()}",
        "Confirmez votre identité immédiatement",
    ])
    body = (
        f"Cher client,\n\nNous avons temporairement limité votre compte suite à une activité "
        f"inhabituelle. Pour rétablir l'accès complet, confirmez vos informations.\n\n"
        f"Vérifiez votre compte : {url}\n\n"
        f"Attention : sans confirmation sous 24h, votre compte sera définitivement fermé.\n\n"
        f"Service Client {brand.capitalize()}"
    )
    return _phish_record(brand, subject, body, url, family="account")


def gen_prize() -> dict:
    brand = random.choice(["amazon", "google", "apple", "netflix"])
    url = _phish_url(brand)
    subject = random.choice([
        "FÉLICITATIONS ! Vous avez gagné un iPhone 15",
        f"Vous avez été sélectionné - Carte cadeau {brand.capitalize()} de 500€",
        "Votre remboursement de 128,50€ est disponible",
        "Réclamez votre récompense exclusive maintenant !!!",
    ])
    body = (
        f"FÉLICITATIONS !!!\n\nVotre adresse email a été tirée au sort pour recevoir une "
        f"récompense exclusive d'une valeur de {random.choice(['500','750','1000'])}€ !\n\n"
        f"Réclamez votre gain avant expiration : {url}\n\n"
        f"Offre limitée - cliquez maintenant, il ne reste que quelques heures !\n\n"
        f"L'équipe des récompenses"
    )
    return _phish_record(brand, subject, body, url, family="prize",
                         sender_brand_name="Service Récompenses")


def gen_ceo() -> dict:
    company = random.choice(COMPANIES)
    ceo = _person()
    subject = random.choice([
        "Demande urgente - confidentiel",
        "Besoin de toi rapidement",
        "Virement à traiter aujourd'hui",
        "Tâche urgente (je suis en réunion)",
    ])
    body = (
        f"Bonjour,\n\nJe suis actuellement en réunion et je ne peux pas être dérangé. "
        f"J'ai besoin que tu effectues un virement urgent à un nouveau fournisseur "
        f"pour finaliser un contrat aujourd'hui. C'est strictement confidentiel pour l'instant.\n\n"
        f"Réponds-moi dès que tu vois ce message, je t'envoie les coordonnées bancaires.\n\n"
        f"Merci,\n{ceo}\nDirecteur Général - {company}"
    )
    # Pas d'URL ni de marque : le BEC repose sur l'ingénierie sociale + usurpation d'identité.
    return _phish_record("", subject, body, "", family="ceo",
                         sender_brand_name=ceo, no_url=True)


def gen_support() -> dict:
    brand = random.choice(["microsoft", "apple", "google"])
    url = _phish_url(brand)
    phone = f"+33 {random.randint(1,9)} {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)}"
    subject = random.choice([
        f"[{brand.capitalize()} Support] Votre appareil est infecté",
        "Alerte de sécurité critique sur votre ordinateur",
        "Votre licence Windows a expiré",
    ])
    body = (
        f"ALERTE DE SÉCURITÉ\n\nNos serveurs ont détecté un virus sur votre appareil. "
        f"Vos données personnelles sont en danger immédiat.\n\n"
        f"Contactez notre support technique au {phone} ou rendez-vous sur {url} "
        f"pour nettoyer votre système maintenant.\n\n"
        f"N'éteignez pas votre ordinateur.\n\n{brand.capitalize()} Support Technique"
    )
    return _phish_record(brand, subject, body, url, family="support")


def _augment_text(text: str) -> str:
    """Augmentation légère : variation des salutations, typos, ponctuation.
    Empêche le modèle de mémoriser les templates exacts -> généralisation
    plus réaliste."""
    # Variation de la salutation
    text = text.replace("Bonjour,", random.choice(
        ["Bonjour,", "Bonjour, ", "Madame, Monsieur,", "Cher client,", "Hello,"]))
    # Insertion occasionnelle de fautes de frappe (réaliste)
    if _maybe(0.3):
        words = text.split(" ")
        if len(words) > 8:
            i = random.randint(0, len(words) - 1)
            w = words[i]
            if len(w) > 4 and w.isalpha():
                j = random.randint(1, len(w) - 2)
                words[i] = w[:j] + w[j + 1] + w[j] + w[j + 2:]  # swap 2 lettres
            text = " ".join(words)
    # Variation de ponctuation finale
    if _maybe(0.25):
        text = text.replace("\n\n", "\n").strip()
    return text


def _compromised_sender(brand: str | None) -> tuple[str, str, str, str]:
    """Expéditeur d'un compte LÉGITIME compromis : domaine réel, auth qui passe.
    Renvoie (sender_email, spf, dkim, dmarc). Le phishing devient alors
    indétectable au niveau métadonnées -> seul le contenu trahit l'attaque."""
    if brand and brand in LEGIT_BRANDS and _maybe(0.5):
        dom = LEGIT_BRANDS[brand]
    else:
        # PME/partenaire réel compromis
        dom = f"{random.choice(COMPANIES).lower()}-{random.choice(['group','corp','fr','sas','consulting'])}.com"
    local = random.choice(["contact", "comptabilite", "rh", "direction", "noreply",
                           "info", "j.martin", "compta", "admin"])
    return f"{local}@{dom}", "pass", "pass", "pass"


def _phish_record(brand, subject, body, url, family,
                  sender_brand_name=None, attach=None, no_url=False):
    """Assemble un enregistrement phishing avec métadonnées cohérentes."""
    # ~22% de phishing "furtif" : compte compromis ou attaquant bien outillé.
    # L'authentification passe, l'URL est en https, le texte est propre. Le
    # modèle ne peut PAS se reposer sur 'auth=fail' -> il doit apprendre les
    # signaux plus fins (domaine lookalike, demande d'identifiants, structure).
    stealth = _maybe(0.28) and family != "ceo"
    compromised = stealth and _maybe(0.5)   # moitié des furtifs = compte compromis

    # Domaine d'envoi : lookalike, free provider, ou domaine random pourri.
    r = random.random()
    if compromised:
        sender_email, spf0, dkim0, dmarc0 = _compromised_sender(brand)
        sender_dom = sender_email.split("@")[-1]
    elif brand and r < 0.45:
        sender_dom = _lookalike_domain(brand)
        sender_email = None
    elif r < 0.75:
        sender_dom = random.choice(["gmail.com", "outlook.com", "yahoo.com",
                                     "hotmail.fr", "mail.ru", "gmx.com"])
        sender_email = None
    else:
        sender_dom = f"{random.choice(PHISH_PREFIXES)}{random.randint(1,999)}.{random.choice(PHISH_TLDS)}"
        sender_email = None

    display = sender_brand_name or (brand.capitalize() + " Service" if brand else _person())
    if sender_email is None:
        local = random.choice(["noreply", "service", "security", "no-reply", "support",
                               "admin", "contact", "info", "alert", "notification"])
        sender_email = f"{local}@{sender_dom}"

    # reply-to différent dans une bonne partie des cas
    reply_to = ""
    if _maybe(0.5) and not compromised:
        reply_to = f"{random.choice(['reply','contact','info'])}@{random.choice(PHISH_PREFIXES)}-{random.randint(1,99)}.{random.choice(PHISH_TLDS)}"

    if compromised:
        spf, dkim, dmarc = spf0, dkim0, dmarc0
        body = body.replace("!!!", ".").replace("!!", ".")
        if url:
            url = url.replace("http://", "https://")
    elif stealth:
        # Auth qui passe + https + nettoyage du ton alarmiste.
        spf, dkim, dmarc = "pass", random.choice(["pass", "none"]), random.choice(["pass", "none"])
        body = body.replace("!!!", ".").replace("!!", ".")
        subject = subject.replace("URGENT:", "").replace("FÉLICITATIONS !", "Information").strip()
        url = url.replace("http://", "https://")
        reply_to = ""
    else:
        # Authentification : majoritairement en échec/absente pour le phishing
        spf = random.choices(["fail", "softfail", "none", "pass"], weights=[40, 15, 35, 10])[0]
        dkim = random.choices(["fail", "none", "pass"], weights=[35, 50, 15])[0]
        dmarc = random.choices(["fail", "none", "pass"], weights=[45, 45, 10])[0]

    body = _augment_text(body)

    attachments = attach if attach is not None else (
        [random.choice(["document.html", "facture.zip", "scan.svg", "details.htm"])]
        if _maybe(0.18) else []
    )

    # Parfois homoglyphe injecté dans le corps
    if _maybe(0.08):
        body = body.replace("o", "о", 1).replace("a", "а", 1)  # cyrillique

    return {
        "subject": subject,
        "body": body,
        "sender_display": display,
        "sender_email": sender_email,
        "reply_to": reply_to,
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "attachments": ";".join(attachments),
        "has_html": int(_maybe(0.6)),
        "num_recipients": random.choices([1, 1, 1, random.randint(2, 50)], weights=[60, 20, 10, 10])[0],
        "label": 1,
        "family": family,
    }


# ---------------------------------------------------------------------------
# Templates BENIGN
# ---------------------------------------------------------------------------

def gen_newsletter() -> dict:
    brand = random.choice(list(LEGIT_BRANDS))
    dom = LEGIT_BRANDS[brand]
    url = _legit_url(dom)
    topic = random.choice(["nouveautés", "votre sélection", "actualités",
                           "les tendances du mois", "nouveaux épisodes"])
    subject = random.choice([
        f"Découvrez {topic} de {brand.capitalize()}",
        f"Votre newsletter {brand.capitalize()} de la semaine",
        f"{brand.capitalize()} : {topic}",
    ])
    body = (
        f"Bonjour,\n\nVoici les dernières actualités de {brand.capitalize()}. "
        f"Nous avons sélectionné pour vous {topic} qui pourraient vous intéresser.\n\n"
        f"Pour en savoir plus, visitez : {url}\n\n"
        f"Vous recevez cet email car vous êtes abonné à notre newsletter. "
        f"Se désabonner : {_legit_url(dom)}/unsubscribe\n\n"
        f"L'équipe {brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="newsletter")


def gen_receipt() -> dict:
    brand = random.choice(["amazon", "paypal", "spotify", "netflix", "apple"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    amount = random.choice(["12,99", "9,99", "49,90", "29,99", "120,00"])
    order = f"{random.randint(100,999)}-{random.randint(1000000,9999999)}"
    subject = random.choice([
        f"Votre reçu {brand.capitalize()} - commande {order}",
        f"Confirmation de paiement : {amount}€",
        f"Merci pour votre achat",
    ])
    body = (
        f"Bonjour {_person().split()[0]},\n\nNous vous confirmons votre commande n°{order} "
        f"d'un montant de {amount}€. Votre paiement a bien été reçu.\n\n"
        f"Consultez le détail de votre commande dans votre espace client : {_legit_url(dom)}\n\n"
        f"Merci de votre confiance,\n{brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="receipt")


def gen_shipping() -> dict:
    brand = random.choice(["dhl", "fedex", "chronopost", "laposte", "amazon"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    track = f"{random.choice('ABCDEFGH')}{random.randint(100000000,999999999)}"
    subject = random.choice([
        f"Votre colis est en route - {track}",
        f"Expédition confirmée",
        f"Votre commande a été expédiée",
    ])
    body = (
        f"Bonjour,\n\nVotre colis (n° de suivi {track}) a été expédié et sera livré "
        f"sous 2 à 3 jours ouvrés.\n\nSuivez votre colis : {_legit_url(dom)}/track\n\n"
        f"Cordialement,\n{brand.upper()}"
    )
    return _benign_record(brand, dom, subject, body, family="shipping")


def gen_colleague() -> dict:
    company = random.choice(COMPANIES).lower()
    sender = _person()
    topic = random.choice(["le rapport trimestriel", "la réunion de demain",
                           "le projet client", "les slides de présentation",
                           "le compte-rendu", "la roadmap produit"])
    subject = random.choice([
        f"RE: {topic}", f"{topic.capitalize()}", f"Question sur {topic}",
        f"Point rapide - {topic}",
    ])
    body = (
        f"Salut,\n\nJ'ai bien avancé sur {topic}. Tu peux jeter un œil quand tu as un moment ?\n"
        f"On en parle à la pause si tu veux.\n\nÀ tout',\n{sender.split()[0]}"
    )
    dom = f"{company}.com"
    return _benign_record("", dom, subject, body, family="colleague",
                          sender_name=sender, sender_local=_slug(sender))


def gen_calendar() -> dict:
    company = random.choice(COMPANIES).lower()
    sender = _person()
    subject = random.choice([
        "Invitation : Réunion d'équipe", "Point projet - calendrier",
        "Invitation: Entretien annuel", "Rappel: réunion à 14h",
    ])
    body = (
        f"Bonjour,\n\nVous êtes invité à la réunion suivante :\n\n"
        f"Sujet : {random.choice(['Sprint review','Comité de pilotage','Daily','Rétrospective'])}\n"
        f"Date : {random.randint(1,28)}/0{random.randint(1,9)}/2026 à {random.randint(9,17)}h00\n"
        f"Lieu : {random.choice(['Salle Jupiter','Visio Teams','Salle 204','Bureau open space'])}\n\n"
        f"Merci de confirmer votre présence.\n\n{sender.split()[0]}"
    )
    dom = f"{company}.com"
    return _benign_record("", dom, subject, body, family="calendar",
                          sender_name=sender, sender_local=_slug(sender))


def gen_notification() -> dict:
    brand = random.choice(["linkedin", "google", "microsoft", "dropbox"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    subject = random.choice([
        f"Vous avez 3 nouvelles notifications",
        f"{_person()} a consulté votre profil",
        f"Récapitulatif de votre activité",
        f"Un document a été partagé avec vous",
    ])
    body = (
        f"Bonjour,\n\nVous avez de nouvelles activités sur votre compte {brand.capitalize()}.\n\n"
        f"Consultez-les ici : {_legit_url(dom)}/notifications\n\n"
        f"Gérez vos préférences de notification dans vos paramètres.\n\n{brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="notification")


def gen_marketing() -> dict:
    brand = random.choice(["amazon", "spotify", "netflix", "orange"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    subject = random.choice([
        f"-20% sur votre prochaine commande",
        f"Offre spéciale abonnés {brand.capitalize()}",
        f"Les soldes commencent maintenant",
    ])
    body = (
        f"Bonjour,\n\nProfitez de nos offres exclusives réservées à nos clients fidèles. "
        f"Jusqu'à -20% sur une sélection de produits.\n\n"
        f"Découvrir les offres : {_legit_url(dom)}/offres\n\n"
        f"Offre valable jusqu'à la fin du mois. Se désabonner : {_legit_url(dom)}/unsubscribe\n\n"
        f"{brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="marketing")


def gen_legit_security_alert() -> dict:
    """Vraie alerte de sécurité (Google/Microsoft) : urgente MAIS légitime.
    Cas difficile : partage le vocabulaire 'sécurité/connexion/vérifier' du phishing."""
    brand = random.choice(["google", "microsoft", "apple", "linkedin"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    city = random.choice(["Paris", "Lyon", "Lille", "Berlin", "Madrid"])
    subject = random.choice([
        f"Nouvelle connexion à votre compte {brand.capitalize()}",
        "Alerte de sécurité : nouvel appareil détecté",
        f"[{brand.capitalize()}] Vérification de connexion",
    ])
    body = (
        f"Bonjour,\n\nUne nouvelle connexion à votre compte a été détectée depuis "
        f"{city} le {random.randint(1,28)}/0{random.randint(1,9)}/2026.\n\n"
        f"Si c'était bien vous, aucune action n'est nécessaire. "
        f"Dans le cas contraire, sécurisez votre compte depuis l'application ou sur {_legit_url(dom)}/security.\n\n"
        f"L'équipe {brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="legit_security",
                          force_auth_pass=True)


def gen_legit_invoice() -> dict:
    """Vraie facture/relance de paiement (urgence légitime). Cas difficile."""
    brand = random.choice(["orange", "spotify", "netflix", "amazon"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    amount = random.choice(["19,99", "12,99", "39,90", "9,99"])
    subject = random.choice([
        f"Votre facture {brand.capitalize()} du mois est disponible",
        f"Échec du prélèvement - mettez à jour votre moyen de paiement",
        "Rappel : paiement de votre abonnement",
    ])
    body = (
        f"Bonjour,\n\nNous n'avons pas pu prélever votre abonnement de {amount}€ ce mois-ci. "
        f"Merci de vérifier votre moyen de paiement pour éviter une interruption de service.\n\n"
        f"Mettez à jour vos informations dans votre espace client : {_legit_url(dom)}/billing\n\n"
        f"Merci,\n{brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="legit_invoice",
                          force_auth_pass=True)


def gen_legit_reset() -> dict:
    """VRAIE réinitialisation de mot de passe (demandée par l'utilisateur).
    Cas difficile majeur : partage TOUT le vocabulaire de gen_reset
    ('réinitialiser', 'cliquez', 'sécurité', 'expire'). Seule différence
    fiable : domaine réel + lien on-domain + auth qui passe (sauf transfert)."""
    brand = random.choice(["google", "microsoft", "apple", "linkedin", "netflix", "spotify"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    url = f"{_legit_url(dom)}/reset?token={random.randint(100000,999999)}"
    subject = random.choice([
        f"Réinitialisation de votre mot de passe {brand.capitalize()}",
        "Votre demande de changement de mot de passe",
        "Lien de réinitialisation de votre mot de passe",
    ])
    body = (
        f"Bonjour,\n\nVous avez demandé à réinitialiser le mot de passe de votre compte "
        f"{brand.capitalize()}. Pour des raisons de sécurité, ce lien expire dans 60 minutes.\n\n"
        f"Cliquez ici pour réinitialiser votre mot de passe : {url}\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet email, "
        f"votre mot de passe restera inchangé.\n\nL'équipe {brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="legit_reset", hard=True)


def gen_legit_bank_alert() -> dict:
    """VRAIE alerte de fraude bancaire/compte : DEMANDE une action (vérifier).
    Partage le vocabulaire de gen_account ('activité inhabituelle', 'vérifiez',
    'compte'). La banque légitime demande bien de se connecter pour vérifier."""
    brand = random.choice(["paypal", "orange", "amazon", "ameli"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    url = f"{_legit_url(dom)}/securite/operations"
    amount = random.choice(["49,90", "129,00", "899,99", "12,99"])
    subject = random.choice([
        f"[{brand.capitalize()}] Vérifiez une opération inhabituelle",
        "Alerte : nouvelle opération sur votre compte",
        f"Confirmation d'activité sur votre compte {brand.capitalize()}",
    ])
    body = (
        f"Bonjour,\n\nNous avons détecté une opération inhabituelle de {amount}€ sur votre "
        f"compte {brand.capitalize()}. Par mesure de sécurité, merci de vérifier qu'il s'agit "
        f"bien de vous.\n\nVérifiez vos opérations récentes : {url}\n\n"
        f"Si vous reconnaissez cette opération, aucune action supplémentaire n'est requise.\n\n"
        f"Service Sécurité {brand.capitalize()}"
    )
    return _benign_record(brand, dom, subject, body, family="legit_account", hard=True)


def gen_legit_delivery() -> dict:
    """VRAIE notification de livraison demandant une action (confirmer adresse,
    régler des frais de douane réels). Partage le vocabulaire de gen_delivery."""
    brand = random.choice(["dhl", "fedex", "chronopost", "laposte", "amazon"])
    dom = LEGIT_BRANDS.get(brand, f"{brand}.com")
    track = f"{random.choice('ABCDEFGH')}{random.randint(100000000,999999999)}"
    url = f"{_legit_url(dom)}/suivi/{track}"
    fee = random.choice(["1,99", "2,50", "0,99", "3,40"])
    subject = random.choice([
        f"[{brand.upper()}] Votre colis est en attente de livraison",
        "Confirmez l'adresse de livraison de votre colis",
        f"Colis {track} : frais de douane à régler",
    ])
    body = (
        f"Bonjour,\n\nVotre colis (suivi {track}) est en attente. Des frais de douane de "
        f"{fee}€ doivent être réglés pour finaliser la livraison.\n\n"
        f"Confirmez votre adresse et réglez les frais : {url}\n\n"
        f"Vous pouvez suivre votre colis à tout moment depuis votre espace client.\n\n"
        f"{brand.upper()}"
    )
    return _benign_record(brand, dom, subject, body, family="legit_delivery", hard=True)


def _benign_record(brand, dom, subject, body, family,
                   sender_name=None, sender_local=None, force_auth_pass=False,
                   hard=False):
    """Assemble un enregistrement bénin avec authentification généralement OK.

    hard=True : email légitime au vocabulaire 'sensible' (reset MDP, alerte
    fraude, livraison). On y dégrade plus souvent l'authentification (~38 %)
    pour simuler les mails transférés / passerelles d'entreprise. Ces cas
    chevauchent l'espace de features du phishing -> faux positifs réalistes."""
    display = sender_name or (brand.capitalize() if brand else _person())
    local = sender_local or random.choice(["noreply", "newsletter", "contact",
                                            "info", "notifications", "no-reply",
                                            "security", "service", "alerts"])
    sender_email = f"{local}@{dom}"
    # reply-to cohérent (même domaine) la plupart du temps
    reply_to = f"contact@{dom}" if _maybe(0.3) else ""

    # Authentification : majoritairement valide, mais une fraction est dégradée
    # (mail transféré, liste de diffusion qui casse DKIM...) -> cas difficiles.
    degrade_p = 0.38 if hard else 0.15
    if force_auth_pass:
        spf, dkim, dmarc = "pass", "pass", "pass"
    elif _maybe(degrade_p):
        spf = random.choices(["none", "softfail", "fail"], weights=[55, 30, 15])[0]
        dkim = random.choices(["none", "fail"], weights=[65, 35])[0]
        dmarc = random.choices(["none", "fail"], weights=[70, 30])[0]
    else:
        spf = random.choices(["pass", "none", "fail"], weights=[82, 16, 2])[0]
        dkim = random.choices(["pass", "none", "fail"], weights=[80, 18, 2])[0]
        dmarc = random.choices(["pass", "none", "fail"], weights=[72, 26, 2])[0]

    # Pièces jointes bénignes occasionnelles
    attachments = []
    if _maybe(0.12):
        attachments = [random.choice(["rapport.pdf", "presentation.pptx",
                                       "facture.pdf", "photo.jpg", "cv.pdf",
                                       "compte-rendu.docx", "tableau.xlsx"])]

    body = _augment_text(body)

    return {
        "subject": subject,
        "body": body,
        "sender_display": display,
        "sender_email": sender_email,
        "reply_to": reply_to,
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "attachments": ";".join(attachments),
        "has_html": int(_maybe(0.55)),
        "num_recipients": random.choices([1, 1, random.randint(2, 30)], weights=[70, 15, 15])[0],
        "label": 0,
        "family": family,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

PHISH_GENERATORS = [gen_invoice, gen_reset, gen_hr, gen_delivery, gen_account,
                    gen_prize, gen_ceo, gen_support]
BENIGN_GENERATORS = [gen_newsletter, gen_receipt, gen_shipping, gen_colleague,
                     gen_calendar, gen_notification, gen_marketing,
                     gen_legit_security_alert, gen_legit_invoice,
                     gen_legit_reset, gen_legit_bank_alert, gen_legit_delivery]

FIELDS = ["subject", "body", "sender_display", "sender_email", "reply_to",
          "spf", "dkim", "dmarc", "attachments", "has_html", "num_recipients",
          "label", "family", "noisy_label"]


def build_dataset(n_phish: int, n_benign: int, seed: int = 42,
                  label_noise: float = 0.02) -> list[dict]:
    random.seed(seed)
    rows: list[dict] = []
    for _ in range(n_phish):
        rows.append(random.choice(PHISH_GENERATORS)())
    for _ in range(n_benign):
        rows.append(random.choice(BENIGN_GENERATORS)())
    random.shuffle(rows)

    # Bruit de labellisation : la stratégie d'annotation repose sur "annotation
    # manuelle + heuristiques" (cf. cahier des charges). Les heuristiques se
    # trompent parfois -> on simule ~3% d'etiquettes erronees.
    #
    #   * "label"        = verite terrain propre (derivee de la famille). Jamais
    #                      bruitee. Sert d'etalon pour l'evaluation par famille.
    #   * "noisy_label"  = etiquette reellement vue a l'entrainement = label
    #                      propre avec ~3% d'inversions. C'est ce que le modele
    #                      apprend. Aucun classifieur ne peut depasser la qualite
    #                      de ses etiquettes -> plafonne le score de maniere
    #                      realiste. Documente dans la model card.
    n_flip = int(len(rows) * label_noise)
    flip_idx = set(random.sample(range(len(rows)), n_flip))
    for i, row in enumerate(rows):
        rows[i] = dict(row)
        clean = rows[i]["label"]
        rows[i]["label"] = clean                       # verite terrain propre
        rows[i]["noisy_label"] = 1 - clean if i in flip_idx else clean
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=2200)
    ap.add_argument("--benign", type=int, default=2200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--noise", type=float, default=0.03,
                    help="taux de bruit de labellisation (heuristiques imparfaites)")
    ap.add_argument("--out", type=str, default=str(Path(__file__).parent / "phishlab_dataset.csv"))
    args = ap.parse_args()

    rows = build_dataset(args.phish, args.benign, args.seed, args.noise)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    # Petit résumé
    from collections import Counter
    fam = Counter(r["family"] for r in rows)
    print(f"Dataset écrit : {args.out}")
    print(f"  Total      : {len(rows)} emails")
    print(f"  Phishing   : {sum(r['label'] for r in rows)}")
    print(f"  Bénins     : {sum(1 - r['label'] for r in rows)}")
    print(f"  Familles   : {dict(fam)}")


if __name__ == "__main__":
    main()
