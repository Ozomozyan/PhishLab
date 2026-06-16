"""
phishlab.simulator
==================

Module de simulation / entrainement (cf. cahier des charges §4).

Objectif : generer des scenarios de phishing realistes pour une "boite de
reception d'entrainement" (sensibilisation des utilisateurs) et estimer un
TAUX DE CLIC plausible par scenario, afin de prioriser les campagnes de
formation.

CADRE ETHIQUE — strict (rappel du cahier des charges) :
  * On ne genere que des leurres SYNTHETIQUES, dans un bac a sable.
  * AUCUN envoi reel, AUCune cible reelle, aucune collecte de donnees.
  * Les "taux de clic" sont SIMULES par un modele de persuasion calibre sur des
    ordres de grandeur publies (rapports de sensibilisation), pas mesures sur
    des personnes. Ils servent d'outil pedagogique de priorisation, rien de plus.

Le modele de clic combine des facteurs de persuasion bien documentes
(Cialdini : urgence, autorite, preuve sociale, peur) en une probabilite via
une fonction logistique. Il est volontairement transparent et ajustable.
"""

from __future__ import annotations

import math
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Réutilise les générateurs de leurres déjà écrits pour le dataset.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "data"))
import generate_dataset as G  # noqa: E402

from .features import Email  # noqa: E402


# --------------------------------------------------------------------------- #
# Catalogue des scénarios d'entraînement (familles offensives réalistes)
# --------------------------------------------------------------------------- #
SCENARIOS = {
    "facture": {
        "gen": G.gen_invoice,
        "titre": "Fausse facture / paiement échoué",
        "pretexte": "Une facture impayée menace de pénalités ou de coupure.",
        "leviers": ["urgence", "autorite", "peur_financiere"],
        "cible": "Comptabilité, dirigeants, achats",
    },
    "reinit_mdp": {
        "gen": G.gen_reset,
        "titre": "Réinitialisation de mot de passe",
        "pretexte": "Alerte de sécurité demandant de « confirmer » ses identifiants.",
        "leviers": ["urgence", "autorite", "peur"],
        "cible": "Tous les employés",
    },
    "rh_paie": {
        "gen": G.gen_hr,
        "titre": "Fraude RH / bulletin de paie",
        "pretexte": "Mise à jour des coordonnées bancaires pour la paie.",
        "leviers": ["autorite", "appat_financier"],
        "cible": "Salariés, service RH",
    },
    "livraison": {
        "gen": G.gen_delivery,
        "titre": "Échec de livraison de colis",
        "pretexte": "Un colis bloqué exige des frais ou une confirmation.",
        "leviers": ["curiosite", "urgence", "preuve_sociale"],
        "cible": "Grand public, tous services",
    },
    "compte_bloque": {
        "gen": G.gen_account,
        "titre": "Compte suspendu / activité suspecte",
        "pretexte": "Le compte sera fermé sans vérification immédiate.",
        "leviers": ["peur", "urgence", "autorite"],
        "cible": "Utilisateurs de services en ligne",
    },
    "fraude_president": {
        "gen": G.gen_ceo,
        "titre": "Fraude au président (BEC)",
        "pretexte": "Un « dirigeant » demande un virement confidentiel urgent.",
        "leviers": ["autorite", "urgence", "confidentialite"],
        "cible": "Finance, assistants de direction",
    },
    "gain_loterie": {
        "gen": G.gen_prize,
        "titre": "Faux gain / loterie",
        "pretexte": "Un gain inattendu à réclamer rapidement.",
        "leviers": ["appat_financier", "urgence"],
        "cible": "Grand public",
    },
    "support_it": {
        "gen": G.gen_support,
        "titre": "Faux support informatique",
        "pretexte": "Le « service IT » demande des accès pour une maintenance.",
        "leviers": ["autorite", "serviabilite"],
        "cible": "Tous les employés",
    },
}


# --------------------------------------------------------------------------- #
# Modèle de taux de clic simulé (persuasion -> probabilité)
# --------------------------------------------------------------------------- #
# Poids des leviers de persuasion. Calibrés pour produire des taux dans une
# fourchette plausible (base ~5-8%, scénarios très persuasifs ~35-45% sans
# formation), cohérente avec les ordres de grandeur publiés.
_LEVER_WEIGHT = {
    "urgence": 0.55, "autorite": 0.60, "peur": 0.45, "peur_financiere": 0.50,
    "appat_financier": 0.50, "curiosite": 0.40, "preuve_sociale": 0.35,
    "confidentialite": 0.45, "serviabilite": 0.35, "peur_": 0.40,
}

# Facteur de réduction du risque selon le niveau de formation de la population.
TRAINING_LEVELS = {
    "aucune": 0.0,
    "sensibilisation_de_base": 0.45,
    "formation_reguliere": 0.70,
    "simulations_repetees": 0.82,
}


@dataclass
class SimResult:
    scenario: str
    titre: str
    base_click_rate: float        # population sans formation
    adjusted_click_rate: float    # après formation
    persuasion_score: float
    leviers: list = field(default_factory=list)
    cible: str = ""
    example: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "titre": self.titre,
            "base_click_rate": round(self.base_click_rate, 3),
            "adjusted_click_rate": round(self.adjusted_click_rate, 3),
            "persuasion_score": round(self.persuasion_score, 3),
            "leviers": self.leviers,
            "cible": self.cible,
            "example": self.example,
        }


def _persuasion_score(leviers: list) -> float:
    """Somme bornée des poids des leviers présents (effet décroissant)."""
    s = 0.0
    for i, lev in enumerate(sorted(leviers, key=lambda l: -_LEVER_WEIGHT.get(l, 0.3))):
        # rendement décroissant : chaque levier supplémentaire compte un peu moins
        s += _LEVER_WEIGHT.get(lev, 0.3) * (0.85 ** i)
    return s


def _logistic(x: float, midpoint: float = 1.35, steep: float = 1.7) -> float:
    return 1.0 / (1.0 + math.exp(-steep * (x - midpoint)))


def simulate_scenario(key: str, training: str = "aucune",
                      seed: int | None = None) -> SimResult:
    if seed is not None:
        random.seed(seed)
    spec = SCENARIOS[key]
    leviers = spec["leviers"]
    pscore = _persuasion_score(leviers)
    base = _logistic(pscore)                      # taux sans formation
    reduction = TRAINING_LEVELS.get(training, 0.0)
    adjusted = base * (1.0 - reduction)
    example = spec["gen"]()
    # On ne conserve qu'un aperçu non opérationnel (sujet + expéditeur + pretexte).
    preview = {
        "subject": example["subject"],
        "sender_display": example["sender_display"],
        "sender_email": example["sender_email"],
        "pretexte": spec["pretexte"],
    }
    return SimResult(
        scenario=key, titre=spec["titre"], base_click_rate=base,
        adjusted_click_rate=adjusted, persuasion_score=pscore,
        leviers=leviers, cible=spec["cible"], example=preview,
    )


def run_campaign(training: str = "aucune", seed: int = 7) -> list:
    """Simule l'ensemble des scénarios et renvoie un rapport trié par risque."""
    random.seed(seed)
    results = [simulate_scenario(k, training=training) for k in SCENARIOS]
    results.sort(key=lambda r: -r.base_click_rate)
    return results


def build_training_inbox(n_per_family: int = 2, seed: int = 7) -> list:
    """Construit une boîte de réception d'entraînement : une liste d'emails
    SYNTHETIQUES étiquetés par scénario, prêts pour une interface de
    sensibilisation (avec leur statut de leurre clairement marqué)."""
    random.seed(seed)
    inbox = []
    for key, spec in SCENARIOS.items():
        for _ in range(n_per_family):
            rec = spec["gen"]()
            inbox.append({
                "scenario": key,
                "titre": spec["titre"],
                "is_leurre": True,            # toujours marqué : usage pédagogique
                "subject": rec["subject"],
                "sender_display": rec["sender_display"],
                "sender_email": rec["sender_email"],
                "body": rec["body"],
                "indices": spec["leviers"],
            })
    random.shuffle(inbox)
    return inbox


# --------------------------------------------------------------------------- #
# Démo CLI
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print("=== Simulation de campagne de sensibilisation (taux de clic SIMULÉS) ===")
    print("Rappel : leurres synthétiques, bac à sable, aucun envoi réel.\n")
    for level in ["aucune", "sensibilisation_de_base", "formation_reguliere"]:
        print(f"\n--- Niveau de formation : {level} ---")
        for r in run_campaign(training=level):
            d = r.as_dict()
            print(f"  {d['titre']:38s} clic≈{d['adjusted_click_rate']:5.1%}  "
                  f"(persuasion {d['persuasion_score']:.2f}, cible: {d['cible']})")
