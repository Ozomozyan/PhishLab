# PhishLab — Détection et anticipation du phishing par IA

> **Détecter aujourd'hui. Anticiper demain.**
>
> Plateforme défensive d'analyse d'emails : elle attribue à chaque message un
> score de risque expliqué, simule des campagnes de sensibilisation, projette
> l'évolution des techniques d'attaque et teste sa propre robustesse face aux
> méthodes d'évasion.

Projet Innov — EPSI. Module **Expert IA / Ingénierie**.

---

## 1. Ce que fait PhishLab

| Capacité | Module | Sortie |
|---|---|---|
| **Détection** d'emails malveillants | `phishlab/detector.py` | score 0–1 + label *bénin / suspect / phishing* |
| **Explicabilité** (pourquoi ?) | `phishlab/explainer.py` | raisons en langage naturel, passages surlignés, attribution SHAP |
| **Simulation** de sensibilisation | `phishlab/simulator.py` | boîte d'entraînement + taux de clic simulés par scénario |
| **Simulation prédictive** | `phishlab/predictive.py` | projection des techniques + test de robustesse « 2026 » |
| **Robustesse adverse** | `phishlab/adversarial.py` | attaques d'évasion + défenses + mesure de récupération |
| **API REST** | `api/app.py` | endpoints Flask (analyse, métriques, simulation…) |
| **Tableau de bord** | `web/dashboard.html` | console d'analyse autonome (fonctionne hors-ligne) |

---

## 2. Architecture

```
                 ┌───────────────────────────────────────────────┐
   email  ──────▶│  Extraction de features (features.py)         │
                 │  • 30 signaux tabulaires (URL, expéditeur,     │
                 │    authentification, texte, pièces jointes)    │
                 │  • texte nettoyé pour le NLP                   │
                 └───────────────┬───────────────────────────────┘
                                 ▼
                 ┌───────────────────────────────────────────────┐
                 │  Détecteur hybride (detector.py)              │
                 │  tabulaire (StandardScaler)                    │
                 │      ⊕ TF-IDF mots (1–2 g)                     │
                 │      ⊕ TF-IDF caractères (3–5 g)               │
                 │  → modèle linéaire calibré (LogReg + sigmoïde) │
                 └───────────────┬───────────────────────────────┘
                                 ▼
        ┌────────────────────────┼─────────────────────────┐
        ▼                        ▼                          ▼
  Explicabilité            Robustesse adverse        Simulation prédictive
  (SHAP linéaire,          (évasions + défenses)     (tendances → futur)
   raisons NL,
   surlignage)
        │                        │                          │
        └────────────────────────┼──────────────────────────┘
                                 ▼
                  API Flask  +  Tableau de bord web
```

Le modèle déployé est **linéaire** par choix : il est explicable de façon exacte
(SHAP en forme fermée) et **exportable** vers un scorer JavaScript embarqué, ce
qui permet une démonstration 100 % hors-ligne dans le navigateur.

---

## 3. Installation

```bash
python -m venv .venv && source .venv/bin/activate   # optionnel
pip install -r requirements.txt
```

Testé avec **Python 3.12**.

---

## 4. Utilisation

### 4.1 Générer les données et entraîner le modèle

```bash
# 1) jeu de données synthétique (4 800 emails par défaut)
python data/generate_dataset.py --out data/phishlab_dataset.csv

# 2) entraînement + évaluation + figures
python train.py
```

`train.py` entraîne trois modèles (régression logistique, forêt aléatoire,
XGBoost), sélectionne le meilleur par F1, exporte le scorer embarqué
(`models/scorer_export.json`) et écrit les métriques + figures dans `reports/`.

### 4.2 Évaluations spécialisées

```bash
python eval_robustness.py     # robustesse adverse  -> reports/robustness.*
python eval_predictive.py     # simulation prédictive -> reports/predictive.*
python -m phishlab.simulator  # campagne de sensibilisation (console)
```

### 4.3 Tableau de bord (hors-ligne)

Ouvrez simplement le fichier dans un navigateur :

```
web/dashboard.html
```

Aucun serveur n'est nécessaire : le scorer linéaire et les lexiques sont
embarqués. Collez un email (ou choisissez un exemple) pour obtenir le verdict
expliqué.

### 4.4 API Flask (scores exacts)

```bash
# regénère les données embarquées du dashboard si besoin
python export_web_data.py

# lance l'API + sert le dashboard sur http://127.0.0.1:5000
python api/app.py
```

| Endpoint | Méthode | Rôle |
|---|---|---|
| `/api/analyze` | POST | analyse complète d'un email |
| `/api/metrics` | GET | métriques d'évaluation |
| `/api/robustness` | GET | résultats de robustesse adverse |
| `/api/predictive` | GET | projections + test prospectif |
| `/api/simulate` | POST | rapport de campagne de sensibilisation |
| `/api/inbox` | GET | boîte de réception d'entraînement |

Exemple :

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"subject":"URGENT compte suspendu","body":"confirmez votre mot de passe http://paypa1.tk","sender_email":"x@paypa1.tk","spf":"fail","dmarc":"fail"}'
```

---

## 5. Résultats (synthèse)

Modèle déployé : **régression logistique calibrée**.

| Mesure | Valeur | Lecture |
|---|---|---|
| F1 (opérationnel) | **0.966** | évalué contre des étiquettes bruitées à 3 % (réaliste) |
| ROC-AUC | 0.966 | |
| Précision / Rappel | 0.965 / 0.967 | |
| Brier | 0.034 | bonne calibration des probabilités |
| F1 (intrinsèque) | 1.000 | plafond sur données séparables (cf. *model card*) |

**Robustesse adverse** (détection du phishing sous attaque → après défenses) :

| Attaque | Nu | Défendu |
|---|---|---|
| Homoglyphes | 27 % | 97 % |
| Caractères invisibles | 47 % | 100 % |
| Leetspeak | 22 % | 66 % |
| Espacement de caractères | 85 % | 99 % |
| Email tout-en-image | 0 % | 55 % (garde) |
| Obfuscation d'URL | 100 % | 100 % (résistance native) |

**Simulation prédictive** : toutes les techniques sont projetées en hausse d'ici
2028 (texte poli par IA 52 → 86 %, quishing 36 → 82 %). Les attaques combinées
« 2026 » font chuter la détection à 64 %, restaurée à 94 % par les défenses.

> Détails et limites honnêtes : voir **`docs/MODEL_CARD.md`**.

---

## 6. Structure du dépôt

```
phishlab/
├── phishlab/                 # package principal
│   ├── features.py           # extraction des 30 features + lexiques
│   ├── detector.py           # détecteur hybride (tabulaire + TF-IDF)
│   ├── explainer.py          # explicabilité (SHAP linéaire + NL + surlignage)
│   ├── adversarial.py        # attaques d'évasion + défenses
│   ├── simulator.py          # simulation de sensibilisation
│   └── predictive.py         # simulation prédictive
├── data/
│   ├── generate_dataset.py   # génération synthétique (avec bruit d'étiquettes)
│   └── phishlab_dataset.csv  # jeu de données généré
├── api/app.py                # API Flask + service du dashboard
├── web/
│   ├── dashboard.html        # console d'analyse autonome (hors-ligne)
│   └── phishlab_data.json    # données embarquées (scorer + lexiques)
├── models/                   # modèle entraîné + scorer exporté
├── reports/                  # métriques + figures (PNG)
├── docs/                     # model card, threat model, éthique
├── train.py                  # entraînement + évaluation
├── eval_robustness.py        # figure de robustesse
├── eval_predictive.py        # figure de projection
├── export_web_data.py        # export des données du dashboard
└── requirements.txt
```

---

## 7. Cadre éthique

PhishLab est strictement **défensif**. Tous les emails sont **synthétiques**,
générés dans un **bac à sable** : aucun envoi réel, aucune cible réelle, aucune
collecte de données personnelles. Les « taux de clic » sont **simulés** par un
modèle de persuasion, jamais mesurés sur des personnes. Voir **`docs/ETHIQUE.md`**.

---

## 8. Équipe

| Membre | Rôle |
|---|---|
| Bozu Esat Can | Expert IA / Ingénierie |
| Mohamed Anouar Bouachour | Cybersécurité |
| Saad Bourrich | Expert Data |
| Mambaye Sow | Développeur |
