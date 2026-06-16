# Model Card - Détecteur PhishLab

Document de transparence sur le modèle de détection. Il décrit honnêtement ce
que le modèle fait, comment il a été évalué, et - surtout - **ses limites**.

---

## 1. Description

- **Tâche** : classification binaire d'emails (phishing vs légitime), avec une
  bande intermédiaire « suspect » fondée sur des seuils.
- **Type de modèle** : modèle **linéaire** (régression logistique) calibré par
  sigmoïde (`CalibratedClassifierCV`), entraîné sur une représentation hybride :
  - 30 features **tabulaires** (StandardScaler) ;
  - TF-IDF **mots** (1–2 grammes, 8 000 dims) ;
  - TF-IDF **caractères** (3–5 grammes, 6 000 dims) - robuste aux fautes/césures.
- **Pourquoi linéaire ?** Explicabilité exacte (SHAP en forme fermée),
  portabilité (export JSON → scorer navigateur), et performance équivalente aux
  modèles à arbres sur ces données (cf. §4).
- **Seuils de décision** : `suspect ≥ 0.40`, `phishing ≥ 0.70`.

---

## 2. Données d'entraînement

- **100 % synthétiques**, générées par `data/generate_dataset.py`.
- **4 800 emails** : 2 400 phishing / 2 400 légitimes, répartis en familles
  réalistes (facture, réinitialisation, RH/paie, livraison, compte suspendu,
  fraude au président, loterie, faux support… ; côté légitime : newsletters,
  reçus, notifications, échanges internes, alertes de sécurité authentiques…).
- **Split** : 75 % entraînement / 25 % test.

### Bruit d'étiquetage volontaire

Une chaîne d'annotation automatique réelle n'est jamais parfaite. Pour le simuler :

- chaque email porte une étiquette **propre** (`label`, vérité terrain issue de
  la famille) **et** une étiquette **bruitée** (`noisy_label`, = `label` avec
  ~3 % d'inversions aléatoires) ;
- le modèle est **entraîné sur l'étiquette bruitée** (réaliste) ;
- la **vérité propre** n'est jamais inversée et sert de référence haute.

---

## 3. Protocole d'évaluation - deux chiffres, lus différemment

| Mesure | Référence | Interprétation |
|---|---|---|
| **Opérationnelle** *(chiffre présenté)* | étiquettes **bruitées** | ce que mesurerait la production avec une annotation imparfaite |
| **Intrinsèque** *(borne supérieure)* | vérité **propre** | compétence pure du modèle ; élevée car données séparables |

L'écart entre les deux **est** le coût du bruit d'étiquetage. Présenter
uniquement la mesure intrinsèque (≈ 100 %) serait trompeur : nous mettons en
avant la mesure **opérationnelle**.

---

## 4. Résultats

Sur le jeu de test (n = 1 200), étiquettes opérationnelles :

| Modèle | Précision | Rappel | F1 | ROC-AUC | Brier |
|---|---|---|---|---|---|
| **LogReg (déployé)** | 0.965 | 0.967 | **0.966** | 0.966 | 0.034 |
| Forêt aléatoire | 0.965 | 0.967 | 0.966 | 0.967 | 0.034 |
| XGBoost | 0.957 | 0.967 | 0.962 | 0.969 | 0.037 |

- **F1 intrinsèque (vérité propre)** : **1.000** → plafond, données séparables.
- **Détection par famille** (mesurée contre la vraie famille) : ~100 % pour
  chaque famille de phishing, ~0 % de faux positifs sur les familles légitimes.
- **Calibration** : Brier 0.034, courbe de fiabilité proche de la diagonale.

Figures : `reports/confusion_matrix.png`, `roc_pr_curves.png`,
`calibration.png`, `feature_importance.png`, `family_detection.png`.

---

## 5. Limites - à lire absolument

1. **Données synthétiques et séparables.**
   Le générateur produit des classes nettement distinctes. Conséquence directe :
   le modèle est **bimodal** - sur les 4 800 emails, **aucun** ne tombe dans la
   bande `[0.42, 0.66]`. La catégorie « suspect » existe par construction
   (seuils) mais est rarement atteinte sur des emails réalistes synthétiques.
   *Sur des emails réels, plus ambigus, cette bande serait davantage peuplée.*

2. **Le chiffre intrinsèque (100 %) n'est pas une performance terrain.**
   C'est un plafond dû à la séparabilité. La vraie indication de difficulté vient
   de la robustesse adverse (§6), où la performance chute nettement.

3. **Dépendance aux signaux d'authentification.**
   Dans les données, le phishing est très corrélé à un échec SPF/DKIM/DMARC. Le
   modèle s'appuie donc fortement sur ces signaux ; un phishing « propre »
   (domaine compromis, authentification valide) est sous-évalué. C'est une limite
   du **jeu de données**, pas seulement du modèle - à corriger en enrichissant
   les exemples furtifs.

4. **Scorer embarqué = approximation.**
   Le tableau de bord hors-ligne reproduit fidèlement la partie linéaire mais
   approxime la normalisation TF-IDF complète. Les scores y sont très proches de
   la production sans être strictement identiques. Pour des scores exacts, passer
   par l'API Flask (même modèle calibré).

5. **Périmètre.**
   Détection sur **sujet + corps + métadonnées fournies**. Pas d'analyse de la
   chaîne `Received`, du contenu réel des pièces jointes, ni des images
   (seulement une **garde** signalant les emails « tout en image »).

6. **Langue.**
   Lexiques et exemples principalement **français/anglais**. Performances non
   garanties sur d'autres langues.

---

## 6. Robustesse adverse (résumé)

Détection de référence : 100 % (sur 300 phishing détectés). Sous attaque (modèle
nu) puis après défenses de canonicalisation :

| Attaque d'évasion | Nu | Défendu |
|---|---|---|
| Homoglyphes Unicode | 27 % | 97 % |
| Caractères invisibles (zero-width) | 47 % | 100 % |
| Leetspeak (`p4ssw0rd`) | 22 % | 66 % |
| Espacement (`p a s s w o r d`) | 85 % | 99 % |
| Email tout-en-image | 0 % | 55 % (garde) |
| Obfuscation d'URL | 100 % | 100 % |

Lectures honnêtes :
- Le **leetspeak** reste l'évasion la mieux résistante (récupération partielle).
- L'**email tout-en-image** contourne toute analyse textuelle : seule une garde
  le signale, d'où une récupération limitée - c'est un angle mort assumé.
- L'**obfuscation d'URL seule** n'a pas d'effet : le modèle s'appuie aussi sur
  des signaux non-URL (texte, authentification). C'est une **force de défense en
  profondeur**, pas un artefact.

Détails : `docs/THREAT_MODEL.md`, `reports/robustness.png`.

---

## 7. Usage prévu et interdit

- **Prévu** : tri/priorisation défensive d'emails, pédagogie, recherche
  défensive, sensibilisation.
- **Interdit** : envoyer de vrais emails de phishing, cibler des personnes
  réelles, ou tout usage offensif. Voir `docs/ETHIQUE.md`.

---

## 8. Maintenance

Les techniques évoluent (cf. simulation prédictive). Le modèle doit être
**ré-entraîné périodiquement** avec des exemples actualisés, et la **dérive**
surveillée (distribution des scores, taux de faux positifs).
