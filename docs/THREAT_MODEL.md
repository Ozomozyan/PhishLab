# Threat Model — PhishLab

Quelles menaces PhishLab cherche-t-il à détecter, quelles techniques d'évasion
sont prises en compte, et que reste-t-il hors de portée.

---

## 1. Périmètre et hypothèses

- **Entrée** : un email représenté par son sujet, son corps, le nom et l'adresse
  de l'expéditeur, l'adresse de réponse, les résultats SPF/DKIM/DMARC, et la
  liste des noms de pièces jointes.
- **Hors périmètre** : analyse de la chaîne `Received`, ouverture réelle des
  pièces jointes, rendu HTML complet, OCR d'images, suivi des redirections
  réseau.
- **Acteur** : un attaquant qui rédige des emails de phishing et tente d'échapper
  à un détecteur automatique par des transformations de surface.

---

## 2. Familles de menaces couvertes (détection)

| Famille | Levier principal | Signaux clés |
|---|---|---|
| Hameçonnage d'identifiants | urgence + lien | TLD à risque, domaine sosie, demande d'identifiants |
| Fausse facture / paiement | peur financière | montant, urgence, pièce jointe |
| Fraude au président (BEC) | autorité + confidentialité | demande de virement, pas d'URL, ton hiérarchique |
| Réinitialisation de mot de passe | peur + urgence | usurpation de marque, lien de « vérification » |
| Livraison de colis | curiosité + frais | domaine sosie, petits frais, urgence |
| RH / bulletin de paie | autorité | changement de coordonnées bancaires |
| Loterie / gain | appât | promesse de gain, montant |
| Faux support IT | serviabilité | demande d'accès, ton « assistance » |

---

## 3. Techniques d'évasion modélisées (attaques)

Toutes sont implémentées dans `phishlab/adversarial.py` et **mesurées**.

| Technique | Principe | Module |
|---|---|---|
| Espacement de caractères | `m o t   d e   p a s s e` casse la tokenisation | `attack_char_spacing` |
| Homoglyphes Unicode | lettres latines remplacées par des sosies cyrilliques/grecs | `attack_homoglyph` |
| Leetspeak | `p4ssw0rd`, `c0mpte` | `attack_leetspeak` |
| Caractères invisibles | insertion de zero-width entre les lettres | `attack_zero_width` |
| Obfuscation d'URL | `@`, sous-domaine trompeur, encodage `%xx` de l'hôte | `attack_url_obfuscation` |
| Email tout-en-image | le texte disparaît, remplacé par une image jointe | `attack_image_only` |

---

## 4. Défenses (canonicalisation)

Pipeline `sanitize_email` appliqué avant re-scoring :

| Défense | Contre | Module |
|---|---|---|
| Suppression des zero-width | caractères invisibles | `strip_zero_width` |
| Normalisation Unicode (NFKC + table) | homoglyphes | `normalize_homoglyphs` |
| Re-collage des mots espacés | espacement de caractères | `despace_words` |
| Dé-leet prudent | leetspeak | `deleet` |
| Canonicalisation d'URL (décodage `%`, résolution `@`) | obfuscation d'URL | `canonicalize_url` |
| Garde « tout-en-image » | emails sans texte | `image_only_guard` |
| Bande d'incertitude | sur-confiance | `uncertainty_band` |

---

## 5. Efficacité mesurée

Détection de référence : 100 % (300 phishing). Voir `reports/robustness.png`.

| Attaque | Détection nue | Après défense | Récupération |
|---|---|---|---|
| Homoglyphes | 27 % | 97 % | +70 pts |
| Caractères invisibles | 47 % | 100 % | +53 pts |
| Leetspeak | 22 % | 66 % | +44 pts |
| Espacement | 85 % | 99 % | +13 pts |
| Tout-en-image | 0 % | 55 % | +55 pts (garde) |
| Obfuscation d'URL | 100 % | 100 % | n/a |

---

## 6. Risques résiduels (angles morts)

1. **Leetspeak agressif** : la récupération est partielle (66 %). Une ambiguïté
   demeure (`1` ↔ `i`/`l`) ; un dé-leet plus riche (dictionnaire) améliorerait
   le résultat.
2. **Contenu en image** : sans OCR, seule la **garde** signale l'absence de
   texte. Un véritable OCR + analyse d'image serait nécessaire pour une couverture
   complète.
3. **Phishing « propre »** : un email sans faute, authentifié (domaine
   compromis), au ton professionnel, est sous-évalué (cf. test « IA polie » :
   −4 pts seulement, mais sur des leurres qui gardent des signaux structurels).
4. **Attaques composites futures** : l'empilement texte-IA + homoglyphes +
   invisibles fait chuter la détection à 64 % (cf. simulation prédictive),
   restaurée à 94 % par les défenses — d'où la nécessité d'un ré-entraînement
   continu.
5. **Dérive** : de nouvelles marques, TLD ou tournures non présentes dans les
   lexiques échappent aux features dédiées (le TF-IDF caractères atténue mais ne
   couvre pas tout).

---

## 7. Recommandations de durcissement

- Enrichir le jeu de données en exemples **furtifs** (authentification valide,
  texte propre) pour réduire la dépendance à SPF/DKIM/DMARC.
- Ajouter un module **OCR** pour les emails en image.
- Mettre en place une **surveillance de dérive** (distribution des scores, taux
  de faux positifs) et un calendrier de **ré-entraînement**.
- Combiner le score avec des **signaux réseau** (réputation de domaine, âge du
  domaine, résolution des redirections) en production.
