# Cadre éthique et conformité — PhishLab

PhishLab traite d'un sujet sensible : le phishing. Ce document fixe les règles
non négociables du projet.

---

## 1. Principe directeur

**PhishLab est un outil exclusivement défensif.** Il sert à *détecter*,
*expliquer*, *sensibiliser* et *anticiper* — jamais à attaquer.

---

## 2. Garanties techniques

1. **Aucun envoi réel.** Le projet ne contient aucun mécanisme d'envoi d'email.
   Les « campagnes » de sensibilisation sont **simulées** en mémoire.
2. **Aucune cible réelle.** Tous les emails (phishing comme légitimes) sont
   **synthétiques**, générés par `data/generate_dataset.py`. Les noms, adresses
   et entreprises sont fictifs.
3. **Taux de clic simulés.** Les taux affichés proviennent d'un **modèle de
   persuasion** (leviers de Cialdini → fonction logistique), calibré sur des
   ordres de grandeur publics. **Aucune personne réelle n'est mesurée.**
4. **Exécution en bac à sable.** L'analyse, l'API et le tableau de bord
   fonctionnent localement, sans accès à des boîtes mail réelles.
5. **Pas de capacité offensive opérationnelle.** Les « attaques » du module
   adverse sont des transformations de surface **déjà publiques**, utilisées
   uniquement pour **mesurer et renforcer la défense** (recherche défensive).

---

## 3. Conformité RGPD

- **Minimisation** : aucune donnée personnelle réelle n'est collectée, stockée
  ni traitée. Les données sont synthétiques.
- **Finalité** : sécurité défensive et pédagogie, exclusivement.
- **En cas de déploiement réel** (hors de ce projet), les principes suivants
  s'appliqueraient :
  - base légale claire (intérêt légitime de sécurité) et information des
    utilisateurs ;
  - conservation limitée des emails analysés, chiffrement au repos ;
  - droit d'accès / d'effacement respecté ;
  - journalisation des accès au système de détection ;
  - analyse d'impact (AIPD) si traitement à grande échelle.

---

## 4. Usage acceptable

**Autorisé**
- Trier et prioriser des emails suspects à des fins défensives.
- Former et sensibiliser des utilisateurs avec des exemples synthétiques.
- Étudier la robustesse des détecteurs (recherche défensive).

**Interdit**
- Envoyer de vrais emails de phishing ou de « test » non consenti.
- Cibler des personnes ou organisations réelles.
- Réutiliser les modules d'évasion à des fins offensives.
- Présenter les taux de clic simulés comme des mesures réelles.

---

## 5. Transparence

- Le tableau de bord affiche en permanence un rappel du cadre éthique.
- Le *model card* (`docs/MODEL_CARD.md`) documente honnêtement les limites, y
  compris les angles morts et les chiffres à ne pas sur-interpréter.
- Les « taux de clic » sont toujours étiquetés **simulés**.

---

## 6. Responsabilité

PhishLab est un projet **pédagogique** (Projet Innov, EPSI). Il n'est pas certifié
pour un usage en production critique. Toute mise en production réelle nécessiterait
un audit de sécurité, une validation sur données réelles et une supervision
humaine des décisions.
