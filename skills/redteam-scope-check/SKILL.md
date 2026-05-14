---
name: redteam-scope-check
description: Vérifie qu'une cible donnée est in_scope pour l'engagement courant avant toute action active. Utiliser proactivement quand l'utilisateur évoque une cible nouvelle ou ambiguë, ou avant tout pipeline qui va lancer des outils actifs.
---

# Vérification de scope (compagnon du hook PreToolUse)

Le hook `scope_gate.py` bloque les commandes hors-scope, mais ce skill permet à Claude
de vérifier **avant** d'avoir construit la commande, et donc d'éviter des allers-retours.

## Quand appliquer
- L'utilisateur cite une nouvelle URL/domaine/IP.
- Avant de lancer un pipeline (recon, scan, exploit) qui contient une cible.
- Si l'utilisateur demande "est-ce que je peux scanner X ?".

## Procédure

1. Trouver l'engagement actif :
   - Variable d'env `REDTEAM_CLIENT` si présente
   - Sinon, `cwd` dans `engagements/<X>/...`
   - Sinon, demander à l'utilisateur quel engagement utiliser.

2. Charger `engagements/<client>/scope.yaml` (`yaml.safe_load`).

3. Pour la cible donnée :
   - Si URL, extraire l'hôte avec `urlparse`.
   - Si IP, comparer aux `in_scope.cidrs` et `out_of_scope.cidrs`.
   - Si hostname, comparer aux `in_scope.domains` et `out_of_scope.domains` (avec wildcards `*.X`).

4. **Règle de priorité** : `out_of_scope` est appliqué **après** `in_scope`. Un host qui matche les deux est OUT.

5. Renvoyer le résultat à l'utilisateur sous forme courte :
   - ✅ `app.acme-corp.com` est in_scope (matche `*.acme-corp.com`).
   - ❌ `blog.acme-corp.com` est out_of_scope (exclusion explicite).
   - ❓ `acme.local` est inconnu — pas dans le scope.

## Erreurs
- `scope.yaml` absent → "engagement non initialisé, lance /scope <client> d'abord".
- Cible non-parsable → fail-closed, demander une URL/host/IP valide.
