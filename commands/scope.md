---
description: Initialise un nouvel engagement red-team (scaffolding + scope.yaml ouvert pour édition)
argument-hint: <client-slug>
---

# /scope $1

Initialise un dossier d'engagement pour le client `$1`.

## Étapes à exécuter

1. Vérifier que `$1` est un slug valide (lowercase, alphanum + tirets). Sinon, demander un slug valide à l'utilisateur.

2. Refuser si `engagements/$1/scope.yaml` existe déjà (pour ne pas écraser un engagement en cours). Proposer alors :
   - reprendre l'engagement existant
   - ou choisir un slug avec un suffixe (`acme-corp-2`, ...).

3. Créer la structure :
   ```bash
   mkdir -p engagements/$1/{recon,findings/raw}
   cp engagements/_template/scope.yaml.tmpl engagements/$1/scope.yaml
   ```

4. Remplacer dans `engagements/$1/scope.yaml` :
   - `__CLIENT__` → `$1`
   - `__ENGAGEMENT_NAME__` → ask user
   - `__AUTHORIZED_BY_EMAIL__` → ask user
   - `__START_ISO__` → maintenant (UTC, format ISO 8601)
   - `__END_ISO__` → ask user (typiquement +2 semaines)

5. **Rappel critique à l'utilisateur** : avant de lancer le moindre scan actif, fournir :
   - Le chemin du document d'autorisation (ROE / lettre de mission)
   - Les domaines/CIDR exactement autorisés dans `in_scope`
   - Les exclusions dans `out_of_scope`

6. Exporter `REDTEAM_CLIENT=$1` dans la session courante (via un message rappelant à l'utilisateur de le faire avec `export REDTEAM_CLIENT=$1` ou en se déplaçant dans `cd engagements/$1`).

7. Afficher un récap : chemin du scope.yaml, prochaine étape recommandée (`/recon <apex>` une fois le scope renseigné).

## Anti-patterns
- Ne pas lancer de recon/scan immédiatement après `/scope` : attendre que l'utilisateur ait renseigné `in_scope`.
- Ne pas pré-remplir `in_scope` à partir du slug (ex: `acme-corp` → `acme-corp.com`) — c'est à l'utilisateur de le valider.
