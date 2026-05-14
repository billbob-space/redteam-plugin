---
description: Lance le pipeline de recon passive sur un apex (subfinder → dnsx → httpx → tlsx)
argument-hint: <apex-domain>
---

# /recon $1

Lance la chaîne de recon passive sur le domaine apex `$1`.

## Étapes à exécuter

1. Identifier le client courant :
   - `$REDTEAM_CLIENT` si défini
   - Sinon, regarder le cwd
   - Sinon, demander à l'utilisateur

2. Invoquer le skill **`redteam-scope-check`** sur la cible `$1`. Si OUT ou UNKNOWN, refuser
   et demander à l'utilisateur de mettre à jour `scope.yaml` ou de fournir une cible in_scope.

3. Invoquer le skill **`redteam-recon-web`** avec :
   - `<client>` = client courant
   - `<apex>` = `$1`

4. Le skill produit les outputs dans `engagements/<client>/recon/`.

5. Une fois fini, résumer en 5-10 bullets, et proposer la suite (typiquement `/scan <subset>`).

## Erreurs
- Pas d'engagement actif → demander `/scope <client>` d'abord.
- Cible hors scope → demander mise à jour du scope.
- Outil manquant → indiquer à l'utilisateur de relancer `./scripts/install.sh`.
