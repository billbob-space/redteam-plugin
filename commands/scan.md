---
description: Lance un scan de vulnérabilités web (nuclei + ffuf optionnel) sur une cible in_scope
argument-hint: <target-url>
---

# /scan $1

Scan de vulnérabilités web sur `$1`.

## Étapes

1. Identifier le client courant (voir `/recon`).

2. Invoquer le skill **`redteam-scope-check`** sur `$1`.

3. Invoquer le skill **`redteam-vuln-scan`** :
   - cible = `$1`
   - utilise `constraints.max_rps` du `scope.yaml` pour le rate-limit
   - sorties dans `engagements/<client>/findings/raw/`

4. Parser les findings, créer un fichier par vuln `severity ≥ medium` selon le template
   `redteam-reporting` dans `engagements/<client>/findings/`.

5. Résumer : nombre de findings par sévérité, top 3 candidats à exploiter, recommandation
   de la prochaine étape (`/exploit <url> <vuln-type>` ou validation manuelle).

## Notes
- Le hook PreToolUse bloquera automatiquement `nuclei -severity critical,high` (intrusif) — c'est intentionnel. Demander confirmation explicite via `/exploit` plutôt.
