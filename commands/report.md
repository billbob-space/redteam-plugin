---
description: Génère le rapport daté de l'engagement (Markdown + INDEX auto)
argument-hint: <client-slug>
---

# /report $1

Agrège tous les findings du client `$1` en un rapport daté.

## Étapes

1. Vérifier que `engagements/$1/scope.yaml` existe.

2. Lister `engagements/$1/findings/*.md`. S'il n'y en a aucun, demander à l'utilisateur si c'est attendu (audit sans findings = info ou anomalie ?).

3. Demander à l'utilisateur le périmètre du rapport (`external` / `internal` / `external+internal` / `web` / `network` / `config`). Par défaut : `external`.

4. Lancer le script d'agrégation :
   ```bash
   .tools/venv/bin/python ${CLAUDE_PLUGIN_ROOT}/skills/redteam-reporting/aggregate_findings.py \
     --client $1 --root . --perimeter <choix>
   ```

5. Le rapport est écrit dans `engagements/$1/rapports/YYYY-MM-DD.md` (UTC). Les INDEX (per-engagement + global) sont régénérés automatiquement.

6. Demander à l'utilisateur s'il veut un PDF :
   ```bash
   pandoc engagements/$1/rapports/<date>.md -o engagements/$1/rapports/<date>.pdf
   ```

7. Demander à l'utilisateur s'il veut un rendu HTML statique (pour consultation via navigateur ou exposition sur un webserver local) :
   ```bash
   .tools/venv/bin/python ${CLAUDE_PLUGIN_ROOT}/skills/redteam-reporting/render_html.py \
     --root . --client $1
   ```
   Output : `engagements/_html/` (gitignored automatiquement par `engagements/*/`). Liens
   relatifs uniquement, aucune URL absolue. L'exposition sur un webserver (nginx,
   Traefik, `python -m http.server`, ...) est laissée au repo consommateur.

8. Proposer la checklist de clôture :
   - [ ] Compléter les sections narratives "_(à compléter)_" du rapport (Résumé exécutif, Chaînes d'attaque, Ce qui a résisté, Risque résiduel).
   - [ ] Vérifier qu'aucun finding ne contient de credentials.
   - [ ] Nettoyer les artefacts uploadés sur la cible (shells de test, comptes créés).
   - [ ] Révoquer les clés API jetables utilisées.
   - [ ] Archiver `engagements/$1/` localement (tar.gz, hors git).
   - [ ] Communiquer le rapport au client par canal sécurisé (PGP / signal).

## Notes

- Le rapport est généré à partir du template bundled `skills/redteam-reporting/templates/default.md.tmpl` du plugin. Pour customiser, copier ce template ailleurs et passer `--template <path>` au script.
- Si un finding a un frontmatter invalide (champ requis manquant, severity hors enum, date non-ISO), `aggregate_findings.py` refuse de générer le rapport (hard-fail) et indique le fichier fautif sur stderr.
- Idempotent : `/report` lancé deux fois le même jour calendaire UTC écrase le snapshot du jour.
- Pour force-régénérer les INDEX sans relancer `/report` (utile après édition manuelle des rapports), utiliser `./scripts/regenerate_indexes.py`.
