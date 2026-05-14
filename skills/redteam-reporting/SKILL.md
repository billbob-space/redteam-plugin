---
name: redteam-reporting
description: Normalise les findings (chaque vuln = un fichier Markdown avec frontmatter strict) et agrège en rapport daté via script + template. Utiliser quand un finding est confirmé ou quand l'utilisateur exécute /report <client>.
---

# Reporting d'engagement

## Quand appliquer
- Une vulnérabilité a été confirmée → créer un fichier finding.
- L'utilisateur exécute `/report <client>` → agréger en rapport daté.

## Format d'un finding individuel

Chaque finding va dans `engagements/<client>/findings/<NN>-<short-name>.md` avec frontmatter **strict** (validation hard-fail au moment du `/report`) :

````markdown
---
title: SQLi authentifiée sur /api/v1/users/search
severity: high            # enum REQUIS : critical | high | medium | low | info
date: 2026-05-15          # ISO 8601 YYYY-MM-DD, REQUIS
cvss: 8.1                 # optionnel
owasp: "A03:2021"         # optionnel
cwe: 89                   # optionnel
endpoint: https://app.acme-corp.com/api/v1/users/search   # optionnel
method: GET               # optionnel
parameter: q              # optionnel
discovered_by: nuclei + manual                            # optionnel
status: open              # optionnel, défaut "open" — enum : open | fixed | accepted_risk | false_positive
---

## Impact
Énumération possible de tous les utilisateurs de la base via injection booléenne.

## Reproduction
```http
GET /api/v1/users/search?q=admin' OR '1'='1 HTTP/1.1
Host: app.acme-corp.com
```

## Remédiation
- Requêtes paramétrées.
- Validation côté serveur du format de `q`.
````

### Règles de validation strictes (mode `/report`)

- Bloc `---...---` requis. Sinon → refus.
- Champs requis : `title`, `severity`, `date`. Sinon → refus.
- `severity` doit être dans l'enum. Sinon → refus.
- `date` doit parser comme `YYYY-MM-DD`. Sinon → refus.
- `status` (si présent) doit être dans l'enum. Sinon → refus.
- Champs inconnus → conservés, warning stderr, pas d'erreur (forward-compat).

## Génération du rapport daté

```bash
.tools/venv/bin/python .claude/plugins/redteam/skills/redteam-reporting/aggregate_findings.py \
  --client <client> --root . --perimeter external
```

Produit `engagements/<client>/rapports/YYYY-MM-DD.md` (UTC, écrasé si re-run le même jour).

Le script régénère également :
- `engagements/<client>/rapports/INDEX.md` — historique tabulaire des audits du client.
- `engagements/INDEX.md` — tableau de bord cross-client (un client = une ligne avec son dernier audit).

Pour un PDF : `pandoc engagements/<client>/rapports/<date>.md -o <date>.pdf`.

## Sections narratives à compléter manuellement

Le template laisse 4 sections `_(à compléter)_` :
- `## Résumé exécutif` — 3-5 phrases sur la posture sécurité globale.
- `## Chaînes d'attaque confirmées` — décrire les chaînes d'exploitation validées.
- `## Ce qui a résisté` — protections en place qui ont bloqué des tentatives.
- `## Risque résiduel` — ce qui reste exploitable ou hors périmètre.

Ne pas envoyer le rapport au client sans avoir comblé ces sections.

## Force-regen des INDEX sans rapport

```bash
./scripts/regenerate_indexes.py
```

Utile après édition manuelle d'un rapport (changement de `status` d'un finding, etc.) sans vouloir re-run `/report`.

## Anti-patterns

- Ne pas commit `engagements/<client>/` dans git (ce dossier reste local).
- Ne pas inclure de credentials clients dans les findings (token, mots de passe, etc.) — utiliser des placeholders.
- Vérifier que le rapport ne contient pas de fragments de session id ou de PII non utiles avant export.
- Ne pas court-circuiter la validation frontmatter : un finding mal formaté = refus du `/report`.
