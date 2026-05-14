# Plugin `redteam`

Plugin Claude Code custom pour le repo `/projects/security`.

## Composants
- **Hook PreToolUse** (`hooks/scope_gate.py`) : intercepte les commandes Bash, parse les
  cibles, vérifie le scope de l'engagement courant, et ALLOW / DENY / ASK selon la
  catégorie de l'outil (passif / actif-léger / intrusif).
- **Skills** (`skills/*`) : pipelines normalisés pour recon web, scan de vulnérabilités,
  exploitation web, et reporting.
- **Slash commands** (`commands/*`) : `/scope`, `/recon`, `/scan`, `/exploit`, `/report`.

## Installation des dépendances Python du hook
Le hook utilise le venv local du projet :
```bash
.tools/venv/bin/pip install -r .claude/plugins/redteam/hooks/requirements.txt
```

## Tests
```bash
.tools/venv/bin/python -m pytest .claude/plugins/redteam/hooks/tests/ -v
```
