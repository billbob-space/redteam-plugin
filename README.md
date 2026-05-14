# Plugin `redteam`

Plugin Claude Code pour des engagements red-team semi-autonomes : recon passive, scan
de vulnérabilités web, exploitation ciblée, reporting daté. Le tout encadré par un hook
PreToolUse de gating par scope (allow/deny/ask selon catégorie d'outil) et un audit trail
JSONL hash-chaîné.

## Composants
- **Hook PreToolUse** (`hooks/scope_gate.py`) : intercepte les commandes Bash, parse les
  cibles, vérifie le scope de l'engagement courant, et ALLOW / DENY / ASK selon la
  catégorie de l'outil (passif / actif-léger / intrusif).
- **Hook PostToolUse** (`hooks/post_tool_log.py`) : journalise exit code, durée et stderr
  tail dans l'audit trail.
- **Skills** (`skills/*`) : pipelines normalisés pour recon web, scan de vulnérabilités,
  exploitation web, et reporting.
- **Slash commands** (`commands/*`) : `/scope`, `/recon`, `/scan`, `/exploit`, `/report`.

## Installation des dépendances Python du hook
Le hook nécessite `pyyaml`. Dans le repo qui utilise le plugin, prévoir un venv local
avec :
```bash
pip install -r hooks/requirements.txt
```
Les wrappers `hooks/*_wrapper.sh` cherchent automatiquement un `.tools/venv/bin/python`
en remontant l'arborescence ; à défaut ils fallback sur `python3` système.

## Tests
```bash
python -m pytest hooks/tests/ -v
python -m pytest skills/redteam-reporting/tests/ -v
```

## Installation comme plugin Claude Code
Via marketplace GitHub :
```
/plugin install redteam@redteam-plugin
```
(après avoir enregistré le marketplace `billbob-space/redteam-plugin` dans
`~/.claude/settings.json` → `extraKnownMarketplaces`).
