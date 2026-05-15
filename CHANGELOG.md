# Changelog

Toutes les évolutions notables de ce plugin sont consignées dans ce fichier.

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ;
versionnage [SemVer](https://semver.org/lang/fr/).

## [0.5.0] — 2026-05-15

Première release formellement taguée. Trois axes : gating de nouveaux outils, refonte CSS du rendu HTML, schéma frontmatter pour rapports de re-vérification.

### Added

- **Gate** : `naabu` (port scanner ProjectDiscovery) et `rpcinfo` (client RPC portmap) sont désormais reconnus par `parser.KNOWN_TOOLS` et classés `ACTIVE_LIGHT` par défaut dans `classifier.ACTIVE_LIGHT_TOOLS`. Promotion automatique en `INTRUSIVE` via le seuil `-c >20` (concurrence). [#1](https://github.com/billbob-space/redteam-plugin/pull/1)
- **Gate** : `-host` ajouté à `parser.TARGET_FLAGS` (naabu utilise `-host` et non `--host`).
- **Reporting** : composants CSS dédiés aux rapports de re-vérification dans le stylesheet global — `.remediation-tiles` (3-up exec-scan), `.finding-strip` / `.finding-row` (diff before→after), `.status-pill.fixed/open/escalated` (pastilles d'état). [#2](https://github.com/billbob-space/redteam-plugin/pull/2)
- **Reporting** : schéma frontmatter `remediation:` formalisé, avec auto-injection des tiles + strip après le `<h1>` (même pattern que `counts:` qui pilote `summary-cards`). Liste plate d'entrées `{id, title, anchor?, status, before, after}`, ordre auteur préservé. [#3](https://github.com/billbob-space/redteam-plugin/pull/3)
- **Reporting** : section dédiée dans `skills/redteam-reporting/SKILL.md` documentant le schéma et les règles de validation.

### Changed

- **Gate** : audit log enrichi (`category`, `tool`, `target`) désormais peuplé correctement pour les invocations `naabu` et `rpcinfo` — auparavant ces commandes passaient avec `reason="Commande non offensive"` sans entrée structurée.
- **Reporting** : pipeline d'injection après `</h1>` étendu de `cards → toc` à `cards → remediation → toc`, avec filtrage des blocs vides (backwards-compat strict).
- **Reporting** : media queries étendues — la responsive 720px → 760px gère désormais aussi `remediation-tiles` (1-col) et `finding-row` (2-col simplifié) ; `@media print` désactive le box-shadow sur les nouveaux composants.

### Fixed

- **Gate** : faille de gating critique — un appel `naabu -host evil-out-of-scope.com -p 1-65535` était silencieusement autorisé sans vérification de scope ni de fenêtre d'engagement, car `detect()` retournait `[]`. Idem pour `rpcinfo -p target`. Reproductible avant cette release ; corrigé par #1.

### Validation

- 177 tests verts (avant cette release : 117) — +60 tests sur le gating + le rendu.
- Nouveau test `test_css_includes_remediation_components` garantit la présence des classes critiques dans le `style.css` global.
- 5 tests dédiés au schéma `remediation:` (tiles, strip, ordre auteur, retro-compat, status inconnu).

### Compatibilité

- **Backwards-compat** : un rapport markdown sans `remediation:` dans le frontmatter est rendu strictement à l'identique d'avant cette release.
- **Marketplace refresh** : pour que le hook `scope_gate` actif d'une session existante voie les nouvelles classifications, exécuter `/plugin marketplace update redteam-plugin` côté consommateur.

## [0.4.0] — antérieur (non tagué)

- Rendu HTML amélioré (`render_html.py`) avec badges de sévérité, summary cards, TOC findings, dashboard cards (commit `05bd4ef`).

## [0.3.0] — antérieur (non tagué)

- Utilisation de `${CLAUDE_PLUGIN_ROOT}` dans les chemins (commit `eaac6a1`).
- Hash-chaining de l'audit log (`audit_log.append`, `verify_chain`).

## [0.2.0] — antérieur (non tagué)

- Extraction initiale du plugin depuis `security/.claude/plugins/redteam/` (commit `ca1f6bb`).
- Hooks `PreToolUse` (scope_gate) et `PostToolUse` (post_tool_log).
- Skills `redteam-recon-web`, `redteam-vuln-scan`, `redteam-exploit-web`, `redteam-scope-check`, `redteam-reporting`.
- Slash commands `/scope`, `/recon`, `/scan`, `/exploit`, `/report`.

[0.5.0]: https://github.com/billbob-space/redteam-plugin/releases/tag/v0.5.0
