---
name: redteam-vuln-scan
description: Scan de vulnérabilités web standardisé (nuclei + ffuf + feroxbuster) avec gestion de rate-limit. Utiliser après la recon, quand l'utilisateur exécute /scan <target> ou demande "scan les vulnérabilités de <host>".
---

# Scan de vulnérabilités web

## Quand appliquer
- Après `redteam-recon-web` (les fichiers `engagements/<client>/recon/http.jsonl` existent).
- L'utilisateur a explicitement demandé un scan ou exécuté `/scan <target>`.

## Pré-conditions
1. Vérifier que la cible est in_scope (le hook bloquera sinon, mais on évite l'aller-retour).
2. Lire `engagements/<client>/scope.yaml` → `constraints.max_rps` ; valeur par défaut 10 si absente.
3. Créer `engagements/<client>/findings/raw/` si absent.

## Étapes

### Étape 1 — nuclei severity info,low (actif-léger)
```bash
RPS=$(python3 -c "import yaml; c=yaml.safe_load(open('engagements/<client>/scope.yaml')); print((c.get('constraints') or {}).get('max_rps', 10))")
nuclei -u <target> \
       -severity info,low,medium \
       -rate-limit "$RPS" \
       -jsonl -o engagements/<client>/findings/raw/nuclei-low.jsonl
```

### Étape 2 — Fuzzing de contenus (si pertinent)
Si la recon a révélé un endpoint web avec status 200 sur la racine :
```bash
ffuf -u <target>/FUZZ \
     -w .tools/share/seclists/Discovery/Web-Content/raft-small-words.txt \
     -mc 200,204,301,302,401,403 \
     -rate "$RPS" -t 10 \
     -of json -o engagements/<client>/findings/raw/ffuf.json
```
> Si SecLists n'est pas installé, l'ajouter au `tools.manifest.json` (`git_clones`) et relancer `./scripts/install.sh`.

### Étape 3 — Directory bruteforce récursif (optionnel, plus lourd)
À ne lancer que si l'utilisateur le demande explicitement.
```bash
feroxbuster --url <target> \
            --wordlist .tools/share/seclists/Discovery/Web-Content/common.txt \
            --rate-limit "$RPS" --threads 10 --depth 2 \
            --output engagements/<client>/findings/raw/feroxbuster.txt
```

## Après le scan
1. Parser `nuclei-low.jsonl` : pour chaque finding avec `severity ≥ medium`, créer un fichier `engagements/<client>/findings/<id>-<short>.md` (cf. skill `redteam-reporting` pour le template).
2. Résumer dans le chat : nombre de findings par sévérité, top 3 à investiguer.
3. Proposer la prochaine étape (validation manuelle ou `/exploit <url> <vuln-type>` pour les leads).

## Erreurs et anti-patterns
- Ne **jamais** lancer nuclei avec `-severity critical,high` directement sans confirmation (le hook le bloquera de toute façon car classé intrusif).
- Si le rate-limit cause des timeouts, baisser plutôt que retirer.
