---
name: redteam-recon-web
description: Pipeline standardisé de recon web/DNS passive. Utiliser quand un engagement red-team démarre et qu'il faut découvrir la surface d'attaque (sous-domaines, services HTTP exposés, certificats) à partir d'un ou plusieurs domaines apex listés dans engagements/<client>/scope.yaml.
---

# Recon web standardisée

## Quand appliquer ce skill
- L'utilisateur exécute `/recon <target>` ou demande "fais la recon sur <domaine>".
- Un engagement actif existe dans `engagements/<client>/` avec un `scope.yaml`.

## Pré-conditions
- Vérifier que la cible apex (ex: `acme-corp.com`) est dans `in_scope.domains` du `scope.yaml` de l'engagement (au moins en wildcard).
- Si non, refuser et demander à l'utilisateur de mettre à jour le scope.

## Pipeline en 4 étapes

Toutes les sorties vont dans `engagements/<client>/recon/` (créer le dossier si absent).

### Étape 1 — Énumération sous-domaines (passive)
```bash
subfinder -d <apex> -all -silent -o engagements/<client>/recon/subdomains.txt
assetfinder --subs-only <apex> >> engagements/<client>/recon/subdomains.txt
sort -u engagements/<client>/recon/subdomains.txt -o engagements/<client>/recon/subdomains.txt
```

### Étape 2 — Résolution DNS
```bash
dnsx -l engagements/<client>/recon/subdomains.txt \
     -a -aaaa -cname -resp \
     -silent -j -o engagements/<client>/recon/dns.jsonl
```

### Étape 3 — Probe HTTP
```bash
httpx -l engagements/<client>/recon/subdomains.txt \
      -silent -title -tech-detect -status-code -j \
      -o engagements/<client>/recon/http.jsonl
```

### Étape 4 — Collecte certificats / SANs
```bash
tlsx -l engagements/<client>/recon/subdomains.txt \
     -san -cn -silent -j \
     -o engagements/<client>/recon/tls.jsonl
```

## Après le pipeline
1. Compter les hosts actifs : `jq '. | select(.status_code != null)' engagements/<client>/recon/http.jsonl | jq -s 'length'`.
2. Produire un résumé court en 5-10 bullets dans le chat : top techs détectées, hosts atypiques, certs avec SANs inattendus.
3. Proposer la prochaine étape (typiquement `/scan <subset>`).

## Erreurs
- Un outil qui crashe : capturer stderr dans `engagements/<client>/recon/_errors.log`, ne pas interrompre la chaîne.
- Si `subdomains.txt` est vide après l'étape 1, demander à l'utilisateur de fournir une seed list manuellement.

## Hors-scope de ce skill
- Scans actifs intrusifs (utiliser `redteam-vuln-scan`).
- Exploitation (utiliser `redteam-exploit-web`).
