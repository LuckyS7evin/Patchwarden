# Décisions et points ouverts

## Décisions validées

| Sujet | Décision |
| :--- | :--- |
| Stack | **Go** : un seul binaire, `net/http`, `golang.org/x/crypto/ssh`, SQLite, templates embarqués + HTMX, logs en direct par SSE |
| Exécution | Pas d'agent dans les invités : `pct exec` (LXC) et `qm guest exec` (VM), par SSH sur les nœuds |
| Accès aux nœuds | Utilisateur dédié `patchwarden`, clé restreinte (`from=`, `restrict`, `command=`) vers un wrapper qui n'accepte qu'un vocabulaire fixe. Scripts d'action installés et versionnés sur le nœud. Rien n'agit sur l'hôte lui-même |
| Inventaire | API Proxmox, un jeton `PVEAuditor` (lecture seule) par nœud, pas de cluster |
| VMs | `qemu-guest-agent` présent et activé sur toutes les VMs |
| LXC de test | LXC « Développement » (LOKI, Debian 13 a priori) |
| Vérification | Sonde `tools/sonde.sh`, lancée à la main sur le nœud, rapport collé dans la conversation |

## Ce que les scripts community-scripts font réellement (lu dans `ProxmoxVE` et `core`)

- `/usr/bin/update` est **généré**. Il exporte `SCRIPT_SLUG` et `UPDATE_SCRIPT_NAME`,
  télécharge `core/misc/update.sh`, qui interroge `community-scripts.org/api/update-info`
  puis exécute `ct/<nom>.sh`. Les anciens conteneurs gardent l'ancien format : une ligne
  `curl …/ct/<nom>.sh`.
- Mode non interactif : `PHS_SILENT=1`, ou aucun terminal. Les questions prennent leur
  réponse par défaut. Codes de sortie : `75` (interactif requis), `113` (CPU/RAM
  inférieurs à `var_cpu`/`var_ram`), `114` (racine `/` pleine à plus de 80 %).
- En mode silencieux, la sortie détaillée va dans `/tmp/build-<date>.log` (`_CS_RUN_LOG`)
  dans le conteneur. **À tester :** exporter `_CS_RUN_LOG=/tmp/patchwarden-<job>.log`
  pour suivre ce fichier en direct.
- Le script ne sait pas « vérifier sans mettre à jour ». PatchWarden détecte donc
  lui-même : version installée dans `/root/.<app>`, dépôt source lu dans
  `check_for_gh_release "<app>" "<owner/repo>"`, dernière version via l'API GitHub
  ou Codeberg. Sur 651 scripts : 452 comparent une version, 98 ne font qu'apt, 101
  ont une logique propre.
- Cas déjà repérés : Termix demande 4 CPU et 4 Go de RAM, et contient un `read -rp` brut.
  `ct/forgejo.sh` ne fait plus qu'un `run_os_update`, sans mettre à jour Forgejo lui-même.
  Semaphore contient un `read -r -p` de migration.

## Docker : impact de Portainer

La plupart des conteneurs viennent de **stacks Portainer**. Leurs fichiers compose
sont dans le volume de Portainer : le label `working_dir` vaut `/data/compose/<id>`,
un chemin vu **depuis le conteneur Portainer**. Lancer `docker compose` depuis
l'hôte risque de désynchroniser Portainer, notamment pour les variables d'environnement
de la stack. Deux options, à trancher après la sonde :

1. Redéployer via l'**API Portainer** (re-pull de l'image). C'est propre, mais il faut
   un jeton par instance Portainer, et il y en a 5 aujourd'hui.
2. `docker compose -p <projet> pull && up -d` sur la copie hôte des fichiers. Plus
   simple, mais plus risqué.

**Watchtower** : à arrêter avant le jalon Docker. Sinon il met les images à jour en
parallèle, et la comparaison de digests montre toujours « à jour ». PatchWarden
signalera les conteneurs Watchtower encore présents.

## Questions encore ouvertes

7. Types de stockage par nœud ; disques en passthrough sur OMV (la sonde le montre).
8. LXC PatchWarden : nœud, VLAN, accès Internet, jeton GitHub en lecture seule.
9. Invités arrêtés : ignorés par défaut ?
10. Code 113 : augmentation temporaire CPU/RAM, ou simple signalement ?
11. « Sécurité uniquement » en mode strict (dépôts `*-security` seulement) ?
12. Versions de PVE et des OS d'invités ; `pve-ups` et Dev inclus ; langue de l'interface.
