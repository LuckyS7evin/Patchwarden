# Décisions et points ouverts

## Décisions validées

| Sujet | Décision |
| :--- | :--- |
| Stack | **Go** : un seul binaire, `net/http`, `golang.org/x/crypto/ssh`, SQLite, templates embarqués + HTMX, logs en direct par SSE |
| Exécution | Pas d'agent dans les invités : `pct exec` (LXC) et `qm guest exec` (VM), par SSH sur les nœuds |
| Accès aux nœuds | Utilisateur dédié `patchwarden`, clé restreinte (`from=`, `restrict`, `command=`) vers un wrapper qui n'accepte qu'un vocabulaire fixe. Scripts d'action installés et versionnés sur le nœud. Rien n'agit sur l'hôte lui-même |
| Inventaire | API Proxmox, jeton `PVEAuditor` (lecture seule). Configuration multi-points d'accès avec dédoublonnage : la sonde a détecté un `corosync.conf` sur LOKI (cluster à confirmer) |
| VMs | `qemu-guest-agent` présent et activé sur toutes les VMs |
| LXC de test | CT 103 `dev` (LOKI, Debian 13, base `ct/debian.sh`) ; CT 104 `termix` pour la détection de version |
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

## Résultats de la sonde n° 1 (LOKI, 13/11/2026)

| Hypothèse | Résultat | Conséquence pour PatchWarden |
| :--- | :--- | :--- |
| H1 entrée `update` | ✅ présente, **ancien format** sur les CT testés, avec une variante (`set -a; . /etc/profile.d/90-http-proxy.sh …; bash -c "$(curl …/ct/<nom>.sh)"`) | Détection par `UPDATE_SCRIPT_NAME`, puis `SCRIPT_SLUG`, puis l'URL `/ct/<nom>.sh`. Le premier `update` migre l'entrée vers le nouveau format |
| H2 version installée | ⚠️ `/root/.guacd=1.6.0` vu ; `/root/.termix` masqué par un filtre trop strict de la sonde (anciens tags Termix : `release-2.2.1-tag`, nouveaux : `v26.11.1`) | Lire exactement les `/root/.<app>` nommés dans le script, et comparer en chaînes (« différente de la dernière ») plutôt qu'en semver |
| H3 tags | ✅ `community-script` sur les 11 LXC de LOKI ; la VM PBS porte le tag `critique` | Un tag Proxmox configurable (par défaut `critique`) déclenche la confirmation renforcée, en plus d'OMV/PBS |
| H4 ressources | ❌ Termix : 2 CPU / 2 Go pour 4 / 4 Go exigés → code 113 garanti | Décision attendue (question 10) |
| H7 apt sécurité | ✅ mode strict = 45/45 (dev) et 65/65 (termix), aucun conflit de dépendance | « Sécurité uniquement » en mode strict, avec `--force-confdef --force-confold` comme le moteur |
| H7 bis index apt | ⚠️ âge 1094 h et 2234 h | La détection doit rafraîchir l'index (`apt-get update`), sinon elle sous-estime tout |
| H8 réseau | ✅ GitHub, community-scripts.org, Docker Hub, ghcr joignables depuis les invités | — |
| Flux `pct exec` | ✅ une ligne par seconde reçue en direct ; une ligne sans `\n` arrive avec la suivante | Lecture en flux d'octets, `\r` traité comme un retour en début de ligne dans l'affichage |
| Encodage | ⚠️ accents abîmés quand le script est passé en argument de `pct exec` | Scripts envoyés par l'entrée standard (ou `pct push`), jamais en argument |
| H9 guest agent | ❌ VM 503 : `ping` OK, mais `guest-exec` → `got timeout` | Diagnostic en cours (sonde n° 2 + journal de qemu-ga dans la VM) |
| Hôte | `sudo` absent, `jq` absent, `perl` et `python3` présents | Wrapper en bash/perl ; accès root à commande forcée plutôt qu'utilisateur + sudo (à valider) |
| Stockage | `local-lvm` (lvmthin) occupé à **77,8 %** ; tous les disques testés sont snapshotables | Vérifier le remplissage du thin pool avant tout snapshot (seuil réglable) |
| Disque des invités | dev : `/` à 70 % (seuil d'arrêt du moteur : 80 %) | Afficher l'occupation, alerter dès 75 % |

### Termix : la question posée sans terminal

`ct/termix.sh` contient `read -rp "Update Nginx configuration? [Y/n]"` hors de toute
condition, alors que le moteur active `set -Ee` (`catch_errors`). Selon l'entrée standard :

- fermée (`/dev/null`) : `read` échoue, le script s'arrête **en pleine mise à jour,
  service Termix arrêté** ;
- ouverte sans réponse : blocage indéfini ;
- une ligne vide : réponse par défaut « oui », `nginx.conf` est écrasé (copie gardée en `.bak`).

Règle retenue : l'entrée standard est toujours explicite. PatchWarden repère les `read`
bruts dans `update_script()` et bloque la mise à jour de l'appli tant qu'une réponse
n'est pas enregistrée pour cet invité. Il recommande aussi le snapshot.

## Questions encore ouvertes

7. Types de stockage par nœud ; disques en passthrough sur OMV (la sonde le montre).
8. LXC PatchWarden : nœud, VLAN, accès Internet, jeton GitHub en lecture seule.
9. Invités arrêtés (ex. CT 108 teamspeak) : ignorés par défaut ?
10. Code 113 (Termix) : augmentation temporaire CPU/RAM puis retour, forçage de `var_cpu`/`var_ram` (risque de manque de mémoire à la compilation), ou simple signalement ?
12. Versions de PVE et des OS d'invités ; `pve-ups` et Dev inclus ; langue de l'interface.
13. Accès aux nœuds : root avec commande forcée (rien à installer sur l'hôte) ou installation de `sudo` ?
14. Cluster : LOKI a un `corosync.conf`. Les 3 nœuds sont-ils en cluster ?
