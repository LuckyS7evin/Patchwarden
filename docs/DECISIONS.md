# Décisions et points ouverts

## Décisions validées

| Sujet | Décision |
| :--- | :--- |
| Stack | **Go** : un seul binaire, `net/http`, `golang.org/x/crypto/ssh`, SQLite, templates embarqués + HTMX, logs en direct par SSE |
| Exécution | Pas d'agent dans les invités : `pct exec` (LXC) et `qm guest exec` (VM), par SSH sur les nœuds |
| Accès aux nœuds | Clé SSH dédiée sur **root**, restreinte par `from=<IP PatchWarden>`, `restrict` et `command=` vers un wrapper qui n'accepte qu'un vocabulaire fixe (pas de `sudo` sur les nœuds, rien à installer hormis le wrapper). Scripts d'action installés et versionnés sur le nœud. Rien n'agit sur l'hôte lui-même. En cluster, `/root/.ssh/authorized_keys` est partagé par tous les nœuds : le wrapper doit être présent sur chacun |
| Inventaire | API Proxmox `/cluster/resources`, jeton `PVEAuditor` (lecture seule). Cluster `Home` de 3 nœuds aujourd'hui, mais sortie possible : la configuration accepte un ou plusieurs points d'accès, chacun avec son jeton, et fusionne les résultats en dédoublonnant (nœud, VMID). Les deux modes fonctionnent sans changement de code |
| VMs | `qemu-guest-agent` présent et activé sur toutes les VMs |
| Docker | Stacks Portainer : API Portainer (re-déploiement avec re-pull, un jeton par instance : VM 102, 107, 503). Compose classique : `docker compose pull && up -d`. `docker run` : détection seulement |
| Emplacement | LXC PatchWarden sur **ODIN**, réseau MGMT |
| Invités arrêtés | Ignorés par défaut (détection et action). Action « démarrer, mettre à jour, arrêter » à la demande |
| Ressources insuffisantes (code 113) | Augmentation temporaire CPU/RAM au niveau demandé par le script, puis **restauration** des valeurs d'origine, même en cas d'échec. Activable invité par invité |
| LXC de test | CT 103 `dev` (LOKI, Debian 13, base `ct/debian.sh`) ; CT 104 `termix` pour la détection de version |
| Vérification | Sonde `tools/sonde.sh`, lancée à la main sur le nœud, rapport collé dans la conversation |
| Historique | Fichiers sur disque (`data_dir/jobs/<id>/meta.json` + `output.jsonl`) plutôt que SQLite : aucune dépendance, lisible à la main, suffisant pour quelques centaines de tâches. Rétention par nombre |
| Journal en direct | Server-Sent Events, un petit script servi par PatchWarden ; sans JavaScript, la page montre l'état au chargement |
| Wrapper | Scripts d'invité contenus dans le wrapper (versionné, `pw.wrapper_version`). Détection en POSIX `sh` envoyée par l'entrée standard de `pct exec` |

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

## Résultats de la sonde n° 2 (LOKI, 13/11/2026)

| Point | Résultat | Conséquence |
| :--- | :--- | :--- |
| Cluster | `Home`, 3 nœuds, quorum OK | Inventaire complet depuis un seul point d'accès ; config prête pour un retour en nœuds autonomes |
| Version Termix | `/root/.termix = release-2.6.1-tag`, alors que les tags actuels sont `v26.11.x` | Comparaison en chaînes confirmée : « installée ≠ dernière » |
| VM 503 `guest-exec` | ✅ fonctionne (qemu-ga 5.2.0). L'échec n° 1 venait probablement du script de 7 Ko passé en argument, qui a bloqué l'agent un moment | Toujours `--pass-stdin` ou fichier, jamais de gros argument ; délais et une seule exécution à la fois par VM |
| Sortie de `qm guest exec` | Encodée deux fois : `qm` lit les octets de la VM comme du latin-1 puis émet du JSON UTF-8 (« systÃ¨me ») | Après décodage JSON, reconvertir chaque caractère (< 256) en octet avant de lire la chaîne en UTF-8 |
| Flux VM | ❌ `exec-status` ne renvoie la sortie qu'à la fin du processus ; après la première lecture du résultat, le PID est libéré | Pour les VMs : lancer la commande en arrière-plan avec sortie dans un fichier de la VM, puis relire ce fichier par décalage toutes les 1 à 2 s (quasi direct), code de sortie écrit dans un second fichier |
| VM 503 OS | Debian 11 (bullseye), index apt vieux de 15 mois, 100 paquets dont 99 de sécurité ; dépôt Docker `buster` sur bullseye | Afficher l'âge de l'index et l'OS ; la fin de support des OS fait partie des propositions |
| Mode sécurité strict | 98 sur 99 en VM : un correctif de sécurité ne passe pas seul (cause exacte à identifier, probablement une dépendance hors dépôt sécurité) | Le mode strict laisse ce paquet de côté : PatchWarden l'indiquera (« 1 correctif de sécurité nécessite « Tout mettre à jour » ») |

### Docker dans la VM 503 (premier aperçu)

| Origine | Conteneurs | Mise à jour envisagée |
| :--- | :--- | :--- |
| Stack Portainer (`/data/compose/<id>`, soit `/var/lib/docker/volumes/portainer_data/_data/compose/<id>` sur la VM) | dozzle, upsnap, ersatztv, lms, mealie, watchtower, portainer_agent | API Portainer : re-déploiement de la stack avec re-pull (l'id de stack = le numéro du dossier) |
| Compose classique | beszel, beszel-agent (`/home/s7evin/beszel`) | `docker compose pull && up -d` dans le dossier du projet |
| `docker run` | portainer | Détection seulement ; pas de recréation automatique |

Constats :
- **Tags épinglés** (`mealie:v1.8.0`, `upsnap:5`, `lms:stable`) : la comparaison de digest dit seulement si
  *ce tag* a été reconstruit. Il faut une seconde information, « nouvelle version disponible »
  (liste des tags du registre ou release GitHub), sans jamais changer le tag automatiquement.
- **Label `org.opencontainers.image.source` peu fiable** : ersatztv pointe vers `ErsatzTV-ffmpeg`
  (label hérité de l'image de base). Ordre retenu pour le lien changelog : correspondance connue
  `ghcr.io/<owner>/<repo>` → GitHub, puis label OCI, puis page Docker Hub.
- Watchtower actif (stack 30) : à arrêter avant le jalon Docker.

## Test H5 : vrai `update` sur le CT 103 (13/11/2026, avec snapshot)

Commande : `pct exec 103 -- env PHS_SILENT=1 TERM=dumb update </dev/null`

| Point | Résultat | Conséquence |
| :--- | :--- | :--- |
| Sans interaction | ✅ aucune question, 43 s | `PHS_SILENT=1` + entrée standard fermée pour les scripts sans `read` brut |
| Code de sortie | ✅ `0`, les 75 paquets sont appliqués (`dist-upgrade -s` : 0 ensuite), pas de redémarrage requis | Code fiable pour le statut de la tâche, à confirmer sur un échec (Termix sera le cas d'école) |
| Sortie standard | Bannières ASCII et lignes `✔️ …` seulement ; aucun détail apt | La sortie seule ne suffit pas au journal en direct |
| Erreurs `curl` (28 : DNS > 5 s ; 22 : 404) | Viennent du téléchargement de la **bannière ASCII** (`core.func`, plusieurs emplacements essayés), sans effet sur la mise à jour | À classer en avertissements. La lenteur DNS du CT 103 est à surveiller |
| Entrée `update` | ✅ l'ancien format est remplacé par le nouveau (`SCRIPT_SLUG`, `UPDATE_SCRIPT_NAME`, `misc/update.sh`) | Les prochaines exécutions passeront par `community-scripts.org/api/update-info` |
| `_CS_RUN_LOG` | ❌ ignoré : `ui/build-ui.func` définit `BUILD_LOG=/tmp/create-lxc-<session>.log`, prioritaire, même pendant une mise à jour | ✅ Le journal `/tmp/create-lxc-<session>.log` contient tout le détail (sortie apt, lignes `[OK]`/`[INFO]` horodatées) et reste après la fin. PatchWarden repère le nouveau fichier créé après le lancement, le suit jusqu'à la fin du processus, l'archive dans son historique puis le supprime de l'invité. Les `\r` (barres de progression d'apt) sont traités à l'affichage |

## Première installation réelle (14/11/2026, PatchWarden dans le CT 103 sur LOKI)

| Constat | Correction |
| :--- | :--- |
| `config.example.toml` activait `[ssh.nodes]` : `check-config` exigeait la clé SSH dès l'étape 4 | Section commentée jusqu'à l'étape 6 ; messages qui expliquent quoi faire |
| Le client SSH Go demandait d'abord la clé d'hôte ECDSA ; `known_hosts` ne contenait que l'ed25519 → « clé différente » à tort | Les algorithmes demandés sont ceux des clés connues pour l'hôte (test avec un serveur à trois clés) |
| TYR : `sshd_config` force `HostKey /etc/ssh/ssh_host_rsa_key`, seule la clé RSA est proposée | Clé RSA enregistrée ; PatchWarden la gère. Changer `sshd_config` reste une décision du propriétaire |
| TYR : `/cluster/resources` renvoie ses invités en `unknown`, sans nom (le nœud ne publie plus leur état, pvestatd probable) | Relecture de `/nodes/<nœud>/lxc` et `/qemu` pour les invités incomplets ; état « inconnu » expliqué ; détection refusée avec la cause |
| Détection réelle : Dev à jour (75 paquets appliqués au test H5) ; Termix 120 paquets dont 65 de sécurité (65 en mode strict), guacd 1.6.0 à jour, termix `release-2.6.1-tag` → `v26.11.1`, question nginx et 4 CPU / 4 Go exigés repérés ; API GitHub joignable depuis le LAN | — |

## Jalon 3 : mises à jour d'un LXC

| Sujet | Décision |
| :--- | :--- |
| Commande apt | `apt-get --with-new-pkgs upgrade` (comme `apt upgrade`) : installe les nouvelles dépendances, ne supprime jamais rien. Les paquets qui n'avancent qu'avec un `dist-upgrade` sont signalés, pas appliqués. La détection simule exactement cette commande |
| Sécurité uniquement | Même commande avec une liste de sources restreinte aux dépôts `*-security`, après un `apt-get update` **complet** (un `update` sur la liste restreinte effacerait les index des autres dépôts) |
| Fichiers de configuration | `--force-confdef --force-confold` : la version locale est gardée, comme le fait le moteur community-scripts |
| `update` community-scripts | Lancé seulement si une version plus récente est publiée (ou si la version est inconnue) ; jamais pour les scripts « OS seul ». `PHS_SILENT=1`, réponses enregistrées sur l'entrée standard ; journal `/tmp/create-lxc-*.log` suivi en direct puis supprimé |
| Questions sans terminal | Réponse obligatoire, choisie une fois par invité (oui / non / Entrée), avant toute mise à jour de l'appli |
| Ressources (code 113) | Augmentation puis restauration faites par le wrapper (piège sur EXIT/HUP/TERM/PIPE), pas par PatchWarden en deux appels |
| Robustesse | Mises à jour réelles détachées sur le nœud (`setsid`, verrou `flock` par CT, journal `/var/log/patchwarden/`, 30 jours) : une coupure SSH ne tue pas `dpkg` |
| Confirmation | Page de plan obligatoire ; « Simuler » sans confirmation ; « Appliquer » avec case à cocher, plus le nom saisi pour les invités critiques ; détection de moins de 24 h exigée |
| Invité hôte | Aucune mise à jour sur l'invité qui héberge PatchWarden (`policy.self_guest`, ou même nom d'hôte) |
| Vérification | Détection relancée en fin de mise à jour, dans la même tâche |
| Snapshots | Reportés au jalon suivant (comme prévu) ; l'interface le rappelle sur la page de confirmation |

## Feuille de route (validée le 14/11/2026, propositions 1 à 11 retenues, 12 écartée)

| Jalon | Contenu |
| :--- | :--- |
| 4 ✅ | Détection planifiée (1), notifications (2), vue sécurité (3) |
| 5 | Snapshots avant mise à jour (exigence initiale), retour arrière en un clic (5) |
| 6 | Lots, regroupement par tags (6), redémarrages requis (8) |
| 7 | VMs via le guest agent, OMV et PBS, fin de support des OS (7) |
| 8 | Docker via l'API Portainer |
| 9 | Vérification après mise à jour (4), fenêtres de maintenance (9), sécurité automatique (10, après les snapshots), métriques Prometheus (11) |

Écartée pour l'instant : comptes multiples / OIDC (12).

## Jalon 4 : planification, notifications, vue sécurité

| Sujet | Décision |
| :--- | :--- |
| Planification | Heures locales fixes (`detect_at`), pas de syntaxe cron. Détection seule, jamais d'action automatique |
| Rapport | Une détection planifiée produit au plus trois messages (sécurité, applis, échecs), seulement s'il y a du nouveau ; les détections manuelles ne notifient pas |
| Nouveauté | Date de première apparition par paquet (nom + version) et par version d'appli, conservée d'une détection à l'autre ; c'est la date de détection par PatchWarden, pas la date de publication |
| Fin de tâche | Mise à jour réelle réussie (`succes`, désactivé par défaut) ou échouée/interrompue (`echec`) ; jamais pour une simulation |
| Cibles | ntfy (publication JSON, UTF-8 sûr), Gotify, webhook générique ; l'e-mail viendra si besoin |
| Envoi | Asynchrone, échecs journalisés, jamais bloquants |

## Questions encore ouvertes

7. Types de stockage par nœud ; disques en passthrough sur OMV (la sonde le montre).
8. LXC PatchWarden : IP, accès Internet, jeton GitHub en lecture seule.
12. Versions de PVE et des OS d'invités ; `pve-ups` et Dev inclus ; langue de l'interface.
