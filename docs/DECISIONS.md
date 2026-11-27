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

## Première mise à jour réelle (15/11/2026, « Sécurité uniquement » sur Termix)

65 paquets installés depuis `trixie-security` en 30 s, code 0 ; la détection de fin trouve
0 correctif de sécurité restant (55 paquets du dépôt principal en attente, attendu). nginx
a été redémarré par son paquet.

Constat : `apt-listchanges` est présent dans l'invité. Les scripts d'invité étant lus par
`sh -s` sur l'entrée standard, une commande qui lit l'entrée standard (question de
`apt-listchanges` ou de `dpkg`) consommerait la suite du script. Wrapper v3 : entrée
standard de toutes les commandes d'invité redirigée depuis `/dev/null`,
`APT_LISTCHANGES_FRONTEND=none`. Test de non-régression : le faux `pct` exécute le script
avec `bash -s` depuis un tuyau (lecture ligne par ligne) et le faux `apt-get` lit
l'entrée standard ; sans la correction, 7 tests échouent.

À prévoir (jalon 6, redémarrages) : des services encore liés aux anciennes bibliothèques
(libssl, par exemple) tant qu'ils ne sont pas redémarrés ; à repérer via les fichiers
`(deleted)` de `/proc/*/maps`.

## Premier « Tout mettre à jour » réel (15/11/2026, Termix)

- apt : 55 paquets, code 0.
- `update` community-scripts : ressources augmentées par le wrapper puis restaurées ;
  réponse enregistrée « oui » à « Update Nginx configuration? » (nginx.conf remplacé,
  ancien fichier sauvegardé par le script). Disque de 33 % à 43 %. Correction : ce n'est pas
  `/opt/termix.backup` (`create_backup` n'y copie que `/opt/termix/.env`, et
  `restore_backup` supprime le dossier à la fin, voir `core/lib/system.func`), mais la
  compilation (cache npm, `node_modules`, fichiers construits).
- Le script ne saute pas directement à la dernière version : il migre par étapes
  (`release-2.6.1-tag` → `release-2.9.2-tag`) et termine par « Run update again ».
  La détection de fin montre donc encore v26.11.1 disponible. Décision : PatchWarden ne
  relance pas tout seul (chaque étape doit pouvoir être vérifiée) ; le résumé de la tâche
  le signale (« le script demande de relancer update ») et il suffit de relancer
  « Tout mettre à jour ».
- Les délais DNS affichés par les en-têtes curl du script sont sans conséquence.
- Deuxième passage (vers v26.11.1) : refus du script, code 113, « Current: 2 CPU, 4096MB
  RAM » alors que le wrapper venait de porter le CT à 4 CPU. Cause (sources pve-container
  et pve-manager) : `pct set --cores` sur un CT démarré n'écrit que la configuration ;
  le cpuset est appliqué par `rebalance_lxc_containers` de `pvestatd`, toutes les 10 s.
  La mémoire, elle, est appliquée tout de suite. Le premier passage avait eu de la chance.
  Wrapper v4 : après `pct set`, attente (60 s au plus) que `nproc` et `/proc/meminfo` vus
  depuis le CT atteignent les valeurs demandées ; sinon, code 32, update non lancé,
  ressources restaurées. Test : le faux `pct` n'applique les CPU qu'après quelques lectures ;
  sans l'attente, le test reproduit le code 113.
- Troisième passage, wrapper v4 (15/11/2026) : CPU vus dans le CT après 4 s, update réussi
  en 2 min 30, Termix en v26.11.1, à jour. Disque à 37 %. Effet inverse constaté : la
  détection lancée 1 s après la restauration voit encore 4 CPU (même délai de pvestatd) ;
  sans conséquence, à traiter avec le jalon 5 (attendre aussi la restauration).

## Retours sur l'interface (15/11/2026)

| Retour | Décision |
| :--- | :--- |
| Boutons « Simuler » / « Appliquer » mal alignés, « Simuler » peu visible | Deux cadres de même hauteur, boutons pleine largeur alignés en bas ; « Simuler » en bouton secondaire coloré, « Appliquer » en rouge |
| Colonnes de l'inventaire non alignées entre nœuds | Largeurs de colonnes fixes (`table-layout: fixed`) identiques pour tous les tableaux ; tag community-scripts masqué (déjà en badge) |
| Icônes des applis et des OS | selfh.st/icons (CC BY 4.0) : nom du script, puis nom de l'invité, puis OS ; alias pour les noms qui diffèrent ; téléchargées et mises en cache par le serveur (CSP inchangée), absence mémorisée 7 jours, initiale en repli |
| Pas de bascule clair/sombre | Bouton « Thème : auto / clair / sombre », mémorisé dans le navigateur |
| Technologie de l'interface | Rendu serveur (Go `html/template`), CSS écrit à la main, deux petits fichiers JS, pas d’étape de compilation : choix de légèreté (un seul binaire, aucune dépendance côté navigateur). Refonte visuelle à discuter |

## Feuille de route (validée le 14/11/2026, propositions 1 à 11 retenues, 12 écartée)

| Jalon | Contenu |
| :--- | :--- |
| 4 ✅ | Détection planifiée (1), notifications (2), vue sécurité (3) |
| 5 ✅ | Snapshots avant mise à jour (exigence initiale), retour arrière en un clic (5) |
| 6 ✅ | Lots, regroupement par tags (6), redémarrages requis (8) |
| 7 ✅ | VMs via le guest agent, OMV et PBS, fin de support des OS (7) |
| 8 ✅ | Docker via l'API Portainer (à recetter) |
| 9 ✅ | Vérification après mise à jour (4), fenêtres de maintenance (9), sécurité automatique (10, désactivée par défaut), métriques Prometheus (11) (à recetter) |

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

## Jalon 5 : snapshots et retour arrière (validé le 15/11/2026)

| Sujet | Décision |
| :--- | :--- |
| Mécanisme | Par le wrapper (choix 1A) : le jeton API reste en lecture seule, aucun nouveau secret. Verbes `lxc-snapshot`, `lxc-snapdel`, `lxc-rollback`, limités par le wrapper lui-même aux noms `pw-AAAAMMJJ-HHMM-(complet\|securite)` |
| Nom, description | `pw-20261115-0141-complet` (40 caractères au plus, imposé par Proxmox) ; description en clair (action, date, utilisateur, paquets, versions), transmise en base64url car la commande SSH n'accepte que `[A-Za-z0-9._ -]` |
| Rétention | 1 snapshot PatchWarden par invité (`keep`), supprimés juste après la création du nouveau ; snapshots manuels jamais touchés |
| Seuil | Refus à 90 % de remplissage d'un stockage du CT (`max_storage_pct`), ou si le remplissage est inconnu |
| Case pré-cochée | Réglage de l'invité (toujours / jamais d'office), sinon réglage global, sinon invité critique ou changement de version majeure ; décochée sinon |
| Échec | Snapshot impossible ou en échec : mise à jour annulée avant toute modification. Échec après le snapshot : l'erreur rappelle le snapshot et le retour arrière possible |
| Possibilité | Lue à chaque détection (`pvesh get /nodes/<n>/lxc/<id>/feature --feature snapshot`, `pvesm status`), revérifiée par le wrapper juste avant le snapshot ; la simulation la vérifie aussi |
| Points de montage liés | Signalés : ils ne font pas partie du snapshot |
| Retour arrière | Nom de l'invité à saisir ; CT arrêté, `pct rollback`, `pct start` s'il tournait, détection ; refusé sur l'invité qui héberge PatchWarden ; possible sur un CT arrêté |
| Restauration des CPU | Le wrapper attend aussi que le CT revoie ses CPU d'origine (non bloquant), pour que la détection de fin soit juste |
| VMs | Jalon 7 (avec le guest agent) |

Premier essai réel (15/11/2026, Forgejo, CT 106, LVM-thin à 82 %) : snapshot en 1 s,
« Sécurité uniquement » (23 paquets), retour arrière en 1 min (dont 47 s de démarrage du CT),
détection de fin cohérente (les 23 correctifs reviennent). Seul défaut : description
illisible (« s��curit�� »). Cause : les commandes `pct` décodent leurs arguments selon la
locale (`PVE::JSONSchema`, `decode('locale', …)`) et le wrapper tourne en `LC_ALL=C`.
Wrapper v6 : `pct snapshot` lancé en `LC_ALL=C.UTF-8`. Le faux `pct` des tests reproduit ce
décodage. Avertissement LVM vu au passage : le pool thin `pve/data` est surréservé
(192 Gio de volumes pour un pool plus petit) ; s'il se remplit, tous les invités dessus
sont touchés.

## Refonte de l'interface (15/11/2026)

Trois maquettes proposées (console, tuiles, file d'actions) ; retenu : la file d'actions
comme accueil, l'inventaire et le tiroir d'aperçu de la console, la fiche de l'invité des
tuiles, en clair et en sombre avec sélecteur. Versions d'une appli : frise « installée →
disponible » (point gris, trait, point coloré ; violet pour une version majeure, orange
sinon) plutôt que des encadrés.

| Sujet | Décision |
| :--- | :--- |
| Technique | Inchangée : rendu serveur (`html/template`), CSS écrit à la main, trois petits scripts (thème, tiroir et sélection, suivi des tâches), aucune dépendance. CSP stricte conservée : jauges en SVG (attributs) au lieu de styles en ligne |
| Sans JavaScript | Tout reste utilisable : une ligne de l'inventaire mène à la fiche, la barre de sélection reste visible, le journal se recharge |
| Accueil « À traiter » | Groupes : Sécurité (plus anciens d'abord), Versions majeures, Applications, Autres paquets, Entretien (redémarrage, snapshot à supprimer, détection absente ou de plus de 48 h). Remplace la page Sécurité (`/securite` redirige) |
| Lots | Sélection multiple dès maintenant, mais **simulation seulement** ; un invité coché en « sécurité » et en « tout » n'est simulé qu'une fois, en « tout ». Lots réels au jalon 6 |
| État des nœuds | `/cluster/resources` lu en entier (invités, nœuds, stockages) : mêmes droits `PVEAuditor`. Stockage affiché : le non partagé accueillant des disques d'invités (`rootdir` ou `images`) le plus rempli. Nœud injoignable : dernières valeurs, grisées |
| Étapes d'une tâche | Déduites du journal par des marqueurs (`▶ lxc-apt`, `pw.apt_rc=`…), mêmes règles côté serveur et dans le navigateur |
| Retours du 16/11 | Sélecteur de thème et compte en bas du panneau de gauche (en haut sur mobile) ; frise des versions qui passe à la ligne (lien changelog toujours visible) ; stockage d'un nœud : celui qui porte les disques des LXC détectés, pas le plus rempli (TYR affichait le disque de données d'OMV à 99 %) |
| Réglages | Lecture seule ; secrets jamais affichés (jetons : « défini (masqué) » ou nom de la variable ; URL de notification réduite à l'hôte, le sujet ntfy valant secret) |

## Jalon 6 : lots, tags, redémarrages (16/11/2026)

| Sujet | Décision |
| :--- | :--- |
| Exécution d'un lot | Une opération à la fois, dans l'ordre affiché (moins de charge sur les nœuds, arrêt au premier échec possible). Lot persisté (`data_dir/lots`), suivi sur `/lots/<id>` ; un lot coupé par un redémarrage de PatchWarden est marqué interrompu, ses opérations restantes annulées |
| Confirmation | Une case pour tout le lot ; snapshot choisi invité par invité (pré-coché comme sur la page d'une mise à jour) ; simulation du lot sans confirmation (les redémarrages, sans simulation, y sont ignorés) |
| Exclusions | Invités à confirmation renforcée (nom à saisir) jamais en lot ; invité de PatchWarden exclu ; une mise à jour et des redémarrages par invité au plus (« tout » l'emporte sur « sécurité ») |
| Notifications | Un seul message par lot réel (réussites, échecs, annulations) ; ses tâches ne notifient pas une à une |
| Tags | Inventaire groupé par tag (un invité multi-tags apparaît dans chaque groupe ; le tag community-scripts est ignoré) avec « préparer un lot : sécurité / tout » ; filtre par tag dans « À traiter » |
| Anciennes bibliothèques | Détection : processus dont `/proc/<pid>/maps` contient une bibliothèque `.so … (deleted)`, rattachés à leur service par `/proc/<pid>/cgroup`. Sans dépendance (needrestart non requis) |
| Redémarrer les services | Liste refaite dans le CT au moment de l'action (PatchWarden n'envoie aucun nom) ; dbus, `systemd-*`, `user@`, consoles exclus : pour eux, redémarrage du CT conseillé |
| Redémarrer le CT | `pct reboot` (arrêt propre), attente du redémarrage, détection ; nom à saisir pour un invité critique |

## Jalon 7 : VM, OMV, PBS, fin de support (16/11/2026)

| Sujet | Décision |
| :--- | :--- |
| Wrapper | Un seul jeu de verbes, préfixe `lxc-` ou `vm-` ; fonctions communes (`g_sh`, `g_stream`, état, snapshots) qui appellent `pct` ou `qm`. Pas de `versions` ni `cs-update` pour une VM |
| Exécution dans une VM | `qm guest exec --pass-stdin` (jamais de gros argument, cf. sonde n° 2) ; sortie décodée deux fois (latin-1 puis UTF-8). Opérations longues : script déposé dans `/var/tmp`, lancé en arrière-plan (`setsid`), journal relu par décalage toutes les 2 s, code de sortie dans un fichier ; fichiers supprimés à la fin |
| Agent absent | Vérifié avant chaque opération (`qm agent ping`) : code 4 et message expliquant quoi installer et activer |
| Snapshots de VM | `qm snapshot` sans état de la RAM (l'agent fige les systèmes de fichiers) ; disques en passthrough : snapshot impossible, signalé |
| Produits particuliers | Reconnus par leurs paquets (`pve-manager`, `proxmox-backup-server`, `openmediavault`). PVE : jamais mis à jour ni redémarré. PBS : `apt-get dist-upgrade`. OMV : `omv-upgrade`. Les deux : nom à saisir, hors lots, refus si un paquet serait supprimé (vérifié par le plan et par le wrapper) |
| Fin de support | Table intégrée (Debian avec LTS, Ubuntu avec Ubuntu Pro, Alpine) rafraîchie en arrière-plan depuis endoflife.date ; une page n'attend jamais le réseau. Alerte 180 jours avant la fin du support standard ; « critique » quand plus aucun correctif n'est publié |

## Questions encore ouvertes

7. Types de stockage par nœud ; disques en passthrough sur OMV (la sonde le montre).
8. LXC PatchWarden : IP, accès Internet, jeton GitHub en lecture seule.
12. Versions de PVE et des OS d'invités ; `pve-ups` et Dev inclus ; langue de l'interface.

## Jalon 8 : Docker (16/11/2026)

| Sujet | Décision |
| :--- | :--- |
| Inventaire | Par la détection (wrapper v9) : `docker inspect` de chaque conteneur (image, empreintes, labels compose et OCI), dans le LXC ou la VM. Aucun agent |
| Comparaison | PatchWarden interroge lui-même les registres (API de distribution OCI, jeton anonyme, `HEAD` du manifeste : ne compte pas dans la limite de téléchargements de Docker Hub). Image à jour si l'empreinte publiée du tag figure dans les `RepoDigests` locaux. lscr.io est interrogé sur ghcr.io (miroir). Cache 6 h |
| Tags épinglés | Une version plus récente (même forme : préfixe, nombre de composants, suffixe) est **signalée, jamais appliquée** ; préversions ignorées |
| Lien changelog | ghcr.io → dépôt GitHub ; linuxserver → `docker-<nom>` ; label OCI `source` seulement si le dépôt porte le nom de l'image (ErsatzTV) ; sinon la page du registre |
| Groupes | Stack Portainer (dossier `/data/compose/<id>`), projet compose classique, `docker run`. Une mise à jour porte sur un groupe entier |
| Stacks Portainer | `PUT /api/stacks/{id}` avec le fichier et les variables relus dans Portainer, `pullImage: true`, `prune: false` ; stacks Git : `git/redeploy` sur la même référence. Instance et environnement trouvés par les conteneurs communs (aucun réglage par invité, insensible aux changements d'IP). Refus : stack arrêtée, autre type que compose, stack contenant Portainer ou son agent |
| Projets compose | Verbe `docker-compose` du wrapper : dossier et fichiers lus dans les labels **dans l'invité**, `pull` puis `up -d --no-deps` des services démarrés seulement (un service arrêté le reste) |
| `docker run` | Détection seulement : options de création inconnues |
| Snapshot | Celui de l'invité, nommé `pw-…-docker` (même règles, même rétention) |
| Images anciennes | Laissées sur le disque (pas de `docker image prune` automatique) |
| Watchtower | Signalé (« À traiter », fiche) : à arrêter |

## Jalon 9 : vérification, fenêtres, sécurité automatique, métriques (27/11/2026)

| Sujet | Décision |
| :--- | :--- |
| Vérification | Après chaque opération réelle (apt, Docker, redémarrages) : services systemd nouvellement en échec, conteneurs arrêtés ou devenus « unhealthy », par rapport à la détection d'avant ; deux nouveaux essais à 30 s si le problème peut être passager. Échec : tâche en échec (le lot s'arrête), retour arrière proposé, jamais automatique |
| Vérification HTTP | Adresse facultative par invité (fiche) ; statut < 400 en 2 minutes ; certificat non vérifié (homelab, auto-signé) |
| Fenêtres | Hebdomadaires (jours, début, durée), tags facultatifs. Hors fenêtre : avertissement, jamais de blocage |
| Lots programmés | Détection puis plan revérifié à l'ouverture ; opérations non commencées à la fermeture : annulées ; fenêtre manquée (PatchWarden arrêté) : lot annulé, jamais lancé en retard |
| Sécurité automatique | Désactivée par défaut ; le tag posé dans Proxmox vaut confirmation (exception assumée à « aucune action sans confirmation dans l'UI »). « Sécurité uniquement » seulement, snapshot exigé par défaut, arrêt au premier échec, une exécution par ouverture, compte rendu toujours notifié |
| Métriques | /metrics au format Prometheus, désactivé sans jeton, jeton Bearer comparé en temps constant ; jauges par invité et tâches par type |
