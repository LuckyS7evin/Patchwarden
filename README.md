# PatchWarden

Interface web auto-hébergée pour surveiller **et** lancer les mises à jour d'un homelab
Proxmox VE (LXC, VM, conteneurs Docker), y compris la commande `update` des LXC
[community-scripts](https://community-scripts.org/). Un seul binaire Go, environ 10 Mo
de mémoire, sans agent dans les invités.

## État

| Jalon | Contenu | État |
| :--- | :--- | :--- |
| 0 | Sonde de vérification des hypothèses (`tools/sonde.sh`) | ✅ |
| 1 | Configuration, authentification, inventaire de tous les nœuds via l'API (lecture seule) | ✅ |
| 2 | Wrapper SSH sur les nœuds, tâches asynchrones, journaux en direct, historique, **détection** (apt, appli community-scripts, dernière version, changelog) | ✅ |
| 3 | Mises à jour d'un LXC : simulation, « Sécurité uniquement », « Tout mettre à jour » (apt + `update` community-scripts), confirmation | ✅ |
| 4 | Détection planifiée, notifications (ntfy, Gotify, webhook), vue sécurité | ✅ |
| 5 | Snapshots avant mise à jour, retour arrière en un clic | ✅ |
| 6 | Lots, regroupement par tags, redémarrages requis | ✅ |
| 7 | VMs (guest agent), OMV/PBS, fin de support des OS | ✅ |
| 8 | Docker : stacks Portainer (API), projets docker compose, comparaison aux registres | ✅ (à recetter) |
| 9 | Vérification après mise à jour, fenêtres de maintenance, sécurité automatique (désactivée par défaut), métriques Prometheus | ✅ (à recetter) |
| 10 | Invités arrêtés (démarrer, mettre à jour, arrêter), nettoyage des images Docker, images Docker dans les notifications, procédure de migration VLAN | ✅ (à recetter) |

Les décisions et les résultats de la sonde sont dans [docs/DECISIONS.md](docs/DECISIONS.md).

**Ce que fait la version actuelle :**

- inventaire de tous les nœuds (LXC et VM, état, tags), avec repérage des LXC
  community-scripts et des invités à confirmation renforcée (tag `critique`, OMV, PBS) ;
- **détection** dans les LXC démarrés, par invité ou en lot : mises à jour apt (sécurité,
  autres, ce qu'installerait « Sécurité uniquement »), appli community-scripts (version
  installée, dernière version publiée, lien vers le changelog et la page du script),
  questions que le script poserait sans terminal, CPU/RAM exigés, disque, redémarrage requis ;
- tâches en arrière-plan (une seule à la fois par invité), journal complet en direct,
  historique conservé.

- **mises à jour d'un LXC**, depuis la page de l'invité, toujours après une page de
  confirmation qui détaille le plan :
  - « Sécurité uniquement » : `apt-get --with-new-pkgs upgrade` limité aux dépôts `*-security` ;
  - « Tout mettre à jour » : apt complet, puis la commande `update` community-scripts si une
    version plus récente de l'appli est publiée ;
  - « Simuler » (`apt-get -s`) ou « Appliquer » (case à cocher ; nom de l'invité à saisir
    pour les invités critiques) ; une détection est relancée à la fin pour vérifier ;
  - jamais de suppression de paquet ; en cas de conflit de configuration, vos fichiers sont gardés ;
  - questions posées par certains scripts sans terminal (Termix : « Update Nginx
    configuration? ») : la réponse est choisie une fois par invité ;
  - CPU/RAM exigés par le script : augmentés temporairement par le wrapper puis restaurés,
    même en cas d'échec ;
  - aucune action sur l'invité qui héberge PatchWarden (`policy.self_guest`).

- **détection planifiée** (`[schedule] detect_at`) : chaque jour aux heures choisies, tous les
  LXC démarrés sont détectés (lecture seule) ; rien n'est jamais mis à jour automatiquement ;
- **notifications** (ntfy, Gotify, webhook) : un seul message par détection planifiée pour les
  nouveaux correctifs de sécurité, un pour les nouvelles versions d'applis, un pour les
  échecs ; fin de chaque mise à jour réelle (réussite ou échec). `patchwarden notify-test`
  vérifie les cibles ;
- **interface** :
  - **À traiter** (accueil) : ce qui attend une action, du plus urgent au moins urgent
    (correctifs de sécurité les plus anciens d'abord, versions majeures, applis, autres
    paquets, entretien : redémarrages, snapshots à supprimer, détections absentes ou
    anciennes), avec sélection multiple et **simulation par lot** ; activité récente ;
  - **Inventaire** : chiffres clés, filtres rapides, tableau par nœud ; un clic sur une ligne
    ouvre l'**aperçu** de l'invité dans un tiroir ;
  - **fiche de l'invité** : versions installée → disponible en frise, onglets Aperçu,
    Paquets, Snapshots, Questions du script, Historique ;
  - **tâche en direct** : étapes (snapshot, apt, appli, vérification) qui avancent avec le
    journal, terminal à côté, lien de retour au snapshot ;
  - **lots** : les éléments cochés dans « À traiter », ou tous les invités d'un tag (inventaire
    groupé par tag), forment un lot à confirmer : opération par invité, snapshot par invité,
    « arrêter au premier échec » ; simulation du lot ou application ; les opérations
    s'enchaînent une par une, suivies sur la page du lot ; une seule notification par lot.
    Les invités à confirmation renforcée (OMV, PBS, tag `critique`) restent un par un ;
  - **VM** (jalon 7) : détection, mises à jour, snapshots, retour arrière et redémarrages
    par l'agent invité QEMU (`qemu-guest-agent` installé et démarré dans la VM, option
    « QEMU Guest Agent » activée dans Proxmox) ; message clair si l'agent ne répond pas ;
  - **produits particuliers**, reconnus dans l'invité : **OpenMediaVault** (« Tout mettre à
    jour » par `omv-upgrade`), **Proxmox Backup Server** (`apt-get dist-upgrade`, méthode
    recommandée par Proxmox) : nom à saisir, jamais en lot, refus si un paquet serait
    supprimé ; un **hôte Proxmox VE** (même dans une VM) n'est jamais mis à jour ni redémarré ;
  - **fin de support des OS** (Debian, Ubuntu, Alpine) : badge dans l'inventaire, ligne
    « Support » sur la fiche, alerte dans « À traiter » ; dates d'endoflife.date, rafraîchies
    une fois par jour (table intégrée sans accès Internet, réglage `[eol]`) ;
  - **redémarrages** : la détection repère les processus qui utilisent encore une
    bibliothèque remplacée par une mise à jour (correctif inactif tant qu'ils tournent) ;
    « Redémarrer les services » (services système exclus) ou « Redémarrer le CT », depuis
    la fiche ou en lot ;
  - **Docker** (jalon 8) : la détection liste les conteneurs de chaque LXC ou VM et compare
    chaque image au registre (Docker Hub, ghcr.io, lscr.io, quay.io…, sans compte) :
    « nouvelle image » quand le tag utilisé a été republié, et, pour un tag de version
    (`v1.8.0`, `5`, `3.12-alpine`), la version plus récente publiée sous un autre tag, **jamais
    appliquée** (lien changelog : dépôt GitHub de l'image, sinon page du registre). Mise à
    jour par groupe, après confirmation, simulation et snapshot possibles :
    - **stacks Portainer** : re-déploiement par l'API Portainer avec téléchargement des
      images, même fichier, mêmes variables, sans suppression (section `[[portainer]]`) ;
    - **projets docker compose** classiques : `docker compose pull` puis `up -d` des seuls
      services démarrés, par le wrapper (dossier lu dans l'invité, jamais transmis) ;
    - conteneurs lancés par `docker run`, Portainer lui-même et son agent : détection
      seulement (à mettre à jour à la main) ; Watchtower démarré : signalé ;
    onglet Docker sur la fiche, groupe Docker dans « À traiter », opération Docker dans les lots ;
  - **Snapshots** (tous les snapshots PatchWarden), **Réglages** (configuration en lecture
    seule, sans secret) ;
  - menu latéral avec l'état des nœuds (CPU, RAM, stockage des invités le plus rempli) ;
  - thème clair, sombre ou automatique (sélecteur en haut, mémorisé par le navigateur) ;
    icône de chaque appli ou OS ([selfh.st/icons](https://selfh.st/icons), CC BY 4.0, mises
    en cache par PatchWarden, réglage `[ui]`) ; utilisable sans JavaScript (le tiroir, la
    sélection et le suivi en direct en ont besoin).

- **snapshots avant mise à jour** (LXC) :
  - case « Prendre un snapshot avant la mise à jour » sur la page de confirmation ; décochée
    par défaut, pré-cochée pour les invités critiques, les changements de version majeure,
    ou partout avec `[snapshots] default = true` ; réglage propre à chaque invité
    (automatique, toujours, jamais d'office) sur sa page ;
  - nom explicite (`pw-20261115-0141-complet`) et description en clair (action, versions,
    utilisateur) ; si le snapshot échoue, **la mise à jour est annulée** ;
  - refusé avec un message clair si le stockage ne permet pas les snapshots (stockage
    `dir`, NFS…) ou s'il est rempli à 90 % ou plus (`max_storage_pct`) ; la simulation le vérifie aussi ;
  - rétention : PatchWarden ne garde que le dernier de ses snapshots par invité (`keep`) ;
    les snapshots créés à la main ne sont jamais touchés ;
  - **retour arrière** depuis la page de l'invité (nom de l'invité à saisir) : le CT est
    arrêté, restauré, redémarré s'il tournait, puis une détection vérifie le résultat ;
    suppression d'un snapshot PatchWarden en un clic (avec confirmation).

## Installation

Cible : un LXC Debian 13 non privilégié, 1 vCPU, 256 Mo de RAM, 2 Go de disque, dans le
réseau d'administration (il doit joindre le port 8006 des nœuds).

### 1. Compiler le binaire

Sur n'importe quelle machine avec Go ≥ 1.24 (Debian 13 : `apt install golang-go make git`) :

```bash
git clone https://github.com/LuckyS7evin/Patchwarden.git && cd Patchwarden
make build            # produit bin/patchwarden, binaire statique
```

Puis copiez `bin/patchwarden`, `config.example.toml` et le dossier `deploy/` dans le LXC.

### 2. Installer dans le LXC

```bash
useradd --system --home-dir /var/lib/patchwarden --shell /usr/sbin/nologin patchwarden
install -m 755 bin/patchwarden /usr/local/bin/patchwarden
install -d -m 750 -o root -g patchwarden /etc/patchwarden
install -m 640 -o root -g patchwarden config.example.toml /etc/patchwarden/config.toml
install -m 640 -o root -g patchwarden deploy/patchwarden.env.example /etc/patchwarden/patchwarden.env
install -m 644 deploy/patchwarden.service /etc/systemd/system/patchwarden.service
```

Le service lit sa configuration mais ne peut pas la modifier (propriétaire root).

### 3. Créer le jeton Proxmox en lecture seule

Sur **un** nœud. En cluster, le jeton vaut pour tous les nœuds. Avec des nœuds autonomes,
répétez l'opération sur chaque nœud et déclarez une section `[[proxmox]]` par nœud.

```bash
pveum user add patchwarden@pve --comment "PatchWarden - lecture seule"
pveum acl modify / --users patchwarden@pve --roles PVEAuditor
pveum user token add patchwarden@pve inventaire --privsep 1 --comment "Inventaire PatchWarden"
pveum acl modify / --tokens 'patchwarden@pve!inventaire' --roles PVEAuditor
```

- `PVEAuditor` ne donne que la lecture (configuration et état des invités, des nœuds et
  des stockages). Aucune action n'est possible avec ce jeton.
- Avec `--privsep 1`, les droits du jeton sont l'intersection de ses ACL et de celles de
  l'utilisateur : c'est pourquoi les deux reçoivent `PVEAuditor`. L'utilisateur
  `patchwarden@pve` n'a pas de mot de passe et ne peut pas se connecter à l'interface Proxmox.
- Le secret du jeton n'est affiché **qu'une fois** : copiez-le dans `/etc/patchwarden/patchwarden.env`.

Empreinte du certificat de chaque nœud déclaré, sur ce nœud :

```bash
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```

Si vous avez installé votre propre certificat (ACME…), prenez `/etc/pve/local/pveproxy-ssl.pem`.
L'empreinte est aussi visible dans l'interface Proxmox : *Nœud > Système > Certificats*.
PatchWarden refuse toute connexion TLS non vérifiée. L'épinglage d'empreinte ne dépend ni
du nom d'hôte ni de l'IP : seule `url` change lors d'un passage en VLAN. En revanche, si le
certificat est régénéré (`pvecm updatecerts`, renouvellement ACME), mettez l'empreinte à jour.

### 4. Configurer

```bash
patchwarden hash-password        # mot de passe de l'interface (12 caractères minimum)
nano /etc/patchwarden/config.toml   # username, password_hash, [[proxmox]] url / fingerprint
nano /etc/patchwarden/patchwarden.env
patchwarden check-config         # valide le fichier et interroge chaque point d'accès
                                 # (laissez [ssh.nodes] commenté jusqu'à l'étape 6)
```

Exemple de sortie attendue :

```
Configuration valide : /etc/patchwarden/config.toml
  ✔ loki : 24 invités sur 3 nœud(s) map[loki:13 odin:3 tyr:8]
```

En cluster, déclarer deux nœuds (par exemple LOKI et TYR) permet de garder l'inventaire
quand l'un est éteint. Les doublons sont fusionnés.

### 5. Démarrer

```bash
systemctl daemon-reload
systemctl enable --now patchwarden
journalctl -u patchwarden -f
```

L'interface répond sur `http://<IP du LXC>:8080`. Pour la servir en HTTPS, placez-la
derrière votre proxy interne (NginxUI) et mettez `cookie_secure = true`.

### 6. Ouvrir l'accès aux nœuds (détection)

Sans cette étape, PatchWarden reste en lecture seule. La clé SSH dédiée ne peut lancer
**qu'une seule commande** sur les nœuds, le wrapper [`deploy/patchwarden-wrapper`](deploy/patchwarden-wrapper),
et seulement depuis l'IP de PatchWarden.

**Sur chaque nœud** (LOKI, TYR, ODIN), en root : copier le wrapper depuis le dépôt, puis
l'installer. Le plus simple est de passer par le nœud qui héberge le LXC PatchWarden : `pct pull`
récupère le fichier dans le conteneur sans réseau, puis le cluster le recopie sur les autres
nœuds (root s'y connecte déjà par clé). Exemple avec PatchWarden dans le CT 103 sur LOKI :

```bash
# Sur LOKI
pct pull 103 /root/Patchwarden/deploy/patchwarden-wrapper /tmp/patchwarden-wrapper
install -m 755 /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper
for n in 192.168.0.43 192.168.0.49; do            # TYR, ODIN
  scp /tmp/patchwarden-wrapper root@$n:/tmp/ &&
  ssh root@$n install -m 755 /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper
done
# Vérification : la même empreinte sur les trois nœuds
for n in 192.168.0.141 192.168.0.43 192.168.0.49; do ssh root@$n sha256sum /usr/local/sbin/patchwarden-wrapper; done
```

Hors cluster, copiez le fichier sur chaque nœud (`scp`, ou copier-coller depuis GitHub en *Raw*).

**Dans le LXC PatchWarden** :

```bash
patchwarden ssh-keygen -key /etc/patchwarden/id_ed25519 -from <IP du LXC PatchWarden>
chown patchwarden:patchwarden /etc/patchwarden/id_ed25519
```

La commande affiche la ligne à ajouter, telle quelle, dans `/root/.ssh/authorized_keys`
des nœuds :

```
command="/usr/local/sbin/patchwarden-wrapper",from="192.168.0.20",restrict ssh-ed25519 AAAA… patchwarden
```

En cluster, `/root/.ssh/authorized_keys` est en général un lien vers
`/etc/pve/priv/authorized_keys`, partagé par tous les nœuds (`ls -l /root/.ssh/authorized_keys`
pour le vérifier). Il suffit alors d'ajouter la ligne une fois. Sinon, ajoutez-la sur chaque nœud.

Clés d'hôte des nœuds, toujours vérifiées (`apt install openssh-client` dans le LXC) :

```bash
ssh-keyscan -t ed25519 192.168.0.141 192.168.0.43 192.168.0.49 > /etc/patchwarden/known_hosts
ssh-keygen -lf /etc/patchwarden/known_hosts          # empreintes reçues…
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub     # …à comparer, sur chaque nœud
chmod 640 /etc/patchwarden/known_hosts && chgrp patchwarden /etc/patchwarden/known_hosts
```

Chaque nœud doit apparaître dans la sortie de `ssh-keygen -lf /etc/patchwarden/known_hosts`
(les lignes commençant par `#` ne sont que des commentaires). Un nœud absent n'a
probablement pas de clé ed25519 : enregistrez le type qu'il possède
(`ls /etc/ssh/ssh_host_*_key.pub` sur le nœud), par exemple
`ssh-keyscan -t ecdsa <IP> 2>/dev/null | grep -v '^#' >> /etc/patchwarden/known_hosts`.
PatchWarden négocie le type de clé enregistré.

Décommentez ensuite la section `[ssh.nodes]` de `config.toml` (adresses des nœuds), puis vérifiez :

```bash
patchwarden check-config
#   Nœuds SSH (wrapper) :
#     ✔ loki : pw.wrapper_version=1 pw.node=loki pw.pve=pve-manager/8.4.21/…
```

Contrôle manuel du verrouillage, depuis le LXC PatchWarden :

```bash
ssh -i /etc/patchwarden/id_ed25519 root@192.168.0.141 ping      # répond
ssh -i /etc/patchwarden/id_ed25519 root@192.168.0.141 'ls /'    # PW-REFUS, code 2
```

Chaque appel au wrapper est journalisé sur le nœud : `journalctl -t patchwarden`.

### 7. Détection planifiée et notifications (facultatif)

Dans `config.toml` :

```toml
[server]
public_url = "http://192.168.0.19:8094"   # pour les liens des notifications

[schedule]
detect_at = ["03:40"]                     # heures locales, plusieurs possibles

[[notify]]
type = "ntfy"                             # ntfy, gotify ou webhook
url = "https://ntfy.sh/mon-sujet-secret"  # ntfy : serveur + sujet
# token_env = "PATCHWARDEN_NTFY_TOKEN"    # si le sujet est protégé
events = ["securite", "applis", "echec"]  # + "succes" pour chaque mise à jour réussie
```

Gotify : `type = "gotify"`, `url` = adresse du serveur, `token_env` = jeton d'application.
Webhook : `POST` JSON `{event, title, message, priority, url, time, source}` (n8n, par exemple).
Puis `patchwarden notify-test` et `systemctl restart patchwarden`. La prochaine détection
automatique est affichée en haut de l'inventaire.

La première détection planifiée signale tous les correctifs déjà en attente (ils sont
nouveaux pour PatchWarden) ; les suivantes ne signalent que ce qui est apparu depuis.

### 8. Docker et Portainer (facultatif)

La comparaison aux registres est active par défaut (`[docker] registry_check`) : PatchWarden
doit pouvoir joindre `registry-1.docker.io`, `auth.docker.io`, `ghcr.io`, `quay.io`… en HTTPS.
Les stacks Portainer ne sont mises à jour que si leur instance est déclarée :

1. Dans Portainer : créez un utilisateur `patchwarden` (Paramètres → Utilisateurs), donnez-lui
   accès aux environnements concernés et la propriété des stacks à mettre à jour (ou faites-en
   un administrateur : Portainer CE n'a pas de rôle plus fin), puis, connecté avec lui,
   **Mon compte → Jetons d'accès → Ajouter**. Une instance Portainer par section.
2. Dans `patchwarden.env` : `PATCHWARDEN_PORTAINER_DOCKER=ptr_…`
3. Dans `config.toml` :

```toml
[[portainer]]
name = "docker"                          # nom libre, affiché dans l'interface
url = "https://192.168.0.50:9443"        # sans /api
token_env = "PATCHWARDEN_PORTAINER_DOCKER"
fingerprint = "AA:BB:…"                  # certificat auto-signé de Portainer (ou ca_file)
```

L'empreinte s'obtient avec `openssl s_client -connect 192.168.0.50:9443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`.
`patchwarden check-config` teste chaque instance (environnements, stacks visibles). Chaque
invité est rattaché tout seul à son environnement Portainer (conteneurs en commun) : rien à
déclarer par invité, rien à changer après un changement d'adresse IP des invités.

**Arrêtez Watchtower** s'il tourne : il met les images à jour de son côté, et PatchWarden
verrait alors tout « à jour ».

### 9. Vérification, fenêtres de maintenance, sécurité automatique, métriques (facultatif)

**Vérification après une opération** : active d'office. Après chaque mise à jour (apt, Docker)
ou redémarrage réel, PatchWarden compare l'invité à son état d'avant : services systemd
nouvellement en échec, conteneurs qui tournaient et ne tournent plus, conteneurs devenus
« unhealthy ». Un problème passager est revérifié deux fois à 30 s d'intervalle ; s'il reste,
la tâche échoue (un lot s'arrête) et le retour arrière au snapshot est proposé, jamais lancé
seul. Sur la fiche d'un invité, « Vérification après une opération » : une adresse HTTP
facultative qui doit répondre ensuite (statut < 400, 2 minutes d'essais).

**Fenêtres de maintenance** :

```toml
[[maintenance]]
name = "nuit"
days = ["dim"]          # lun, mar, mer, jeu, ven, sam, dim ; vide : tous les jours
start = "03:00"
duration = "2h"
tags = []               # invités concernés (avertissement hors fenêtre) ; vide : tous
```

Une action lancée hors de la fenêtre d'un invité affiche un avertissement, sans être bloquée.
Sur la page d'un lot, « Programmer le lot » : à l'ouverture de la fenêtre, PatchWarden détecte
les invités, revérifie le plan, puis enchaîne les opérations ; celles qui n'ont pas commencé à
la fermeture sont annulées. Un lot programmé reste annulable (page du lot) jusqu'à son lancement.

**Sécurité automatique** (désactivée par défaut) : à l'ouverture de sa fenêtre, « Sécurité
uniquement » sur les invités qui portent le tag choisi, après une détection, avec snapshot
(un invité dont le snapshot est impossible est ignoré), vérification et arrêt au premier
échec. Jamais les applis, les versions majeures, Docker, ni les invités critiques, OMV, PBS
ou celui de PatchWarden. Une seule exécution par ouverture de fenêtre ; son compte rendu est
toujours notifié, quel que soit le filtre `events`.

```toml
[auto_security]
enabled = true
tag = "auto-securite"   # à poser dans Proxmox sur les invités concernés
window = "nuit"         # une section [[maintenance]]
snapshot = true
```

**Métriques Prometheus** : `PATCHWARDEN_METRICS_TOKEN=…` dans `patchwarden.env`
(`openssl rand -hex 24`), puis :

```toml
[metrics]
token_env = "PATCHWARDEN_METRICS_TOKEN"
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: patchwarden
    scrape_interval: 5m
    authorization:
      credentials: "<le jeton>"
    static_configs:
      - targets: ["192.168.0.19:8094"]
```

Par invité : correctifs de sécurité, paquets apt, applis, images Docker, redémarrage requis,
services en échec, support de l'OS, âge de la détection, snapshots ; plus les tâches par type
et résultat. Tableau de bord Grafana d'exemple : [deploy/grafana-dashboard.json](deploy/grafana-dashboard.json)
(Dashboards → Importer).

### 10. Invités arrêtés, nettoyage Docker, migration VLAN

**Invité arrêté** : sa fiche propose « Démarrer, mettre à jour, arrêter ». PatchWarden le
démarre, le détecte, établit le plan sur cette détection, applique « Sécurité uniquement » ou
« Tout mettre à jour » (ou les simule), vérifie le résultat, puis l'arrête proprement, même en
cas d'échec (jamais d'arrêt forcé : si l'arrêt propre échoue, la tâche le dit et l'invité reste
démarré). Confirmation renforcée pour les invités critiques, OMV et PBS.

**Nettoyage Docker** : les mises à jour laissent les anciennes versions des images, sans nom.
L'onglet Docker les compte et propose « Lister » ou « Nettoyer » (`docker image prune -f` :
jamais une image qui a un nom, même inutilisée) ; « À traiter » le signale à partir de 3.

**Notifications** : la détection planifiée signale aussi les nouvelles images Docker, dans le
message « applis ».

**Migration VLAN** : voir [docs/MIGRATION-VLAN.md](docs/MIGRATION-VLAN.md).

**Sécurité** : modèle de menace, protections, risques acceptés et recommandations dans
[docs/SECURITE.md](docs/SECURITE.md).

### Mettre à jour PatchWarden

Aide-mémoire complet (PatchWarden, wrapper, vérification, problèmes courants) :
[docs/MISE-A-JOUR.md](docs/MISE-A-JOUR.md).

Dans le LXC où le dépôt est cloné et compilé :

```bash
cd /root/Patchwarden
git pull --ff-only
make build
install -m 755 bin/patchwarden /usr/local/bin/patchwarden
systemctl restart patchwarden
patchwarden check-config      # signale aussi un wrapper trop ancien sur les nœuds
```

En résumé : remplacez `/usr/local/bin/patchwarden`, puis `systemctl restart patchwarden`. Les sessions
sont gardées en mémoire : il faudra se reconnecter. Une tâche en cours au moment du
redémarrage est marquée « interrompue » dans l'historique (une mise à jour, elle, se termine
sur le nœud : voir son journal dans `/var/log/patchwarden/`).

Si une nouvelle version change le wrapper, réinstallez-le sur les nœuds (mêmes commandes
qu'à l'étape 6, depuis le nœud qui héberge PatchWarden). `check-config` signale un nœud dont
le wrapper est trop ancien.

## Droits nécessaires (moindre privilège)

| Accès | Utilisé pour | Droits | Depuis |
| :--- | :--- | :--- | :--- |
| Jeton API `patchwarden@pve!inventaire` | Inventaire, état des nœuds et des stockages (`/cluster/resources`) ; liste des snapshots d'un invité (`/nodes/<nœud>/<lxc\|qemu>/<id>/snapshot`), pour que les pages suivent un snapshot supprimé ou restauré hors de PatchWarden | `PVEAuditor` sur `/` (lecture seule) | Jalon 1 |
| Clé SSH vers root des nœuds, **commande forcée** | Verbes du wrapper | Une seule commande possible (le wrapper), depuis la seule IP de PatchWarden, `restrict` : ni terminal, ni redirection de ports, ni agent | Jalon 2 |
| Jeton GitHub (facultatif) | Dernières versions des applis | Aucun droit : lecture des dépôts publics | Jalon 2 |
| Registres d'images | Empreinte actuelle d'un tag, liste des tags | Aucun compte : jeton anonyme en lecture, dépôts publics seulement | Jalon 8 |
| Jeton d'accès Portainer (facultatif) | Liste des environnements, conteneurs et stacks ; re-déploiement d'une stack | Ceux de l'utilisateur Portainer du jeton : accès aux environnements concernés et aux stacks à mettre à jour. PatchWarden n'appelle que `GET /endpoints`, `GET /endpoints/{id}/docker/containers/json`, `GET /stacks`, `GET /stacks/{id}`, `GET /stacks/{id}/file`, `PUT /stacks/{id}` et `PUT /stacks/{id}/git/redeploy` | Jalon 8 |

Le wrapper n'accepte qu'un vocabulaire fixe ; tout le reste est refusé (code 2) et journalisé.
Il ne vise que des CT **présents sur ce nœud et démarrés**, jamais l'hôte. PatchWarden
n'envoie que des verbes et des numéros : le code exécuté dans les invités est contenu dans
le wrapper, relisible sur le nœud.

| Verbe (wrapper v13) | Effet |
| :--- | :--- |
| `ping` | Aucun (version du wrapper, nom du nœud) |
| `lxc-detect <vmid> <0\|1>` | Lecture : OS, disque, `/usr/bin/update`, simulation apt (`apt-get -s`), Docker. Avec `1` : `apt-get update` (rafraîchit l'index, n'installe rien) |
| `lxc-versions <vmid> <app>…` | Lecture des fichiers `/root/.<app>` (versions community-scripts) |
| `lxc-apt <vmid> <security\|full> <0\|1>` | `apt-get update` puis `apt-get --with-new-pkgs upgrade` (dépôts `*-security` seuls en mode `security`). `1` = simulation (`apt-get -s`), rien n'est modifié |
| `lxc-cs-update <vmid> <réponses> <cpu> <ram>` | Commande `update` community-scripts sans terminal (`PHS_SILENT=1`), réponses aux questions sur l'entrée standard. Si le CT a moins que `cpu`/`ram` (exigés par le script) : `pct set` temporaire, attente que le CT voie les nouvelles valeurs (les CPU sont appliqués par `pvestatd`, jusqu'à 10 s), puis restauration des valeurs d'origine |
| `lxc-snapshot <vmid> <nom> <garder> <seuil> <0\|1> <description>` | `pct snapshot` (nom `pw-AAAAMMJJ-HHMM-(complet\|securite\|docker)` exigé), après vérification du stockage (`pvesh …/feature`, `pvesm status`) ; puis `pct delsnapshot` des snapshots PatchWarden au-delà de `garder`. `1` = vérification seule |
| `lxc-snapdel <vmid> <nom>` | `pct delsnapshot` d'un snapshot PatchWarden (`pw-…`) uniquement |
| `lxc-rollback <vmid> <nom>` | `pct rollback` vers un snapshot PatchWarden (`pw-…`) uniquement, puis `pct start` si le CT tournait |
| `lxc-restart-services <vmid>` | Dans le CT : `systemctl restart` des services encore liés à une bibliothèque remplacée (liste établie dans le CT, jamais transmise par PatchWarden ; dbus, `systemd-*`, sessions et consoles exclus) |
| `lxc-reboot <vmid>` | `pct reboot` du CT, puis attente qu'il soit de nouveau démarré |
| `lxc-docker-compose <vmid> <projet> <0\|1>` | Dans l'invité : retrouve le dossier et les fichiers du projet compose dans les labels de ses conteneurs (rien n'est transmis par PatchWarden), refuse une stack Portainer, puis `docker compose pull` et `up -d --no-deps` des seuls services démarrés. `1` = simulation (`docker compose config`) |
| `lxc-start <vmid>` | `pct start` d'un CT arrêté (refus, code 54, s'il tourne déjà), puis attente qu'il soit démarré |
| `lxc-shutdown <vmid>` | `pct shutdown --timeout 180` : arrêt propre, jamais forcé ; en cas d'échec, le CT reste démarré (code 55) |
| `lxc-docker-prune <vmid> <0\|1>` | Dans l'invité : `docker image prune -f`, images sans nom seulement (anciennes versions), jamais une image avec un nom. `1` = liste seule |
| `vm-detect`, `vm-apt`, `vm-snapshot`, `vm-snapdel`, `vm-rollback`, `vm-restart-services`, `vm-reboot`, `vm-docker-compose`, `vm-start`, `vm-shutdown`, `vm-docker-prune` | Mêmes arguments et effets pour une VM : `qm guest exec` (agent invité, script sur l'entrée standard), `qm snapshot`/`delsnapshot`/`rollback`/`start`/`reboot`. Opérations longues lancées en arrière-plan dans la VM (dossier créé par `mktemp -d` dans `/var/tmp`, supprimé à la fin) et journal relu toutes les 2 s |
| Modes de `*-apt` | `security`, `full`, et pour les produits particuliers `dist` (PBS : `apt-get dist-upgrade`) et `omv` (OpenMediaVault : `omv-upgrade`) ; ces deux modes refusent toute mise à jour qui supprimerait un paquet (code 22) |

La détection lit aussi les services systemd en échec (`systemctl list-units --state=failed`)
et l'état de santé des conteneurs (healthcheck) : lecture seule, pour la vérification après
une opération.

La détection lit aussi la liste des conteneurs (`docker ps`, `docker inspect`, `docker image
inspect`, `docker compose version`) : lecture seule.

Le wrapper refuse de lui-même tout snapshot dont le nom n'est pas `pw-…` : même une instance
PatchWarden compromise ne pourrait ni supprimer ni restaurer vos snapshots manuels. Il lit
aussi, sans rien modifier, la possibilité de snapshot, le remplissage des stockages et la
liste des snapshots de chaque CT détecté (`pvesh get`, `pvesm status`).

Les mises à jour réelles tournent **détachées sur le nœud**, sous un verrou par CT : si la
connexion SSH est perdue (redémarrage de PatchWarden, réseau), l'opération se termine quand
même, ressources restaurées comprises. Leur journal complet reste 30 jours sur le nœud dans
`/var/log/patchwarden/`. Le wrapper écrit donc sur l'hôte uniquement ce journal et un fichier
de verrou dans `/run/lock`, et lance `pct set` (ressources), `pct snapshot`,
`pct delsnapshot`, `pct rollback`, `pct start`, `pct reboot` et `pct shutdown` sur le CT visé, ou leurs
équivalents `qm` pour une VM (plus `qm agent ping` et `qm guest exec`) ; rien d'autre.
La détection lit aussi, dans le CT, `/proc/*/maps` et `/proc/*/cgroup` pour repérer les
processus encore liés à une bibliothèque remplacée (lecture seule).

## Sécurité

- Secrets hors du dépôt : `config.toml` et `patchwarden.env` sont exclus de Git. Les jetons
  peuvent être lus dans des variables d'environnement (`token_secret_env`).
- TLS obligatoire et vérifié vers Proxmox : empreinte épinglée ou autorité fournie.
- Un seul compte, mot de passe haché en bcrypt, comparaison en temps constant.
  Blocage de 15 minutes après 5 échecs pour une même IP.
- Cookie de session `HttpOnly` et `SameSite=Strict`, jeton CSRF et contrôle de l'origine
  sur chaque formulaire, en-têtes CSP stricts. Le seul JavaScript, servi par PatchWarden,
  affiche le journal en direct (`tache.js`) et change de thème (`theme.js`).
- Les icônes sont téléchargées par le serveur depuis `ui.icon_base` (https uniquement),
  vérifiées (format WebP, 512 Ko maximum) et servies depuis le cache local : le navigateur
  ne contacte aucun site tiers.
- Clés d'hôte SSH toujours vérifiées ; une clé différente de celle enregistrée bloque la connexion.
- Les scripts community-scripts ne sont lus que depuis les sources autorisées
  (`community_scripts.allowed_bases`) : un invité compromis ne peut pas faire télécharger
  une URL de son choix à PatchWarden.
- Le fichier de configuration est refusé en cas de clé inconnue, et signalé s'il est lisible par tous.
- Service systemd durci : utilisateur dédié, système en lecture seule, mémoire plafonnée à 256 Mo.

## Développement

```bash
make test     # tests (avec détection de concurrence)
make check    # tests + go vet + gofmt + shellcheck de la sonde
make build
```

| Dossier | Rôle |
| :--- | :--- |
| `cmd/patchwarden` | Commandes `serve`, `check-config`, `hash-password`, `version` |
| `internal/config` | Lecture et validation de la configuration |
| `internal/proxmox` | Client API en lecture seule, épinglage TLS |
| `internal/inventory` | Fusion des points d'accès, classification, rafraîchissement en arrière-plan |
| `internal/sshx` | Exécution SSH vers le wrapper (known_hosts, flux ligne à ligne) |
| `internal/jobs` | Tâches : une par invité, limite globale, journal sur disque, diffusion en direct |
| `internal/detect` | Lecture de la sortie de détection, dernier résultat par invité |
| `internal/cs` | Analyse des scripts community-scripts (applis suivies, exigences, questions) |
| `internal/upstream` | Dernières versions sur GitHub, Codeberg, GitLab (avec cache) |
| `internal/engine` | Assemble le tout : détection, plans et mises à jour, rapport planifié, notifications de fin |
| `internal/notify` | Notifications ntfy, Gotify, webhook |
| `internal/schedule` | Déclenchement quotidien aux heures configurées |
| `internal/web` | Interface : sessions, CSRF, pages, journal en direct (SSE), gabarits embarqués |
| `deploy/patchwarden-wrapper` | Wrapper à installer sur les nœuds |
| `tools/sonde.sh` | Sonde de diagnostic à lancer sur un nœud (lecture seule) |

## La sonde (jalon 0)

[`tools/sonde.sh`](tools/sonde.sh) collecte sur un nœud ce qu'il faut savoir avant
d'agir : identification de l'appli community-scripts, version installée, apt, Docker,
capacité de snapshot, comportement de `pct exec` et du guest agent. Elle est en lecture
seule (exceptions, toujours dans les invités : fichiers temporaires dans `/tmp`,
`apt-get update` avec `--refresh-apt`, boucle `echo` avec `--test-stream`).

```bash
bash sonde.sh --ct <CTID> --vm <VMID> --refresh-apt --test-stream
```

Le rapport est écrit dans `./patchwarden-sonde-<nœud>-<date>.txt`. Relisez-le avant de le
partager : il montre les IP, les noms et les chemins.
