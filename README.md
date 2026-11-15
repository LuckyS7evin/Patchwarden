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
| 5 | Snapshots avant mise à jour, retour arrière en un clic | à faire |
| 6 | Lots, regroupement par tags, redémarrages requis | à faire |
| 7 | VMs (guest agent), OMV/PBS, fin de support des OS | à faire |
| 8 | Docker (API Portainer) | à faire |
| 9 | Vérification après mise à jour, fenêtres de maintenance, sécurité automatique, métriques Prometheus | à faire |

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
- **vue Sécurité** : correctifs de sécurité en attente par invité, les plus anciens d'abord,
  et LXC sans détection récente ;
- **interface** : thème clair, sombre ou automatique (bouton « Thème » en haut à droite,
  mémorisé par le navigateur) ; icône de chaque appli ou OS ([selfh.st/icons](https://selfh.st/icons),
  CC BY 4.0, mises en cache par PatchWarden, réglage `[ui]`) ; une migration par étapes
  (le script demande de relancer `update`) est signalée dans le résumé de la tâche.

Pas encore de snapshot automatique avant mise à jour (prochain jalon) : gardez vos
sauvegardes PBS à jour pour les invités sensibles.

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

### Mettre à jour PatchWarden

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
| Jeton API `patchwarden@pve!inventaire` | Inventaire | `PVEAuditor` sur `/` (lecture seule) | Jalon 1 |
| Clé SSH vers root des nœuds, **commande forcée** | Verbes du wrapper | Une seule commande possible (le wrapper), depuis la seule IP de PatchWarden, `restrict` : ni terminal, ni redirection de ports, ni agent | Jalon 2 |
| Jeton GitHub (facultatif) | Dernières versions des applis | Aucun droit : lecture des dépôts publics | Jalon 2 |

Le wrapper n'accepte qu'un vocabulaire fixe ; tout le reste est refusé (code 2) et journalisé.
Il ne vise que des CT **présents sur ce nœud et démarrés**, jamais l'hôte. PatchWarden
n'envoie que des verbes et des numéros : le code exécuté dans les invités est contenu dans
le wrapper, relisible sur le nœud.

| Verbe (wrapper v4) | Effet |
| :--- | :--- |
| `ping` | Aucun (version du wrapper, nom du nœud) |
| `lxc-detect <vmid> <0\|1>` | Lecture : OS, disque, `/usr/bin/update`, simulation apt (`apt-get -s`), Docker. Avec `1` : `apt-get update` (rafraîchit l'index, n'installe rien) |
| `lxc-versions <vmid> <app>…` | Lecture des fichiers `/root/.<app>` (versions community-scripts) |
| `lxc-apt <vmid> <security\|full> <0\|1>` | `apt-get update` puis `apt-get --with-new-pkgs upgrade` (dépôts `*-security` seuls en mode `security`). `1` = simulation (`apt-get -s`), rien n'est modifié |
| `lxc-cs-update <vmid> <réponses> <cpu> <ram>` | Commande `update` community-scripts sans terminal (`PHS_SILENT=1`), réponses aux questions sur l'entrée standard. Si le CT a moins que `cpu`/`ram` (exigés par le script) : `pct set` temporaire, attente que le CT voie les nouvelles valeurs (les CPU sont appliqués par `pvestatd`, jusqu'à 10 s), puis restauration des valeurs d'origine |

Les mises à jour réelles tournent **détachées sur le nœud**, sous un verrou par CT : si la
connexion SSH est perdue (redémarrage de PatchWarden, réseau), l'opération se termine quand
même, ressources restaurées comprises. Leur journal complet reste 30 jours sur le nœud dans
`/var/log/patchwarden/`. Le wrapper écrit donc sur l'hôte uniquement ce journal et un fichier
de verrou dans `/run/lock`, et lance `pct set` sur le CT visé (ressources) ; rien d'autre.

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
