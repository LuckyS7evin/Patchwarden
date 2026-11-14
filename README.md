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
| 3 | Mises à jour d'un LXC : simulation, « Sécurité uniquement », « Tout mettre à jour », confirmation | à faire |
| 4 et + | « Sécurité uniquement », lots, VMs, Docker, snapshots | à faire |

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

**Elle n'installe encore rien.** La détection lance seulement `apt-get update` dans les
invités, pour rafraîchir l'index des paquets (désactivable : `detection.apt_refresh`). Les
VM, Docker et les actions de mise à jour arrivent dans les jalons suivants.

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
set -a; . /etc/patchwarden/patchwarden.env; set +a
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

### Mettre à jour PatchWarden

Remplacez `/usr/local/bin/patchwarden`, puis `systemctl restart patchwarden`. Les sessions
sont gardées en mémoire : il faudra se reconnecter. Une tâche en cours au moment du
redémarrage est marquée « interrompue » dans l'historique. Si une nouvelle version change
le wrapper, réinstallez-le sur les nœuds : `check-config` affiche la version installée.

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

| Verbe (wrapper v1) | Effet dans l'invité |
| :--- | :--- |
| `ping` | Aucun (version du wrapper, nom du nœud) |
| `lxc-detect <vmid> <0\|1>` | Lecture : OS, disque, `/usr/bin/update`, simulation apt (`apt-get -s`), Docker. Avec `1` : `apt-get update` (rafraîchit l'index, n'installe rien) |
| `lxc-versions <vmid> <app>…` | Lecture des fichiers `/root/.<app>` (versions community-scripts) |

Les verbes de mise à jour (`apt`, `update` community-scripts, snapshots) viendront au jalon 3,
avec la même règle : un verbe par action, rien d'arbitraire.

## Sécurité

- Secrets hors du dépôt : `config.toml` et `patchwarden.env` sont exclus de Git. Les jetons
  peuvent être lus dans des variables d'environnement (`token_secret_env`).
- TLS obligatoire et vérifié vers Proxmox : empreinte épinglée ou autorité fournie.
- Un seul compte, mot de passe haché en bcrypt, comparaison en temps constant.
  Blocage de 15 minutes après 5 échecs pour une même IP.
- Cookie de session `HttpOnly` et `SameSite=Strict`, jeton CSRF et contrôle de l'origine
  sur chaque formulaire, en-têtes CSP stricts. Le seul JavaScript (`tache.js`, servi par
  PatchWarden) affiche le journal en direct.
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
| `internal/engine` | Assemble le tout : construit le travail de chaque tâche |
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
