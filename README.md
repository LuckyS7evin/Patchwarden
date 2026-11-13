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
| 2 | Wrapper SSH sur les nœuds, tâches asynchrones, journaux en direct, historique | à faire |
| 3 | Prototype de bout en bout sur un LXC : détection apt + appli, simulation, « Tout mettre à jour » | à faire |
| 4 et + | « Sécurité uniquement », lots, VMs, Docker, snapshots | à faire |

Les décisions et les résultats de la sonde sont dans [docs/DECISIONS.md](docs/DECISIONS.md).

**Ce que fait la version actuelle :** elle lit l'inventaire (LXC et VM de tous les nœuds,
état, tags) et repère les LXC community-scripts et les invités à confirmation renforcée
(tag `critique`, OMV, PBS). **Elle ne peut encore rien modifier** : le jeton utilisé est en
lecture seule et aucun accès SSH n'est configuré.

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

### Mettre à jour PatchWarden

Remplacez `/usr/local/bin/patchwarden`, puis `systemctl restart patchwarden`. Les sessions
sont gardées en mémoire : il faudra se reconnecter.

## Droits nécessaires (moindre privilège)

| Accès | Utilisé pour | Droits | Depuis |
| :--- | :--- | :--- | :--- |
| Jeton API `patchwarden@pve!inventaire` | Inventaire | `PVEAuditor` sur `/` (lecture seule) | Jalon 1 |
| Clé SSH vers root des nœuds, **commande forcée** | `pct exec`, `qm guest exec`, snapshots | Une seule commande possible (le wrapper), depuis la seule IP de PatchWarden, sans terminal ni redirection | Jalon 2 (pas encore) |

## Sécurité

- Secrets hors du dépôt : `config.toml` et `patchwarden.env` sont exclus de Git. Les jetons
  peuvent être lus dans des variables d'environnement (`token_secret_env`).
- TLS obligatoire et vérifié vers Proxmox : empreinte épinglée ou autorité fournie.
- Un seul compte, mot de passe haché en bcrypt, comparaison en temps constant.
  Blocage de 15 minutes après 5 échecs pour une même IP.
- Cookie de session `HttpOnly` et `SameSite=Strict`, jeton CSRF et contrôle de l'origine
  sur chaque formulaire, en-têtes CSP stricts, aucun JavaScript pour l'instant.
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
| `internal/web` | Interface : sessions, CSRF, pages, gabarits embarqués |
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
