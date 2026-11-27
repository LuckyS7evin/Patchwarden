# Hôte autonome (VPS) : installation

Un hôte autonome est une machine hors Proxmox (un VPS chez un hébergeur, par exemple) que
PatchWarden joint **directement par SSH**. Il apparaît dans l'inventaire, dans le groupe
« Hôtes autonomes », avec la même détection que les invités : paquets apt, correctifs de
sécurité, services à redémarrer, fin de support de l'OS et conteneurs Docker s'il y en a.

Systèmes pris en charge : Debian et Ubuntu (apt), avec systemd.

## Ce qui change par rapport à un invité Proxmox

| | Invité Proxmox | Hôte autonome |
| :--- | :--- | :--- |
| Connexion | root du nœud, `pct exec` ou agent QEMU | compte dédié `patchwarden` sur l'hôte, qui ne peut lancer que le wrapper (sudo, sans argument) |
| Snapshot avant mise à jour, retour arrière | oui | **non** : faites une sauvegarde, ou un snapshot chez l'hébergeur, avant une mise à jour importante |
| Confirmation | simple (renforcée pour les invités critiques) | **renforcée** à chaque fois : nom de l'hôte à saisir |
| Lots, sécurité automatique | oui | non : uniquement depuis la fiche de l'hôte |
| Démarrer / arrêter | oui (invités arrêtés) | non |
| Redémarrage | `pct reboot` / `qm reboot` | `systemctl reboot` programmé 5 s plus tard ; PatchWarden attend le retour de l'hôte (10 minutes au plus) |

Le wrapper refuse de lui-même les verbes `host-*` sur un nœud Proxmox. `check-config` et
l'inventaire signalent aussi un nœud Proxmox déclaré par erreur en `[[host]]`.

## Prérequis

- L'IP publique de la box (celle que voit le VPS). Elle sert à limiter la clé (`from=`) :
  depuis le CT 103, `curl -s https://ifconfig.me`.
- Un accès administrateur au VPS (votre compte habituel, avec sudo).
- Le port SSH du VPS (2222 dans les exemples).

## 1. Sur le VPS, en root

### Copier le wrapper sur le VPS

Le CT 103 n'a pas votre clé personnelle du VPS (et ne doit pas l'avoir) : le fichier passe
par **votre PC**, celui qui se connecte déjà au VPS.

1. Récupérer le wrapper sur le PC, au choix :
   - GitHub (connecté) : `deploy/patchwarden-wrapper` sur la branche `main` → bouton
     « Download raw file » ;
   - ou depuis le CT 103, si le PC s'y connecte en SSH :
     `scp root@192.168.0.19:/root/Patchwarden/deploy/patchwarden-wrapper .`
2. L'envoyer sur le VPS avec votre clé, depuis le dossier où il se trouve (Linux, macOS, ou
   PowerShell sous Windows) :

   ```bash
   scp -P 2222 -i ~/.ssh/<votre_clé_vps> patchwarden-wrapper <vous>@<vps>:/tmp/
   ```

   (Sous Windows, `~` fonctionne aussi dans PowerShell ; sinon `$env:USERPROFILE\.ssh\…`.)
3. Vérifier que le fichier est intact : la même empreinte dans le CT 103 et sur le VPS.

   ```bash
   sha256sum /root/Patchwarden/deploy/patchwarden-wrapper    # CT 103
   sha256sum /tmp/patchwarden-wrapper                         # VPS
   ```

   Une empreinte différente vient en général d'un fichier ouvert puis enregistré sous
   Windows (fins de ligne changées) : retéléchargez-le sans l'ouvrir.

Sans `scp` possible depuis le PC : sur le VPS, `cat > /tmp/patchwarden-wrapper`, coller tout
le contenu du fichier, puis Entrée et Ctrl+D ; vérifiez ensuite l'empreinte (étape 3).

### Installer, sur le VPS (`sudo -i`)

Ouvrez d'abord un **shell root** (`sudo -i`) et restez-y jusqu'à la fin de la partie 2. Avec
`sudo cat > fichier`, c'est votre compte, pas root, qui écrit le fichier : « Permission denied ».

```bash
apt install sudo                                      # souvent déjà présent

# Le wrapper
install -m 755 -o root -g root /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper

# Compte dédié : pas de mot de passe utilisable, aucun droit en dehors du wrapper
useradd --system --create-home --home-dir /home/patchwarden --shell /bin/sh patchwarden
usermod -p '*' patchwarden

# sudo : le wrapper seul, en root, SANS argument (« "" »), et la commande SSH demandée
# transmise (SSH_ORIGINAL_COMMAND, le reste de l'environnement est effacé par sudo)
cat > /etc/sudoers.d/patchwarden <<'EOF'
Defaults!/usr/local/sbin/patchwarden-wrapper env_keep += "SSH_ORIGINAL_COMMAND"
patchwarden ALL=(root) NOPASSWD: /usr/local/sbin/patchwarden-wrapper ""
EOF
chmod 440 /etc/sudoers.d/patchwarden
visudo -cf /etc/sudoers.d/patchwarden                 # doit répondre « parsed OK »
```

Si `/etc/ssh/sshd_config` limite les comptes autorisés (`AllowUsers` ou `AllowGroups`),
ajoutez-y `patchwarden`, puis `systemctl reload ssh`.

## 2. La clé

La clé de PatchWarden est celle des nœuds (`/etc/patchwarden/id_ed25519`). Afficher sa
partie publique, dans le CT 103 :

```bash
ssh-keygen -y -f /etc/patchwarden/id_ed25519      # pas de fichier .pub : recalculée depuis la clé privée
```

Copiez cette ligne (copier-coller dans le terminal suffit, il n'y a pas de fichier à
transférer). Sur le VPS, en root, avec votre IP publique dans `from=` et la clé affichée :

```bash
install -d -m 700 -o patchwarden -g patchwarden /home/patchwarden/.ssh
cat > /home/patchwarden/.ssh/authorized_keys <<'EOF'
command="sudo -n /usr/local/sbin/patchwarden-wrapper",from="<IP publique>",restrict ssh-ed25519 AAAA… patchwarden
EOF
chown patchwarden:patchwarden /home/patchwarden/.ssh/authorized_keys
chmod 600 /home/patchwarden/.ssh/authorized_keys
```

`command=` impose le wrapper quelle que soit la commande demandée ; `from=` refuse toute
connexion venant d'ailleurs que votre box ; `restrict` interdit terminal, redirections et agent.

## 3. Dans le CT 103

Clé d'hôte du VPS, toujours vérifiée. **Ajouter** (`>>`) au fichier existant, sans écraser
les nœuds :

```bash
ssh-keyscan -p 2222 -t ed25519 <vps> 2>/dev/null | grep -v '^#' >> /etc/patchwarden/known_hosts
ssh-keygen -lf /etc/patchwarden/known_hosts | grep 2222   # empreinte reçue…
# …identique à celle affichée sur le VPS par : ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Une empreinte différente : ne continuez pas (quelqu'un s'intercale, ou ce n'est pas le bon
serveur).

Dans `/etc/patchwarden/config.toml` :

```toml
[[host]]
name = "vps"
address = "<vps>:2222"      # nom DNS ou IP, et le port SSH
tags = ["cloud"]            # facultatif
```

Puis :

```bash
systemctl restart patchwarden
patchwarden check-config
#   ✔ vps : pw.wrapper_version=14 pw.node=<nom du VPS> pw.pve= pw.boot_id=…
```

`pw.pve=` doit rester vide : sinon, c'est un nœud Proxmox.

Contrôle manuel du verrouillage, depuis le CT 103 :

```bash
ssh -i /etc/patchwarden/id_ed25519 -p 2222 patchwarden@<vps> ping      # répond
ssh -i /etc/patchwarden/id_ed25519 -p 2222 patchwarden@<vps> 'ls /'    # PW-REFUS, code 2
ssh -i /etc/patchwarden/id_ed25519 -p 2222 patchwarden@<vps> 'host-start 0'   # PW-REFUS
```

Sur le VPS, chaque appel est journalisé : `journalctl -t patchwarden` (et `sudo` dans
`/var/log/auth.log`).

## 4. Dans l'interface

« Inventaire » → groupe « Hôtes autonomes » → **Détecter**. Les mises à jour se lancent depuis
la fiche de l'hôte, comme pour un invité, avec le nom à saisir pour confirmer et sans case
snapshot. La simulation reste disponible.

## Mettre à jour le wrapper sur le VPS

À refaire à chaque nouvelle version du wrapper (`check-config` le signale), en plus des nœuds :

1. Copier le nouveau fichier sur le VPS en passant par le PC (partie 1, « Copier le wrapper
   sur le VPS »), et vérifier l'empreinte.
2. Sur le VPS, en root :

   ```bash
   install -m 755 -o root -g root /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper
   ```

3. Dans le CT 103 : `patchwarden check-config` (version attendue sur `vps`).

## En cas de problème

| Symptôme | Piste |
| :--- | :--- |
| `check-config` : `unable to authenticate` | Ligne `authorized_keys` (clé, `from=`), droits du dossier `.ssh` (700) et du fichier (600), `AllowUsers` ; sur le VPS : `journalctl -u ssh -n 20` |
| `from=` refusé alors que la clé est bonne | L'IP publique a changé : corrigez `from=` |
| `sudo: a password is required` | Ligne sudoers absente ou mal écrite (`visudo -cf /etc/sudoers.d/patchwarden`), ou chemin du wrapper différent |
| `PW-REFUS: commande vide` | `env_keep` absent de sudoers : la commande demandée n'arrive pas au wrapper |
| `sudo: sorry, you must have a tty` | `Defaults requiretty` dans sudoers : ajoutez `Defaults!/usr/local/sbin/patchwarden-wrapper !requiretty` |
| Inventaire : « hôte vps : … » en erreur, hôte en état inconnu | Le VPS ne répond pas en SSH (réseau, pare-feu de l'hébergeur, fail2ban) |
| Redémarrage : « l'hôte n'a pas répondu après un nouveau démarrage » | Ouvrez la console de l'hébergeur : PatchWarden ne peut rien faire d'autre |
