# Mettre à jour PatchWarden

Aide-mémoire pour l'installation du homelab : PatchWarden dans le **CT 103** sur **LOKI**,
nœuds LOKI (192.168.0.141), TYR (192.168.0.43) et ODIN (192.168.0.49). Adaptez les adresses
après la migration VLAN.

Ordre : PatchWarden d'abord, puis le wrapper (seulement si le commit le demande, voir
plus bas), puis la vérification.

## 1. PatchWarden, dans le CT 103 (root)

```bash
cd /root/Patchwarden
git pull --ff-only
make build
install -m 755 bin/patchwarden /usr/local/bin/patchwarden
systemctl restart patchwarden
systemctl status patchwarden --no-pager
```

- `git log --oneline -1` montre la version installée.
- Si `git pull` demande quelle branche suivre :
  `git pull --ff-only origin <branche>`.
- Le redémarrage déconnecte l'interface : reconnectez-vous. Une mise à jour d'invité en
  cours se termine quand même sur le nœud (journal dans `/var/log/patchwarden/`).

## 2. Le wrapper, sur LOKI (root)

À faire quand `deploy/patchwarden-wrapper` a changé, c'est-à-dire quand `check-config`
signale un wrapper trop ancien (étape 3), ou quand le commit l'annonce (« wrapper vN »).
Dans le doute, le refaire ne coûte rien.

```bash
pct pull 103 /root/Patchwarden/deploy/patchwarden-wrapper /tmp/patchwarden-wrapper
install -m 755 /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper
for n in 192.168.0.43 192.168.0.49; do            # TYR, ODIN
  scp /tmp/patchwarden-wrapper root@$n:/tmp/ &&
  ssh root@$n install -m 755 /tmp/patchwarden-wrapper /usr/local/sbin/patchwarden-wrapper
done
# La même empreinte doit s'afficher sur les trois nœuds
for n in 192.168.0.141 192.168.0.43 192.168.0.49; do ssh root@$n sha256sum /usr/local/sbin/patchwarden-wrapper; done
```

## 3. Vérifier, dans le CT 103

```bash
patchwarden check-config
```

Attendu :

- chaque point d'accès Proxmox en ✔ ;
- les trois nœuds en ✔ avec `pw.wrapper_version=` égal à la version attendue (sinon :
  refaire l'étape 2) ;
- chaque instance `[[portainer]]` en ✔, si vous en avez déclaré.

Dans le navigateur, rechargez avec **Ctrl+Maj+R** pour charger le nouveau CSS et le
nouveau JavaScript (sur téléphone : vider le cache du site, ou fermer et rouvrir l'onglet).

## Vérifier le code avant de fusionner (facultatif)

La CI GitHub ne se lance plus qu'à la main (quota épuisé sur le dépôt privé). Les mêmes
vérifications tournent dans le CT 103, sur la branche à fusionner :

```bash
cd /root/Patchwarden
make ci          # gofmt, go vet, tests, shellcheck, compilation
```

`apt install gcc shellcheck` pour la version complète (tests avec `-race`, shellcheck) ; sans
eux, ces deux étapes sont allégées ou sautées et la commande le dit.

## Changer de branche

Le CT 103 met à jour la branche sur laquelle le dépôt est placé. Pour en changer :

```bash
cd /root/Patchwarden
git fetch origin
git status -sb                 # 1re ligne : branche actuelle (ex. « ## main...origin/main »)
git switch main                # ou le nom d'une autre branche ; la crée en local si besoin
```

Puis l'étape 1 habituelle (`git pull --ff-only`, `make build`, …). Une branche qui ne contient
pas encore les dernières versions fait revenir en arrière : vérifiez avec `git log --oneline -3`.
Si `git switch` refuse à cause de modifications locales : `git stash`, puis recommencez.

## En cas de problème

| Symptôme | Piste |
| :--- | :--- |
| `git pull` refuse (« not possible to fast-forward ») | Une modification locale existe dans `/root/Patchwarden` : `git status`, puis `git stash` ou `git checkout -- <fichier>` |
| `patchwarden: command not found` alors que `/usr/local/bin/patchwarden` existe | Le `PATH` du shell ne contient plus `/usr/local/bin` (`echo $PATH`). Tout de suite : `export PATH=/usr/local/sbin:/usr/local/bin:$PATH`. Pour de bon : retrouver la ligne qui écrase le `PATH` (`grep -n PATH ~/.bashrc ~/.profile ~/.bash_profile`) et y garder `/usr/local/bin`. Le service n'est pas touché : il lance le chemin complet |
| Disque du CT 103 qui se remplit | Le cache de compilation de Go grossit à chaque `make build` : `go clean -cache` le vide sans risque |
| `make build` : `go: command not found` | Go absent du PATH (installé depuis l'archive officielle) : `export PATH=$PATH:/usr/local/go/bin` |
| Le service ne redémarre pas | `journalctl -u patchwarden -n 50` : une clé inconnue ou invalide dans `config.toml` est nommée dans le message |
| `check-config` : wrapper trop ancien | Étape 2 non faite, ou faite sur un seul nœud : comparer les `sha256sum` |
| `check-config` : un nœud en ✘ | `ssh -i /etc/patchwarden/id_ed25519 root@<IP> ping` depuis le CT 103 ; sur le nœud, `journalctl -t patchwarden` |
| Les tâches échouent avec « verbe inconnu » | Wrapper pas à jour sur le nœud de cet invité : étape 2 |
