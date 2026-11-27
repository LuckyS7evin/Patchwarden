# Migration VLAN : changer les adresses IP

Aide-mémoire pour un changement d'adresses des nœuds Proxmox, de PatchWarden (CT 103) ou
des invités. Rien n'est écrit en dur dans le code : tout est dans les fichiers ci-dessous.
Le wrapper des nœuds ne contient aucune adresse et n'est pas à réinstaller.

## Avant

- Notez les anciennes et les nouvelles adresses : TYR, ODIN, LOKI, CT 103 (PatchWarden),
  Portainer, cibles de notification, Prometheus.
- Aucune mise à jour ne doit tourner : page « Tâches », rien en cours ; aucun lot programmé
  pendant la migration (annulez-le depuis sa page, ou reprogrammez-le).

## 1. La clé SSH des nœuds : adresse de PatchWarden

C'est le point le plus facile à oublier. La clé de PatchWarden n'est acceptée **que depuis
son adresse** : `from="<IP de PatchWarden>"` dans `/root/.ssh/authorized_keys` des nœuds
(en cluster, `/etc/pve/priv/authorized_keys`, partagé par les trois nœuds).

Si l'adresse du CT 103 change, sur un nœud, en root :

```bash
nano /etc/pve/priv/authorized_keys
# ligne patchwarden : from="ANCIENNE_IP" → from="NOUVELLE_IP"
```

Sans cela, `check-config` affiche les nœuds en ✘ (refus d'authentification), et toute
détection échoue.

## 2. La configuration de PatchWarden (`/etc/patchwarden/config.toml`)

| Clé | À changer si… |
| :--- | :--- |
| `[[proxmox]] url` | l'adresse du nœud interrogé change. `fingerprint` ne change pas (il dépend du certificat, pas de l'adresse) |
| `[ssh.nodes]` | l'adresse d'un nœud change |
| `server.listen` | rarement : `0.0.0.0:8094` écoute sur toutes les adresses |
| `server.public_url` | l'adresse de PatchWarden change (liens des notifications) |
| `[[portainer]] url` | l'adresse d'une instance Portainer change. `fingerprint` ne change pas |
| `[[notify]] url` | l'adresse d'un serveur ntfy, Gotify ou du webhook change |

Les invités sont rattachés à leur environnement Portainer par leurs conteneurs, et
l'inventaire vient de l'API Proxmox : un changement d'adresse d'un invité ne demande rien ici.

## 3. Les clés d'hôte des nœuds (`/etc/patchwarden/known_hosts`)

Elles sont enregistrées par adresse. Si l'adresse d'un nœud change, dans le CT 103 :

```bash
ssh-keyscan -t ed25519 NOUVELLE_IP_LOKI NOUVELLE_IP_TYR NOUVELLE_IP_ODIN > /etc/patchwarden/known_hosts
ssh-keygen -lf /etc/patchwarden/known_hosts        # empreintes reçues…
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub   # …identiques à celles d'avant, sur chaque nœud
chmod 640 /etc/patchwarden/known_hosts && chgrp patchwarden /etc/patchwarden/known_hosts
```

Les empreintes doivent être **les mêmes qu'avant** : seule l'adresse change. Une empreinte
différente signale autre chose qu'une migration : ne continuez pas sans comprendre pourquoi.

## 4. Les adresses de vérification des invités

Les adresses HTTP vérifiées après une opération (fiche d'un invité, « Vérification après une
opération ») sont dans `/var/lib/patchwarden/verifications.json`. Corrigez-les depuis la fiche
de chaque invité concerné (le plus simple), ou dans le fichier, PatchWarden arrêté.

## 5. À l'extérieur de PatchWarden

- Prometheus : la cible `targets: ["IP:8094"]` du `scrape_configs`.
- Pare-feu (Proxmox, routeur) : PatchWarden doit joindre les nœuds en SSH (22) et en API
  (8006), Portainer (9443), les registres Docker et GitHub en HTTPS.
- Le webhook ou ntfy, s'ils filtrent l'adresse de l'expéditeur.

## 6. Vérifier

```bash
systemctl restart patchwarden
patchwarden check-config
```

Attendu : chaque point d'accès Proxmox, chaque nœud SSH (`pw.wrapper_version=…`) et chaque
instance Portainer en ✔. Puis, dans l'interface : « Détecter » sur un invité, et
`patchwarden notify-test` si les adresses de notification ont changé.
