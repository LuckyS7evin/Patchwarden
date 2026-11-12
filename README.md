# PatchWarden

Interface web auto-hébergée pour surveiller **et** lancer les mises à jour d'un homelab
Proxmox VE (LXC, VM, conteneurs Docker), y compris la commande `update` des LXC
[community-scripts](https://community-scripts.org/).

> **État : jalon 0, vérification des hypothèses.** Aucune application n'est encore
> écrite. Les décisions prises sont dans [docs/DECISIONS.md](docs/DECISIONS.md).

## Jalon 0 : la sonde

[`tools/sonde.sh`](tools/sonde.sh) collecte, sur un nœud, tout ce qu'il faut savoir
avant d'écrire le code : comment l'appli community-scripts est identifiée, où est sa
version, ce que donnent apt et Docker, si les snapshots sont possibles, si la sortie
arrive en direct.

Elle est en **lecture seule**. Seules exceptions, toujours dans les invités :
fichiers temporaires dans `/tmp`, `apt-get update` avec `--refresh-apt`, une boucle
`echo` de quelques secondes avec `--test-stream`.

### Copier la sonde sur le nœud

Le dépôt est privé, donc pas de `curl` direct. Depuis ton PC :

```bash
git fetch origin && git checkout ccr-4d98ed35-yxvq1t
scp tools/sonde.sh root@<IP du nœud>:/root/
```

Autre solution : ouvre le fichier sur GitHub, clique sur *Raw*, copie le texte, puis
colle-le dans `nano /root/sonde.sh` sur le nœud.

### Lancer la sonde

En root, sur le nœud qui héberge les invités à analyser :

```bash
bash /root/sonde.sh --ct <CTID Dev> --ct <CTID d'un LXC appli> --vm <VMID Docker> --refresh-apt --test-stream
```

| Option | Effet |
| :--- | :--- |
| `--ct ID` / `--vm ID` | Analyse cet invité (option répétable) |
| `--all` | Tous les invités démarrés du nœud |
| `--refresh-apt` | `apt-get update` avant la simulation, pour un résultat à jour |
| `--test-stream` | Mesure si `pct exec` et `qm guest exec` diffusent la sortie en direct |

Le rapport est aussi enregistré dans `./patchwarden-sonde-<nœud>-<date>.txt`.
**Relis-le avant de le partager.** Il ne contient ni variables d'environnement Docker
ni descriptions d'invités, mais il montre les IP, les noms et les chemins.
