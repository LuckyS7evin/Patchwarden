# Revue de sécurité (27/11/2026)

Revue de l'ensemble du code après le jalon 10 : wrapper des nœuds, interface web, appels
sortants, traitement des données venant des invités, gestion des secrets. Elle a été faite
par relecture du code et par les tests automatiques ; aucun test d'intrusion n'a été mené
contre l'installation réelle.

## Modèle de menace

| Acteur | Ce qu'il ne doit pas pouvoir faire |
| :--- | :--- |
| Un appareil du réseau local, sans compte | Lire ou modifier quoi que ce soit, lancer une action |
| Un invité compromis (LXC, VM, conteneur) | Agir sur l'hôte Proxmox ou sur un autre invité ; faire exécuter du code à PatchWarden ; s'en servir pour joindre d'autres machines |
| Une instance PatchWarden compromise | Prendre la main sur les nœuds au-delà du vocabulaire du wrapper ; toucher aux snapshots manuels |
| Un site tiers ouvert dans le navigateur de l'administrateur | Déclencher une action à sa place (CSRF), lire les pages |

## Ce qui est en place

**Nœuds (wrapper, root)**
- La clé SSH est limitée par `command=` (le wrapper seul), `from=` (l'adresse de PatchWarden)
  et `restrict` (ni terminal, ni redirection, ni agent).
- Les commandes reçues sont filtrées sur leurs caractères (`[A-Za-z0-9._ -]`), puis sur un
  vocabulaire fixe ; chaque argument est validé : VMID, modes, noms de snapshot
  `pw-…-(complet|securite|docker)`, noms de projet compose, description en base64url.
- Le code exécuté dans les invités est contenu dans le wrapper : PatchWarden n'envoie que des
  verbes et des identifiants, jamais de code ni de chemin. Le dossier d'un projet compose est
  relu dans l'invité, jamais transmis.
- Seuls les invités présents sur ce nœud sont visés, jamais l'hôte. Une instance compromise ne
  peut ni supprimer ni restaurer un snapshot manuel.
- Les clés d'hôte des nœuds sont toujours vérifiées (`known_hosts`).

**Interface web**
- Un compte, mot de passe bcrypt, comparaison en temps constant de l'identifiant ; 5 essais
  puis 15 minutes de blocage par adresse.
- Session aléatoire (256 bits), cookie `HttpOnly`, `SameSite=Strict`, `Secure` sur option ;
  nouvelle session à chaque connexion.
- Jeton CSRF sur chaque formulaire, vérification de l'en-tête `Origin`.
- `Content-Security-Policy` stricte (`default-src 'self'`, aucun script en ligne),
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, pages non mises en cache.
- Rendu par `html/template` : texte échappé, adresses de liens assainies. Les liens venant des
  invités (label OCI `source`) ne sont gardés que s'ils pointent vers GitHub, GitLab ou
  Codeberg.
- Confirmation explicite pour toute action ; nom de l'invité à saisir pour les invités
  critiques, OMV et PBS, et pour un retour arrière.

**Appels sortants et secrets**
- API Proxmox : jeton en lecture seule (PVEAuditor), certificat épinglé.
- Portainer : certificat épinglé ou autorité dédiée ; jeton jamais affiché ni journalisé.
- Scripts community-scripts : seules les sources de `allowed_bases` sont lues.
- Secrets hors du dépôt (variables d'environnement, `patchwarden.env` en 640) ; avertissement si
  un fichier de configuration est lisible par tous ; page Réglages sans aucun secret.
- `/metrics` désactivé sans jeton ; jeton comparé en temps constant.

## Corrections faites lors de cette revue

| Gravité | Problème | Correction |
| :--- | :--- | :--- |
| Moyenne | **Invité compromis → requêtes de PatchWarden vers n'importe quelle adresse.** La référence d'une image Docker vient de l'invité ; son registre (et l'adresse d'authentification qu'il renvoie) était contacté tel quel. Un invité pouvait faire envoyer des requêtes GET/HEAD vers une machine interne | Liste de registres autorisés, `[docker] registries` (Docker Hub, ghcr.io, lscr.io, quay.io…). Une image d'un autre registre reste « inconnu » |
| Faible | **Fichiers temporaires prévisibles dans les VM.** Le script envoyé par l'agent invité était déposé sous un nom prévisible dans `/var/tmp` ; un utilisateur de la VM pouvait y préparer un lien. Le noyau Debian bloque déjà ce cas (`fs.protected_symlinks`), mais rien ne le garantissait | Dossier créé par `mktemp -d` (droits 700), supprimé à la fin (wrapper v13) |
| Faible | Même cas pour le journal d'`apt-get update` de la détection, sous un nom fixe dans `/tmp` | `mktemp` (wrapper v13) |
| Faible | La table des essais de connexion pouvait grossir sans limite (une entrée par adresse) | Ménage des entrées anciennes au-delà de 1 000 |

## Risques acceptés et recommandations

| Sujet | Analyse | Recommandation |
| :--- | :--- | :--- |
| Interface en HTTP | Le mot de passe et le cookie circulent en clair sur le réseau local | Servir l'interface en HTTPS (reverse proxy) et activer `server.cookie_secure` ; à défaut, la garder sur le VLAN d'administration |
| Vérification HTTP après une opération | Le certificat de l'adresse vérifiée n'est pas contrôlé : il s'agit seulement de savoir si le service répond. L'adresse est réglée par l'administrateur | Aucune |
| Données de détection | Tout ce que renvoie un invité est déclaratif : un invité compromis peut mentir sur ses paquets, ses conteneurs ou ses services. Il ne peut ni exécuter de code dans PatchWarden ni agir hors de lui-même | Garder la confirmation humaine (déjà la règle) ; la sécurité automatique ne concerne que les invités du tag choisi |
| Rattachement Portainer | L'environnement Portainer d'un invité est trouvé par les identifiants de conteneurs qu'il déclare. Un invité compromis qui connaîtrait ceux d'un autre hôte pourrait faire afficher les stacks de cet hôte sur sa fiche ; une mise à jour demande toujours la confirmation de l'administrateur | Donner au jeton Portainer les seuls environnements utiles |
| Jeton Portainer | Portainer CE n'a pas de rôle intermédiaire : le jeton peut souvent plus que le re-déploiement | Utilisateur dédié, accès limité aux environnements et stacks concernés |
| Variables `PATCHWARDEN_*` du wrapper | Elles servent aux tests (chemins, délais). sshd ne les transmet pas par défaut | Ne jamais les ajouter à `AcceptEnv` sur les nœuds |
| Journaux | Le journal d'une tâche reprend la sortie des commandes de l'invité | Ne pas y faire afficher de secrets (scripts tiers) |
| Sécurité automatique | Exception assumée à « aucune action sans confirmation » : le tag vaut confirmation | Désactivée par défaut ; limitée à « Sécurité uniquement », snapshot, vérification, arrêt au premier échec |

## Vérifications automatiques

L'intégration continue (`.github/workflows/ci.yml`) lance à chaque pull request : `gofmt`,
`go vet`, les tests avec détection des accès concurrents (`-race`), `shellcheck` sur le
wrapper et la sonde, et la compilation.
