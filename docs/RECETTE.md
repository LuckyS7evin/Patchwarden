# Cahier de recette — jalons 6 et 7

À dérouler dans l'ordre : chaque partie prépare la suivante. Durée : 1 h 30 à 2 h,
dont beaucoup d'attente pendant les mises à jour. Les tests marqués *(facultatif)*
peuvent être sautés sans gêner la suite.

**Avant de commencer :**
- [ ] une sauvegarde PBS récente existe pour les invités que vous allez mettre à jour
  « pour de vrai » (Forgejo, Termix, VM 503, et PBS/OMV si vous testez leur mise à
  jour réelle) ;
- [ ] aucune sauvegarde, vérification ou synchronisation PBS n'est en cours pendant la partie F.

**En cas d'écart**, notez l'identifiant du test (par exemple `D3`) et envoyez :
le journal de la tâche (page de la tâche, « journal complet »), le chemin
`pw.node_log=…` qu'il contient (journal complet sur le nœud, gardé 30 jours) et
une capture de la page.

---

## A. Installation

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| A1 | Dans le CT 103 : `cd /root/Patchwarden && git pull --ff-only && make build && install -m 755 bin/patchwarden /usr/local/bin/patchwarden && systemctl restart patchwarden` | Le service redémarre (`systemctl status patchwarden` : *active*) | [ ] |
| A2 | Sur LOKI : réinstaller le wrapper sur les 3 nœuds (`pct pull 103 /root/Patchwarden/deploy/patchwarden-wrapper /tmp/patchwarden-wrapper`, `install`, boucle `scp` vers TYR et ODIN, voir README étape 6) | Même empreinte `sha256sum` sur les 3 nœuds | [ ] |
| A3 | Dans le CT 103 : `patchwarden check-config` | Les 3 nœuds en ✔ avec `pw.wrapper_version=8` | [ ] |
| A4 | Ouvrir l'interface, recharger avec Ctrl+Maj+R | Pied de page avec la nouvelle version ; menu, thème, compte en bas à gauche | [ ] |

## B. Détection (LXC et VM)

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| B1 | « Détecter tout » (en haut) | Le nombre entre parenthèses inclut désormais les VM démarrées ; une tâche par invité dans « Tâches » | [ ] |
| B2 | Ouvrir la détection de la VM 503 (docker) | Tâche réussie, verbe `vm-detect 503 1` ; paquets apt, OS, stockage ; les accents du journal sont corrects | [ ] |
| B3 | Inventaire : colonne « Mises à jour » des VM | Plus aucun « VM : prochain jalon » ; badges apt/sécu comme pour les LXC | [ ] |
| B4 | Fiche de la VM PBS et de la VM OMV | Badge « Proxmox Backup Server x.y » / « OpenMediaVault x.y » ; ligne « Produit » dans « Système » : *confirmation renforcée, hors lots* | [ ] |
| B5 | Fiche de la VM 503 (Debian 11) | Ligne « Support » rouge : *plus aucun correctif de sécurité depuis le 31/08/2026* ; badge « OS sans support » dans l'inventaire | [ ] |
| B6 | Fiche d'un LXC Debian 12 | Ligne « Support » orange : *support standard terminé le 10/06/2026 ; correctifs Debian LTS jusqu'au 30/06/2028* | [ ] |
| B7 | « À traiter », groupe « Entretien » | Une ligne par OS sans support ou en fin de support ; aucune case à cocher sur ces lignes | [ ] |
| B8 *(facultatif)* | Sur une VM sans importance : `systemctl stop qemu-guest-agent` dans la VM, puis « Détecter » sur sa fiche ; relancer l'agent ensuite | Tâche échouée : *agent invité … injoignable (qemu-guest-agent installé et démarré…)* | [ ] |

## C. Redémarrages (jalon 6)

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| C1 | « À traiter » | Groupe « Redémarrages » si des services utilisent d'anciennes bibliothèques (fréquent juste après des mises à jour, ex. Termix ou Forgejo) ; badge « N service(s) à redémarrer » dans l'inventaire | [ ] |
| C2 | Fiche d'un tel LXC non critique → carte « Redémarrage » → « Redémarrer les services… » | Page de confirmation : liste des services, services système à part ; bouton actif seulement après la case | [ ] |
| C3 | Valider sans cocher la case, puis en la cochant | Sans case : refus ; avec : tâche « redémarrage des services », étapes qui avancent, `PW: xxx.service redémarré`, détection de fin ; la carte disparaît ou ne garde que les services système | [ ] |
| C4 | Même LXC (ou un autre sans importance) → « Redémarrer le CT… » | Tâche « redémarrage du CT » : `pct reboot`, `PW: état après : running`, détection de fin ; l'appli répond ensuite | [ ] |

## D. Lots (jalon 6)

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| D1 | « À traiter » : cocher la case d'en-tête du groupe « Sécurité » | Toutes les lignes du groupe se cochent ; barre en bas « N invités sélectionnés · Préparer le lot… » ; les invités critiques n'ont pas de case | [ ] |
| D2 | Filtre par tag (puces en haut de « À traiter ») | Seuls les invités du tag restent affichés | [ ] |
| D3 | « Préparer le lot… » | Page « Préparer un lot » : une ligne par invité, opération modifiable, snapshot par invité (pré-coché pour les versions majeures), lignes ignorées grisées avec la raison | [ ] |
| D4 | « Simuler le lot » (sans cocher la confirmation) | Page du lot qui se met à jour seule ; une simulation par invité, l'une après l'autre ; statut final « terminé » ; aucune notification ntfy | [ ] |
| D5 | Préparer un lot réel de 2 ou 3 LXC sans importance en « sécurité uniquement », snapshot coché sur au moins un ; « Appliquer le lot » d'abord **sans** cocher la confirmation, puis en la cochant | Sans case : retour avec message d'erreur ; avec : opérations une par une, snapshot pris pour l'invité concerné, page du lot à jour, **un seul** message ntfy en fin de lot | [ ] |
| D6 | « Tâches » | Section « Lots récents » avec les deux lots, lien vers chacun | [ ] |
| D7 | Inventaire → « Grouper : par tag » → sur un groupe, « préparer un lot : sécurité (N) » | Page de préparation avec les invités du tag qui ont des correctifs | [ ] |
| D8 | Mettre PBS ou OMV dans une sélection (depuis l'inventaire par tag, ou un lot par tag qui les contient) | Ligne ignorée : *… à lancer depuis sa fiche (confirmation renforcée)* | [ ] |
| D9 *(facultatif)* | Pendant un lot réel, `systemctl restart patchwarden` | Le lot apparaît « interrompu », les opérations restantes « annulée » ; celle en cours se termine sur le nœud (journal `pw.node_log`) | [ ] |

## E. VM (jalon 7) — avec la VM 503 ou une autre VM sans importance

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| E1 | Fiche VM → « Sécurité uniquement… » → « Simuler » | Tâche réussie, `vm-apt 503 security 1`, liste des paquets ; snapshot « possible » si coché par défaut | [ ] |
| E2 | « Appliquer » avec « Prendre un snapshot avant » coché | `vm-snapshot` puis `vm-apt` ; le journal apt **arrive par morceaux toutes les 2 s environ** ; détection de fin ; dans Proxmox, snapshot `pw-…` sur la VM | [ ] |
| E3 | Dans la VM : `ls /var/tmp/patchwarden-*` | Aucun fichier restant | [ ] |
| E4 *(facultatif)* | Fiche VM → onglet « Snapshots » → « Revenir à cet état… » (nom à saisir) | `qm rollback`, puis `qm start` ; la VM redémarre ; détection de fin : les correctifs sont de nouveau en attente | [ ] |
| E5 | Onglet « Snapshots » → « Supprimer » (avec la case) | Snapshot supprimé dans Proxmox | [ ] |
| E6 | Si la carte « Redémarrage » apparaît : « Redémarrer les services… » | Comme C3, dans la VM (`vm-restart-services`) | [ ] |
| E7 *(facultatif)* | « Redémarrer la VM… » | `qm reboot`, puis *agent invité de nouveau joignable* ; détection de fin | [ ] |

## F. OMV et PBS (jalon 7)

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| F1 | Fiche PBS → aperçu de « Tout mettre à jour » | Étape *apt-get dist-upgrade (méthode recommandée par Proxmox pour PBS)* ; avertissement « aucune sauvegarde … en cours » ; s'il y a des suppressions, action bloquée avec le nombre de paquets | [ ] |
| F2 | Page de confirmation PBS | Nom de l'invité à saisir pour appliquer ; « Simuler » fonctionne sans le nom | [ ] |
| F3 | Fiche OMV → aperçu de « Tout mettre à jour » | Étape *omv-upgrade (méthode OpenMediaVault…)* ; snapshot impossible si des disques sont en passthrough, avec la raison | [ ] |
| F4 | « Simuler » sur OMV | Tâche réussie : simulation de `dist-upgrade` | [ ] |
| F5 *(facultatif, sauvegarde à jour !)* | Appliquer « Sécurité uniquement » sur PBS, nom saisi | Mise à jour réussie, détection de fin ; PBS répond toujours (interface web, datastores) | [ ] |
| F6 *(facultatif, sauvegarde à jour !)* | Appliquer « Tout mettre à jour » sur OMV | `omv-upgrade` dans le journal ; partages toujours accessibles après | [ ] |

## G. Non-régression rapide

| # | Étapes | Résultat attendu | OK |
| :--- | :--- | :--- | :---: |
| G1 | Une mise à jour LXC seule, avec snapshot, depuis la fiche | Comme avant : étapes, terminal, snapshot, détection de fin | [ ] |
| G2 | Inventaire : clic sur une ligne | Tiroir d'aperçu, avec la ligne « Support » si l'OS est concerné | [ ] |
| G3 | Téléphone : « À traiter », une fiche, la page d'un lot | Lisible, boutons accessibles, frise des versions avec son lien changelog | [ ] |

---

**Bilan** : nombre de tests OK : ___ / ___ · écarts : ______________________
