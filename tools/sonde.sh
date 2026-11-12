#!/usr/bin/env bash
# ==============================================================================
# PatchWarden - sonde de vérification des hypothèses (jalon 0)
# ==============================================================================
# À lancer en root sur UN nœud Proxmox. Lecture seule, à trois exceptions près,
# toutes dans les invités et sans effet sur les applis :
#   - fichiers temporaires dans /tmp de l'invité (simulation apt « sécurité seule ») ;
#   - avec --refresh-apt uniquement : `apt-get update` (rafraîchit l'index apt) ;
#   - avec --test-stream uniquement : une boucle `echo` de 4 à 5 secondes.
# Rien n'est installé, mis à jour, redémarré ni snapshotté.
#
# Usage :
#   bash sonde.sh                          # inventaire du nœud seulement
#   bash sonde.sh --ct 119 --ct 121        # + analyse de LXC
#   bash sonde.sh --vm 236                 # + analyse d'une VM (guest agent)
#   bash sonde.sh --all                    # tous les invités démarrés du nœud
# Options :
#   --refresh-apt   lance `apt-get update` dans l'invité avant la simulation
#   --test-stream   mesure si la sortie de pct exec / qm guest exec arrive en direct
#
# La sortie est aussi écrite dans ./patchwarden-sonde-<nœud>-<date>.txt.
# Relis-la avant de la partager : la sonde évite les variables d'environnement
# Docker et les descriptions d'invités, mais elle affiche IP, noms et chemins.
# ==============================================================================

set -uo pipefail
export LC_ALL=C

CTS=()
VMS=()
ALL=0
REFRESH=0
STREAM=0

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
  --ct) CTS+=("${2:?--ct attend un CTID}"); shift 2 ;;
  --vm) VMS+=("${2:?--vm attend un VMID}"); shift 2 ;;
  --all) ALL=1; shift ;;
  --refresh-apt) REFRESH=1; shift ;;
  --test-stream) STREAM=1; shift ;;
  -h | --help) usage; exit 0 ;;
  *) echo "Option inconnue : $1" >&2; usage; exit 2 ;;
  esac
done

for id in "${CTS[@]}" "${VMS[@]}"; do
  [[ "$id" =~ ^[0-9]+$ ]] || { echo "ID invalide : $id" >&2; exit 2; }
done

if [[ "$(id -u)" != 0 ]] || ! command -v pct >/dev/null 2>&1; then
  echo "À lancer en root sur un nœud Proxmox VE (pct introuvable ou pas root)." >&2
  exit 1
fi

NODE="$(hostname)"
OUT="./patchwarden-sonde-${NODE}-$(date +%Y%m%d-%H%M).txt"
exec > >(tee "$OUT") 2>&1

h1() { printf '\n==============================================================\n%s\n==============================================================\n' "$1"; }
h2() { printf '\n--- %s ---\n' "$1"; }

# ------------------------------------------------------------------------------
# Script exécuté DANS l'invité (LXC via pct exec, VM via qm guest exec).
# Arguments : $1 = rafraîchir apt (0/1), $2 = slug community-scripts ou « - ».
# ------------------------------------------------------------------------------
read -r -d '' INNER <<'INNER_EOF'
REFRESH="${1:-0}"; SLUG="${2:--}"
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
sec() { printf '\n--- %s ---\n' "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }

sec "système"
if [ -r /etc/os-release ]; then . /etc/os-release; fi
echo "os=${ID:-?} ${VERSION_ID:-?} (${PRETTY_NAME:-?})"
echo "nproc=$(nproc 2>/dev/null) ram_mo=$(awk '/^MemTotal:/{printf "%d",$2/1024}' /proc/meminfo)"
df -P / | awk 'NR==2{print "racine_utilisée="$5" libre_ko="$4}'
line=""
for c in bash curl wget jq whiptail apt-get unattended-upgrade needrestart docker omv-upgrade proxmox-backup-manager; do
  if has "$c"; then line="$line $c=oui"; else line="$line $c=non"; fi
done
echo "outils :$line"
if [ -e /var/run/reboot-required ]; then echo "redémarrage_requis=oui"; else echo "redémarrage_requis=non"; fi

sec "community-scripts : /usr/bin/update"
if [ -f /usr/bin/update ]; then
  ls -l /usr/bin/update
  sed -n '1,30p' /usr/bin/update
else
  echo "absent (invité non créé par community-scripts, ou entrée supprimée)"
fi

sec "fichiers de version /root/.<app>"
found=0
for f in /root/.[!.]*; do
  [ -f "$f" ] || continue
  [ "$(stat -c %s "$f")" -le 80 ] || continue
  [ "$(wc -l <"$f")" -le 1 ] || continue
  v="$(tr -d '\r\n' <"$f")"
  if printf '%s' "$v" | grep -Eq '^v?[0-9][0-9A-Za-z._+-]*$'; then
    printf '%s=%s (modifié le %s)\n' "${f##*/}" "$v" "$(stat -c %y "$f" | cut -d. -f1)"
    found=1
  fi
done
[ "$found" = 1 ] || echo "aucun"

sec "addons, état community-scripts, journaux"
ls -1 /usr/local/bin/update_* 2>/dev/null | sed 's/^/addon : /' || true
ls -la /usr/local/community-scripts 2>/dev/null || echo "/usr/local/community-scripts absent"
ls -lt /tmp/build-*.log /root/.install-*.log 2>/dev/null | head -5 || true

if has apt-get; then
  sec "apt : sources"
  grep -hsE '^[[:space:]]*deb[[:space:]]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list | sed 's/^/  /'
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] && awk -v f="${f##*/}" '/^(URIs|Suites|Components|Enabled):/{printf "  %s  %s\n", f, $0}' "$f"
  done
  newest="$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -1)"
  if [ -n "$newest" ]; then echo "âge de l'index apt : $(( ($(date +%s) - ${newest%.*}) / 3600 )) h"; fi
  if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then echo "unattended-upgrades : configuré"; fi

  if [ "$REFRESH" = 1 ]; then
    sec "apt-get update"
    apt-get update -q >/tmp/pw-sonde-apt-update.log 2>&1
    echo "code de sortie : $?"
    tail -n 4 /tmp/pw-sonde-apt-update.log
    rm -f /tmp/pw-sonde-apt-update.log
  fi

  sec "apt : simulation complète (dist-upgrade -s)"
  sim="$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>&1)"
  inst="$(printf '%s\n' "$sim" | grep '^Inst ')"
  total="$(printf '%s\n' "$inst" | grep -c '^Inst ')"
  secu="$(printf '%s\n' "$inst" | grep -ci 'securi')"
  up="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ')"
  echo "paquets : $total (dist-upgrade), $up (upgrade simple), dont origine sécurité : $secu"
  printf '%s\n' "$inst" | head -n 40
  [ "$total" -gt 40 ] && echo "… ($((total - 40)) lignes de plus)"
  printf '%s\n' "$sim" | grep -E '^(W|E):' | head -n 5

  sec "apt : simulation « sécurité seule » stricte (dépôts *-security uniquement)"
  tmp="$(mktemp -d /tmp/pw-sonde.XXXXXX)"
  mkdir -p "$tmp/parts"
  : >"$tmp/sources.list"
  grep -hsE '^[[:space:]]*deb[[:space:]].*-security' /etc/apt/sources.list /etc/apt/sources.list.d/*.list >"$tmp/sources.list"
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    awk 'BEGIN{RS="";ORS=""}
      { n=split($0,L,"\n"); out=""; keep=0; off=0
        for(i=1;i<=n;i++){
          if (L[i] ~ /^Enabled:[ \t]*no/) off=1
          if (L[i] ~ /^Suites:/){ m=split(L[i],W,/[ \t]+/); s="Suites:"
            for(j=2;j<=m;j++) if (W[j] ~ /-security$/){ s=s" "W[j]; keep=1 }
            L[i]=s }
          out=out L[i] "\n" }
        if (keep && !off) print out "\n" }' "$f" >"$tmp/parts/${f##*/}"
  done
  nsrc="$(cat "$tmp/sources.list" "$tmp"/parts/* 2>/dev/null | grep -cE '^(deb |Suites:)')"
  echo "entrées de dépôt sécurité trouvées : $nsrc"
  if [ "$nsrc" -gt 0 ]; then
    ssim="$(apt-get -s -o Debug::NoLocking=1 -o Dir::Etc::SourceList="$tmp/sources.list" \
      -o Dir::Etc::SourceParts="$tmp/parts" dist-upgrade 2>&1)"
    echo "paquets en mode sécurité strict : $(printf '%s\n' "$ssim" | grep -c '^Inst ')"
    printf '%s\n' "$ssim" | grep '^Inst ' | head -n 20
    printf '%s\n' "$ssim" | grep -E '^(W|E):|broken|unmet' | head -n 8
  fi
  rm -rf "$tmp"
fi

sec "accès réseau depuis l'invité"
if has curl; then
  urls="https://raw.githubusercontent.com/community-scripts/core/main/misc/update.sh https://api.github.com/rate_limit https://registry-1.docker.io/v2/ https://ghcr.io/v2/"
  [ "$SLUG" != "-" ] && urls="$urls https://community-scripts.org/api/update-info?slug=$SLUG"
  for u in $urls; do
    printf '%s %s\n' "$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$u")" "$u"
  done
  [ "$SLUG" != "-" ] && echo "update-info : $(curl -s -m 10 "https://community-scripts.org/api/update-info?slug=$SLUG" | head -c 300)"
  echo "(401 sur les registres = joignable, authentification attendue)"
else
  echo "curl absent"
fi

if has docker && ! docker info >/dev/null 2>&1; then
  sec "Docker"
  echo "client docker présent mais démon injoignable"
elif has docker; then
  sec "Docker"
  docker version --format 'moteur {{.Server.Version}}' 2>&1 | head -n 1
  docker compose version 2>/dev/null | head -n 1 || echo "plugin compose absent"
  echo "conteneurs (nom | image | état | projet compose | working_dir | config_files | service | oci.source | oci.version | watchtower.enable) :"
  for id in $(docker ps -aq); do
    docker inspect -f '{{.Name}} | {{.Config.Image}} | {{.State.Status}} | {{index .Config.Labels "com.docker.compose.project"}} | {{index .Config.Labels "com.docker.compose.project.working_dir"}} | {{index .Config.Labels "com.docker.compose.project.config_files"}} | {{index .Config.Labels "com.docker.compose.service"}} | {{index .Config.Labels "org.opencontainers.image.source"}} | {{index .Config.Labels "org.opencontainers.image.version"}} | {{index .Config.Labels "com.centurylinklabs.watchtower.enable"}}' "$id" 2>&1
  done
  echo
  echo "images utilisées (id | RepoTags | RepoDigests) :"
  for img in $(docker ps -aq | xargs -r docker inspect -f '{{.Image}}' | sort -u); do
    docker image inspect -f '{{.Id}} | {{json .RepoTags}} | {{json .RepoDigests}}' "$img" 2>&1
  done
  echo
  echo "montages de Portainer (où sont stockées les stacks) :"
  for id in $(docker ps -aq); do
    img="$(docker inspect -f '{{.Config.Image}}' "$id")"
    case "$img" in
    *portainer*) docker inspect -f '{{.Name}} ({{.Config.Image}}) : {{range .Mounts}}{{.Source}} -> {{.Destination}}; {{end}}' "$id" ;;
    esac
  done
  echo "conteneurs Watchtower : $(docker ps -a --format '{{.Image}}' | grep -ci watchtower)"
fi
INNER_EOF

# ------------------------------------------------------------------------------
# Côté hôte
# ------------------------------------------------------------------------------
declare -A STYPE=()
while read -r t n; do STYPE["$n"]="$t"; done < <(sed -nE 's/^([a-z0-9]+):[[:space:]]+([A-Za-z0-9._-]+)[[:space:]]*$/\1 \2/p' /etc/pve/storage.cfg)

# Verdict snapshot pour une ligne de disque/rootfs/mp. $1 = lxc|vm, $2 = valeur de config.
snap_verdict() {
  local kind="$1" val="$2" vol st t
  vol="${val%%,*}"
  case "$vol" in
  /dev/*) echo "NON (disque physique en passthrough)"; return ;;
  /*) echo "ignoré (bind mount hôte, hors snapshot)"; return ;;
  none) echo "ignoré (pas de média)"; return ;;
  esac
  [[ "$val" == *media=cdrom* ]] && { echo "ignoré (cdrom)"; return; }
  st="${vol%%:*}"
  t="${STYPE[$st]:-inconnu}"
  case "$t" in
  zfspool | lvmthin | btrfs | rbd) echo "oui (stockage $st de type $t)" ;;
  dir | nfs | cifs | glusterfs | cephfs)
    if [[ "$kind" == vm && "$vol" == *.qcow2 ]]; then echo "oui (qcow2 sur $st de type $t)"
    else echo "NON (stockage $st de type $t sans qcow2)"; fi ;;
  lvm | iscsi | iscsidirect) echo "NON (stockage $st de type $t)" ;;
  *) echo "à vérifier (stockage $st de type $t)" ;;
  esac
}

# Analyse du script ct/<nom>.sh community-scripts (téléchargé par l'hôte).
analyse_ct_script() {
  local name="$1" base="$2" body
  h2 "script ${base}/ct/${name}.sh"
  if ! body="$(curl -fsSL -m 15 "${base}/ct/${name}.sh")"; then
    echo "introuvable (script renommé ou supprimé ?)"
    return
  fi
  printf '%s\n' "$body" | grep -E '^var_(cpu|ram|disk|os|version)=' | sed 's/^/  /'
  echo "  éléments de la fonction update_script :"
  printf '%s\n' "$body" | awk '/^function update_script|^update_script\(\)/,/^}/' |
    grep -nE 'check_for_[a-z_]*(release|tag)|fetch_and_deploy|run_os_update|apt(-get)? .*upgrade|npm (install|update)|pip|uv |docker|read -r|whiptail|msg_menu|prompt_confirm|exit [0-9]+' |
    head -n 25 | sed 's/^/    /'
}

probe_ct() {
  local id="$1"
  local conf="/etc/pve/nodes/${NODE}/lxc/${id}.conf" status out name base
  h1 "LXC ${id}"
  if [[ ! -f "$conf" ]]; then echo "CT ${id} absent de ce nœud (${NODE})."; return; fi
  status="$(pct status "$id" 2>&1)"
  echo "$status"
  h2 "configuration (sans la description)"
  sed -n '/^\[/q;p' "$conf" | grep -vE '^#|^description:' | sed 's/^/  /'
  h2 "capacité de snapshot"
  while IFS= read -r l; do
    printf '  %s -> %s\n' "${l%%:*}" "$(snap_verdict lxc "${l#*: }")"
  done < <(sed -n '/^\[/q;p' "$conf" | grep -E '^(rootfs|mp[0-9]+):')
  echo "  snapshots existants :"
  pct listsnapshot "$id" 2>&1 | sed 's/^/    /'

  if [[ "$status" != *running* ]]; then
    echo "Invité arrêté : analyse interne impossible (pct exec exige un CT démarré)."
    return
  fi

  # Slug lu dans /usr/bin/update, pour l'appel update-info et l'analyse du script.
  name="$(timeout 30 pct exec "$id" -- sh -c "sed -nE 's/^export UPDATE_SCRIPT_NAME=\"?([A-Za-z0-9._-]+).*/\1/p' /usr/bin/update 2>/dev/null | head -n1")"
  [[ -z "$name" ]] && name="$(timeout 30 pct exec "$id" -- sh -c "grep -oE '/ct/[A-Za-z0-9._-]+\.sh' /usr/bin/update 2>/dev/null | head -n1 | sed 's|.*/ct/||; s|\.sh\$||'")"
  base="$(timeout 30 pct exec "$id" -- sh -c "sed -nE 's/^export COMMUNITY_SCRIPTS_URL=\"?([^\"]+).*/\1/p' /usr/bin/update 2>/dev/null | head -n1")"
  base="${base:-https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main}"
  echo "appli community-scripts détectée : ${name:-aucune}"

  out="$(timeout 600 pct exec "$id" -- bash -c "$INNER" pw-sonde "$REFRESH" "${name:--}" 2>&1)"
  echo "code de sortie de pct exec : $?"
  printf '%s\n' "$out"

  [[ -n "$name" ]] && analyse_ct_script "$name" "$base"

  if [[ "$STREAM" == 1 ]]; then
    h2 "test de flux pct exec (horodatage à la réception côté hôte, attendu : 1 ligne/s)"
    timeout 30 pct exec "$id" -- bash -c 'for i in 1 2 3 4; do echo "ligne $i"; sleep 1; done; printf "sans saut de ligne\r"; sleep 1; echo fin' 2>&1 |
      while IFS= read -r l; do printf '  %s  %s\n' "$(date +%T.%N | cut -c1-12)" "$l"; done
  fi
}

# Exécute une commande via le guest agent et affiche sortie + code.
qga_exec() {
  local vmid="$1"; shift
  qm guest exec "$vmid" --timeout 600 -- "$@" 2>&1 | perl -MJSON::PP -0777 -ne '
    my $j = eval { JSON::PP->new->decode($_) };
    if (!$j) { print "réponse brute : $_\n"; exit }
    print $j->{"out-data"} // "";
    print "\n[stderr]\n", $j->{"err-data"} if defined $j->{"err-data"} && length $j->{"err-data"};
    print "\n[code de sortie : ", ($j->{exitcode} // "?"), "]";
    print " [SORTIE TRONQUÉE]" if $j->{"out-truncated"};
    print " [pas terminé dans le délai]" unless $j->{exited};
    print "\n";'
}

probe_vm() {
  local id="$1"
  local conf="/etc/pve/nodes/${NODE}/qemu-server/${id}.conf" status
  h1 "VM ${id}"
  if [[ ! -f "$conf" ]]; then echo "VM ${id} absente de ce nœud (${NODE})."; return; fi
  status="$(qm status "$id" 2>&1)"
  echo "$status"
  h2 "configuration (extrait)"
  sed -n '/^\[/q;p' "$conf" | grep -E '^(name|ostype|cores|memory|balloon|agent|onboot|tags|machine|bios|hostpci[0-9]+|usb[0-9]+|(scsi|virtio|sata|ide|efidisk|tpmstate)[0-9]+):' | sed 's/^/  /'
  h2 "capacité de snapshot"
  while IFS= read -r l; do
    printf '  %s -> %s\n' "${l%%:*}" "$(snap_verdict vm "${l#*: }")"
  done < <(sed -n '/^\[/q;p' "$conf" | grep -E '^(scsi|virtio|sata|ide|efidisk|tpmstate)[0-9]+:')
  grep -qE '^hostpci[0-9]+:' "$conf" && echo "  hostpci présent : le snapshot avec état RAM est impossible, et Proxmox peut refuser le snapshot"
  echo "  snapshots existants :"
  qm listsnapshot "$id" 2>&1 | sed 's/^/    /'

  if [[ "$status" != *running* ]]; then echo "VM arrêtée : analyse interne impossible."; return; fi
  h2 "guest agent"
  if ! timeout 15 qm agent "$id" ping >/dev/null 2>&1; then
    echo "le guest agent ne répond pas (agent: 1 dans la config ? qemu-guest-agent installé et démarré dans la VM ?)"
    return
  fi
  echo "ping : OK"
  qga_exec "$id" bash -c "$INNER" pw-sonde "$REFRESH" "-"

  if [[ "$STREAM" == 1 ]]; then
    h2 "test de flux qm guest exec (la sortie arrive-t-elle avant la fin du processus ?)"
    local pid t st
    pid="$(qm guest exec "$id" --synchronous 0 -- bash -c 'for i in 1 2 3 4 5; do echo "ligne $i"; sleep 1; done' 2>&1 |
      perl -MJSON::PP -0777 -ne 'my $j = eval { JSON::PP->new->decode($_) }; print $j->{pid} // ""')"
    if [[ -z "$pid" ]]; then echo "  impossible de lancer en asynchrone"; return; fi
    for t in 1 2 3 4 5 6 7; do
      sleep 1
      st="$(qm guest exec-status "$id" "$pid" 2>&1 | perl -MJSON::PP -0777 -ne '
        my $j = eval { JSON::PP->new->decode($_) } or do { print "illisible"; exit };
        my $o = $j->{"out-data"} // ""; $o =~ s/\n/\\n/g;
        print "terminé=", ($j->{exited} ? "oui" : "non"), " sortie=\"$o\""')"
      echo "  t+${t}s : $st"
    done
  fi
}

# ------------------------------------------------------------------------------
h1 "PatchWarden - sonde - nœud ${NODE} - $(date '+%F %T')"
echo "options : refresh-apt=${REFRESH} test-stream=${STREAM}"

h1 "Hôte"
pveversion 2>&1
if [[ -f /etc/pve/corosync.conf ]]; then echo "cluster : oui"; else echo "cluster : non (nœud autonome)"; fi
line=""
for c in sudo perl jq python3 curl timeout; do
  if command -v "$c" >/dev/null 2>&1; then line="$line $c=oui"; else line="$line $c=non"; fi
done
echo "outils :$line"
if qm help guest exec 2>/dev/null | grep -q pass-stdin; then echo "qm guest exec --pass-stdin : disponible"; else echo "qm guest exec --pass-stdin : absent"; fi
h2 "stockages"
pvesm status 2>&1
h2 "types de stockage (storage.cfg, en-têtes seulement)"
for n in "${!STYPE[@]}"; do echo "  $n : ${STYPE[$n]}"; done

h1 "Inventaire du nœud"
h2 "LXC (CTID | hostname | état | tags | non privilégié | features)"
for f in /etc/pve/nodes/"$NODE"/lxc/*.conf; do
  [[ -f "$f" ]] || continue
  id="$(basename "$f" .conf)"
  printf '  %s | %s | %s | %s | %s | %s\n' "$id" \
    "$(sed -n '/^\[/q;s/^hostname: //p' "$f")" "$(pct status "$id" 2>/dev/null | sed 's/status: //')" \
    "$(sed -n '/^\[/q;s/^tags: //p' "$f")" "$(sed -n '/^\[/q;s/^unprivileged: //p' "$f")" \
    "$(sed -n '/^\[/q;s/^features: //p' "$f")"
  [[ "$ALL" == 1 && "$(pct status "$id" 2>/dev/null)" == *running* ]] && CTS+=("$id")
done
h2 "VM (VMID | nom | état | tags | agent)"
for f in /etc/pve/nodes/"$NODE"/qemu-server/*.conf; do
  [[ -f "$f" ]] || continue
  id="$(basename "$f" .conf)"
  printf '  %s | %s | %s | %s | %s\n' "$id" \
    "$(sed -n '/^\[/q;s/^name: //p' "$f")" "$(qm status "$id" 2>/dev/null | sed 's/status: //')" \
    "$(sed -n '/^\[/q;s/^tags: //p' "$f")" "$(sed -n '/^\[/q;s/^agent: //p' "$f")"
  [[ "$ALL" == 1 && "$(qm status "$id" 2>/dev/null)" == *running* ]] && VMS+=("$id")
done

for id in "${CTS[@]}"; do probe_ct "$id"; done
for id in "${VMS[@]}"; do probe_vm "$id"; done

h1 "Fin de la sonde"
echo "Rapport enregistré dans ${OUT}"
